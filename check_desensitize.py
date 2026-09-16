# -*- coding: utf-8 -*-
"""
公开版脱敏自检脚本 —— push 前跑一遍。

用法：
    python check_desensitize.py .                   # 检查（退出码 0 = 可 push）
    python check_desensitize.py . --update-baseline # 存量定基（首次 / 大改后跑一次）

退出码：0 = 实测类无活目标、无新增，可 push；1 = 必须先处理

设计要点（三个坑都踩过，别改回去）：
  1. **只扫 git 追踪的 md**。本地 `知识库/_work/` 是 gitignore 的中间产物，扫它全是
     GitHub 上根本不存在的假警报。
  2. **`git ls-files` 必须 `-z` + `core.quotePath=false`**。默认对中文路径做八进制转义
     （返回 "知识库/..."），join 后文件不存在被跳过 → 「知识库 90 个文件全没扫」却报 OK。
     这是本脚本最危险的历史 bug：**假 OK 比报错危险得多**。
  3. **区分实测类 / 公开报告类**。`*-cases.md` 里的域名来自已公开收录的 SRC 报告
     （报告原文就带），属公开信息二次整理 → 豁免，只提示不报错。

两道护栏（防止「往 cases 文件里补自己的实测」被静默放过）：
  - 护栏 1：cases 文件若出现自建实测标记（如「2026-09-16 实测」「第五轮实测」「实测 234 站」），
    取消豁免，按严格模式审查。实测命中 `vendor-system-cases.md`。
  - 护栏 2：与基线比对，任何文件命中数增长即报。兜底「补了实测但没写『实测』二字」。
  两道护栏都**只对「基线之外的新增域名」报错**——否则会把文件里原有的公开报告域名
  一并报出，噪音会让人麻木，护栏等于没有。

基线文件 `.desens_baseline.json` 存的是各文件域名清单，**仅本地、已 gitignore**，
不会随仓库公开（它本身就是目标清单，绝不能 commit）。
"""
import os
import re
import sys
import io
import json
import subprocess

# ── 白名单：厂商官网 / 公开平台 / 示例域名（有意保留，不算泄露）
WHITELIST = [
    'wisedu.com',        # 金智教育官网
    'wrdtech.com',       # 网瑞达官网
    'weaver.com.cn',     # 泛微官网
    'seeyon',            # 致远
    'xyt-tech.com',      # 新云腾
    '163.com', '127.net',
    'src.sjtu.edu.cn',   # EDUSRC 平台本身（公开漏洞平台）
    'vulsrc.sjtu.edu.cn',
    'yale.edu',          # CAS 协议命名空间
    'github.com', 'apache.org', 'spring.io', 'w3.org', 'iana.org',
    'target.com', 'cdn.com', 'example.com', 'test.com', 'demo.com',
    'xxx.edu.cn', 'x.edu.cn',
]

# ── 公开报告来源（默认豁免，见护栏 1 的取消条件）
CASE_PAT = re.compile(r'(-cases\.md$|edusrc-cases|^ima-|subkb-|archive-inventory|other-census)')

# ── 自建实测标记：出现即说明该文件含「我们自己扫的」内容，不是公开报告摘录
SELFTEST_RE = re.compile(
    # ⚠️ 中间用 [^\n。] 而非 [^，。]：实测过「补录 2026-09-16，实测」这种写法中间有中文逗号，
    #    被 [^，。] 挡住会漏判。换行/句号才断句。
    r'20\d\d-\d\d-\d\d[^\n。]{0,12}实测'      # 2026-09-16 实测 / 补录 2026-09-16，实测
    r'|第[一二三四五六七八九十\d]+轮实测'      # 第五轮实测
    r'|实测\s*\d+\s*站'                       # 实测 234 站
)

IP_WHITELIST_PREFIX = (
    '127.', '0.', '255.', '10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.',
    '172.20.', '172.30.', '192.0.2.', '198.51.100.', '203.0.113.', '0.0.0.0',
    '169.254.', '100.100.100.200',
    '1.1.1.1', '8.8.8.8', '114.114.114.114',
    '1.2.3.4', '5.6.7.8', '9.9.9.9',
    '3.4.24.2', '3.9.8.', '3.9.9.', '4.0.0.0',
)

DOMAIN_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._\-]*\.(?:edu\.cn|ac\.cn)')
IP_RE = re.compile(r'(?<![\d.])\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?(?![\d.])')

BASELINE = '.desens_baseline.json'


def tracked_files(root):
    """git 追踪的 md（中文路径安全）；非 git 目录时回退 walk（排除 _work）。"""
    try:
        out = subprocess.check_output(
            ['git', '-C', root, '-c', 'core.quotePath=false', 'ls-files', '-z', '*.md'],
            stderr=subprocess.DEVNULL).decode('utf-8', 'ignore')
        return [os.path.join(root, p) for p in out.split('\0') if p]
    except Exception:
        res = []
        for dp, dn, fn in os.walk(root):
            if '.git' in dp.split(os.sep) or '_work' in dp.split(os.sep):
                continue
            res += [os.path.join(dp, f) for f in fn if f.endswith('.md')]
        return res


def rel(p, root):
    return p.replace(root, '').lstrip('/\\') or p


def scan(root):
    """返回 {文件: {'dom':set, 'ip':set, 'case':bool, 'selftest':bool}}"""
    res = {}
    for p in tracked_files(root):
        if not os.path.exists(p):
            continue
        t = io.open(p, encoding='utf-8', errors='ignore').read()
        d = {'dom': set(), 'ip': set(),
             'case': bool(CASE_PAT.search(os.path.basename(p))),
             'selftest': bool(SELFTEST_RE.search(t))}
        for m in DOMAIN_RE.finditer(t):
            s = m.group(0)
            if '**' in s or any(w in s for w in WHITELIST):
                continue
            d['dom'].add(s)
        for m in IP_RE.finditer(t):
            s = m.group(0)
            if s.startswith(IP_WHITELIST_PREFIX):
                continue
            d['ip'].add(s)
        if d['dom'] or d['ip']:
            res[rel(p, root)] = d
    return res


def main():
    args = [a for a in sys.argv[1:] if not a.startswith('-')]
    root = os.path.abspath(args[0] if args else '.')
    data = scan(root)
    ntracked = len(tracked_files(root))
    base_f = os.path.join(root, BASELINE)
    base = None
    if os.path.exists(base_f):
        try:
            base = json.load(io.open(base_f, encoding='utf-8'))
        except Exception:
            base = None

    print('扫描 %d 个 md（git 追踪，已排除 _work/）：%s\n' % (ntracked, root))

    must, must_ip, exempt, grew, ip_hit, downgraded = {}, {}, {}, [], {}, []

    for f, d in sorted(data.items()):
        b = base.get(f) if base else None
        known = set(b['dom']) if isinstance(b, dict) else (set(b) if b else set())
        new = d['dom'] - known                       # 基线之外的新增域名
        exempt_case = d['case'] and not d['selftest']  # 护栏 1：含实测标记 → 取消豁免
        if d['case'] and d['selftest']:
            downgraded.append(f)

        if exempt_case:
            if d['dom']:
                exempt[f] = d['dom']
        else:
            # 严格模式：只报「新增」，避免把文件里原有的公开报告域名一并报出造成噪音
            if new:
                must[f] = new
            elif not base and d['dom']:
                must[f] = d['dom']                   # 无基线：首次全量，请人工过一遍
        if base and b is not None and len(d['dom']) > len(known):
            grew.append((f, len(known), len(d['dom'])))

        # 缺口 3：IP 比域名更直接可用。仅在「严格模式文件」（非豁免 / 已取消豁免）
        # 里把 IP 纳入退出码；豁免的公开报告文件只提示，避免噪音。
        if d['ip']:
            ip_hit[f] = d['ip']
            if not exempt_case:
                known_ip = set(b['ip']) if isinstance(b, dict) else set()
                new_ip = d['ip'] - known_ip
                if new_ip or (b is None and d['ip']):
                    must_ip[f] = new_ip or d['ip']

    if downgraded:
        print(':: 护栏 1 —— 含自建实测标记的 cases 文件，已取消豁免按严格模式审查：')
        for f in sorted(downgraded):
            print('   %s' % f)
        print()
    if must:
        print('!! 实测类未打码域名 —— 必须处理：%d 个文件' % len(must))
        for f in sorted(must, key=lambda x: -len(must[x])):
            print('   %-42s %2d 个  %s' % (f, len(must[f]), ', '.join(sorted(must[f])[:8])))
        print()
    if must_ip:
        print('!! 严格模式文件中的公网 IP —— 必须处理：%d 个文件' % len(must_ip))
        for f in sorted(must_ip, key=lambda x: -len(must_ip[x])):
            print('   %-42s %s' % (f, ', '.join(sorted(must_ip[f])[:8])))
        print()
    if grew:
        print(':: 护栏 2 —— 命中数较基线增长，确认是否为新增实测记录：')
        for f, b, c in sorted(grew, key=lambda x: -(x[2] - x[1])):
            print('   %-42s %d → %d（+%d）' % (f, b, c, c - b))
        print()
    if ip_hit:
        print(':: 公网 IP / CIDR —— 人工确认是否示例：%d 个文件' % len(ip_hit))
        for f in sorted(ip_hit):
            print('   %-42s %s' % (f, ', '.join(sorted(ip_hit[f])[:8])))
        print()
    if exempt:
        print(':: 公开报告类（豁免，仅提示）：%d 个文件 / %d 个域名'
              % (len(exempt), sum(len(v) for v in exempt.values())))
        for f in sorted(exempt, key=lambda x: -len(exempt[x])):
            print('   %-42s %2d 个' % (f, len(exempt[f])))
        print()

    # 缺口 1：定基前必须先清空待处理项，否则一次手滑就把问题域名写进基线 → 此后永久静默，
    #         护栏退化成「一次性护栏」。这里直接拒绝。
    if '--update-baseline' in sys.argv:
        if must or must_ip:
            print('!! 有 %d 个文件待处理（域名 %d / IP %d），拒绝定基 —— 先修再定，防止洗白。'
                  % (len(set(must) | set(must_ip)),
                     sum(len(v) for v in must.values()),
                     sum(len(v) for v in must_ip.values())))
            return 1
        json.dump({f: {'dom': sorted(d['dom']), 'ip': sorted(d['ip'])} for f, d in data.items()},
                  io.open(base_f, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
        print('基线已写入 %s（%d 个文件，仅本地、已 gitignore）。' % (base_f, len(data)))
        return 0

    if not base:
        print('!! 尚无基线：以上为全量清单，人工过一遍后跑 `--update-baseline` 定基。')
        return 1
    if must or must_ip:
        print('实测类 %d 处待处理（域名 %d / IP %d），修完再 push。'
              % (len(set(must) | set(must_ip)),
                 sum(len(v) for v in must.values()),
                 sum(len(v) for v in must_ip.values())))
        return 1
    if grew:
        print('有 %d 个文件命中数增长，确认后再 push。' % len(grew))
        return 1
    print('OK 实测类无活目标、无新增，可以 push。')
    return 0


if __name__ == '__main__':
    sys.exit(main())
