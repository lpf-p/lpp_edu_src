# -*- coding: utf-8 -*-
"""
公开版脱敏自检脚本 —— push 前跑一遍。

用法：python check_desensitize.py [仓库目录]     （默认当前目录）
退出码：0 = 实测类干净，可 push；1 = 实测类有活目标，先处理

与初版的区别（两个关键修正）：
  1. 只扫 **git 追踪** 的 md —— 本地 `知识库/_work/` 是 gitignore 的中间产物，
     扫它会产生一堆 GitHub 上根本不存在的假警报。
  2. 区分「实测类」与「公开报告类」：*-cases.md / edusrc-cases / ima-* / subkb-*
     里的域名来自**已公开收录的 SRC 报告**（报告原文就带），属公开信息二次整理，
     列入豁免区只提示不报错；我们自己实测记录里的域名才是活目标，命中即报错。

判定逻辑：
  - 高校域名：命中 .edu.cn / .ac.cn 且不含 "**" 打码、不在白名单 -> 报出
  - 公网 IP ：形如 a.b.c.d 或 a.b.c.d/nn，排除私网 / 保留 / 示例 -> 提示人工确认
"""
import os
import re
import sys
import io
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

# ── 公开报告来源（豁免区：只提示，不报错）
CASE_PAT = re.compile(r'(-cases\.md$|edusrc-cases|^ima-|subkb-|archive-inventory|other-census)')

IP_WHITELIST_PREFIX = (
    '127.', '0.', '255.', '10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.',
    '172.20.', '172.30.', '192.0.2.', '198.51.100.', '203.0.113.', '0.0.0.0',
    '169.254.', '100.100.100.200',
    '1.1.1.1', '8.8.8.8', '114.114.114.114',
    '1.2.3.4', '5.6.7.8', '9.9.9.9',
    '3.4.24.2', '3.9.8.', '3.9.9.', '4.0.0.0',     # 文档示例
)

DOMAIN_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._\-]*\.(?:edu\.cn|ac\.cn)')
IP_RE = re.compile(r'(?<![\d.])\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?(?![\d.])')


def tracked_files(root):
    """git 追踪的 md；非 git 目录时回退 walk（排除 _work）。

    ⚠️ 两个坑（都踩过）：
      1. 中文路径：`git ls-files` 默认对非 ASCII 路径做八进制转义
         （返回 "知识库/..." 的引号转义形式），直接 join 会文件不存在被跳过，
         导致「知识库/ 下全没扫」却报 OK。必须 `-z` + `core.quotePath=false`。
      2. `_work/` 是 gitignore 的中间产物，扫它全是假警报。
    """
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


def scan(root):
    must, exempt, ip, exempt_ip = {}, {}, {}, {}
    files = tracked_files(root)
    for p in files:
        if not os.path.exists(p):
            continue
        t = io.open(p, encoding='utf-8', errors='ignore').read()
        is_case = bool(CASE_PAT.search(os.path.basename(p)))
        for m in DOMAIN_RE.finditer(t):
            s = m.group(0)
            if '**' in s or any(w in s for w in WHITELIST):
                continue
            (exempt if is_case else must).setdefault(p, set()).add(s)
        for m in IP_RE.finditer(t):
            s = m.group(0)
            if s.startswith(IP_WHITELIST_PREFIX):
                continue
            (exempt_ip if is_case else ip).setdefault(p, set()).add(s)
    return len(files), must, exempt, ip, exempt_ip


def rel(p, root):
    return p.replace(root, '').lstrip('/\\') or p


def main():
    root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else '.')
    n, must, exempt, ip, exempt_ip = scan(root)
    print('扫描 %d 个 md（git 追踪，已排除 _work/）：%s\n' % (n, root))

    if must:
        print('!! 实测类未打码域名 —— 必须处理：%d 个文件' % len(must))
        for p in sorted(must, key=lambda x: -len(must[x])):
            print('   %-42s %2d 个  %s' % (rel(p, root), len(must[p]),
                                           ', '.join(sorted(must[p])[:8])))
        print()
    if ip:
        print(':: 公网 IP / CIDR —— 人工确认是否示例：%d 个文件' % len(ip))
        for p in sorted(ip):
            print('   %-42s %s' % (rel(p, root), ', '.join(sorted(ip[p])[:8])))
        print()
    if exempt:
        print(':: 公开报告类（豁免，仅提示）：%d 个文件 / %d 个域名 / %d 个 IP' %
              (len(exempt), sum(len(v) for v in exempt.values()),
               sum(len(v) for v in exempt_ip.values())))
        for p in sorted(exempt, key=lambda x: -len(exempt[x])):
            print('   %-42s %2d 个' % (rel(p, root), len(exempt[p])))
        print()

    if must:
        print('实测类 %d 处待处理，修完再 push。' % sum(len(v) for v in must.values()))
        return 1
    print('OK 实测类无活目标，可以 push。')
    return 0


if __name__ == '__main__':
    sys.exit(main())
