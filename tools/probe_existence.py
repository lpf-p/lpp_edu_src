# -*- coding: utf-8 -*-
"""第 -1 步 · 判存在性（双轨四象限 + 门闸页排除）

配套 `rules/asset-existence-and-coverage.md`。进站前先跑本脚本，只对「确证存在」的做全类型矩阵。

用法:
    python probe_existence.py hosts.txt                 # 每行一个主机名
    python probe_existence.py hosts.txt -o out/
    python probe_existence.py -H a.example.com,b.example.com   # 直接给主机名

产出（落 -o 指定目录，默认 ./_raw）:
    asset_baseline.tsv   原始数据：状态码 / 长度 / sha1 / 主机级基线 / 路径级基线
    asset_ledger.md      账本骨架（表 A 格式，判定列已填，直接贴进 资产/资产账本.md）

纪律（内置，别绕过）:
    · 只发 GET，不带任何凭据
    · 单轮，不重试，主机间 sleep（默认 1s）
    · 不做目录爆破、不绕 WAF、不碰挑战页后面的东西

判定表（判定列只输出这五个值，与规则 §6 对齐）:
    确证存在           异形 + 未命中门闸页四联征
    存在但被门闸挡住   能建连、有独立响应体，但命中门闸页四联征
    不可判定           建连失败 / 等于路径级基线
    已被边缘登记·无后端 等于主机级基线
    确证未配置         DNS 无记录

门闸页四联征（命中即判"被门闸挡住"，详见规则 §3 第 4 条）:
    ① 无 <title>
    ② Server 头缺失或被掩码（****** / Server: Server）
    ③ 正文以 <script> 开头且含混淆或转义（_0x… / \\x…）
    ④ 提及 webdriver / BOM / 挑战类关键字
"""
import argparse
import hashlib
import io
import os
import random
import re
import socket
import ssl
import string
import sys
import time
import urllib.error
import urllib.request

UA = {"User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                     "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36")}
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

CHALLENGE_KEYS = ("webdriver", "stripBOM", "navigator[", "challenge", "verify you are human",
                  "人机", "滑块", "安全检查", "请稍候")
MASKED_SERVER = ("******", "*", "Server", "server")


def fetch(url, timeout=8):
    """返回 (status, length, sha1_12, server, body_head, body_text)。失败返回 status='ERR'。"""
    try:
        req = urllib.request.Request(url, headers=UA)
        r = urllib.request.urlopen(req, timeout=timeout, context=CTX)
        raw = r.read(400000)
        st, hdr = r.status, r.headers
    except urllib.error.HTTPError as e:
        try:
            raw = e.read(400000)
        except Exception:
            raw = b""
        st, hdr = e.code, e.headers
    except Exception as e:
        return "ERR", 0, type(e).__name__, "", "", ""

    body = raw.decode("utf-8", "replace")
    return (st, len(raw), hashlib.sha1(raw).hexdigest()[:12],
            (hdr.get("Server") or "").strip(), body[:200], body)


def is_gate_page(st, server, head, body):
    """门闸页四联征。返回 (bool, 命中了哪几条)。"""
    hit = []
    title = re.search(r"<title[^>]*>(.*?)</title>", body, re.S | re.I)
    if not title:
        hit.append("①无title")
    if not server or server in MASKED_SERVER:
        hit.append("②Server缺失/掩码")
    if re.match(r"\s*<!DOCTYPE html>\s*<meta[^>]*>\s*<script", body, re.I) or \
       re.match(r"\s*<script", body, re.I):
        if re.search(r"_0x[0-9a-f]{4,}|\\x[0-9a-f]{2}", body, re.I):
            hit.append("③script开头+混淆/转义")
    low = body[:20000].lower()
    if any(k.lower() in low for k in CHALLENGE_KEYS):
        hit.append("④含挑战关键字")
    # 四条里命中 >=3 才判门闸页，避免误伤普通无 title 的 SPA
    return (len(hit) >= 3), "+".join(hit)


def probe(host, rand, timeout=8, sleep=1.0, root=""):
    """probe 一台。root 缺省从 host 取后三段（a.b.example.com -> example.com）。"""
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return {"host": host, "ip": "", "verdict": "确证未配置",
                "why": "DNS 无记录", "tgt": None, "hbl": None, "pbl": None}

    if not root:
        parts = host.split(".")
        root = ".".join(parts[-3:]) if len(parts) >= 3 else host

    hbl = fetch("https://zzz-%s.%s/" % (rand, root), timeout)          # 主机级基线
    tgt = fetch("https://%s/" % host, timeout)                          # 目标
    pbl = fetch("https://%s/zzz-%s.html" % (host, rand), timeout)       # 路径级基线
    time.sleep(sleep)

    if tgt[0] == "ERR":
        v, why = "不可判定", "建连失败(%s)" % tgt[2]
    elif hbl[0] != "ERR" and tgt[2] == hbl[2]:
        v, why = "已被边缘登记·无后端", "= 主机级基线(默认 vhost)"
    else:
        gate, marks = is_gate_page(tgt[0], tgt[3], tgt[4], tgt[5])
        real_page = bool(re.search(r"<title[^>]*>\s*\S", tgt[5], re.S | re.I))

        if tgt[2] == pbl[2]:
            # 路径 catch-all。但「路径不存在」≠「业务未运行」：
            # catch 到的如果是一张真业务页（有 title、非门闸页），host 仍判确证存在。
            # 详见 rules/asset-existence-and-coverage.md §3 第 4 条补充 / 任务侧 P4 留痕。
            if gate:
                v, why = "存在但被门闸挡住", "= 路径级基线且命中门闸页四联征: " + marks
            elif real_page:
                ttl = re.search(r"<title[^>]*>(.*?)</title>", tgt[5], re.S | re.I).group(1).strip()
                v, why = "确证存在", "= 路径级基线，但 catch 到真业务页(title=%s) ⇒ host 真实、路径 catch-all" % ttl[:30]
            else:
                v, why = "不可判定", "= 路径级基线(catch-all，且未取到真业务页)"
        elif gate:
            v, why = "存在但被门闸挡住", "异形但命中门闸页四联征: " + marks
        else:
            v, why = "确证存在", "异形(两条基线均不命中)"
    return {"host": host, "ip": ip, "verdict": v, "why": why,
            "tgt": tgt, "hbl": hbl, "pbl": pbl}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("hostfile", nargs="?", help="主机清单文件，每行一个")
    ap.add_argument("-H", "--hosts", default="", help="逗号分隔的主机名")
    ap.add_argument("-o", "--outdir", default="_raw")
    ap.add_argument("--root", default="", help="根域（用于主机级基线），缺省自动推")
    ap.add_argument("--timeout", type=int, default=8)
    ap.add_argument("--sleep", type=float, default=1.0)
    a = ap.parse_args()

    hosts = []
    if a.hostfile:
        with io.open(a.hostfile, encoding="utf-8") as f:
            hosts = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    if a.hosts:
        hosts += [x.strip() for x in a.hosts.split(",") if x.strip()]
    if not hosts:
        ap.error("给主机清单文件，或用 -H 逗号分隔")

    os.makedirs(a.outdir, exist_ok=True)
    rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))

    print("# 第 -1 步 判存在性 | 主机 %d 台 | rand=%s | 根域=%s"
          % (len(hosts), rand, a.root or "自动"))
    print("# 纪律：只发 GET、不带凭据、单轮、间隔 %.1fs\n" % a.sleep)

    rows = []
    for h in hosts:
        r = probe(h, rand, a.timeout, a.sleep, a.root)
        rows.append(r)
        t = r["tgt"]
        print("%-34s %-16s %-22s %s" % (
            r["host"], r["ip"] or "-",
            ("%s/%s/%s" % (t[0], t[1], t[2])) if t else "—",
            r["verdict"]))

    tsv = os.path.join(a.outdir, "asset_baseline.tsv")
    with io.open(tsv, "w", encoding="utf-8", newline="\n") as f:
        f.write("host\tip\ttgt_st\ttgt_len\ttgt_sha1\thbl_st\thbl_len\thbl_sha1"
                "\tpbl_st\tpbl_len\tpbl_sha1\tverdict\twhy\n")
        for r in rows:
            t, hb, pb = r["tgt"] or ("", 0, "", "", "", "", ""), \
                r["hbl"] or ("", 0, "", "", "", "", ""), r["pbl"] or ("", 0, "", "", "", "", "")
            f.write("\t".join(map(str, [
                r["host"], r["ip"], t[0], t[1], t[2], hb[0], hb[1], hb[2],
                pb[0], pb[1], pb[2], r["verdict"], r["why"]])) + "\n")

    ledger = os.path.join(a.outdir, "asset_ledger.md")
    with io.open(ledger, "w", encoding="utf-8", newline="\n") as f:
        f.write("# 资产账本（脚本骨架 · 待人工补「已做测试」「备注」两列）\n\n")
        f.write("> rand=%s ｜ 判定列取值见 `rules/asset-existence-and-coverage.md` §6\n\n" % rand)
        f.write("| # | 主机 | 状态码 | SHA1(体) | CNAME 形态 | 判定 | 依据 | 已做测试 | 备注 |\n")
        f.write("|---|---|---|---|---|---|---|---|---|\n")
        for i, r in enumerate(rows, 1):
            t = r["tgt"]
            f.write("| %d | `%s` | %s | %s | 待补 | **%s** | %s | 待补 | |\n" % (
                i, r["host"],
                t[0] if t else "ERR",
                ("动态" if t and t[2] and len(t[2]) > 20 else (t[2] if t else "-")),
                r["verdict"], r["why"]))

    print("\n原始数据 -> %s" % tsv)
    print("账本骨架 -> %s" % ledger)
    print("\n⚠️ 本脚本只出「存在性」。「异形」不等于「有后端」，")
    print("   门闸页判定为启发式（四联征≥3），拿不准时人工同 host 取两次比对（见规则 §3 第 4 条）。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
