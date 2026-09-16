# -*- coding: utf-8 -*-
"""跟一跳验证：对 result.tsv 里 root 301/302/307/308 且 sz<300 的站，
手动跟跳（≤4 跳，只 GET），对落地页重跑判据，验证「跟一跳」增益。
2026-09-16 实测基线：root 未定性站跟一跳后 44% 拿到判据，56% 仍零命中。

用法: python follow_redirects.py result.tsv --raw-dir ./_raw --max 30 --out follow_report.txt
      --all 全量跑；--max 0 = 不限量
"""
import argparse, os, ssl, sys, urllib.parse, urllib.request, urllib.error
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fingerprint_markers import classify  # noqa: E402

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
      "Accept": "text/html,application/xhtml+xml,*/*;q=0.8", "Accept-Language": "zh-CN,zh;q=0.9"}
HTTPS_PORTS = {"443", "8443", "4101", "4500"}
CTX = ssl._create_unverified_context()


def get(url):
    req = urllib.request.Request(url, headers=UA, method="GET")
    with urllib.request.urlopen(req, timeout=8, context=CTX) as r:
        return r.status, r.headers, r.read(300000)


def follow(host, port, hops_max=4):
    scheme = "https" if port in HTTPS_PORTS else "http"
    url = f"{scheme}://{host}/" if (scheme, port) in (("https", "443"), ("http", "80")) else f"{scheme}://{host}:{port}/"
    hops, cks_all = [], []
    for _ in range(hops_max):
        try:
            st, hd, body = get(url)
        except urllib.error.HTTPError as e:
            st, hd, body = e.code, e.headers, e.read(300000)
        except Exception as e:
            return hops, None, f"{type(e).__name__}: {e}"
        srv = (hd.get("Server") or "").strip()
        ckn = [c.split("=", 1)[0].strip() for c in (hd.get_all("Set-Cookie") or [])]
        cks_all += ckn
        hops.append((url, st, srv, ";".join(ckn)))
        loc = hd.get("Location")
        if loc and st in (301, 302, 303, 307, 308):
            url = urllib.parse.urljoin(url, loc)
            continue
        return hops, (st, url, srv, ";".join(cks_all), body.decode("utf-8", "replace")), None
    return hops, None, "too many redirects"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("result_tsv")
    ap.add_argument("--raw-dir", default=None)
    ap.add_argument("--max", type=int, default=30, help="本轮最多测几个站（均匀铺开；0=不限）")
    ap.add_argument("--all", action="store_true", help="不限 sz<300，全部 redirect 站都测")
    ap.add_argument("--out", default="follow_report.txt")
    args = ap.parse_args()
    rawd = args.raw_dir or os.path.join(os.path.dirname(os.path.abspath(args.result_tsv)), "_raw")

    pool = []
    with open(args.result_tsv, encoding="utf-8") as f:
        for line in f:
            p = line.rstrip("\n").split("\t")
            while len(p) < 8:
                p.append("")
            host, port, st, sz, srv, _pby, loc, cks = p[:8]
            if st not in ("301", "302", "307", "308"):
                continue
            try:
                szi = int(sz)
            except ValueError:
                szi = -1
            if not args.all and not (0 <= szi < 300):
                continue
            pool.append((host, port, st, szi, srv, loc, cks))
    pool.sort()
    if args.max and len(pool) > args.max:
        step = len(pool) / args.max
        sel = [pool[int(i * step)] for i in range(args.max)]
    else:
        sel = pool[:]

    buf = [f"样本池: redirect{'(+sz<300)' if not args.all else ''} 共 {len(pool)} 个，本轮实测 {len(sel)} 个", "=" * 70]
    gain, still, errs = [], [], []
    for host, port, st0, sz0, srv0, loc0, cks0 in sel:
        orig_body = ""
        ob = os.path.join(rawd, host.replace(":", "_") + ".bod")
        if os.path.exists(ob):
            orig_body = open(ob, encoding="utf-8", errors="replace").read()
        orig_hits = classify(srv0, orig_body, [loc0 or ""], [cks0 or ""])

        hops, fin, err = follow(host, port)
        buf.append(f"\n[{host}:{port}] 原始[{st0} sz={sz0} srv={srv0 or '-'}]")
        for (u, s, sv, ck) in hops:
            buf.append(f"  hop {s} srv={sv or '-'} ck={ck or '-'}  {u[:110]}")
        if err:
            buf.append(f"  ✘ 探测失败: {err}")
            errs.append((host, err))
            continue
        st1, url1, srv1, ck1, body1 = fin
        fn_hits = classify(srv1, body1, [], [ck1])
        new_hits = [h for h in fn_hits if h not in orig_hits]
        buf.append(f"  final {st1} srv={srv1 or '-'} sz={len(body1)}  {url1[:110]}")
        if fn_hits:
            buf.append(f"  命中: {', '.join(fn_hits)}")
            if new_hits:
                gain.append((host, new_hits))
                buf.append(f"  ✔ 跟一跳新增识别: {', '.join(new_hits)}")
            else:
                buf.append("  = 命中与 root 相同（root 本就可识别）")
        else:
            still.append((host, st1, len(body1)))
            buf.append("  ✘ 落地页仍无判据命中")

    buf += ["", "=== 汇总 ===",
            f"实测: {len(sel)}  成功: {len(sel) - len(errs)}  失败: {len(errs)}",
            f"跟一跳后新增识别: {len(gain)} / {len(sel)}"]
    for h, nh in gain:
        buf.append(f"  + {h}: {', '.join(nh)}")
    buf.append(f"\n落地页仍零命中: {len(still)}")
    for h, s, l in still:
        buf.append(f"  - {h} (final {s}, {l}B)")
    buf.append(f"\n探测失败: {len(errs)}")
    for h, e in errs:
        buf.append(f"  ! {h}: {e}")
    buf.append("\n=== 新增判据命中分布 ===")
    for m, c in Counter(h for _, nh in gain for h in nh).most_common():
        buf.append(f"  {c:3d}  {m}")

    open(args.out, "w", encoding="utf-8").write("\n".join(buf))
    print("done ->", args.out)


if __name__ == "__main__":
    main()
