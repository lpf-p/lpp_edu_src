# -*- coding: utf-8 -*-
"""分类：对 probe_roots.py 产出的 result.tsv + _raw/ 做指纹分类与统计报告。
stdout 可重定向为报告文件。判据表在 fingerprint_markers.py（唯一来源）。

用法: python classify_results.py result.tsv --raw-dir ./_raw --top 30
"""
import argparse, os, sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fingerprint_markers import classify, vendor  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("result_tsv")
    ap.add_argument("--raw-dir", default=None, help="probe_roots 的 _raw 目录（缺省取 tsv 同级）")
    ap.add_argument("--top", type=int, default=30, help="未定性清单最多列多少条")
    args = ap.parse_args()
    rawd = args.raw_dir or os.path.join(os.path.dirname(os.path.abspath(args.result_tsv)), "_raw")

    rows = []
    with open(args.result_tsv, encoding="utf-8") as f:
        for line in f:
            p = line.rstrip("\n").split("\t")
            while len(p) < 8:
                p.append("")
            host, port, st, sz, srv, pby, loc, cks = p[:8]
            bod = ""
            bp = os.path.join(rawd, host.replace(":", "_") + ".bod")
            if os.path.exists(bp):
                bod = open(bp, encoding="utf-8", errors="replace").read()
            hits = classify(srv, bod, [loc or ""], [cks or ""])
            rows.append(dict(host=host, port=port, st=st, sz=sz, srv=srv, loc=loc, cks=cks, hits=hits))

    P = print
    P(f"样本数: {len(rows)}\n")
    P("=== 特征命中统计 ===")
    hc = Counter(h for r in rows for h in r["hits"])
    for h, c in hc.most_common():
        P(f"  {c:3d}  {h}")
    P("\n=== Server 头分布 ===")
    for s, c in Counter(r["srv"] for r in rows).most_common(18):
        P(f"  {c:3d}  {s or '(空)'}")
    P("\n=== Cookie 分布 ===")
    ckc = Counter(c.strip() for r in rows for c in (r["cks"] or "").split(";") if c.strip())
    for c, n in ckc.most_common(22):
        P(f"  {n:3d}  {c}")
    P("\n=== 厂商归属（按首个命中）===")
    for v, c in Counter(vendor(r["hits"]) for r in rows).most_common():
        P(f"  {c:3d}  {v}")
    n_unk = 0
    P(f"\n=== 未定性样本（前 {args.top}）===")
    for r in rows:
        if not r["hits"]:
            n_unk += 1
            if n_unk <= args.top:
                P(f"  [{r['st']}] {r['host']}:{r['port']} sz={r['sz']} srv={r['srv'] or '-'} ck={r['cks'] or '-'}")
                P(f"      loc={(r['loc'] or '-')[:95]}")
    P(f"  ... 共 {n_unk} 个未定性")


if __name__ == "__main__":
    main()
