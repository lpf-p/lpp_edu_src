# -*- coding: utf-8 -*-
"""探根：对 host 列表逐个 GET /（不跟跳），落盘 result.tsv + _raw/（hdr/bod）。
只发 GET、不带凭据、串行 8s 超时。仅用于已授权资产。

用法: python probe_roots.py hosts.txt --out-dir ./sweep_out
hosts.txt 每行: host 或 host:port（缺省端口 https=443 / http=80，按端口猜协议，失败自动换 scheme）
result.tsv 列: host\tport\tst\tsz\tsrv\tpby\tloc\tcks
"""
import argparse, os, ssl, sys, urllib.parse, urllib.request, urllib.error

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
      "Accept": "text/html,application/xhtml+xml,*/*;q=0.8", "Accept-Language": "zh-CN,zh;q=0.9"}
HTTPS_PORTS = {"443", "8443", "4101", "4500"}
CTX = ssl._create_unverified_context()


def base_url(host, port):
    scheme = "https" if port in HTTPS_PORTS else "http"
    if (scheme == "https" and port == "443") or (scheme == "http" and port == "80"):
        return f"{scheme}://{host}/"
    return f"{scheme}://{host}:{port}/"


def get(url):
    req = urllib.request.Request(url, headers=UA, method="GET")
    with urllib.request.urlopen(req, timeout=8, context=CTX) as r:
        return r.status, r.headers, r.read(300000)


def probe(host, port):
    """依次试 https/http（失败换 scheme），返回 (st, hdr, body, err)。"""
    first = "https" if port in HTTPS_PORTS else "http"
    for scheme in (first, "http" if first == "https" else "https"):
        url = f"{scheme}://{host}/" if (scheme, port) in (("https", "443"), ("http", "80")) else f"{scheme}://{host}:{port}/"
        try:
            st, hd, body = get(url)
            return st, hd, body, None, url
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read(300000), None, url
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
    return None, None, b"", err, ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("hosts", help="host 列表文件，每行 host 或 host:port")
    ap.add_argument("--out-dir", default="./sweep_out")
    args = ap.parse_args()

    rawd = os.path.join(args.out_dir, "_raw")
    os.makedirs(rawd, exist_ok=True)
    tsv = os.path.join(args.out_dir, "result.tsv")

    rows, ok = [], 0
    with open(args.hosts, encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    for i, line in enumerate(lines, 1):
        host, _, port = line.partition(":")
        port = port or "443"
        st, hd, body, err, url = probe(host, port)
        if st is None:
            print(f"[{i}/{len(lines)}] {host}:{port} FAIL {err}")
            rows.append(f"{host}\t{port}\t000\t\t\t\t\t")
            continue
        srv = (hd.get("Server") or "").strip()
        pby = (hd.get("X-Powered-By") or "").strip()
        loc = hd.get("Location") or ""
        cks = ";".join(c.split("=", 1)[0].strip() for c in (hd.get_all("Set-Cookie") or []))
        safe = host.replace(":", "_")
        with open(os.path.join(rawd, safe + ".hdr"), "w", encoding="utf-8", errors="replace") as fh:
            fh.write(f"URL: {url}\nSTATUS: {st}\n" + str(hd))
        with open(os.path.join(rawd, safe + ".bod"), "wb") as fb:
            fb.write(body)
        rows.append(f"{host}\t{port}\t{st}\t{len(body)}\t{srv}\t{pby}\t{loc}\t{cks}")
        ok += 1
        print(f"[{i}/{len(lines)}] {host}:{port} {st} {len(body)}B srv={srv or '-'}")

    with open(tsv, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(rows) + "\n")
    print(f"done: {ok}/{len(lines)} -> {tsv}")


if __name__ == "__main__":
    sys.exit(main())
