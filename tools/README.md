# tools/ — 判存在性 / 批量探根 / 指纹分类 / 跟一跳验证

入口类资产（统一认证 / WebVPN / 资源代理）批量识别的脚本组。判据表外置在 `fingerprint_markers.py`，**加新指纹只改这一个文件**，后三个脚本共享。

`probe_existence.py` 是**第 -1 步**，配套 `rules/asset-existence-and-coverage.md`：**先判这台存不存在，再谈探根/分类**。

## 纪律（先读）

- **只发 GET**，不带任何凭据，不爆破、不碰利用；跟跳上限 4。
- 串行请求、8s 超时；目标必须是**已授权范围**内的资产。
- 判据是「相关不等于定性」：命中多条再下结论，`Server: none` / `Server: Server` 这类字面量**不能单独定性**（见 `知识库/recon-fingerprint-cdn-wildcard.md` §1.3）。

## 用法

```bash
# 0) 第 -1 步 判存在性：双轨四象限（sha1 体 × 主机级实时基线 × 路径级实时基线）
#    + 门闸页四联征排除（WAF JS 挑战页 / 5 秒盾）
#    判定列只出五个值：确证存在 / 存在但被门闸挡住 / 不可判定 / 已被边缘登记·无后端 / 确证未配置
#    产出 asset_baseline.tsv（原始数据）+ asset_ledger.md（账本骨架，直接贴进 资产/资产账本.md）
python tools/probe_existence.py hosts.txt -o ./_raw

# 1) 探根：hosts.txt 每行一个 host 或 host:port → result.tsv + _raw/（hdr/bod 落盘）
python tools/probe_roots.py hosts.txt --out-dir ./sweep_out

# 2) 分类：对 result.tsv + _raw/ 出统计报告（特征命中 / Server 分布 / Cookie 分布 / 厂商归属 / 未定性清单）
python tools/classify_results.py ./sweep_out/result.tsv --raw-dir ./sweep_out/_raw --top 30

# 3) 跟一跳：挑 root 301/302/307/308 且 sz<300 的站（可用 --all 全量、--max 限数），
#    跟跳 ≤4 次，对落地页重新分类 → 实测 2026-09-16：root 未定性站跟一跳后 44% 拿到判据
python tools/follow_redirects.py ./sweep_out/result.tsv --raw-dir ./sweep_out/_raw --max 30 --out follow_report.txt
```

## 经验值（实战校准过，别自己再踩）

1. **认入口类必须跟一跳，但跟一跳不充分**：44% 增益后，仍零命中的站第二步打 `/login`、`/cas/login`、`/sso` 常见路径与 JS 引用。
2. **Set-Cookie 名在 302 上就要扫**（`wengine_vpn_ticket*` 在跳转响应上就出现，别等落地页）。
3. 同名陷阱：cookie `Sharetop.ClientId/.Session` 是某 Web 应用框架判据，与深圳 Sharetop（光通信）无关；`Server: ******`（通配屏蔽）+ `*.webvpna.**.edu.cn` 域名模式 = 某高校 WebVPN 指纹。
4. **`sha1` 各异 ≠ 有后端**：WAF JS 挑战页**按 Host 定制**，同一套页在不同主机名下哈希两两不同。
   反向确认 = **同一 host 连取两次**：两次同哈希 + 跨 host 各异 ⇒ 门闸页；两次异哈希 + 长度相同 ⇒ 动态业务页。
   （2026-09-19 实测 9 台，详见 `rules/asset-existence-and-coverage.md` §3 第 4 条。）
5. **状态 200 也可能一个字都拿不到**：`Server: ******` + 无 `<title>` + 44~53KB 的混淆 `<script>` 正文 = 挑战页，不是站点内容。

判据来源与完整打法表：`知识库/recon-fingerprint-cdn-wildcard.md` §1.3。
