# waf-bypass

# WAF Bypass Techniques — Evasion Playbook


## 1. PHASE 0 — IDENTIFY THE WAF

Before bypassing, know what you're fighting.

### 1.1 Tools

| Tool | Usage |
|---|---|
| `wafw00f target.com` | Fingerprint WAF vendor from response headers/behavior |
| `nmap --script=http-waf-detect` | NSE script for WAF detection |
| Manual header inspection | `Server`, `X-CDN`, `X-Cache`, `cf-ray` (Cloudflare), `x-sucuri-id`, `x-akamai-*` |

> ⚠️ **`wafw00f` 对国产防护基本无效**（它认的是 Cloudflare/Akamai/Imperva 那批）。**国内目标别指望工具报名字**，看 §9.3 的实测结论。

### 1.2 Behavioral Fingerprinting

```
1. Send benign request → record baseline response (status, headers, body size)
2. Send obvious attack: /?q=<script>alert(1)</script>
3. Compare: 403? Custom block page? Redirect? Connection reset?
4. Block page content reveals WAF: "Cloudflare", "Access Denied (Imperva)", "ModSecurity"
5. If transparent proxy: check response time difference (WAF adds latency)
6. ★ 国产动态防护走另一条路：见 §9 —— 412 + $_ts 就是瑞数，不用发包就能认
```

> ★ **第 6 步是本文件 2026-09-16 补的重点**：国内目标的防护形态和国外完全不同，**第 1~5 步（发攻击载荷看阻断）经常走不通**，因为国产动态防护**在「基线请求」阶段就已经把你挡在外面了**（412 + JS 挑战）。所以先做「基线形态识别」，再谈绕过。

---

## 2. GENERIC BYPASS CATEGORIES

### 2.1 Encoding Bypasses

| Technique | Example | Bypasses |
|---|---|---|
| URL encoding | `%3Cscript%3E` | Basic string matching |
| Double URL encoding | `%253Cscript%253E` | WAFs that decode once, app decodes twice |
| Unicode encoding | `%u003Cscript%u003E` | IIS-specific Unicode normalization |
| HTML entities | `&#60;script&#62;` or `&#x3c;script&#x3e;` | WAFs not performing HTML entity decoding |
| Hex encoding (SQL) | `0x756E696F6E` = `union` | WAFs matching SQL keywords |
| Octal encoding | `\74script\76` | Rare but some parsers handle it |
| Overlong UTF-8 | `%C0%BC` (invalid encoding for `<`) | Legacy parsers with loose UTF-8 handling |
| Mixed case | `SeLeCt`, `uNiOn` | Case-sensitive rule matching |
| Null byte | `sel%00ect` | WAFs that stop parsing at null |

### 2.2 Chunked Transfer Encoding

Split the payload across HTTP chunks so no single chunk contains the blocked pattern:

```http
POST /search HTTP/1.1
Transfer-Encoding: chunked

3
sel
3
ect
1
 
4
from
0

```

WAFs that inspect the full body may not reassemble chunks before matching.

### 2.3 HTTP/2 Binary Format Bypasses

HTTP/2 transmits headers as binary HPACK-encoded frames. Some WAFs only inspect after downgrading to HTTP/1.1:

- Header names can contain characters illegal in HTTP/1.1
- Pseudo-headers (`:method`, `:path`) bypass header-based WAF rules
- H2 → H1 downgrade may introduce request smuggling (see [request-smuggling](http-smuggling-test.md))

### 2.4 HTTP Parameter Pollution (HPP)

Different servers handle duplicate parameters differently:

| Server | Behavior for `?a=1&a=2` |
|---|---|
| PHP/Apache | Last value: `a=2` |
| ASP.NET/IIS | Concatenated: `a=1,2` |
| Python/Flask | First value: `a=1` |
| Node.js/Express | Array: `a=[1,2]` |

WAF checks `a=1` (benign), app uses `a=2` (malicious). Or combine: `a=sel&a=ect` → ASP.NET sees `a=sel,ect`.

### 2.5 IP Source Spoofing (Bypass IP-Based Rules)

Headers trusted by some WAFs/apps for client IP:

```
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
Forwarded: for=127.0.0.1
```

Use case: WAF whitelists internal IPs or has different rule sets per source.

### 2.6 Path Normalization Tricks

| Technique | Example | Effect |
|---|---|---|
| Dot segments | `/./admin` or `/../target/admin` | WAF sees different path than app |
| Double slash | `//admin` | Some normalizers collapse, WAFs may not |
| URL encoding path | `/%61dmin` | WAF sees encoded, app decodes |
| Null byte in path | `/admin%00.jpg` | Legacy: app truncates at null, WAF sees .jpg |
| Backslash (IIS) | `/admin\..\/secret` | IIS treats `\` as `/` |
| Trailing dot/space | `/admin.` or `/admin%20` | OS-level normalization (Windows) |
| Semicolon (Tomcat) | `/admin;jsessionid=x` | Tomcat strips after `;`, WAF may not |

### 2.7 Content-Type Manipulation

WAFs often have format-specific parsers. Switching Content-Type can bypass rules:

```
Default:  Content-Type: application/x-www-form-urlencoded  → WAF parses params
Switch:   Content-Type: application/json  → WAF may not parse JSON body
Switch:   Content-Type: multipart/form-data  → WAF may not inspect all parts
Switch:   Content-Type: text/xml  → WAF expects XML, payload in different format
```

**Trick**: If app accepts both JSON and form-urlencoded, use JSON — WAFs often have weaker JSON inspection rules.

### 2.8 Multipart Boundary Abuse

```http
Content-Type: multipart/form-data; boundary=----WAFBypass

------WAFBypass
Content-Disposition: form-data; name="q"

<script>alert(1)</script>
------WAFBypass--
```

Variations: long boundary strings, boundary with special characters, missing final boundary, nested multipart.

#### 2.8.1 上传文件名 / 头字段实战绕过（真实复盘）

WAF 与后端对 multipart 头的**解析不一致**是最稳的一类绕过。以下均来自授权演练复盘，案例细节见 `attack-chain-cases.md` §2.4：

| 手法 | 写法 | 原理 |
|---|---|---|
| **双 `Content-Disposition` + 大小写 + `$20`** | `Content-Disposition: form-datA*;name="file" filename1123="1.aspx";$20 filename="test.asp"` | WAF 取第一个（`1.aspx` 看着危险就拦/或取 `file` 判白名单），后端取最后生效的 |
| **`filename;;;;` + 非常规后缀** | `filename;;;;="1.cer"` | 分隔符畸形使 WAF 正则失配；`.cer` 不在黑名单但能被解析 |
| **`Content-Encoding:` 传输编码** | 加 `Content-Encoding: gzip` 之类头，内容不真压缩 | 后缀已过、**内容检测**被绕过（网络层解压失败但应用层照样落盘） |
| **`filename=".w\a\r"`** | 用 `\` 拆开 `war` 关键字 | 关键词分割（对应 §2.10），部署后访问 `/123.jsp` |
| **`Content-Type` 逐段替换** | 只改文件段的 `Content-Type`（对应 §2.7） | WAF 按第一段类型整体判定 |

**另一类：白名单是"文件名包含判断"而不是"扩展名判断"**——如 `Extension.IndexOf(".jpg") > -1` 对整个文件名做包含，此时 `123123.png.asp` 既能过校验又能被解析。**这类要在源码/回显里确认判断依据，不是 WAF 层的事**（`file-upload-test.md` 亦有此面）。

### 2.9 Newline & Whitespace Injection

```sql
-- SQL keyword splitting
SEL
ECT * FROM users

-- SQL comment insertion
SEL/**/ECT * FR/**/OM users
UN/**/ION SEL/**/ECT 1,2,3

-- Tab/vertical tab as separator
SELECT\t*\tFROM\tusers
```

### 2.10 Keyword Splitting & Alternative Syntax

| Blocked | Alternative |
|---|---|
| `UNION SELECT` | `UNION ALL SELECT`, `UNION DISTINCT SELECT` |
| `OR 1=1` | `OR 2>1`, `OR 'a'='a'`, `\|\|1` |
| `<script>` | `<svg/onload=alert(1)>`, `<img src=x onerror=alert(1)>` |
| `alert(1)` | `prompt(1)`, `confirm(1)`, `print()` (Chrome) |
| `eval()` | `Function('code')()`, `setTimeout('code',0)` |
| `' OR '1'='1` | `' OR 1-- -`, `'\|\|'1` |
| `SLEEP(5)` | `BENCHMARK(5000000,SHA1('x'))`, `pg_sleep(5)` |

### 2.11 Body Flooding & Nested Encoding (实战复盘：JSON `@type` 被网络层拦)

> 来源：猎洞时刻《通杀 Edusrc通杀70rank漏洞实战高危思路和WAF绕过》（2026-09-14）。目标 WAF 对 **`@type`** 这类 JSON 关键字在**网络层**直接阻断（应用本身照常解析），两式可破：

| 手法 | 做法 | 为什么有效 | 前提 |
|---|---|---|---|
| **请求体洪泛**（junk flood） | 在 JSON 里加一个**业务 DTO 中不存在**的字段，塞海量垃圾，如 `"f":"aaaa…"`（原文用了两万个 `a`），把 `@type` 埋进大 body | 网络层 WAF 有 body **检测长度/成本上限**，超限即跳过深度匹配；后端多一个未知字段不影响反序列化 | WAF 属**长度截断**型（非流式全量）；字段名要挑业务不认识的，否则字段校验先失败 |
| **敏感词嵌套编码** | 被拦的命令字先 base64 再 hex：`whoami` → `d2hvYW1p` → `6432687659573170` | 现代 WAF 会**解一层**（base64 / unicode 都能解出来）；**叠两层**后单次解码仍非明文，规则命中不到 | 必须能改**服务端那侧的回显模块**在解码端还原（否则服务端认不出命令，见 `jndi-injection-test.md` §4 TOOLING 的「二开点」） |

**通用形式**：凡"关键字被拦 + 应用自身对长度/格式宽容"的场景都能试 —— 把被拦串**埋进洪水**，或**多编码一层**。

**单层为什么不行**（原文实测）：`whoami` 直接 base64、或 unicode 编码，都被 WAF 解出并阻断；**base64→hex 两层**通过。

**同源手法**（本文第三种绕过，思路一致）：通杀的大部分站禁止访问 CXF 服务，拿不到接口 → 转从**前端登录页抓包**；前端请求体虽然加密，**后端 CXF 接口并未加密** → 打断点分析前端加密、用 python 复刻加解密，再把 payload 加密后发出。
> 可复用观察：**"前端加密"经常只是前端装饰**，同一业务另有未加密入口（尤其是内部/中间件接口）。别看到密文就放弃，先找同业务的直连口。

---

## 3. PROTOCOL-LEVEL BYPASS TECHNIQUES

### 3.1 Request Line Abuse

```http
GET /path?q=attack HTTP/1.1    ← WAF inspects
```

vs.

```http
GET http://target.com/path?q=attack HTTP/1.1   ← Absolute URI: some WAFs miss the path
```

### 3.2 Header Injection via CRLF

If WAF inspects original headers but app processes injected ones:

```
X-Custom: value\r\nX-Forwarded-For: 127.0.0.1
```

### 3.3 Connection-State Bypass

```
1. Establish connection through WAF (normal request)
2. On same keep-alive connection, send attack request
3. Some WAFs reduce inspection on subsequent requests in same connection
```

---

## 4. WAF BYPASS DECISION TREE

```
Payload blocked by WAF?
├── Identify WAF (wafw00f, response headers, block page)
│
├── Try encoding bypasses
│   ├── URL encode payload → still blocked?
│   ├── Double URL encode → still blocked?
│   ├── Unicode/overlong UTF-8 → still blocked?
│   ├── Mixed case keywords → still blocked?
│   └── HTML entities (for XSS) → still blocked?
│
├── Try protocol-level bypasses
│   ├── Switch Content-Type (JSON, multipart, XML)
│   │   └── App accepts alternate format? → re-send payload
│   ├── HTTP Parameter Pollution (duplicate params)
│   ├── Chunked Transfer-Encoding to split payload
│   ├── HTTP/2 direct if available (binary framing bypass)
│   └── Request line: absolute URI format
│
├── Try path-based bypasses
│   ├── Path normalization (/./path, //path, ;param)
│   ├── Different HTTP method (POST vs PUT vs PATCH)
│   └── Alternate endpoint serving same function
│
├── Try payload mutation
│   ├── SQL: comments (/**/), alternative functions, hex literals
│   ├── XSS: alternative tags/events, JS template literals
│   ├── RCE: wildcard abuse, string concatenation, variable expansion
│   └── Check WAF_PRODUCT_MATRIX.md for vendor-specific mutations
│
├── Try IP-source bypass
│   ├── X-Forwarded-For / True-Client-IP spoofing
│   ├── Access origin server directly (bypass CDN)
│   └── Find origin IP (Shodan, historical DNS, email headers)
│
└── Try request smuggling to skip WAF entirely
    └── See http-smuggling-test.md
```

---

## 5. COMMON MISTAKES & TRICK NOTES

1. **Test bypass with actual exploitation, not just 200 OK**: WAF may return 200 but strip the payload silently.
2. **WAFs often have size limits**: Very large request bodies (>8KB–128KB depending on WAF) may bypass inspection entirely.
3. **Rate limiting ≠ WAF**: Getting 429s is rate limiting, not payload blocking. Different bypass needed.
4. **CDN caching**: If the WAF is at CDN level, cached responses bypass WAF on subsequent requests. Poison cache with clean request, exploit cache.
5. **Origin server direct access**: If you find the origin IP behind CDN/WAF, connect directly — WAF is bypassed completely.
6. **Multipart file upload fields**: WAFs often skip inspection of file content in multipart uploads — embed payload in filename or file content if reflected.

---

## 6. DEFENSE PERSPECTIVE

| Measure | Notes |
|---|---|
| WAF + application-level input validation | WAF is a layer, not a fix |
| Parameterized queries | Eliminates SQLi regardless of WAF |
| CSP + output encoding | Eliminates XSS regardless of WAF |
| Regularly update WAF rules | Vendor signatures lag behind new bypasses |
| Deny by default, not block-list | Allowlist valid input patterns |
| Log and alert on WAF blocks | Bypass attempts are visible in logs |


---


## 附件：WAF_PRODUCT_MATRIX

# WAF Product Bypass Matrix


## 1. Cloudflare WAF

### Detection

- `cf-ray` header, `Server: cloudflare`, block page references "Cloudflare"
- Cookie: `__cfduid`, `__cf_bm`

### Known Bypass Techniques

| Category | Technique |
|---|---|
| Unicode normalization | Cloudflare normalizes Unicode differently than backend — `＜script＞` (fullwidth) may pass WAF but render as `<script>` |
| Chunked body | Split payloads across HTTP chunks; Cloudflare may not reassemble before inspection |
| Payload mutation (SQLi) | `/*!50000UniOn*/SeLeCt` — MySQL version comments bypass keyword matching |
| Payload mutation (XSS) | `<svg/onload=alert&#40;1&#41;>`, `<details open ontoggle=alert(1)>` |
| Origin direct access | Find origin IP via DNS history, Shodan `ssl.cert.subject.cn:target.com`, email headers |
| JSON body | Switch from form-urlencoded to JSON — different parser, weaker rules |
| Super-long parameter names | Parameter name >128 chars may cause Cloudflare to skip inspection |

### Cloudflare-Specific Notes

- Cloudflare has multiple WAF modes: "Managed Rules" (Cloudflare-authored) and "OWASP ModSecurity Core Rule Set". Each has different bypass surfaces.
- Cloudflare's free-tier WAF has significantly fewer rules than Business/Enterprise.
- Browser Integrity Check and Bot Management are separate from WAF — don't confuse them.

---

## 2. AWS WAF

### Detection

- `x-amzn-requestid` header, runs in front of ALB/CloudFront/API Gateway
- Block response often returns 403 with JSON body or custom error page

### Known Bypass Techniques

| Category | Technique |
|---|---|
| Regex complexity | AWS WAF regex rules have execution time limits — complex input can cause regex to timeout → request passes |
| Size limits | AWS WAF inspects first 8KB of body (16KB for CloudFront). Payload after this boundary is uninspected |
| Custom rule gaps | Default AWS Managed Rules miss many edge cases; custom rules often have logic errors |
| JSON depth | Deeply nested JSON objects may exceed parser depth limits |
| Base64 in parameters | AWS WAF doesn't auto-decode Base64 in parameter values (unless custom transform configured) |
| URI vs body rules | Rules may cover URI but not body, or vice versa — test both |

### AWS WAF-Specific Notes

- AWS WAF v2 (WAFV2) has `SizeConstraintStatement` — bodies over the size limit are either blocked or allowed, depending on config. If "allow on oversize", pad payload beyond 8KB.
- AWS Managed Rule Groups update regularly but lag behind novel attack patterns.
- IP reputation lists may be stale — new IPs from cloud providers often aren't listed.

---

## 3. ModSecurity + OWASP CRS

### Detection

- `Server: Apache` or `nginx` with ModSecurity module
- Block page: "ModSecurity" reference, or generic 403
- Error contains rule ID (e.g., `id:942100`)

### Known Bypass Techniques

| Category | Technique |
|---|---|
| Paranoia Level (PL) gaps | PL1 (default) has minimal rules; PL2-4 progressively stricter. Most deployments run PL1-2, missing many attack patterns |
| Rule ID specific bypass | Each rule targets specific patterns — identify blocking rule ID from error, craft bypass for that specific regex |
| SQL comment injection | `/*! ... */` MySQL conditional comments bypass many CRS SQLi rules |
| Unicode in PL1 | PL1 doesn't check Unicode-encoded payloads: `%u0027` for `'` |
| Transformation order | CRS applies `t:urlDecodeUni,t:htmlEntityDecode` but not all transformations on all rules |
| Multipart parser | CRS multipart parsing can be confused by malformed boundaries |
| Request body limit | `SecRequestBodyLimit` default is 13MB — but `SecRequestBodyNoFilesLimit` is only 128KB (changeable). Payloads in file upload fields bypass body rules if only `NoFiles` limit is enforced |

### CRS-Specific Notes

- CRS v4 (2023+) significantly improved coverage vs v3. Check target's CRS version.
- Anomaly scoring mode: individual rule violations add to score, blocked only if total exceeds threshold. Keep individual violations below detection but accumulate effect.
- `SecRuleRemoveById` directives in config may disable specific rules — test for holes.

---

## 4. Akamai (Kona Site Defender / App & API Protector)

### Detection

- `Server: AkamaiGHost`, `x-akamai-*` headers
- Error reference number in block page

### Known Bypass Techniques

| Category | Technique |
|---|---|
| Header injection | Akamai processes certain headers differently; `X-Forwarded-Host` injection can confuse routing |
| Encoding chains | Triple encoding or mixed encoding (URL + Unicode + HTML) |
| JSON body bypass | Akamai's JSON parser may not inspect deeply nested objects |
| Slow POST | Akamai has timeout-based protections; slow delivery may cause incomplete inspection |
| HTTP/2 push | H2 server push responses may bypass WAF inspection |
| IP rotation | Akamai rate limits per IP; rotating source IPs avoids behavioral blocks |

### Akamai-Specific Notes

- Akamai has "Adaptive Security Engine" — it learns application behavior. New attack patterns that don't match learned behavior may bypass initially.
- Penalty box: after triggering Akamai WAF, your IP may be rate-limited for minutes. Use fresh IP for each test.
- Akamai Pragma headers (`Pragma: akamai-x-check-cacheable`) can leak internal routing information useful for understanding the setup.

---

## 5. Imperva / Incapsula

### Detection

- `X-CDN: Imperva`, `Set-Cookie: incap_ses_*`, `visid_incap_*`
- Block page: "Powered by Incapsula" or Imperva branding

### Known Bypass Techniques

| Category | Technique |
|---|---|
| Parameter pollution | Duplicate parameters: Imperva inspects one occurrence, app processes another |
| JSON deep nesting | `{"a":{"b":{"c":{"d":"payload"}}}}` — deeply nested JSON exceeds parser depth |
| Multipart abuse | Malformed multipart boundaries confuse Imperva's parser |
| UTF-8 BOM injection | `\xEF\xBB\xBF` at start of body may shift parser alignment |
| Large Cookie header | Extremely long Cookie headers may cause truncated inspection |
| WebSocket upgrade | After WebSocket upgrade, subsequent traffic may bypass WAF inspection |

### Imperva-Specific Notes

- Imperva has "Client Classification" — browser fingerprinting. Headless browsers may be blocked before WAF rules even apply. Use real browser fingerprints.
- Imperva's API security module is separate from web WAF — API endpoints may have weaker protection.
- Custom rules in Imperva use "IncapRule" syntax — misconfigurations are common.

---

## 6. F5 BIG-IP ASM / Advanced WAF

### Detection

- `Server: BigIP`, `BIGipServer` cookie, `TS` cookie prefix
- Block page: "The requested URL was rejected" with support ID

### Known Bypass Techniques

| Category | Technique |
|---|---|
| Serialized format bypass | ASM has weak inspection of serialized data (Java, PHP, .NET serialization) |
| JSON/XML content switching | Switch between JSON and XML — ASM may have different rule sets per content type |
| Parameter meta-characters | ASM's "meta-character enforcement" can be bypassed with double encoding |
| Cookie manipulation | ASM sets tracking cookies; modifying them can cause session tracking issues that affect rule application |
| Evasion techniques | ASM has explicit "evasion detection" for directory traversal, multiple encoding, etc. But combinations of techniques may still bypass |
| Learning mode exploitation | If ASM is in "transparent" (learning) mode, no blocking occurs — test with obviously malicious payload first |

### F5-Specific Notes

- BIG-IP ASM distinguishes between "attack signatures" and "violations". Signatures are pattern-based; violations are structural (parameter length, data type). Both must be bypassed.
- ASM's "Bot Defense" module is separate and can be detected via JavaScript challenge injection.
- The `TS` cookie contains session data — tampering with it causes ASM to treat the request as a new session.

---

## 7. Sucuri WAF

### Detection

- `Server: Sucuri/Cloudproxy`, `X-Sucuri-ID` header
- Block page: "Access Denied - Sucuri Website Firewall"

### Known Bypass Techniques

| Category | Technique |
|---|---|
| Tag/event combos | Sucuri blocks common XSS tags but may miss: `<svg/onload>`, `<details/ontoggle>`, `<marquee onstart>` |
| SQL function alternatives | `MID()` instead of `SUBSTRING()`, `CONV()` for hex conversion |
| Path traversal encoding | `..%252f..%252f` (double URL encode) for directory traversal |
| Origin direct access | Sucuri is a reverse proxy; origin IP discovery bypasses it entirely |
| HTTP method switch | Sucuri may have different rules for GET vs POST vs PUT |
| Null byte injection | `%00` in parameter values may truncate Sucuri's inspection |

### Sucuri-Specific Notes

- Sucuri is common on WordPress sites — combine with WordPress-specific attack vectors.
- Sucuri's "Hardening" features (block PHP in uploads, etc.) are separate from WAF rules.
- Free Sucuri tier has significantly weaker WAF rules than paid tiers.

---

## 8. QUICK REFERENCE — BYPASS-BY-WAF CHEAT SHEET

| WAF | Top Bypass Vector | Size Limit | Key Weakness |
|---|---|---|---|
| Cloudflare | Unicode normalization + origin IP | 128KB | Fullwidth chars, free tier gaps |
| AWS WAF | Body size > 8KB | 8KB (body) | Size limit bypass, regex timeout |
| ModSecurity CRS | PL1 gaps + MySQL comments | Configurable | Low paranoia defaults |
| Akamai | Encoding chains + slow POST | Varies | Adaptive engine learning delay |
| Imperva | HPP + JSON nesting | Unknown | Parameter pollution |
| F5 BIG-IP | Serialized data + learning mode | Configurable | Weak serialization inspection |
| Sucuri | Origin IP + alt tags | Unknown | WordPress-centric rules |
| **瑞数 Botgate** | 无头浏览器 / JS 补环境生成 cookie | — | **不是规则型 WAF，是动态混淆，没有「payload 绕过」这条路** |

---

## 9. 瑞数信息 Botgate（国产 · 动态防护）—— 2026-09-16 实测

> **为什么必须补这一节**：本文件 §1~§7 的矩阵（Cloudflare / AWS / ModSecurity / Akamai / Imperva / F5 / Sucuri）**清一色是国外产品**。而面向国内 SRC / EDUSRC 时，**遇到最多的是国产防护**，此前**零覆盖**。这是本文件最大的结构性缺口。

### 9.1 识别（单请求可判，2026-09-16 实测样本 `mcoa.**.edu.cn`）

一次 `GET /` 就能认，**不需要发包攻击**：

| 观测点 | 实测值 |
|---|---|
| 状态码 | **`412 Precondition Failed`**（不是 403） |
| Set-Cookie | **随机名** cookie（实测 13 位大小写数字混排，如 `61zqTsrO93nzO`），值 100+ 字符，带 `Secure; HttpOnly`，过期时间约 10 年后 |
| 正文 | 含全局变量 **`$_ts`**、`$_ts.nsd=<数字>`、`$_ts.cd="<随机串>"` |
| 正文 | `<meta id="<随机10位>" content="<随机串>" r='m'>`、`<script r='m'>` —— **`r='m'` 属性是显著特征** |
| 正文 | DOCTYPE 用 `XHTML 1.0 Transitional`，但内容是混淆 JS（**年代错位本身就是线索**） |
| `cache-control` | `no-store` |

**一句话判据**：`412` + `$_ts` + 随机名 cookie = 瑞数。

### 9.2 处置（关键：思路和静态 WAF 完全不同）

- 瑞数**不是规则型 WAF**，它是**人机对抗网关**：每次请求下发的 JS 都不同（VMP 混淆），要**执行 JS 换出 cookie** 才能进站。所以 §2「GENERIC BYPASS CATEGORIES」（编码绕过、HPP、分块传输……）**对它基本无效**——你绕的不是规则，是**客户端环境检测**。
- 可行路径只有两类：**① 无头浏览器**（Playwright/Selenium 真跑 JS，最省事，SRC 场景推荐）；**② JS 补环境**（Node + `jsdom`/`vm` 补 `window`/`document`/`navigator`，逆向 VMP 逻辑）。公开资料（瑞数 5/6 代逆向文）一致指出这条路是**逐版本对抗**，成本高。
- **SRC 实战建议**：认到瑞数 → **先判断值不值得啃**。它是「防爬/防自动化」为主，**不代表后端没洞**；如果你的目标是业务逻辑漏洞（越权、密码重置、支付），用无头浏览器正常走流程即可，**不要把时间耗在破防护上**。

### 9.3 顺带一条实测结论：国产网关倾向「抹掉」Server 头

2026-09-16 两轮批量实测（226 个教育资产 + 234 个高校统一认证 / WebVPN 资产），**字面量 `Server: none` 累计 48 站**（第一轮 20 + 第二轮 28），横跨两所高校 / 泛微系 / 瑞数防护站 / **网瑞达 WebVPN** / 金智统一认证 / 正方 / CAS 系，另有 `Server: Server`、`Server: *****`、`Server` 后接一长串空格等变体。**这跟 Cloudflare/Akamai「大方报自己名字」的行为完全相反。**

⚠️ **但别把它当单一产品的判据**：实测 48 站分属**多个不同系统**（泛微 e-cology、瑞数、**网瑞达 WebVPN**、金智统一认证、正方、CAS 系、多所高校自研），说明它是**某几类网关的通用默认配置**，不是某一家独有。**只能读作「有网关介入」。**

推论（对打法有直接影响）：**面对国内目标，「特征匹配法」经常失效，「行为指纹法」（§1.2 那套 baseline → 攻击 → 比对）才是主力**。见到 Server 头被抹成字面量/星号/空格 → 判为「有网关或防护介入」，别当「无 Server 头」。

### 9.4 国产防护矩阵（2026-09-16 批量实测 226 个教育资产填充）

> 上一版此节标为「空白」。本轮批量实测后，**把能确证的填进来，没确证的继续留空**。

| 产品 | 识别判据（单请求可判，不用发攻击载荷） | 实测样本 | 阻断形态 |
|---|---|---|---|
| **瑞数 Botgate** | `412` + 正文含 `$_ts`（`$_ts.nsd`/`$_ts.cd`）+ 随机名 cookie + 标签属性 `r='m'` | `mcoa.**.edu.cn`、`coa.**.edu.cn`、`oa.**.edu.cn` | **412** + JS 挑战页 |
| **华为云 WAF** | **`Server: CloudWAF`** + `Set-Cookie: HWWAFSESID` / `HWWAFSESTIME` + 正文 `The access is blocked.` + `requestid` 形如 `32-0000-0000-0000-<时间戳>-<hex>` | `oa.**.edu.cn` | **418**（非标准码）+ 拦截页 |
| **`wengine` 认证准入网关**（**2026-09-16 确证厂商 = 北京网瑞达科技** `wrdtech.com`，与 WebVPN 同一家，`wengine` 是其产品代号） | **`488`** + title「访问出错 - 488」+ 正文引用 `/wengine-auth-failed.png` + `Server: none` | `oa.**.edu.cn`、`moa.**.edu.cn`、`oaem.**.edu.cn` | **488** + 认证失败页 |

**⭐ 本轮最重要的一条通用规律：国产防护爱用「非标准状态码」做阻断。**

| 状态码 | 实测对应 | 记忆点 |
|---|---|---|
| `412` | 瑞数 Botgate | 人机对抗，要跑 JS |
| `418` | 华为云 WAF | `Server: CloudWAF` |
| `488` | `wengine` 认证网关 | `wengine-auth-failed.png` |
| `403` | 通用 WAF / 访问控制 | 中文自定义页居多 |

→ **见到 4xx 里「不像标准码」的（412/418/488…），先按「有防护」处理，别当成「站点异常」。**

**发现但尚未确证的（只记录，不入表）**：
- `SF_cookie_32` cookie → 深信服（Sangfor）系（`bhmoa.**.edu.cn`）；同类 `sauth` cookie 亦指向深信服认证产品
- `acw_tc` cookie → 阿里云 SLB / CDN
- `route` cookie → Spring Cloud Gateway（说明前面挂了网关）
- **`Server: none`（实测累计 48 站）→ 不是单一产品**：在泛微、瑞数、`wengine` 网关、多所高校自研上都出现。**只能读作「有网关介入」，不能当任何单一产品的判据**（`*****` / 长空格同理）
- **⚠️ 例外修正（2026-09-16 第五轮）：`Server: Server` 反而能当指纹用**。与 `none` 不同，**`Server: Server` 实测 100% 落在 WebVPN 上**（清一色 `vpn.*` / `*.vpn.*` 域名），第五轮进一步确认其中 6 站是**同一款国产 SSL VPN**（硬判据：`/com/64sys.js` + `<!-- 旧方案 -->` / `<!-- 新方案 -->` 注释 + JS 变量 `is_old_solution` / `g_midatk`）。**看到 `Server: Server` 可直接往「WebVPN」方向判** —— 这是少数「值被写错反而成为指纹」的特例

**仍未确证、保持空白的**：长亭雷池 / 安恒明御 / 知道创宇创宇盾 / 腾讯云 WAF / 安全狗 / 云锁。

**处理原则（别凭想象补）**：遇到疑似国产防护时，**先在实测中把三件事记下来再落笔** —— ① 基线响应（状态码/头/体积）② 发一个明显攻击载荷后的**阻断特征**（403？自定义页？连接重置？还是非标准码？）③ 阻断页正文里的**产品字样/文件名/图片名**。攒够 2~3 个同产品样本再写进本表，**单个样本不写**。

> **⚠️ 2026-09-16 第七轮：这块空白不是「还没采到」，是「按现有方法根本采不到」—— 必须先改方法。**
> 实测经过：从长亭官方案例（`chaitin.com/showcase/17`）确证**某双一流高校部署了雷池 SafeLine**，于是对 `**.edu.cn` 发正常 GET 采样。结果：**响应头与正文里 `safeline`/`chaitin`/`雷池` 零命中**，Server 头为空，只剩通用的 `X-Frame-Options`、`X-XSS-Protection`。

> **结论（写死，别再重复踩）**：WAF 是**反向代理串在业务前面**的，正常流量它原样透传、**不留任何自身痕迹**；只有触发拦截时才会吐出阻断页/非标准码。**想采 WAF 指纹 = 必须发攻击载荷 = 对他人资产做未授权的攻击性探测**——这与本技能红线（禁止拿 `'` 当 WAF 检测）直接冲突。所以指望「多扫几个学校就能凑齐 WAF 指纹」是死路：本轮 22 个站零命中，下一轮 200 个站还是零命中。

> **合规的替代采集路径（按可行性排序）**：
> 1. **自有靶机部署（唯一能拿到精确指纹的路径）**：雷池社区版一条命令即可起（`bash -c "$(curl -fsSLk https://waf-ce.chaitin.cn/release/latest/manager.sh)"`，Docker，管理口 9443）；安全狗、云锁等亦有免费版。**在自己的靶机上随便打**，阻断页、非标准码、产品字样全都能采全。这是把空白填上唯一干净的办法。
> 2. **被动捞公开阻断页**：用搜索引擎/dork 找被收录的 WAF 阻断页（拦截页常被搜索引擎抓到），或厂商官方案例里的截图。**不发任何载荷**。
> 3. **厂商案例与校内公告反查归属**：能确定「某校用了某 WAF」（如南开=雷池），但**只能记归属、不能验证指纹**。有价值——知道归属后，遇到该校资产可直接按该产品的已知绕过思路试探，不必先识别。
> 4. **❌ 禁止**：对非自有资产发攻击载荷只为验证 WAF 型号。哪怕载荷无害（`'`、`<script>`），性质上仍是对他人资产的攻击性探测，且会被对方 SOC 记录。


> 1. **自有靶机部署（唯一能拿到精确指纹的路径）**：雷池社区版一条命令即可起（`bash -c "$(curl -fsSLk https://waf-ce.chaitin.cn/release/latest/manager.sh)"`，Docker，管理口 9443）；安全狗、云锁等亦有免费版。**在自己的靶机上随便打**，阻断页、非标准码、产品字样全都能采全。这是把空白填上唯一干净的办法。
