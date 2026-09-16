# recon-fingerprint-cdn-wildcard

> **实战案例（双向引用）** → `attack-chain-cases.md` §2.2 资产测绘手法清单（`*.js.map` + reverse-sourcemap、被动接口扫描 APIKit/HaE、**C 段统计 ≥5 优先打**）；`idor-cases.md` §二 B **CNVD/CNCERT 设备指纹速查表**（FOFA/鹰图语法 → 端口 → 未授权接口/POC；打法：`FOFA 指纹 → 默认口令只试一次 → 找模板/导出/日志下载接口 → 退出会话匿名重访`）；`vendor-system-cases.md` §1（按产品的 FOFA 语法）；`edusrc-cases.md` §四 指纹 × 打法速查表。

**进站三件事，每个种子都要过一遍，不是「对得上才做」**：① 认指纹 ② 判 CDN / 找源站 ③ 判泛解析 / 过滤垃圾子域。

顺序不能反：**先过滤再打**。泛解析不过滤，子域爆破结果全是垃圾，会浪费整个种子；CDN 不穿透，扫到的 IP 是 CDN 节点的，端口扫描结果全是假的。

`recon-methodology.md` §4 只有命令堆砌（whatweb / httpx），本文件补它没写的三块：**国产系统指纹 → 打法映射**、**favicon hash 算法**、**CDN 穿透**、**泛解析过滤**。

---

## §1 指纹识别

### 1.1 为什么必须人工认国产系统

whatweb / wappalyzer **认不出国内 SRC 的绝大多数系统**（站点群、AWS PaaS、强智、正方、帆软、泛微、致远……）。它们只认 WordPress/Joomla/Drupal 这类海外的。**认不出不代表没有指纹**——国产系统特征极明显，只是工具没收录。

### 1.2 快速指纹位（按性价比排序）

| 位置 | 看什么 |
|---|---|
| **response body** | 特有路径 `/virexp/` `/sys/` `/gsapp/`、CSS 名 `awsui.css`、`WIS_CONFIG`、版权注释「 powered by XXX」 |
| **`<title>`** | 直接写系统名（但 SPA 常为空，别只看这个） |
| **Cookie 名** | `JSESSIONID`=Java / `PHPSESSID`=PHP / `ASP.NET_SessionId`=.NET / `laravel_session` / `thinkphp_show_page_trace` |
| **Server / X-Powered-By** | 有的被隐藏成 `*****` 或 `Server         `（带空格），**被隐藏本身就是指纹**（说明运维动过） |
| **favicon.ico** | 默认图标 + hash 能反查同套系统的其他站（§1.4） |
| **JS/CSS 文件名** | `static/js/app.7cfb0f9c.css` → Vue CLI；`chunk-vendors` → Vue；`umi.js` → Ant Design Pro |
| **特有接口** | `/api/swagger/doc.json`（GVA）、`/sys/emapcomponent/file/*`（emap） |

### 1.3 国产系统指纹 → 该打什么（核心表）

认到就照着打，别再从头跑字典。

| 指纹特征 | 系统 | 优先打什么 |
|---|---|---|
| `gin-vue-admin`、`/assets/xxxxindex.xxx.js` + `/api/swagger/doc.json` | **Gin-Vue-Admin** | Swagger 未授权（123 接口）、`/api/init/initdb` 是否在、默认 JWT 密钥 `qmPlus`、登录口账号枚举 |
| `awsui.css`、`_bpm.portal`、`vsharinglogin`、「AWS PaaS实例控制台」 | **炎黄盈动 AWS PaaS** | 管理员控制台暴露公网、默认口令、BPM 接口未授权 |
| `emap.js`、`bh.min.js`、`WIS_CONFIG`、`schoolId=`、`.do` 接口 | **BH 框架**（强智/青谱，教务/研究生） | `/sys/emapcomponent/file/getFileByToken` 任意文件下载、越权查他人、登录口 userType 差分 |
| `_sitegray`、`/system/resource/js/`、站点群版权 | **站点群**（苏迪/方正/万户） | 前台注入、编辑器上传、越权、老 CVE |
| `/jsxsd/` | **正方教务** | 越权、注入、默认口令 |
| `/jwglxt/`、`URP` | **强智 URP 教务** | 越权、注入 |
| `/decision/`、`FineReport` | **帆软报表** | 未授权、任意文件读（历史 Nday 多） |
| `/weaver/`、`E-Mobile`、`泛微` | **泛微 OA** | 大量历史 Nday（先用 nuclei 收窄） |
| `/seeyon/`、`A8`、`致远` | **致远 OA** | 大量历史 Nday |
| `/jeecg-boot/`、`jeecg` | **JeeCG Boot** | 默认密钥、SQL 注入、Swagger |
| `ruoyi`、`/ruoyi`、`若依` | **RuoYi** | 默认口令 `admin/admin123`、Swagger、定时任务 |
| `/dede/`、`plus/`、`织梦` | **DedeCMS** | 前台 getshell、历史漏洞 |
| `/e/`、`EmpireCMS` | **帝国 CMS** | 历史漏洞 |
| `/virexp/`、`润尼尔`、`虚拟仿真` | **润尼尔虚拟仿真** | 未授权、文件上传 |
| `/mooc`、超星 | **超星/泛雅** | 越权、接口未授权 |
| `MG 127`、`mg.127.net`、`qiye.163.com` | **网易企业邮箱** | 注意：**核心漏洞归网易**，只挖学校自研部分（自研 JSP / 定制页），别在厂商代码上耗 |
| `thinkphp`、cookie `thinkphp` | **ThinkPHP** | 历史 RCE（5.0.x/5.1.x 等），先核版本 |

**判不出系统时**：看是什么语言 + 什么年代。老 PHP/Java 自研后台 → 优先试 `知识库/redirect-ear-unauth.md`（3xx 截断跳转，PHP 的 `header` 不 `exit` 是重灾区）。

### 1.4 favicon hash 反查（找同套系统的其他站）

FOFA / Shodan 支持 `icon_hash`。算法是 **MurmurHash3 x86 32-bit，seed=0**，输入是 favicon 的 base64 串（**每 76 字符插一个 `\n`**）：

```python
import base64, urllib.request, ssl
ssl._create_default_https_context = ssl._create_unverified_context
b = urllib.request.urlopen('https://target/favicon.ico', timeout=10).read()
s = base64.encodebytes(b).decode()          # 关键：带换行，不是 b64encode
try:
    import mmh3; print(mmh3.hash(s))
except ImportError:
    print('pip install mmh3')
```

拿到 hash 后 FOFA 搜 `icon_hash="123456789"` → **同套系统的所有站**。学校往往给多个院系部署同一套，一挖一串。

注意：默认图标（浏览器/server 自带）的 hash 是全互联网通用的，**搜出来几万条就没意义**，先确认 favicon 是定制的。

---

## §2 CDN 识别与源站穿透

### 2.1 先判断有没有 CDN

| 判据 | 说明 |
|---|---|
| **CNAME** | 指向 `*.cdn.com` / `alicdn` / `cloudfront` / `akamai` / `qiniudn` / `wscdns` / `chinacache` / `lxdns` / `txcdn` / `cdntip` |
| **响应头** | `X-Cache` / `CF-RAY`（Cloudflare）/ `X-Served-By`（Fastly）/ `Via` / `Age` / `Server: cloudflare` / `X-CDN` |
| **多 IP** | 同一域名解析出多个 A 记录，或各地 ping 结果不同 |
| **TTL 小** | 60 / 120 这种短 TTL |
| **IP 归属** | A 记录 IP 属于阿里云/腾讯云/Cloudflare 段，但 `nslookup` 反解无 PTR |

**不用穿透的情况**：只挖 Web 层漏洞（注入/越权/逻辑）时，**CDN 不影响**，直接打域名就行。
**必须穿透的情况**：要打**端口/服务/中间件**（Redis、MySQL、Shiro、Fastjson、Nacos）时——扫 CDN 节点没意义。

### 2.2 穿透找源站（按成功率排序）

1. **子域直连**（最高性价比）：CDN 通常只配 `www` 和 `@`。试这些子域的 A 记录：
   `mail` `oa` `test` `dev` `api` `direct` `origin` `cpanel` `ftp` `mx` `old` `staging` `beta` `admin` `vpn` `erp` `crm` `file` `upload` `download` `ip` `cdn-origin`
   拿到 IP 后验证：`curl -H "Host: 目标域名" -i http://IP` 内容和域名访问一致 → 是源站

2. **历史 DNS 记录**（CDN 上线前的 A 记录就是源站）：SecurityTrails、ViewDNS、DNSDB、微步在线、circl.lu/passive-dns

3. **SSL 证书反查**：crt.sh / censys 搜 `证书=目标域名`，同 IP 上同证书的**其他域名**可能指向源站

4. **BIG-IP / F5 cookie 解码**（很实用）：响应 Cookie 里 `BIGipServer<pool>=vi20010112000000000000000000000030.20480` 这种，格式是 `A.B.C.D.port` 的倒序编码：
   ```
   取第一段十进制 → 转十六进制 → 每两位倒序拼回 → 得到 IP
   ```
   能直接解出**内网真实 IP + 端口**。同理 `X-Forwarded-For` / `X-Real-IP` 有时直接带

5. **邮件头**：注册/找回密码触发一封邮件，看 `Received:` 里的服务器 IP（常是源站或内网）

6. **phpinfo / 报错页 / 配置泄露**：`SERVER_ADDR` 字段直接给真实 IP

7. **FOFA 反查**：`title="XXX" && is_cdn=false`，或按系统特征（body="版权文字"）搜同套系统的裸奔 IP

8. **SPF / TXT 记录**：`dig TXT 目标域名` 里可能有机器的真实 IP 段

9. **端口扫描旁证**：确认源站网段后扫 22/3306/3389/8080 等，看是不是同一台
10. **同 C 段扫漏网资产**（实测最有效，别跳过）：把已确认归属的资产 IP 归到一起，如果落在同一 `/24`，**扫整个段的 80/443 拿 title**，能挖出**没有域名、FOFA/CSV 里都没有**的资产。

    实测例子：某高校已确认资产全在 `101.231.216.0/24`，扫全段后新发现 `*.118`=**Harbor**（74 个镜像）、`*.26`/`*.27`=另一个 CAS 实例、`*.203`=网易账户集成平台——**前面 6 轮按域名打全都没发现**，因为它们没绑域名。

    ```python
    # 扫段：只取 title + 状态码，不做任何攻击
    # 254 IP × 2 端口，max_workers=28 约 1 分钟
    # 归属判定：title/body 含目标名，或内容与已知资产同源，才入资产表
    ```
    **纪律**：只收集 title 定性，**不做漏洞探测**；归属存疑的（内容像个人/第三方服务）先标「待确认」，确认前不打。

### 2.3 验证拿到的是不是源站

```bash
curl -i --noproxy '*' -H "Host: 目标域名" http://候选IP/
# 对比 title / body 和直接访问域名是否一致
```
**不一致** → 只是同 IP 的其他站（vhost 不同），不是源站。
**一致** → 是源站，可以开始打端口和服务。

### 2.4 假点

- 把 CDN 节点当源站扫端口 → 结果全是 CDN 的，白扫
- 「多 IP = 有 CDN」不成立，有些源站本身就是多 IP 负载均衡
- 子域拿到 IP 就当源站 → 必须先 Host 头验证

---

## §3 泛解析判定与过滤

### 3.1 判定

解析一个**绝对不存在**的随机子域：

```bash
nslookup zzz-random-9x7a3f.target.com
# 或
dig zzz-random-9x7a3f.target.com +short
```

**能解析出 IP → 泛解析开着**。这是必须做的第一步，不做直接爆破就是浪费时间。

### 3.2 泛解析的几种形态（别只判一种）

| 形态 | 表现 | 坑 |
|---|---|---|
| A 记录全泛 | `*.target.com → 1.2.3.4` | 最常见 |
| CNAME 全泛 | `*.target.com → xxx.cdn.com` | 容易误判成「每个子域都是真站」 |
| **部分泛** | 只泛 `*.dev.target.com`，`*.target.com` 不泛 | 判一次就下结论会漏 |
| **分层泛** | 二级泛、三级不泛（或反之） | 逐层都要判 |

**每层都要单独判**：`*.target.com`、`*.a.target.com`、`*.dev.target.com` 各判一次。

### 3.3 过滤（两层，缺一不可）

**第一层：DNS 层 —— 建泛解析 IP 黑名单**

解析 5~10 个不同的随机子域，把返回的 IP 收集成集合：

```python
import socket, random, string
ips = set()
for _ in range(8):
    sub = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
    try:
        ips.add(socket.gethostbyname(f'{sub}.target.com'))
    except Exception:
        pass
print('泛解析 IP 黑名单:', ips)
```

爆破结果里 **IP 在这个集合中的，标记为疑似垃圾**。

**第二层：HTTP 层 —— 用内容二次确认（这层才是关键）**

**泛解析 IP 上也可能跑着真实业务**（靠 vhost 区分）。只按 DNS 层过滤会**丢掉真实资产**。

做法：对 DNS 层标疑似的子域，发 HTTP 请求，和随机子域的响应对比：

```
基准 A = 随机不存在子域的响应（title + body 长度 + body md5）
候选 B = 待判子域的响应

B 与 A 完全相同  → 垃圾，丢
B 与 A 不同      → 真站，留（哪怕 IP 在黑名单里）
```

**对比维度**（按可靠度）：body 的 md5 > title > 响应长度 > 状态码。长度会抖，优先用 md5。

### 3.4 和 SPA catch-all 的区别（别混）

| | 表现 | 判定 |
|---|---|---|
| **SPA catch-all** | 前端路由把**所有 path** fallback 到首页，任何文件名都返 200 | 看**同一域名下不同 path** 响应是否一致 |
| **泛解析** | 所有**子域**解析到同一 IP | 看**不同子域** 解析/响应是否一致 |

两者经常同时存在（一个 SPA 站又开了泛解析），**要各判一次**。`知识库/artifact-intel-guide.md` §3.1 记的 SPA catch-all 去伪方法在这里同样适用。

### 3.5 工具

- `dnsx -wd` 自动过滤泛解析
- `subfinder` / `ksubdomain` 爆破后必须再过一遍 §3.3 两层过滤
- **工具只做第一层**，第二层（HTTP 内容对比）必须自己做，工具不管

---

## §4 进站检查清单（每条种子过一遍）

```
[ ] 指纹：title / body 特有串 / Cookie 名 / JS 名 / favicon → 对照 §1.3 表定打法
[ ] favicon hash 反查同套系统（§1.4）
[ ] 判 CDN：CNAME + 响应头 + 多 IP（§2.1）
[ ] 要打端口/中间件 → 穿透找源站（§2.2），拿到后 Host 头验证（§2.3）
[ ] 判泛解析：随机子域 + 逐层判（§3.1/3.2）
[ ] 子域列表过两层过滤（§3.3）
[ ] 打之前先排除 SPA catch-all / WAF 拦截页假阳性
```

## §5 一句话

**指纹决定打法，CDN 决定能不能打端口，泛解析决定子域列表能不能用。** 这三件没做就开打，等于闭眼扔飞镖。
