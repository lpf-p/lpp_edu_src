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
| **Server / X-Powered-By** | 有的被隐藏成 `*****` 或 `Server         `（带空格），**被隐藏本身就是指纹**（说明运维动过）。⚠️ **陷阱（2026-09-16 实测）**：还会出现**字面量** `Server: none`、`Server: Server` —— 那是**值被写错**，不是「没有 Server 头」，**别拿它当判据**（实测 `card.**.edu.cn` / `survey.**.edu.cn` / `student.career.**.edu.cn` / `napp.**.edu.cn` 全是 `none`，横跨两所高校，属某类网关的默认配置） |
| **favicon.ico** | 默认图标 + hash 能反查同套系统的其他站（§1.4） |
| **JS/CSS 文件名** | `static/js/app.7cfb0f9c.css` → Vue CLI；`chunk-vendors` → Vue；`umi.js` → Ant Design Pro |
| **特有接口** | `/api/swagger/doc.json`（GVA）、`/sys/emapcomponent/file/*`（emap） |
| **防护指纹** | 见到 **`412 Precondition Failed`** + 正文含 `$_ts` 变量（`$_ts.nsd` / `$_ts.cd`）+ **随机 13 位名 cookie** + meta 随机 id + 标签属性 `r='m'` → **瑞数信息 Botgate 动态防护**（国产，教育/政务站极常见）。**别拿它当「站点挂了」**，它是人机对抗网关，要跑 JS 换 cookie 才能进。矩阵见 `waf-bypass.md` 附件「国产防护矩阵」 |
| **自研栈关联线索** | `Set-Cookie: keepalive='<base64>'`（值带单引号）—— 2026-09-16 实测在 `faculty.**.edu.cn` / `courses.**.edu.cn` / `feedback.**.edu.cn` 同现，**同一套自研网关**。见到它可判断「这几个站同源自研」，进而横向复用接口/参数命名 |

**⚠️ 认系统看技术栈指纹，不看域名语义（2026-09-16 实测）**

同一个语义的域名，可能是**完全不同**的系统。实测「教师主页系统」在三所学校：

| 域名 | 实测技术栈 |
|---|---|
| `faculty.**.edu.cn` | JSP + 自研网关（`keepalive` cookie） |
| `faculty.**.edu.cn` | JSP（无 Server 头） |
| `web.**.edu.cn` | **Apache/2.4.57 (Win64) + PHP** |

**三套不同实现。** 看到 `faculty.*` / `oa.*` / `portal.*` 这类语义域名，**不要假设「跟上次那个一样」就复用 payload**——先取 `Server` / `Set-Cookie` / `X-Powered-By` 定技术栈。

**顺带（3 样本，2026-09-16）**：高校**实验室 / 课题组**站实测 3/3 是 **WordPress**（`lemon.**` / `nsec.**` / `perovskite.**`，正文 `wp-content` 命中数十次）。遇到 `*.lab.*` 或实验室/课题组域名，先试 `/wp-json/wp/v2/users`（用户枚举）、`/xmlrpc.php`（`pingback.ping` XXE，打法见 `edusrc-cases.md` §2.13.4）。

**另（2026-09-16 修正，原判据有误导性）**：`Set-Cookie: route=<32 位 hex>` 原记「实测 5/5 与泛微 e-cology 同现，是泛微旁证」。**后续采样推翻了这条** —— 同批实测里 `zfxk.**.edu.cn`（正方教务，Tengine + ASP.NET，非泛微）与 `webproxy.**.edu.cn`（**网瑞达** WebVPN，cookie `wengine_vpn_ticketwebproxy_dhu_edu_cn`）**同样下发 `route`**。结论：**`route` 是 SLB / 反向网关的会话保持 cookie，与后端是什么产品无关，不能作为任何产品的旁证**。原「5/5 与泛微同现」只是样本同源（都是某批 OA 站）造成的巧合 —— 这是「相关不等于因果」的典型反例，已按新样本降级为**纯噪声**。

### 1.3 国产系统指纹 → 该打什么（核心表）

认到就照着打，别再从头跑字典。

> **⭐ 认「入口类资产」（统一认证 / WebVPN / 资源代理）的关键前提（2026-09-16 第五轮实测，234 站）**：**只看根路径 `GET /`，会有 54%~76% 认不出来**。实测 134 个未定性站里，**103 站（76%）的响应体是「空体（0 B）」或「纯跳转页（< 300 B）」** —— 根路径只有一个 301/302，**厂商信息全在跳转之后的登录页上**。
> **所以：认入口类资产必须跟一跳**（`curl -L`，或手动 GET `Location` 的目标），否则必然大面积「未定性」。**这是入口类资产比 OA 难认的根本原因，不是指纹表不够全。**
> 另一条实测结论：**这批资产的响应体里 0 个厂商署名、0 个 ICP 备案号** —— 别指望从版权信息认厂商，要靠 **cookie 名 / 路径 / JS 名 / title** 这四个字段。
> **✅ 跟一跳已实测验证（2026-09-16 第六轮，30 站手动跟跳，30/30 成功）**：25 个 root 未定性的跳转站，跟一跳后 **11 站（44%）直接拿到判据**（网瑞达 ×5、CAS ×6、`Server: Server` SSL VPN ×1、SSO ×1、泛微 ×1）；**14 站（56%）落地页仍零命中** → **跟一跳是入口类的第一步，但不充分**：仍零命中的站，第二步打 `/login`、`/cas/login`、`/sso` 常见路径与 JS 引用，再不行归「无公开指纹」。三条硬细则：① **Set-Cookie 名在 302 上就要扫**（`wengine_vpn_ticket*` 在跳转响应上就出现，别等落地页）；② **某高校 WebVPN 把 Server 头写成 `******`（通配屏蔽）+ `*.webvpna.**.edu.cn` 域名模式，屏蔽本身即指纹**；③ 同名陷阱：cookie `Sharetop.ClientId` / `Sharetop.Session`（某校 scholar 站）是某 Web 应用框架的判据，与深圳 Sharetop（光通信设备，xyt-tech.com）无关，**勿按英文名误归属**。

| 指纹特征 | 系统 | 优先打什么 |
|---|---|---|
| `gin-vue-admin`、`/assets/xxxxindex.xxx.js` + `/api/swagger/doc.json` | **Gin-Vue-Admin** | Swagger 未授权（123 接口）、`/api/init/initdb` 是否在、默认 JWT 密钥 `qmPlus`、登录口账号枚举 |
| `awsui.css`、`_bpm.portal`、`vsharinglogin`、「AWS PaaS实例控制台」 | **炎黄盈动 AWS PaaS** | 管理员控制台暴露公网、默认口令、BPM 接口未授权 |
| `emap.js`、`bh.min.js`、`WIS_CONFIG`、`schoolId=`、`.do` 接口 | **BH 框架**（强智/青谱，教务/研究生） | `/sys/emapcomponent/file/getFileByToken` 任意文件下载、越权查他人、登录口 userType 差分 |
| `_sitegray`、`/system/resource/js/`、站点群版权 | **站点群**（苏迪/方正/万户） | 前台注入、编辑器上传、越权、老 CVE |
| **`/authserver/`**（302 跳 `/authserver/`）、**`/authserver/login?service=`**（标准部署 = `authserver.<域名>` + 该路径；2026-09-16 实测 `smp.**.edu.cn`→`authserver.**.edu.cn/authserver/login?service=`）、**`Server: wisedu`**（⭐ **直接把产品名写在 Server 头**，实测 3 站）、**`/lyuapServer/login?service=`**（**实测 7 站，是金智最普遍的判据**）、**⭐ USB Key / 证书登录组件文案（第五轮新证，硬指纹）**：可见文本「**组件版本号**」「**请选择证书**」「**选择的证书ID**」「**请选择设备序列号**」「**选择的设备序列号**」（2026-09-16 实测 `lib.**.edu.cn`，并由搜索在 `cas.**.edu.cn/lyuapServer/login`、`cas.**.edu.cn`、`jwxt.**.edu.cn/sso/lyNoFilterLogin` 交叉印证 —— 该证书组件正是金智认证平台自带，**很多站只暴露这段文案、不暴露 `/lyuapServer/` 路径**）、**⭐ `assets/js/less.min.js` + `assets/js/ai.min.js` + title「统一身份认证平台」**（第五轮实测 3 站同款：`cas.**.edu.cn:4101` / `hr.**.edu.cn:4101`（**两站响应体逐字节相同**，3133 B） / `lib.**.edu.cn`；⚠️ **这套常挂在非标端口 `4101`**）、**`/build/ecodesdk/`**（`ecodesdk` = 金智 ecode 平台前端 SDK；实测 `ehallpro.**.edu.cn` 的 `/build/passport/` + `/build/vendor/` + `/build/utils/` + `/build/ui/` + `/build/layout/` 同套构建产物；官方演示站 `ciap.show.wisedu.com` 署名「江苏金智教育信息股份有限公司」）、`/new/index.html`（ehall 门户首页）、`/rsfw/sys/`（人事）、`serviceValidate` 返 Yale CAS XML（`xmlns:cas='http://www.yale.edu/tp/cas'`）、页面 title「统一身份认证」、域名前缀 `authserver.` / `sso.` / `cas.` / `ehall.` | **金智教育统一身份认证（wisedu）** —— 基于 **Apereo CAS** 定制 | ⚠️ **全校通行证，打一个等于打一片**。① 初始口令规则：**学号 + 身份证后 6 位**（最常见），先小样本试；② CAS 面：`service` 参数开放重定向 / ticket 泄露、`lt`+`execution` 令牌、`_eventId` 状态机跳步、`serviceValidate`/`p3/serviceValidate` XML 解析（XXE）；③ 历史 Nday：**CNVD-2018-17443「逻辑设计漏洞 → 重置任意账号密码」，厂商 6.2.4 已修**（认到先核版本，≥6.2.4 别指望）；④ 打法定式见 `知识库/authbypass-test.md` + `知识库/password-reset-test.md` |
| **.NET OIDC 身份服务（第五轮新证）**：页面同时出现 **`Discovery Document`** + **`Login`** 两个链接、`/Home/SetLanguage?returnUrl=`、`Set-Cookie: .AspNetCore.Antiforgery.*`、静态资源 `/dist/js/bundle.min.js` + `/dist/css/bundle.min.css` + `/dist/css/web.min.css`、12 国语言下拉（English / Persian / French / Russian / Swedish / Chinese / Spanish / Danish / German / Dutch / Finnish / Portuguese）、HTML 注释 `Site name` / `Menu item` / `Menu button - show in < MD` | **IdentityServer4 / Duende IdentityServer / OpenIddict（.NET 自建统一认证）** —— 站点名可自定义（实测 `bpm.**.edu.cn:4500` 站点名写作「Iduo统一身份认证」，**`Iduo` 是站点名不是厂商，别记错**） | ① **OIDC 客户端配置泄露**：`/.well-known/openid-configuration` 拿 issuer / endpoints，再试 `client_id`（本页跳转里可见 `client_id=`）→ **校验 `redirect_uri` 是否白名单严格**（宽泛则授权码可劫持）；② `Discovery Document` 页会**列出全部 scope / claims**，据此找过度授权；③ `/Home/SetLanguage` 之类控制器做**开放重定向**探测（`returnUrl=` 未校验）；④ 默认 `client_secret` 未改（IdentityServer4 常见）；⑤ 授权码 `code` 复用 / PKCE 缺失 |
| **WebVPN · 网瑞达线（⭐ 高校电子资源访问主力，也是通往内网的跳板）**：**URL 结构 `/http/<hex>/` 或 `/https/<hex>/`，且 `<hex>` 以 `77726476706e69737468656265737421` 开头** —— 该串是**硬编码 IV**，hex→ASCII = `wrdvisthebest!`（`wrd` = 网瑞达）；**`Set-Cookie: wengine_new_ticket`** / **`wengine_vpn_ticket<域名去点>`**（如 `wengine_vpn_ticketwebvpn_<域名去点>`、`wengine_vpn_ticket<域名去点>` —— **cookie 名里直接编码了域名，是铁证**）；`/wengine-auth/login`、`?fromUrl=`、正文 `wengine-vpn` / `aes-js.js` / `portal.js`；**`Server: none`（字面量）** | **网瑞达 WebVPN**（北京网瑞达科技有限公司，`wrdtech.com`，产品名「资源访问控制系统」）—— **2026-09-16 实测 234 个高校统一认证 / WebVPN 资产，网瑞达系 10 站（⭐ 10/10 全部 `Server: none`）**：`webvpn.**.edu.cn` / `wvpn.**.edu.cn` / `webvpn.**.edu.cn` / `webvpn.**.edu.cn` / `webvpn.**.edu.cn` / `testvpn.**.edu.cn` / `ngx.**.edu.cn` / `rsc.**.edu.cn` / `portal.**.edu.cn` / `*.vpn.**.edu.cn`，客户含多所双一流高校 | ⭐ **价值不在系统自身，在「进去之后」**：① **默认 key/iv 未改是普遍现象** —— 前端用 `aes-js` 做 AES-CFB，key/iv 常为默认值（加密脚本里变量名就叫 `wrdvpnKey` / `wrdvpnIV`），拿到后可**加密任意内网地址** → 拼 `/http/<enc>/` → **直接访问内网资源**；② URL 可带协议和端口（`/http-xxx/`、`/https-xxxx/`）；③ **RCE**：普通账户登录后访问 `1.1.1.1@127.0.0.1:8860`，返回 `pong` 即存在（返回 401 则不可，可把域名解析到 127 绕过）；④ **弱口令 CNVD-2021-84288**（可批量登录 VPN 前台）。详见 `nday-watchlist-2026.md` |
| **WebVPN · 奇安信线（2026-09-16 采样）**：**title「奇安信VPN」**（正文含 `Qianxin` / 「奇安信」字样，**厂商名直接写在页面上，属直接证据不是推断**）+ `Server: nginx` + cookie 组 `PHPSESSID;user_lang_id;client_style;portal_param;3g_login;mod_pass_param` （其中 `3g_login` / `mod_pass_param` / `client_style` 是少见组合，可作辅助） | **奇安信 VPN**（原网康，Qianxin） | 实测 1 站（`vpn.**.edu.cn`，29833 B 登录页）。⚠️ **单样本**：title 明写厂商名所以定性可靠，但**上述 cookie 组是否通用未验证**，再遇到 1~2 个同款前不要把它当硬判据。**判奇安信优先看 title/正文的厂商字样，其次才是 cookie**。另：`vpn.**.edu.cn` 官网提供 EasyConnect 客户端但网关是另一款（见下方「三家厂商」），**别把 EasyConnect 当成深信服网关的证据** |
| **WebVPN · 锐捷线（2026-09-16 新确证，第 4 款 WebVPN）**：**`Server: sslvpn 1.0`（字面量，注意是小写 `sslvpn` 不是 `SSL VPN`）** + **`Set-Cookie: rjsslvpnSID` / `rjsslvpnCF` / `rjsslvpnVER`**（`rj` = **锐捷**）+ title「**SSLVPN登录页面**」+ 响应体 **2465 B** | **锐捷网络 SSL VPN**（Ruijie，锐捷网络股份有限公司）—— 与网瑞达、深信服并列的第三家高校常见 VPN 厂商 | 实测 2 站同款（`vpn.**.edu.cn`、`sslvpn.**.edu.cn`，**响应体逐字节相同，均 2465 B**）；厂商旁证：西安理工大学信息化管理处官网《WebVPN 使用说明》明写「在『开始』菜单中搜索『SSL VPN』查找**锐捷 VPN** 快捷方式」，且该校 VPN 客户端下载页指向 `ruijie.com.cn`。**打法未实测，只写识别**：① 与网瑞达同属「资源代理型入口」，进去之后才是价值所在；② 三款 VPN 的区分要点：网瑞达看 `wengine_vpn_ticket*` cookie + `/http/<hex 以 77726476706e69737468656265737421 开头>/`，锐捷看 `rjsslvpn*` cookie + `Server: sslvpn 1.0`，深信服看 `/por/login.csp` / `EasyConnect` 客户端（如 `vpn.**.edu.cn` 系 openresty + 深信服登录页）。⚠️ **title「SSLVPN登录页面」不是锐捷独有**（别的厂商也用这个标题），**必须配 `rjsslvpn*` cookie 或 `sslvpn 1.0` 才定性** |
| **WebVPN · 其他实现**：`Server: Sangine` + 端口 **`:8118`** + 跳转 `vpn.<域名>?redirect_uri=<原URL>` 或 `/controller/v1/public/verify?t=<JWT>`（JWT 内含 `gateway_ip` / `client_ip`）；**`Server: Server`（字面量）实测 8/8 全是 WebVPN**（清一色 `vpn.*` / `*.vpn.*` 域名）—— **第五轮进一步定性为「同一款国产 SSL VPN」**，硬判据：`/com/js/common.min.js` + `/com/common.js` + **`/com/64sys.js`**、HTML 注释 **`<!-- 旧方案 -->` / `<!-- 新方案 -->`**、JS 变量 **`is_old_solution`** / **`g_midatk`**（中间人攻击自检）/ `selectline_timeout`（多线路选路）、正文 `alert(tr("您访问的SSL VPN系统正受到中间人攻击(SSL Strip攻击)..."))`、开发者注释 `luyi 20120223`（2012 年代码）。第五轮实测 6 站同套：`vpn1.**.edu.cn:4433` / `webvpn.**.edu.cn` / `vpn.**.edu.cn:8080` / `vpn1.**.edu.cn` / `www.vpn.**.edu.cn` / `vpn.**.edu.cn:4433`（响应体 7177~9133 B），另 `navi-cnki-net-s.vpn.**.edu.cn` 亦 `Server: Server`（**厂商名未确证**）；**第 3 款 WebVPN：`Server: appframe` + `/vpn/theme/auth_home.html`**（实测 `webvpn.**.edu.cn`，搜索印证 `vpn.**.edu.cn` 同路径）；`/users/sign_in` + `_astraeus_session`（Rails/Devise 栈，代号 Astraeus；**2026-09-16 交叉印证为多校同款产品**：urlscan 存档显示 `webvpn.**.edu.cn` / `webvpn.**.edu.cn` / `webvpn.**.edu.cn` / `webvpn.**.ac.cn` / `webvpn.**.cn` 同款登录页 + `SERVERID=Server1/Server2` —— **不是单校自研，是通用产品，厂商中文名仍未公开确证**）；自研 `/go?http://`、`/vpn_key/update` | **Sangine 网关（厂商未确证）/ Astraeus / 自研 WebVPN** | 先只做到识别。**⚠️ 关键澄清**：`Server: none` 与 `Server: Server` 都是**网关把 Server 头写错**（是字面量，不是「无 Server 头」），**不能单独定性** —— `Server: none` 实测 **28 站**，跨**网瑞达 10 站 + 金智 / 正方 / CAS 等认证网关 18 站**，必须结合 cookie / Location 判断 |
| **图书馆电子资源 ERMS（第五轮新证，新厂商）**：`/ermsLogin/SSOLogin.do?msgcode=login_valid`、`/ermsLogin/view.do?msgcode=login_valid`、`/ermsClient/home.do`、**`Set-Cookie: CWJSESSIONID`**（`CW` = 创文）、页面底部署名 **「©北京创文科技有限公司」**、域名形如 `libproxy.*` / `dbproxy.*` / `eds.*` | **北京创文科技有限公司 · 图书馆电子资源管理平台（ERMS）** —— 高校图书馆「校内外统一访问电子资源」入口 | 实测 2 站：`cw.**.edu.cn`、`libproxy.**.edu.cn`；**⚠️ 2026-09-16 反例（归入「域名语义 ≠ 产品」）：`libproxy.**.edu.cn:8080` 域名看着像图书馆代理，实测 `Server: squid/5.8` + 400 —— 是自建 squid 反代，不是任何商业代理产品。认厂商只看技术栈指纹（Server 头 / cookie / 路径 / 响应体），域名前缀只能用来猜、不能用来定。**搜索印证同款另见 `dbproxy.**.edu.cn`、`eds.**.edu.cn`、`res.**.org.cn`。**⚠️ 这是「资源代理」型入口，与 WebVPN 同属「通往内网 / 授权资源的路」**：① `SSOLogin.do` / `view.do` 的 `msgcode` 参数做**越权 / 逻辑绕过**探测；② `ermsClient` 系列 `.do` 接口（Struts 风格）试**未授权访问 / 目录遍历**；③ 与学校统一认证对接处看 `ticket` / `token` 能否伪造 |
| `/jwglxt/xtgl/login_slogin.html`、`/xtgl/login_slogin.html`、title「教学管理信息服务平台」、**`X-Powered-By: ZFSOFT-SERVER`**（Servlet/3.0 JSP/2.2）、`/jsxsd/`（老版） | **正方教务**（新版 `/jwglxt/`，老版 `/jsxsd/`） | 越权、注入、默认口令。**新版特有**：`X-Powered-By` 直接吐 `ZFSOFT-SERVER` 与 JDK 版本；老版认 `/jsxsd/`。学工侧（`xgxt/`）另有一套：`commXszz.do?method=uploadFile` 上传 getshell、`xgxt/mmzhgl_mmzh.do?method=xgmm&yhm=zf01` 重置内置超管 |
| `URP`、`emap.js`、`bh.min.js`、`WIS_CONFIG`、`schoolId=`、`.do` 接口 | **强智 URP / BH 框架**（教务、研究生） | 越权、注入。**注意：`/jwglxt/` 是正方不是强智**，别混 |
| `/decision/`、`FineReport` | **帆软报表** | 未授权、任意文件读（历史 Nday 多） |
| **e-cology 线**：`Set-Cookie: ecology_JSessionid`（集群版另发 `ecologycluster` / `__clusterSessionCookieName`）、`/js/jquery/jquery_wev8.js`（`wev8`）、`/system/index_wev8.js`、`/wui/index.html`、`/api/ec/dev/`。**单请求硬指纹（2026-09-16 实测，批量 30+ 站命中）**：首页 `ETag` + `Last-Modified` + 正文 `window.location.href="/wui/index.html#/?logintype=1&time="` —— **连 cookie 都不用看就能一眼认**。**⚠️ 有两个版本，ETag 不同，别只记一个**：① 新版 `Content-Length: 3235` / `ETag: "HCPGHF5c4V7"` / `Last-Modified: Thu, 06 May 2021 01:48:18 GMT`；② 老版 `Content-Length: 3139` / `ETag: "+bN7Mb724j6"` / `Last-Modified: Tue, 17 Jul 2018 09:20:10 GMT`。**体积随版本变，3235 不是唯一值**（实测还见 3139 / 3215 / 3352）。**⭐ 辅助判据（2026-09-16 实测 25/25 命中）**：`Server: WVS` —— 25 个带 `Server: WVS` 的站**全部**是泛微 e-cology（`WVS` 具体是什么未确证，但关联性极强，可当泛微的旁证） | **泛微 e-cology** | ① **未授权**：`GET /api/ec/dev/app/test` → `{"msg":"ok","ec_id":"…","ec_url":"…","em_url_open":"…"}`，**未认证吐内部 id + 旁系资产地址（含非标端口）**；② `/mobile/%20/plugin/browser.jsp` SQL 注入（**须三层 URL 编码**）；③ 默认口令 `sysadmin/1`、`sysadmin/Weaver@2001`；④ 配置 `weaver.properties`；⑤ 历史 Nday 多（含 E-cology 10 未认证 RCE，见 `nday-watchlist-2026.md` §1）。⚠️ **教育资产中最常见的厂商成品系统之一**（2026-09-16 批量实测 234 站，泛微系占多数；**注意样本来自某报告集合，存在选择偏差，不是行业市占率**）。见 `vendor-system-cases.md` §一 #39~#42 |
| **e-office / E-Mobile 线**：`/weaver/`、`E-Mobile`、页面版权「泛微」、**`Set-Cookie: EM_JSESSIONID`**（E-Mobile 的会话 cookie，实测 `oa.**.edu.cn`）、`emobilecluster`（集群版） | **泛微 e-office / E-Mobile**（**注意与 e-cology 是不同产品线，路径不通用**） | 大量历史 Nday（先用 nuclei 收窄）。⚠️ **实测提醒**：E-Mobile 与 e-cology 常**同机共存**（同一站可能同时发 `EM_JSESSIONID` 和 `ecology_JSessionid`），认到任一个都要再探另一个 |
| **移动端线（第三条）**：title「**移动管理平台-企业管理**」、`/page/manage/js/main.js`（`vendor.js`/`main.js` 带 `?YYYYMMDD` 版本戳）、正文 `window.apiPrifix="/emp"`、`/page/manage/js/jsencrypt.min.js`（新版有）、`weaver` 图标字体（`.weaver-icon`）、默认 logo `ms.wx.weaver.com.cn/common/images/tenant_default.png` | **泛微 移动管理平台（`/emp` 线）** —— **2026-09-16 批量实测 23+ 站**（`moa.*` / `mobile.*` / `app.*` / `oa-wechat.*` 等命名居多），**泛微第三条产品线，路径与 e-cology / e-office 全不通用** | 前端 Vue SPA + 后端 **Spring Boot**（404 返 `{"timestamp":"yyyy-MM-dd HH:mm:ss","status":404,"error":"Not Found","path":"…"}`，**时间戳非 ISO 是定制格式，可作辅助指纹**）。**未实测过打法，先只做到识别**：`/emp` 下枚举未授权接口；`accessToken` 存在 `localStorage`，可关注 XSS→token 窃取。⚠️ **别拿 e-cology 的 `/api/ec/dev/` 打这条线**。⚠️ **判据只能靠 title + `/page/manage/`，不能靠体积**：实测 `Transfer-Encoding: chunked` 无 `Content-Length`，正文体积随**版本戳**与**语言**变（2021 版 `?20211012` ≈835B 精简壳；2026 版 `?20260909` ≈2162B 带内联跳转 + jsencrypt；同代还有 2100/2112 等变体） |
| `/seeyon/`、`A8`、`致远` | **致远 OA** | 大量历史 Nday |
| `/jeecg-boot/`、`jeecg` | **JeeCG Boot** | 默认密钥、SQL 注入、Swagger |
| `ruoyi`、`/ruoyi`、`若依` | **RuoYi** | 默认口令 `admin/admin123`、Swagger、定时任务 |
| `/dede/`、`plus/`、`织梦` | **DedeCMS** | 前台 getshell、历史漏洞 |
| `/e/`、`EmpireCMS` | **帝国 CMS** | 历史漏洞 |
| `/virexp/`、`润尼尔`、`虚拟仿真` | **润尼尔虚拟仿真** | 未授权、文件上传 |
| `/mooc`、超星 | **超星/泛雅** | 越权、接口未授权 |
| `MG 127`、`mg.127.net`、`qiye.163.com` | **网易企业邮箱** | 注意：**核心漏洞归网易**，只挖学校自研部分（自研 JSP / 定制页），别在厂商代码上耗 |
| `thinkphp`、cookie `thinkphp` | **ThinkPHP** | 历史 RCE（5.0.x/5.1.x 等），先核版本 |
| `Server` 含 `aTrust`、title「**aTrust 2.0**」、cookie `sauth` | **深信服 aTrust**（零信任 SDP / 校园网准入） | ⚠️ **多数是学校网络准入层，不是业务系统**。先判它是不是你要打的目标（`moa.*` / `oa.*` 域名指向 aTrust 的，说明业务系统在准入后面，别把它当 OA 打） |
| title「**Zimbra Web Client Sign In**」、正文 `ZM_` 前缀、`/service/soap` | **Zimbra**（自建邮件） | 历史 Nday 多（XXE / SSRF / 反序列化），先核版本；`/service/soap` 是主要攻击面 |
| title 含 `mattermost`、`/api/v4/` | **Mattermost**（自建协作平台） | `/api/v4/users` 等接口未授权枚举、历史 Nday |
| title 形如「**ELOG - $subject**」（`$subject` 未替换即特征）、`/elog/` | **ELOG**（开源电子日志/实验记录本） | 未授权读、历史 CVE；**`$subject` 字面量残留说明模板未正确渲染，本身就是线索** |

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

**⚠️ 环境准备（2026-09-16 实测踩坑）**：本机 Python 是**隔离 managed 环境**，直接跑上面脚本会卡在 `mmh3` 未安装。装包**不要**用系统 pip：

```bash
# 建/复用隔离 venv，然后装
PY=~/.workbuddy-ai/binaries/python/versions/3.13.12/python.exe
"$PY" -m venv ~/.workbuddy-ai/binaries/python/envs/default
~/.workbuddy-ai/binaries/python/envs/default/Scripts/pip.exe install mmh3 -q
# 之后统一用这个 venv 跑
~/.workbuddy-ai/binaries/python/envs/default/Scripts/python.exe your_script.py
```

**⚠️ 两个实战坑**：
- **根目录未必有 favicon**：实测正方教务站 `GET /favicon.ico` 直接 **404**（图标在子路径），这时 hash 法失效，回退到 §1.3 的 header/title 指纹
- **默认图标 hash 无意义**：浏览器/server 自带图标的 hash 全互联网通用，搜出几万条 —— 先确认 favicon 是定制的

**已知 icon_hash 对照表**（认到 hash 直接对系统，省一次 FOFA 查询；**实测值，可继续累积**）：

| icon_hash | 系统 | 来源 |
|---|---|---|
| `-1730633433` | **泛微 e-cology** | 2026-09-16 实测（`ecology.**.edu.cn`） |

拿到 hash 后 FOFA 搜 `icon_hash="123456789"` → **同套系统的所有站**。学校往往给多个院系部署同一套，一挖一串。

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

    实测例子：某高校已确认资产全在 `<某高校 C 段>/24`，扫全段后新发现 `*.118`=**Harbor**（74 个镜像）、`*.26`/`*.27`=另一个 CAS 实例、`*.203`=网易账户集成平台——**前面 6 轮按域名打全都没发现**，因为它们没绑域名。

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

20120223`（2012 年代码）。第五轮实测 6 站同套；**第七轮再补 3 站**（`ivpn.**.edu.cn` / `newvpn.**.edu.cn` / `vpn.**.edu.cn`，均命中 `Server: Server` + `g_midatk`），**累计 9 站**：`vpn1.**.edu.cn:4433` / `madagascar.vpn.**.edu.cn` / `vpn.**.edu.cn:8080` / `vpn1.**.edu.cn` / `www.vpn.**.edu.cn` / `vpn.**.edu.cn:4433`（响应体 7177~9133 B），另 `navi-cnki-net-s.vpn.**.edu.cn` 亦 `Server: Server`（**厂商名未确证**）。**⚠️ 第七轮认知（重要）：网关 / 客户端 / 认证源可以是三家不同厂商，别交叉推断** —— `vpn.**.edu.cn` 实测是这款国产 SSL VPN（命中 `g_midatk`），但该校官网《VPN 使用指南》提供的客户端是 **EasyConnect（深信服产品）**、账号体系是**锐捷账号**。三个环节分属三家：**判网关只认网关自己的指纹（Server 头 / JS 变量 / 路径），不能用客户端型号或账号体系反推**；**第 3 款 WebVPN：`Server: appframe` + `/vpn/theme/auth_home.html`**（实测 `webvpn.**.edu.cn`，搜索印证 `vpn.**.edu.cn` 同路径）；`/users/sign_in` + `_astraeus_session`（Rails/Devise 栈，代号 Astraeus；**2026-09-16 交叉印证为多校同款产品**：urlscan 存档显示 `webvpn.**.edu.cn` / `webvpn.**.edu.cn` / `webvpn.**.edu.cn` / `webvpn.**.ac.cn` / `webvpn.**.cn` 同款登录页 + `SERVERID=Server1/Server2` —— **不是单校自研，是通用产品，厂商中文名仍未公开确证**）；自研 `/go?http://`、`/vpn_key/update` **待定性（第七轮）**：cookie `bzb_jsxsd` 在 `jwx.**.edu.cn` 稳定复现（root 仅 142 B，疑似纯跳转页）。`bzb_` 前缀 + `jsxsd` 路径疑似**强智教务**特征，但**仅 1 个样本，按纪律不写指纹**，需再找 1~2 个同款确认。（教务类系统 root 常返回极小响应体，探根时别因体积小就判「无指纹」——

."))`、开发者注释 `luyi 20120223`（2012 年代码）。第五轮实测 6 站同套；**第七轮再补 3 站**（`ivpn.**.hitwh` / `newvpn.**.cumt` / `vpn.**.dlpu`，均命中 `Server: Server` + `g_midatk`），**累计 9 站**：`vpn1.**.succ:4433` / `madagascar.vpn.**.cqepc` / `vpn.**.sgmart:8080` / `vpn1.**.sit` / `www.vpn.**.gxu` / `vpn.**.muhn:4433`（响应体 7177~9133 B），另 `navi-cnki-net-s.vpn.**.dufe` 亦 `Server: Server`（**厂商名未确证**）。**⚠️ 第七轮认知（重要）：网关 / 客户端 / 认证源可以是三家不同厂商，别交叉推断** —— `vpn.**.dlpu` 实测是这款国产 SSL VPN（命中 `g_midatk`），但该校官网《VPN 使用指南》提供的客户端是 **EasyConnect（深信服产品）**、账号体系是**锐捷账号**。三个环节分属三家：**判网关只认网关自己的指纹（Server 头 / JS 变量 / 路径），不能用客户端型号或账号体系反推**；**第 3 款 WebVPN：`Server: appframe` + `/vpn/theme/auth_home.html`**（实测 `webvpn.**.hlju`，搜索印证 `vpn.**.cqwu` 同路径）；`/users/sign_in` + `_astraeus_session`（Rails/Devise 栈，代号 Astraeus；**2026-09-16 交叉印证为多校同款产品**：urlscan 存档显示 `webvpn.**.shu` / `webvpn.**.cueb` / `webvpn.**.blcu` / `webvpn.**.iccas` / `webvpn.cams.cn` 同款登录页 + `SERVERID=Server1/Server2` —— **不是单校自研，是通用产品，厂商中文名仍未公开确证**）；自研 `/go?http://`、`/vpn_key/update` **待定性（第七轮）**：cookie `bzb_jsxsd` 在 `jwx.**.dgut` 稳定复现（root 仅 142 B，疑似纯跳转页）。`bzb_` 前缀 + `jsxsd` 路径疑似**强智教务**特征，但**仅 1 个样本，按纪律不写指纹**，需再找 1~2 个同款确认。（教务类系统 root 常返回极小响应体，探根时别因体积小就判「无指纹」—— 要跟一跳或直接打 `/jsxsd`
