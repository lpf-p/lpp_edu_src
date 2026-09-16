# nday-watchlist-2026

> **实战案例（双向引用）** → `cmd-injection-cases.md` §一 **组件指纹速查表**（Struts2/Shiro/Fastjson/Log4j/ThinkPHP/泛微/致远/WebLogic/Jenkins/Solr/Nacos/XXL-JOB：指纹 → 入口路径 → payload → 回显或外带方式）+ §四 Checklist；`vendor-system-cases.md` §1（生态环境部 `resetpwd_getServerDate.action` 仍是 S2-016，证明政府老站 Struts2 大量存活）+ §3（**同手法跨单位复现 = 高概率拒收**：通达 OA `logincheck_code.php` + `UID=1` 在兵器工业/青山钢铁/宏润化工/成都棠湖四家完全同手法）；`attack-chain-cases.md` §3 国产 OA / 中间件 Nday 速查。

**Nday 速查表。认到对应系统就回来查，别凭记忆。** 本文件按「国内 Web SRC 可挖程度」排序，**不是按 CVSS 排**。

> ⏱ **新鲜度（用前必看）**：本表 **导入日 2026-09-13**，此后未逐条复核。表内 CVE 编号、受影响版本、入口路径**用前必须回厂商通告 / CNVD / CNNVD 核一遍**——已修复、已改路径、编号写错都会导致白打一枪。核完在条目后补 `✓核于YYYY-MM-DD`，核不过的划掉。**表龄超过 2 周即视为不可信，只当线索不当结论。**

来源：奇安信 CERT《2026 上半年高危漏洞合集》等公开通告。新漏洞从公开到在野利用平均 **2.4 天**，PoC 公开 ≤ 3 天——**Nday 拼的是手速，认到就当天核，别攒着**。

**打法**：用 nuclei 收窄（`recon-methodology.md` §9），**不要全量跑**。核到版本再打，别见站就扔 payload。

---

## §1 国内 SRC 优先（高校/政务/企业都常见）

### 泛微 E-cology 10 — QVD-2026-14149 未认证 RCE

- **影响**：泛微 E-cology 10（OA）
- **洞**：未认证远程代码执行
- **利用视角**：外网 OA 直接沦陷 → 拿全员通讯录 / 流程权限 → 内网钓鱼
- **为什么优先**：泛微是国内 OA 市占率最高的之一，**高校/政务极常见**
- **认**（e-cology 线）：`Set-Cookie: ecology_JSessionid`、`/js/jquery/jquery_wev8.js`（`wev8`）、`/wui/index.html`、`/api/ec/dev/app/test`。⚠️ **`/weaver/` + `E-Mobile` 是泛微 e-office/E-Mobile 线，路径与 e-cology 不通用**，别拿 `/weaver/` 去打 e-cology 站
- **验**：核版本 → 打公开 PoC。**拿到权限立刻停手**，不要翻通讯录数据
- **附带**：`/api/ec/dev/app/test` 未认证即返回 `ec_id` / `ec_url` / `em_url_open`（旁系资产地址，含非标端口）—— 这条**本身也常被平台判为有效未授权**，且能顺出下一个资产

### 网瑞达 WebVPN（资源访问控制系统）— 弱口令 + 登录后 RCE + 默认密钥内网穿透

- **影响**：北京网瑞达科技有限公司（`wrdtech.com`）「资源访问控制系统（WebVPN）」，**高校电子资源访问主力**，客户含清华 / 南开 / 北理工 / 中科大。**2026-09-16 实测 234 个高校统一认证 / WebVPN 资产，网瑞达系 10 站，10/10 全部 `Server: none`**
- **洞**：① **弱口令 CNVD-2021-84288**（可批量登录 VPN 前台）；② **登录后 RCE**（2020-09 公开）；③ **默认 key/iv → 任意内网访问**（属设计缺陷，非编号漏洞）
- **利用视角**：⚠️ **这套系统的价值不在自身，在「进去之后」**——它是**通往内网的跳板**。进去后可直接访问图书馆 / 教务 / OA 等内网资源，再以之为跳板打横向。公开案例：有研究者用其加密跳转特性打到内网自助服务平台并提交 EDUSRC 获收录
- **为什么优先**：① 高校覆盖率极高（几乎每校一个 `webvpn.*`）；② 默认配置普遍未改（key/iv 就是默认值）；③ **直达内网，危害层级高**
- **认**：**URL 结构 `/http/<hex>/` 或 `/https/<hex>/`，且 `<hex>` 以 `77726476706e69737468656265737421` 开头**（硬编码 IV，hex→ASCII = `wrdvisthebest!`）；`Set-Cookie: wengine_new_ticket` / **`wengine_vpn_ticket<域名去点>`**（cookie 名里直接编码域名）；`/wengine-auth/login`、`?fromUrl=`；正文 `wengine-vpn` / `aes-js.js` / `portal.js`；**`Server: none`（字面量）**。详见 `recon-fingerprint-cdn-wildcard.md` §1.3
- **验**：① 弱口令**先小样本试**，**不要撞库**；② RCE 判据：普通账户登录后访问 `1.1.1.1@127.0.0.1:8860`，返回 `pong` 即存在（返回 401 则不可，可把域名解析到 127 绕过）；③ 默认 key/iv：从 `/portal.js` 或取 key 的接口拿 key/iv，用 `aes-js`（AES-CFB）加密目标地址 → 拼 `/http/<enc>/`
- **注意**：**只验不挖**。拿到「内网可达」的证明即停手，**不要遍历内网、不要下载数据**——越权访问内网资源本身即可定级，多走一步就是越界

### 任务调度面板类 — QVD-2026-10895 路径大小写绕过认证

- **洞**：路径大小写 + `/open/user/init` 滥用绕过认证 → admin 被重置 → 服务器执行任意命令
- **状态**：**已被挖矿团伙在野利用**
- **为什么优先**：若依 / XXL-JOB / 各类调度面板在国内遍地都是，且常年不打补丁
- **认**：`/xxl-job-admin`、quartz / elastic-job / powerjob 等调度台；默认端口常见 8080 / 9999
- **验**：试 `/API/` 类路径的大小写变体（`/api/` ↔ `/API/`）、试 `/open/user/init`
- **应急口径**：升级 v2.20.2+，WAF 拦 `/API/` 大小写变体

### OpenAM — CVE-2026-33439 / QVD-2026-18805 反序列化 RCE

- **洞**：白名单不全导致反序列化 RCE
- **利用视角**：**SSO 失守 → 全域通杀**，所有接入 OpenAM 的业务系统门户沦陷
- **为什么优先**：高校几乎都有统一身份认证（CAS / OpenAM / IDaaS 类），**打一个等于打一片**
- **验**：升级 16.0.6+ 是修复版本；认到 OpenAM 先核版本

### 金智教育统一身份认证（wisedu）— CNVD-2018-17443 逻辑漏洞（**已修，仅作认系统的锚点**）

- **影响**：江苏金智教育统一身份认证系统（**高校市占率极高**，基于 Apereo CAS 定制）
- **洞**：逻辑设计漏洞 → **重置任意账号密码**
- **状态**：厂商 **6.2.4 已修复**（2018-09 披露）。**别把它当在野 Nday 打** —— 它的价值是：认到这个系统后知道**该往哪条线挖**
- **认**：`authserver.` / `sso.` / `cas.` 域名前缀；`302 → /authserver/`；`/authserver/login`；`serviceValidate` 返 Yale CAS XML（`xmlns:cas='http://www.yale.edu/tp/cas'`）；title「统一身份认证」
- **为什么优先**：**全校通行证** —— 教务 / OA / 一卡通 / 图书馆 / 邮箱全接在它后面，进一个等于进一片
- **打什么**：① **初始口令规则 = 学号 + 身份证后 6 位**（教育行业最常见，先小样本试，别喷）；② CAS 面：`service` 开放重定向 / ticket 泄露、`lt`+`execution` 令牌、`_eventId` 状态机跳步、`serviceValidate` XML 解析（XXE）；③ 找回密码链走 `知识库/password-reset-test.md`
- **验**：核版本（< 6.2.4 才有上面那条）；**认到就核，别只核 CVE**

### Apache Tomcat — CVE-2026-34486 集群消息 RCE

- **洞**：集群消息 RCE，**是 CVE-2026-29146 的修复回归**
- **重点**：**打了早期补丁的 Tomcat 集群反而比不打更危险** —— 别以为打过补丁就安全
- **验**：核 Tomcat 版本 + 是否开了 cluster；升级前**关闭 cluster receiver**

### Next.js — CVE-2026-44578 / QVD-2026-26372 WebSocket SSRF

- **洞**：WebSocket Upgrade 路径 SSRF
- **利用视角**：直打云元数据 `169.254.169.254`，**偷 IAM 临时凭证接管云上资源**
- **认**：Next.js 站点（`/_next/`、`X-Powered-By: Next.js`）
- **验**：升级 15.5.16+ / 16.2.5+；关闭对外不必要的 WebSocket Upgrade

### NGINX — CVE-2026-42945 rewrite 堆溢出 RCE

- **洞**：`ngx_http_rewrite_module` 堆缓冲区溢出 → RCE
- **范围**：**0.6.27 至最新版的全部 NGINX**（埋藏 16 年）
- **条件**：需要**特定 rewrite 规则**才触发 → 不是见 NGINX 就能打
- **启示**：基础组件的"裸奔"问题比想象中普遍，别忽略基础设施

### Starlette / FastAPI — CVE-2026-48710 BadHost

- **洞**：**畸形 Host 头绕过身份验证**
- **利用视角**：**未在反代后的 MCP / VLLM / FastAPI 站点，单字符 Host 注入即可冒充内部服务调用**
- **为什么值得记**：AI 类服务（学校/企业都在上）常直接暴露，**不走反代**
- **认**：FastAPI（`/docs`、`/openapi.json` 是标配，一眼认出）

### Ghost CMS — CVE-2026-26980 Content API SQL 注入

- **洞**：Content API SQL 注入 → 未授权拿 Admin API Key
- **状态**：**已被用于 700+ 站点投毒**（篡改文章植入恶意 JS）
- **认**：Ghost 博客（`/ghost/`、默认 Ghost 主题）
- **验**：升级 6.19.1+；审计 Admin API Key 是否被异常签发

---

## §2 次优先（看 SRC 范围）

| 产品 | 编号 | 洞 | 备注 |
|---|---|---|---|
| Splunk Enterprise | CVE-2026-20253 | PostgreSQL Sidecar 端点缺认证 → 任意文件创建 → RCE | **CVSS 9.8，预认证**。控制整个 SIEM |
| Exchange Server | CVE-2026-42897 | OWA 存储型 XSS（已野利用） | 恶意邮件触发，偷邮件内容与 Cookie |
| LiteLLM | CVE-2026-42271 | 默认账户 + 预认证 RCE 链 | AI 网关失守 → 全模型 API Token 泄露 |
| OpenClaw | CVE-2026-25253 / 28472 / 25593 / 33579 / 44115 / 44118 / 41295 | 7 个 CVE 可串 **Claw Chain** 完整 RCE | 公网暴露 17500+ 实例；`auth.token` 参数存在即绕过；`/pairapprove` 作用域检查缺失提权 admin |
| Cisco SD-WAN | CVE-2026-20127 / 20182 / 20245 | 控制器认证绕过 + 推送恶意配置 | 拿到 SD-WAN 控制权可重路由所有分支流量 |
| Samba 打印子系统 | CVE-2026-4480 | RCE | Linux 文件共享，外网暴露后作横向跳板 |
| Linux Kernel | QVD-2026-29453 (CIFSwitch) / 27616 (PinTheft) | 本地提权 root | 双链串联：Container 普通用户 → 宿主 root |
| Windows Netlogon | CVE-2026-41089 | 域控零点击 RCE（UDP/389） | 外网 → 域控沦陷 → 内网总钥匙 |
| Chrome V8 | CVE-2026-11645 / 3910 | 沙箱逃逸 RCE（已野利用） | 浏览器侧，SRC 一般不收 |

---

## §3 2026 的六个新变化（影响挖洞节奏）

1. **AI 网关成为新主战场** —— LiteLLM / Starlette / OpenClaw 类比传统 OA 更容易拿下外网入口。**学校/企业新上的 AI 应用优先看**。
2. **72 小时武器化窗口成基线** —— 公告到 PoC ≤ 3 天。**Nday 要快，攒着就废了**。
3. **"零号漏洞"重新抬头** —— NGINX 埋 16 年。老组件值得回头重看。
4. **修复回归** —— Tomcat 那例说明打补丁可能引入新缺陷，**别默认打过补丁就是安全的**。
5. **投毒式攻击规模化** —— Ghost CMS 700+ 站点被植入恶意 JS。
6. **安全设备本身失守** —— SIEM / SD-WAN 也是攻击面，纳入资产表。

## §4 用法

```
1. 认到系统 → 回本文件 §1/§2 查有没有对应 Nday
2. 有 → 核版本（版本号通常在 登录页/JS/响应头/报错页）
3. 版本命中 → nuclei 收窄打一枪，或用公开 PoC
4. 拿到权限立刻停手，够定性就够
5. 没命中 / 查不到 → 回 edge-asset-hunting / 常规打法，别在 Nday 上耗
```

**定期更新**：本表是 2026 上半年的快照。看到新的高危通告就往 §1/§2 加，并记下日期。
