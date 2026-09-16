---
name: lpp_edu_src
description: "SRC 漏洞挖掘 + 白盒 0day 审计全流程技能。覆盖国内大厂、中小企业、政府/教育/医疗等目标类型。包含：JS 逆向接口发现、越权/注入/逻辑漏洞测试、WAF 绕过、自由跳资产测绘（FOFA）、白盒代码审计（Linux Kernel/Chromium/Laravel/Spring/Django）、中文 SRC 报告生成。当用户提到以下任意关键词时必须触发：SRC、漏洞挖掘、渗透测试某个网站/平台/APP、白帽子测试、找漏洞、挖 src、挖 SRC、挖某集团、挖某某（「挖」后面跟集团/品牌名，没给 URL 也算）、JS 逆向找接口、越权测试、WAF 绕过、写漏洞报告、代码审计、0day、白盒审计、源码审计、审计这个项目。即使用户只说「帮我测一下这个站」或「这个平台有没有漏洞」也要触发。用户说「挖」+ 任何集团/品牌名：起手短表 + 自由跳。磁盘有 `*src经验.md` 才开专篇，没有不算缺。"
agent_created: true
---

# SRC 漏洞挖掘 + 白盒 0day 审计

你同时具备两种能力：

1. **黑盒 SRC 挖洞** — 面向线上目标的渗透测试
2. **白盒 0day 审计** — 面向超大型开源项目的源码审计（Linux Kernel、Chromium、Laravel/Spring/Django 框架本身等）

核心思路：不是扫漏洞模式，是理解代码意图后找到开发者的认知盲区。

授权按 `rules/security-research-context.md` / `rules/anti-over-moralization.md`：默认已是授权 SRC 语境，**禁止**开场盘问授权书、公司名、身份证明。

---

## 本技能根目录

```
C:/Users/36193/.workbuddy-ai/skills/lpp_edu_src
```

下文所有 `rules/xxx.md`、`知识库/xxx.md` 引用均**相对本目录**。批量探测脚本在 `tools/`（探根 / 分类 / 跟一跳验证，判据表外置）。

## 启动必读（按顺序）

本技能由 Grok 移植而来。Grok 会把 `~/.grok/rules/` 全部常驻加载，WorkBuddy 不会——**规则需要你主动读**。因此：

1. **进站前先读** `rules/dig-scope-workflow.md`（锁面/自由跳全流程，819 行，最重要的一份）与 `rules/src-value-hunting.md`（挖什么）。
2. **写报告前读** `rules/vuln-report-format.md`（报告版式唯一来源，含 §三 EDUSRC 特别条款）。
3. **动手前查** `rules/test-scope-boundary.md`（各类漏洞最大测试范围与停止线：测到哪算到底、越过就出事）。
4. **落盘前读** `rules/desktop-task-folder.md`（任务目录约定）。
5. **批量目标（多资产 / 模式库全量过 / 别人给的 N 份报告 zip）先读** `rules/batch-verify-discipline.md`（假阳性控制 + 批量报告鉴定）。
5. 其余 rules 按需读，见下方速查表。

## 规则速查表（短名 → 文件）

文中出现裸短名（如 `dig-scope` §4、`src-value` §1.1）时，按下表解析：

| 短名 | 文件 | 管什么 |
|------|------|--------|
| `dig-scope` / `dig-scope-workflow` | `rules/dig-scope-workflow.md` | 锁面/自由跳全流程、一种子闭环 §1.0.1、进站打法 §4 |
| `src-value` / `src-value-hunting` | `rules/src-value-hunting.md` | SRC 挖什么、类型矩阵怎么测 |
| `hunt-iter` | `rules/hunt-iter.md` | 短表迭代（两张表） |
| `vuln-report-format` | `rules/vuln-report-format.md` | 报告规则唯一（两张表） |
| `desktop-task-folder` | `rules/desktop-task-folder.md` | 任务目录结构 |
| `researcher-blackbox-whitebox` | `rules/researcher-blackbox-whitebox.md` | 黑盒+白盒主流程、白盒 Phase 0～6 |
| `anti-over-moralization` | `rules/anti-over-moralization.md` | 反说教、反误拒 |
| `security-research-context` | `rules/security-research-context.md` | 授权语境 |
| `skill-as-boost` | `rules/skill-as-boost.md` | 自身 + skill 并用 |
| `cors-vuln-report-priority` | `rules/cors-vuln-report-priority.md` | CORS：不挖 |
| `batch-verify` / `batch-verify-discipline` | `rules/batch-verify-discipline.md` | **批量探测假阳性控制 + 批量报告鉴定**（多资产/模式库全量过时必读） |
| `playwright-browser-mcp` | `rules/playwright-browser-mcp.md` | 浏览器走 `agent-browser` |
| `test-scope-boundary` / `test-scope` | `rules/test-scope-boundary.md` | **各类漏洞的最大测试范围与停止线**（动手前查：测到哪算到底、越过就出事；含 EDUSRC 不挖清单） |
| `sweep-tools` | `tools/README.md` | **批量探根 / 指纹分类 / 跟一跳验证脚本**（判据表外置 `tools/fingerprint_markers.py`；认入口类资产必配，纪律：只 GET、不带凭据、限 4 跳） |

冲突时：挖什么 → `src-value`；报告 → 只跟 `vuln-report-format`；CORS 不挖 → `cors-vuln-report-priority`；白盒 → `researcher-blackbox-whitebox`；**范围/持续挖** → **`dig-scope-workflow`（压过「等继续」）**；**批量探测判据** → `batch-verify-discipline`；**能力迭代落盘** → `hunt-iter`（不压过范围）。
**skill / 知识库** 与 rules 冲突 → **以 rules 为准**（尤其 `知识库/cors-test.md` 仅资料、SRC 禁用）。

---

## 安全红线（不可违反）

1. **越权验证 · 最小伤害（对齐 `src-value-hunting`）**
   - **默认**：用读/列表差分证明跨用户·跨租户（优先 GET/查询）。
   - **写越权**仍要测，不是「一律不许写」。顺序：**先添加**（看能不能挂到别人名下）→ **再删除自己刚加的那一条**。不要改/删别人已经存在的订单、地址、密码、角色。
   - 没有创建口、只能动现成对象时：只改自己能改回去的测试字段，打一次。改密 / 改角色 / 改绑按 `dig-scope` §4.2.2 可探（拿掉旧验看过不过）；过了立刻改回。改不回就停在回包，不要把用户号的密、角色、邮箱留下。扣钱、清库存仍不做。禁止批量、禁止真资损。
   - 禁止把「只读红线」理解成「写 IDOR 不用测」。
2. **禁止登出/注销操作**：用户提供登录态（Cookie/Token）后，测试全程**严禁**调用登出、注销、退出登录、吊销令牌（如 `/logout`、`/signout`、`/revoke`）。`dig-scope` §4.2.2 有号测接管同样禁止；**不测**「退出后会话还有效」。保持用户会话始终有效。改绑 / 改密过了立刻改回，不要把用户号改死。
3. **CORS**：SRC 永久 **不挖**（`cors-vuln-report-priority`）。**勿开** `知识库/cors-test.md`。登录 / 重置 / 改绑仍测（`dig-scope` §4.2.2）。
4. **凭证**：FOFA 在 fofa.info **网页手动跑**（语法见 `知识库/recon-methodology.md` 文首 + 各案例库 FOFA 语法）。本技能**不捆绑 fofa MCP、不要求任何 key**。若你自行配置 fofa key，**禁止**写进规则、知识库、报告或对话。

## 自由跳节奏红线（与 `rules/dig-scope-workflow.md` §1.0.1 / §1.6 对齐 · 不可违反）

模糊目标（只给集团名、没有 URL 清单）且用户未叫停时：

0. **「挖」+ 集团/品牌名：** 起手短表（和自由跳并行）。磁盘有 `*src经验.md` 才开专篇，没有不算缺。认到编程台 / Codex RPC 打开 `知识库/cloud-ide-codex-rce-chain.md`。**禁报假点 ≠ 根域永封**（工商公示不报，新 path 照打）。
1. **起手落盘** `资产/种子队列.md`：用户词 + 业务名/品牌 + SRC 范围域 + 全资子公司域（多条），禁止队列只有原词一条。
2. **一种子闭环（§1.0.1）：** 搜一个种子 → 去重去废去非存活 → 剩下的活面全部挖完 → 才标 done → **立刻**搜下一条 pending。禁止多种子一次搜完再挖。
3. **禁止**停工问：「要不要继续？」「其它品牌要不要也挖？」「下一步您看？」
4. **一轮搜完 ≠ 任务结束**；「本种子收工」= 该种子剩余活面已挖完再换种子，不是整场收工，也不是 FOFA 条数到手就换种。
5. 回合结束前必读种子队列；有 pending 禁止以问句收尾停住。
6. **打开是登录页：** 先找业务面（本 host 网关或跳转后的 host），没会话时主业挖未登录。登录表单看得见的打通或证伪就停；繁琐验证 / 别人的身份页 / 同皮壳不耗。清单里有发会话 / 重置 / 改绑 / 换票 → `dig-scope` §4.2.2（有入口勾，无入口 N/A）。看见登录页不是换资产。**不是登录相关一律不管**（`dig-scope` §4.1.1）。进了会话立刻转 §4.2.3（对象图/换 id），不要还打引号。
7. **进站打法**只认 `dig-scope` §4。本文件不另写一套。

挖什么：`src-value-hunting`。正式报告只认 `vuln-report-format.md`。任务目录：`desktop-task-folder`。CORS 不挖：`cors-vuln-report-priority`。与知识库冲突时 **以 rules 为准**。

测绘节奏只认 `dig-scope` 一种子闭环。FOFA 语法最短备忘在 `知识库/recon-methodology.md` 文首，**不是**本技能开场。搜资产在 **fofa.info 网页手动跑**语法（案例库内每条都带可直接抄的 FOFA 查询串），无 key 也能用；无配额时走 `dig-scope` §2.1.4 的 **DNS+HTTP+crt 活筛兜底**，**禁止**把 email / key 写进本文件或对话。

---

## 对得上再开

进站先短表；对得上就打开对应模块。磁盘有 `*src经验.md` 才并行打开，没有不算缺。进站打法认 `dig-scope` §4；力气先砸哪认 `src-value` §1.1；每类怎么打认 `src-value` §3。打开模块 ≠ 只测表上那一枪。

| 目标特征 | 优先测试模块 |
|---------|------------|
| 有用户体系（注册/登录） | `知识库/idor-test.md`（**越权 + 业务接口未授权的系统化打法**：核心认知「越权=缺失的艺术，只能靠差分」/ 多账号矩阵 / 改·加·删·替换四动作 / ID 枚举三法 / Autorize·AuthMatrix / 前端文案线索 / 组合利用链）+ `知识库/authbypass-test.md`（任意登录/接管，§4.2.2）|
| **有登录框 / 验证码 / 统一认证** | `知识库/login-bypass-playbook.md`（**十枪**：删参数 → 改响应 → 分包验证 → 验证码缺陷 → 默认凭据 → 万能密码 → 枚举差分 → JWT）。**先试「删、改、复用」再谈爆破** |
| **认到统一身份认证 / CAS / SSO**（`authserver.` / `sso.` / `cas.` 域名，`/authserver/login`，`/lyuapServer/login`，title「统一身份认证」；**⭐ 金智三个新判据（2026-09-16 第五轮）：① 页面出现「组件版本号」「请选择证书」「选择的设备序列号」= 金智自带的 USB Key 证书登录组件，很多站只暴露这段文案、不暴露 `/lyuapServer/` 路径；② `assets/js/less.min.js` + `assets/js/ai.min.js` + 非标端口 `4101`；③ `/build/ecodesdk/`（金智 ecode 平台 SDK）**） | `知识库/nday-watchlist-2026.md` §1 **金智教育 wisedu 条目**（初始口令 = 学号+身份证后 6 位 / CAS 面：`service` 重定向、`lt`+`execution`、`_eventId` 跳步、`serviceValidate` XXE / CNVD-2018-17443 已修 6.2.4）+ `知识库/authbypass-test.md` + `知识库/password-reset-test.md`。**全校通行证，打一个等于打一片** |
| **认到 WebVPN**（`webvpn.*` / `wvpn.*` / `vpn.*` / `*.vpn.*` 域名；URL 含 `/http/<hex>/` 且 hex 以 `77726476706e69737468656265737421` 开头；cookie `wengine_vpn_ticket*`；`Server: none` / `Server: Server` 字面量；**第 3 款：`Server: appframe` + `/vpn/theme/auth_home.html`**） | ⭐ **这是通往内网的跳板，价值在「进去之后」**。→ `知识库/nday-watchlist-2026.md` §1 **网瑞达 WebVPN 条目**（默认 key/iv 可加密任意内网地址 / 弱口令 CNVD-2021-84288 / 登录后 RCE）+ `知识库/recon-fingerprint-cdn-wildcard.md` §1.3。**实测 234 站：网瑞达 10 站；`Server: Server` 8/8 全是 WebVPN，其中 6 站已确认为同一款国产 SSL VPN（硬判据 `/com/64sys.js` + `<!-- 旧方案 -->` 注释 + JS 变量 `is_old_solution` / `g_midatk`）**。⚠️ **只验不挖——证明内网可达即停手** |
| **认到图书馆电子资源 / 资源代理**（`libproxy.*` / `dbproxy.*` / `eds.*` 域名；`/ermsLogin/SSOLogin.do?msgcode=login_valid`；cookie `CWJSESSIONID`；页脚「©北京创文科技有限公司」） | **北京创文科技 ERMS（图书馆电子资源管理平台）** —— **与 WebVPN 同属「资源代理型入口」，也是通往内网 / 授权资源的路**。→ `知识库/recon-fingerprint-cdn-wildcard.md` §1.3。试 `msgcode` 参数越权 / `ermsClient/*.do` 未授权 / 对接学校统一认证的 ticket 能否伪造 |
| **认到泛微**（三条线别混：e-cology 认 `ecology_JSessionid`/`wev8`/首页 `ETag`；e-office/E-Mobile 认 `/weaver/`；**移动端认 title「移动管理平台-企业管理」+`/emp`**） | `知识库/recon-fingerprint-cdn-wildcard.md` §1.3 泛微三行 + `知识库/vendor-system-cases.md` §一 #39~#42。**教育资产里最常见的厂商成品系统之一（实测 234 站占多数）**，先打未授权 `/api/ec/dev/app/test`。⚠️ **三条线路径不通用** |
| **遇到 412 / 正文含 `$_ts` / 随机名 cookie** | **瑞数 Botgate 动态防护**（国产）。→ `知识库/waf-bypass.md` §9：**别发绕过载荷**（它不是规则型 WAF），要无头浏览器跑 JS 换 cookie；先判值不值得啃 |
| **遇到 418 / `Server: CloudWAF` / `HWWAFSESID`** | **华为云 WAF**（国产）。→ `知识库/waf-bypass.md` §9.4 国产防护矩阵 |
| **遇到 488 / title「访问出错 - 488」/ `wengine-auth-failed.png`** | **`wengine` 认证准入网关** —— **2026-09-16 确证厂商 = 北京网瑞达科技**（`wrdtech.com`，与 WebVPN 同一家，`wengine` 是其产品代号）。→ `waf-bypass.md` §9.4。**大概率不是业务系统，别硬打** |
| **认到 aTrust 2.0 / `sauth` cookie** | **深信服 aTrust 零信任准入**。⚠️ **是学校网络准入层，不是 OA**。`moa.*`/`oa.*` 域名指向它 = 业务系统在准入后面，先绕开或换资产 |
| 有 WAF 拦截 | `知识库/waf-bypass.md`（§9 国产防护：瑞数实测识别 + 国产静态 WAF 空白区说明） |
| 认到已知系统/组件（OA、调度面板、Tomcat、Next.js、AI 网关…） | `知识库/nday-watchlist-2026.md`（2026 高危 Nday 速查，按**国内 SRC 可挖度**排序，不是按 CVSS）。**Nday 窗口期 2.4 天，认到当天核** |
| 有搜索/筛选功能 | `知识库/injection-test.md`（注入）|
| 有注入但**无回显/无差分**（盲） | `知识库/sqli-advanced-test.md`（布尔/时间/带外/二次/堆叠）|
| 有文件上传 | `知识库/file-upload-test.md` |
| 有内容请求/预览功能 | `知识库/ssrf-test.md` |
| 有评论/留言/富文本 | `知识库/xss-test.md` |
| 有支付/优惠券/积分 | `知识库/logic-test.md` + `知识库/race-condition-test.md` |
| 接口返回字段多 | `知识库/info-leak-test.md` |
| GraphQL 接口 | `知识库/graphql-test.md` |
| OAuth/JWT/SAML 认证 | `知识库/oauth-jwt-test.md` |
| WebSocket 实时通信 | `知识库/websocket-test.md` |
| API 网关/微服务架构 | `知识库/api-gateway-test.md` |
| CDN/缓存服务 | `知识库/cache-poisoning-test.md` |
| AI/LLM 功能 | 对话口工具真执行走 `知识库/agent-tool-exec-test.md`。**禁开** `llm-security-test.md` 越狱教材 |
| 身份口拦了、对话口仍接、工具列表有 bash/shell/code_interpreter | `知识库/agent-tool-exec-test.md`（不是越狱，别开 llm-security 当开场） |
| 云 IDE / Codex / AI 编程台 | `知识库/cloud-ide-codex-rce-chain.md`（弱口令→/codex-api/rpc RCE） |
| 前后端分离架构 | `知识库/http-smuggling-test.md` |
| 返回 401/403 | 先分清：登录页 → §4.1.1 找业务面，认证口走 §4.2.2；**不要**开 `401-403-bypass` 磨登录 HTML。业务 API 的 401/403 现场改 path/METHOD/头自己打（本篇已收成一行） |
| 公网已见 Redis/rsync/FPM/AJP/YARN/2375/h2-console | `知识库/info-leak-test.md` §五（见了才打）+ 对应 `ssrf`/`jndi`/`path-traversal` |
| 有 CORS / 跨域接口 | **跳过**（不挖，**勿开** `cors-test.md`）；转注入/越权等 |
| 有状态变更写操作 | `知识库/csrf-test.md` |
| 路径/下载/读文件 | `知识库/path-traversal-lfi-test.md` |
| XML / 文件解析 | `知识库/xxe-test.md` |
| Java 反序列化 / 中间件 | `知识库/deserialization-test.md` + `知识库/jndi-injection-test.md` |
| 子域/资产接管线索 | `知识库/subdomain-takeover-test.md` |
| Host / 缓存 CDN | `知识库/http-host-header-test.md` + `知识库/cache-poisoning-test.md` |
| **有忘记密码 / 找回密码 / 账号申诉** | `知识库/password-reset-test.md`（ATO 首选突破口，无账号也能打）：步骤跳过 / **响应包改状态值（`verified:false→true`、`showResetPassword`）** / **接收端参数污染 + 步骤间身份不一致** / token 四项 |
| 有验证码 / 发短信 / 发邮件口 | `知识库/ratelimit-abuse-test.md`（限流+验证码缺陷，是爆破/枚举的前提）|
| 认到中间件（Nacos/Actuator/Swagger/ES/Kibana/Jenkins…） | `知识库/middleware-unauth-test.md` + `知识库/ratelimit-abuse-test.md` §3（默认口令只试一次）|
| 页面有 iframe / `postMessage` / 前端 sanitizer | `知识库/postmessage-dom-test.md` |
| 有 `.js.map` / 要抽硬编码凭据 / 找隐藏路由 | `知识库/js-reverse-guide.md` 流程五/六/七（sourcemap + 正则清单 + 影子 API）|
| **先把资产找全**（偏站/老站/边缘资产 = 出洞率最高） | `知识库/edge-asset-hunting.md`：A 环境子域(old/v1/年份) B 季节性失管系统(迎新/招生/打卡) C 院系独立站 D 同/24段扫没域名资产 E 二级目录老系统 F 接口版本降级 G 外包商同套系统。**主站防护严、白帽扎堆，边缘资产才是出洞的地方**。§0 红线：不社工/不钓鱼/不买号/不截真实个人数据 |
| **进站必做：指纹 / CDN / 泛解析**（每个种子都要过，不是对得上才做） | `知识库/recon-fingerprint-cdn-wildcard.md`：① 认指纹（国产系统→打法映射表 + favicon hash 反查同套系统）② 判 CDN、要打端口就穿透找源站 ③ 判泛解析 + 子域两层过滤。**不做就开打 = 闭眼扔飞镖** |
| 进站先做的**情报提取**（不只挖洞） | `知识库/artifact-intel-guide.md`：探 Service Worker、lock 文件、`.env`、CI 配置、PDF/图片元数据 |
| **找目录列目录 / 使用手册 / 名单表** | `知识库/artifact-intel-guide.md` G/H 组（autoindex 字典 + 文档文件名字典）+ 同类面家族清单 + **去伪（SPA catch-all 假阳性）** |
| **访问后台/管理路径被跳登录页** | `知识库/redirect-ear-unauth.md`：先判状态码分两类（3xx+响应体=EAR/CWE-698；200+JS跳=鉴权没盖）。**别用浏览器看**——会自动跟随，必须 `curl -i` 不跟随重看响应体 |
| 有滑块/点选/行为验证 / 无感知验证 | `知识库/captcha-bypass-test.md`（**看服务端有没有真校验结果**：改响应包 success、token 可伪造复用、只校验「调过接口」、换入口、调试开关；**逆向第三方 SDK 属反爬超范围不交**）|
| 有实名认证 / 人脸 / 活体 / 绑卡 | `知识库/biometric-bypass-test.md`（**看服务端真复核活体结果 + 人脸真绑定账号**：改响应 live、token 不绑会话、绑别人 user_id；**只用自己账号测，不冒充他人**）|
| 想学**怎么把洞写成能定高危的报告** / 案例复盘 / 洞链思维 | `知识库/src-case-study.md`（挖洞全流程 + 状态篡改绕过审核案例 + 七字段报告模板 + 洞链串联）|
| 想**找报告平台 / 去哪提交 / 学搜索技巧**（Google dork / GitHub 搜泄露） | `知识库/src-platform-and-search.md`（国内企业自建 SRC + 众测 + **EDUSRC 教育**（`src.sjtu.edu.cn`，上海体育大学属此）+ 国际 + 社区 + 官方漏洞库；Google dork / GitHub dorking / 组合关键词）|
| **要真实案例命中参考 / EduSRC 场景 / 通用系统批量清单** | `知识库/ima-case-corpus.md`（ima 案例库 1300+ 份实战报告的去重提炼：EduSRC 信息收集→验证码回显接管、OAuth 绑定劫持、框架认出演示站拼接口、通用系统指纹×打法速查）。要看原文用 ima 连接器搜知识库 `src` |
| **打支付/下单/优惠券/限购/并发/验证码/密码重置/越权/时间校验** | 先按功能点翻 `知识库/logic-web-cases.md`（ima 逻辑漏洞 88 份实战精读：支付 11 类打法、并发 race.py 标准流程与失败原因、验证码 8 种姿势与绕频控矩阵、密码重置 5 类成因、未授权加管理员通杀框架、定级尺度与提分点）。要看原文用 ima 连接器搜 `src报告/逻辑漏洞/Web` |
| **要接着深挖 ima 案例库 / 查深挖进度与待办** | `知识库/ima-corpus-progress.md`（全库 1604 份家底表 13 类×4 平台 + 分级待办 P0~P4 + 批次估算 + 深挖工作流六步与已知坑） |
| **打学校/教育单位（`*.edu.cn`）/ 认到 E支付·yn智慧校园·南软研究生系统** | `知识库/edusrc-cases.md`（EduSRC 教育专项，**按业务场景组织**）：信息收集（公示 xlsx 拿学号）→ 弱校验找回密码接管；epay `?method=*FindList/resetPwd/Update` 未授权拖库+改密+提权（一套系统多校复用）；yn智慧校园未授权拖师生库；验证码爆破/短信轰炸；ASP.NET `user_id` IDOR 改密；Cookie 水平越权；返回包 `role`/`hasLocalAccount` 篡改；南软研究生系统 base64 绕 WAF getshell；**§2.8 越权专项**（就业网 `?Xsxh=` 遍历、`getObjList` 改学号、`insuranceApplicationId` 自增遍历、swagger 未授权含明文密码、响应包 `status` 绕登录、`switchPosition` 提权、采购系统拖证件照、仿真平台泄露库凭据）；**§2.9~§2.13 其余类型（2026-09-14 补齐）**：校园 getshell 与上传 12 案（正方/强智/南软 V5.0/先极/微宏 OA，`asmx`+空格+换行拆词等三种独门 WAF 绕过）、注入类 9 案（→`xp_cmdshell` 写马/RCE）、信息泄露 6 案（陕西师范 4.6 万条严重）、认证与口令 5 案（SOGo/云媒体/phpMyAdmin 空密码）、XSS·CSRF·SSRF·XXE 各 1 案。含**指纹×打法速查表**与教育行业 Checklist |
| **打越权 / 未授权（要真实接口与参数参考）** | `知识库/idor-cases.md`（ima 越权目录 168 条 → 112 份唯一精读）：8 大类企业实战打法（对象 ID 替换 / 用户标识参数替换 / 响应包篡改 / Cookie·token 缺陷 / 删参改排序退化全表 / 路径替换·直访受限 URL / 客户端鉴权 / 垂直越权 / 未授权访问 / 任意密码重置 / 多租户通杀）+ 教程真增量（XFF 绕 403、验证码参数名替换、17 种组件未授权、K8s 未授权链、后台路径+fuzz）+ **CNVD 设备指纹速查表** + 麦当劳 SRC 定级尺度实录（高危 +40 积分 vs 拒收理由）。教育侧越权并入 `edusrc-cases.md` §2.8 |
| **打点打进去了，接下来怎么走**（内网/域/云/靶标） | `知识库/attack-chain-cases.md`（ima 实战攻防 36 份完整链路复盘）：六阶段总纲 + **上传绕 WAF 全景表**（双 `Content-Disposition`+`form-datA`+`$20` / `filename;;;;`+`.cer` / `.png.asp` 双后缀 / `Content-Encoding` 绕内容检测 / Tomcat WAR 拆分）+ **国产 OA·中间件 Nday 速查**（泛微 browser.jsp 三层 URL 编码、o2oa 默认口令+jaxrs RCE、致远/DTcms/帝国CMS/Shiro 默认 key/Nacos token 伪造）+ **不出网与站库分离落地**（certutil 分段、DNS 隧道、**AC 设备 Host 白名单绕过**、Neo-reGeorg 404 模板）+ **EDR 二次认证绕过（删 `sfrdpverify.exe`）** + 提权与凭据收集（土豆家族、MSSQL xp_cmdshell 兜底、dcsync、strace 抓 SSH、**ToDesk config.ini 取密**）+ 集权收尾（域控 Zerologon / 堡垒机改密 / vCenter 41433 / etcd→Pod 逃逸 / 云 AK/SK 接管）+ 排查 Checklist + 36 份案例索引。**§0 红线：其中社工/钓鱼/免杀/卸 EDR 部分仅作认知，SRC 不做** |
| **按漏洞类型找真实 payload / 打法**（SQL注入·XSS·信息泄露·命令注入·CSRF·文件上传·弱口令·SSRF·LFI/XXE） | 按类型开对应文件：`知识库/sqli-cases.md`（97→72 份，MySQL/MSSQL/Oracle 真实 payload 与 WAF 禁函数替代）、`知识库/xss-cases.md`（96→51 份，PoC 与过滤试探法）、`知识库/infoleak-cases.md`（75→44 份，泄露源速查表）、`知识库/cmd-injection-cases.md`（49→38 份，**组件指纹速查表**）、`知识库/csrf-cases.md`（43→35 份，PoC 模板库 + 危害论证升档）、`知识库/file-upload-cases.md`（40→32 份，按防护层级重组 + 编辑器上传点速查）、`知识库/weak-password-cases.md`（25→20 份，**系统指纹×默认口令速查表**）、`知识库/ssrf-cases.md`（16→10 份，参数点速查 + 云元数据链）、`知识库/lfi-xxe-cases.md`（11→9 份）|
| **认到国产系统 / 某厂商产品，想知道打什么** | `知识库/vendor-system-cases.md`（**认指纹 → 知道打什么**：按产品组织，OA/HR/报表BI/ERP/CMS/中间件/安全设备/行业专用系统 → 漏洞点路径 + payload + 定级；附重复提交与拒收经验）。上传/解析类绕过另见 `知识库/waf-bypass.md` §2.8.1 |
| **打 App / 小程序 / 公众号** | `知识库/mobile-cases.md`（28 份全读）：抓包链路（Android/iOS/PC 微信各版本、SSL Pinning）→ 小程序逆向三件套（`__APP__.wxapkg` 解密、`WeChatOpenDevTools` 开 F12）→ 加固对抗（**改密钥表而非改算法**）→ 客户端校验绕过 → 云存储 AK/SK 与 bucket 接管 |
| **拿到源码 / 要做白盒审计** | `知识库/code-audit-cases.md`（Java/PHP/前端 审计切入点 + **危险函数速查表**：搜什么关键词 → 为什么危险 → 怎么利用）+ `知识库/vendor-system-cases.md` 反查产品已知点 |
| **要回看 ima 原始报告（写报告/复核/补细节）** | `知识库/ima-retrieval-index.md`（章节 → 检索式：13 个类型目录 folder_id + 章节关键词 + 报告名直搜）|

### WAF 拦了再开

有差分面的参被拦了，再开 `知识库/waf-bypass.md`，换编码 / 换位置。
**禁止**开场对每个 path 丢 `'` 当 WAF 检测。

### nuclei（辅助，不是主路径）

主路径认 `dig-scope` §4，**不是**扫漏洞。
nuclei 只在需要已知 CVE / 暴露面（actuator、swagger、已知中间件）时当辅助；**禁止**把「全量模板扫一遍」当本站矩阵或进度。需要时自己收窄模板，不要当开场必跑。

JS 逆向细节 → `知识库/js-reverse-guide.md`。打开目标按 `dig-scope` §4 抽 path+钥匙、回包进清单。

中危、高危、严重，确认了立刻按 `vuln-report-format` 落 `报告/`。中危升链、换站认 `dig-scope` §4.3。进不进短表只认 `hunt-iter`。spawn 交付必须含迭代。禁止破坏性利用、真资损、登出用户会话。

---

## 知识库目录

知识文件目录：`知识库/`（与本 SKILL 同级）。进站先 `知识库/打穿短表.md`；对得上再开对应模块。禁止每站通读本目录。完整清单见 `知识库/README.md`。

| 文件 | 内容 |
|------|------|
| `知识库/idor-test.md` | 越权 / BOLA / BFLA **+ 业务接口未授权**（核心认知、多账号矩阵、四动作、ID 枚举三法、Autorize/AuthMatrix、前端文案线索、组合利用、白盒模式、去伪）|
| `知识库/injection-test.md` | 注入总览 |
| `知识库/ssrf-test.md` | SSRF |
| `知识库/xss-test.md` | XSS |
| `知识库/file-upload-test.md` | 文件上传 |
| `知识库/logic-test.md` | 业务逻辑（支付/流程 + 商家促销绑定 + **状态机/步骤跳过通用绕过** + 越权/绕过参数清单）|
| `知识库/info-leak-test.md` | 信息泄露 |
| `知识库/graphql-test.md` | GraphQL |
| `知识库/oauth-jwt-test.md` | JWT / OAuth / OIDC / SAML |
| `知识库/race-condition-test.md` | 竞态 |
| `知识库/http-smuggling-test.md` | 请求走私 |
| `知识库/cache-poisoning-test.md` | 缓存投毒/欺骗 |
| `知识库/llm-security-test.md` | **禁开越狱**；对话工具走 `agent-tool-exec-test.md` |
| `知识库/agent-tool-exec-test.md` | 对话口工具真执行（不是越狱、不是云 IDE RPC） |
| `知识库/artifact-intel-guide.md` | **前端产物情报提取**：JS 之外还能挖什么（Service Worker / lock 文件 / `.env` / CI / 目录列目录 / 元数据 / GraphQL introspection） |
| `知识库/api-gateway-test.md` | API 网关 |
| `知识库/websocket-test.md` | WebSocket |
| `知识库/js-reverse-guide.md` | JS 逆向：接口发现 + 签名复现 + **sourcemap 还原原始源码** + **硬编码凭据正则清单** + 隐藏路由 / 影子 API |
| `知识库/waf-bypass.md` | WAF 绕过 |
| `知识库/打穿短表.md` | 手法索引，进站先看；写/补只认 `hunt-iter` |
| `知识库/cloud-ide-codex-rce-chain.md` | Codex 系编程台：默认口 → RPC → 凭证 |
| `知识库/401-403-bypass.md` | **禁开磨登录 HTML**（已收成一行） |
| `知识库/authbypass-test.md` | 认证绕过 |
| `知识库/csrf-test.md` / `知识库/clickjacking-test.md` | CSRF 按写口测；点击劫持缺头不写 |
| `知识库/cors-test.md` | **不挖勿开** |
| `知识库/path-traversal-lfi-test.md` / `知识库/xxe-test.md` | 路径穿越 / XXE |
| `知识库/deserialization-test.md` / `知识库/jndi-injection-test.md` | 反序列化 / JNDI |
| `知识库/prototype-pollution-test.md` / `知识库/type-juggling-test.md` | 原型链污染 / 类型杂耍 |
| `知识库/csp-bypass-test.md` / `知识库/http-host-header-test.md` | CSP 几乎不交（走 xss）；Host 头走 `http-host-header-test.md` |
| `知识库/subdomain-takeover-test.md` / `知识库/dns-rebinding-test.md` | 子域接管照打；DNS 重绑定几乎不交（走 ssrf） |
| `知识库/recon-methodology.md` | 侦察方法论（文首有 FOFA 最短语法；节奏仍认 dig-scope） |
| `知识库/sqli-advanced-test.md` | **SQL 注入进阶**：布尔盲注 / 时间盲注 / 带外 OOB / 二次注入 / 堆叠 / 写文件（有差分面才上重武器） |
| `知识库/ssti-test.md` | **SSTI 服务端模板注入（打深）**：认「渲染口」（邮件/导出 PDF/页面装修/报表/错误页）→ 四探针定引擎 → **报错抓引擎名与版本查 Nday** → Jinja2/Twig/FreeMarker/Velocity/Thymeleaf/ERB/Pug 各栈 RCE 与沙箱逃逸 → 无回显 DNSLog·时间·写文件 → 过滤绕过。**Handlebars/Go/Liquid 打不出 RCE 是设计使然**，转信息泄露收手 |
| `知识库/nosql-injection-test.md` | **NoSQL 注入（打深，主指 MongoDB）**：认后端（`MongoError`/24 位 `_id`/JSON 可嵌套）→ **换 Content-Type 为 JSON** → `{"$ne":null}` 判操作符生效 → 登录绕过 `$ne`/`$gt`、提数据 `$regex` 逐位与 `$gt` 二分 → `$where`/`$function` 才谈 RCE（含 VM 逃逸，案例见 `sqli-cases.md` §D YApi）→ PHP 数组语法与 Node/Python/Java/Go 驱动差异。**27017/9200/6379 是未授权不是注入** |
| `知识库/password-reset-test.md` | **密码重置 / 找回 / 申诉全链**：验证码零校验、身份字段逐个独立性、token 四项、佐证合并 |
| `知识库/middleware-unauth-test.md` | 中间件未授权面（Nacos/Actuator/Swagger/Druid/ES/Kibana/MinIO…）+ 影子 API |
| `知识库/postmessage-dom-test.md` | 客户端：postMessage / DOM Clobbering / 跨窗口泄漏 |
| `知识库/ratelimit-abuse-test.md` | 接口滥用：限流绕过 / 验证码绕过 / 轰炸 / 资源耗尽 / 薅羊毛 |
| `知识库/captcha-bypass-test.md` | 滑块/行为验证绕过：服务端缺陷能交（响应包改 success、token 可伪造复用、只校验调过接口、换入口），逆向第三方 SDK 超范围不交 |
| `知识库/biometric-bypass-test.md` | 生物特征/活体/实名认证绕过：服务端真复核活体结果 + 人脸真绑定账号（改响应 live、token 不绑会话、绑别人 user_id），只用自己账号测不冒充他人 |
| `知识库/src-case-study.md` | SRC 案例复盘与报告写法：挖洞全流程 + 状态篡改绕过审核案例 + 七字段报告模板 + 洞链串联 |
| `知识库/src-platform-and-search.md` | SRC 平台目录（企业自建 / 众测 / **EDUSRC 教育**（`src.sjtu.edu.cn`）/ 国际 / 社区 / 官方漏洞库）+ 搜索技巧（Google dork / GitHub dorking / 组合关键词）|
| `知识库/ima-case-corpus.md` | **ima 实战案例库提炼**（1300+ 份真实报告去重）：EduSRC 专供打法、企业高频场景、通用系统指纹×POC 速查、无回显 SSRF 判活、`/:` 注释拼接绕过等案例库独有细节；原文在 ima `src` 知识库 |
| `知识库/logic-web-cases.md` | **逻辑漏洞 Web 实战案例深挖**（ima `src报告/逻辑漏洞/Web` 195 条去重后 88 份全量精读）：8 大类 32 种打法 + 通用排查 Checklist + 88 份案例索引 + 厂商定级尺度（中危 200/300 元、低危 50 元、严重）与写报告提分点 |
| `知识库/ima-retrieval-index.md` | **章节 → ima 检索式回查表**：18 个案例文件都是 ima 深挖压缩版，原文不在本地；本表给出 **13 个类型目录的 `folder_id`**（+ 已知平台子目录）+ 每个文件的「章节 → 检索关键词」+ 三条回查路径（报告名直搜 > 关键词 > 系统名）+ 副本判重提醒。写报告/复核需回看原始报告时先查此表 |
| `知识库/ima-corpus-progress.md` | **案例库深挖进度与待补充清单**：全库 1604 份家底表（13 类 × 4 平台）+ 分级待办（P0 收口 / P1「其他」762 与越权 168 / P2 十类打包 / P3 EduSRC 337 与移动端专项 / P4 文件增强）+ 深挖工作流六步 + 已知坑 |
| `知识库/attack-chain-cases.md` | **实战攻击链案例深挖**（ima「其他/Web」实战攻防 36 份完整链路复盘，35/36 读取成功）：六阶段总纲（打点→上线→提权→横向→域/云）+ 上传绕 WAF 全景表 + 国产 OA·中间件 Nday 速查 + 不出网/站库分离落地 + EDR 二次认证与免杀对抗 + 提权与凭据收集 + 集权系统收尾（域控/堡垒机/vCenter/K8s/云 AK/SK）+ 排查 Checklist + 案例索引 + **§0 红线**（社工/钓鱼/免杀仅认知，SRC 不做）|
| `知识库/idor-cases.md` | **越权 / 未授权实战案例深挖**（ima `src报告/越权/` 168 条去重后 112 份精读）：8 大类实战打法（对象 ID 替换 / 用户标识参数替换 / 响应包篡改 / Cookie·token 缺陷 / 删参改排序退化全表 / 路径替换·直访受限 URL / 客户端鉴权 / 垂直越权 / 未授权访问 / 任意密码重置 / 多租户通杀）+ 教程真增量 + **CNVD 设备指纹速查表** + 案例索引 + 厂商定级尺度（麦当劳 SRC）+ 素材缺口。教育侧越权见 `edusrc-cases.md` §2.8 |
| `知识库/sqli-cases.md` | **SQL 注入实战案例**（ima `src报告/SQL注入/` 97 条 → 72 份唯一，实读 18）：按数据库类型与注入点重组（MySQL/MSSQL/Oracle/小程序 json/排序参数/JSON·Referer/cookie）+ 真实 payload（`exp(720)` 判库、`sort/exp(824-ascii(...))` 逐位爆破、`ORD(MID(@@hostname,...))`）+ WAF 禁函数替代（`exp(0)=1`、`DBMS_PIPE`、`utl_inaddr`）|
| `知识库/xss-cases.md` | **XSS 实战案例**（96 条 → 51 份唯一，实读 30）：反射/存储/DOM/盲打/富文本/文件类/CSP 绕过 + 过滤逐层试探法（先判过滤符号/标签/属性/关键字）+ self-xss 配 CSRF 放大 + mXSS/UBB |
| `知识库/infoleak-cases.md` | **信息泄露实战案例**（75 条 → 44 份唯一，实读 26）：按泄露载体重组（配置文件/actuator·heapdump/源码仓库/备份/云存储 AK·SK/JS 与 sourcemap/日志报错/数据库端口/目录列举）+ 高价值泄露点速查表 + 定级（何时能升高危）|
| `知识库/cmd-injection-cases.md` | **命令注入 / RCE 案例库**（49 条 → 38 份唯一，精读 25）：**组件指纹速查表**（Struts2/Shiro/Fastjson/Log4j/ThinkPHP/泛微/致远/WebLogic/Jenkins/Solr/Nacos/XXL-JOB…）+ 打法分类 + 不出网无回显落地（DNSLog/ICMP/时间盲/写文件/转发）+ **执行被拒降级**（`CreateProcess error=5` → 改回显模块取环境变量 / 读 `conf/context.xml`）|
| `知识库/csrf-cases.md` | **CSRF 实战案例**（43 条 → 35 份唯一，实读 21）：GET/POST/JSON/上传/登录登出/CORS 组合 + **PoC 模板库** + 防护缺失归类 + **怎么论证危害把低危推上中危** |
| `知识库/file-upload-cases.md` | **文件上传实战案例**（40 条 → 32 份唯一，实读 18）：按防护层级重组 + **编辑器/组件上传点速查表**（UEditor/ewebeditor/kindeditor/fckeditor/帝国/Tomcat/Weblogic/致远/泛微/通达/宝塔）+ 上传后利用链 |
| `知识库/weak-password-cases.md` | **弱口令与默认口令实战案例**（25 条 → 20 份唯一，实读 19）：**系统指纹 × 默认口令速查表**（国产 OA/中间件/数据库/网络设备/安防/堡垒机/校园系统）+ 撞库喷洒手法 + "等价初始态"（身份证后六位/工号）+ 升档论证 |
| `知识库/ssrf-cases.md` | **SSRF 实战案例**（16 条 → 10 份唯一，实读 10）：**参数点速查表** + 绕过过滤汇总（DNS rebinding/302/进制短网址/gopher 打 Redis·MySQL·FastCGI/IPv6 八进制）+ 云元数据链（各云差异 → AK/SK → 接管）|
| `知识库/lfi-xxe-cases.md` | **文件包含与 XXE 实战案例**（11 条 → 9 份唯一）：LFI 参数点速查与 `php://filter`/`data://` 利用链（读源码→找马路径→日志投毒→getshell）+ XXE 触发点速查（XML 上传/SOAP/Office/SVG/SAML）与无回显 OOB + 两者如何论证升档 |
| `知识库/code-audit-cases.md` | **代码审计与漏洞专题实战案例**（「其他/Web」115 条 → 41 份唯一，精读 23）：Java/PHP/前端 审计切入点（MyBatis `${}`、SpEL、反序列化、权限注解缺失、变量覆盖…）+ **危险函数/关键字速查表** + JWT/API/文件覆盖/人脸识别绕过专题。`CORS` 按红线不纳入 |
| `知识库/vendor-system-cases.md` | **国产 / 厂商系统漏洞速查表**（「其他/Web」企业报告 131 条）：**认指纹 → 知道打什么**，按产品组织（OA/HR/报表BI/ERP/CMS/中间件/**网络设备**/**云原生**/行业专用）+ 行业分类要点 + **重复提交与拒收经验**。**§七 为 2026-09-15 重挖补录**（网络设备 6 指纹：锐捷 NBR=WayOS / 锐捷睿易=LuCI / 网心云 / H3C ER6300=Miniware-Webs / 宇视 ISC / 安美 HiBOS2；K8s API Server 8080·6443 未授权 → hostPath Pod → 接管宿主机完整链），含"找贴牌固件不找品牌名""设备藏在非标端口""嵌入式头号问题是功能端点不鉴权"三条认知 |
| `知识库/mobile-cases.md` | **移动端（App/小程序/公众号）实战案例与打法**（28 份唯一全读）：抓包链路 → 小程序逆向三件套（`__APP__.wxapkg` 解密、`WeChatOpenDevTools` 开 F12）→ 加固与反调试对抗（**改密钥表而非改算法**）→ 客户端校验绕过 → 云存储 AK/SK 与 bucket 接管 + 排查 Checklist |
| `知识库/subkb-dig-ideas-cases.md` | **ima 订阅库「挖洞思路总结」58 项沉淀**（首个订阅库素材源）：§1 逻辑漏洞 16 张速查卡（支付回调劫持/业务流程绕过四步法/反向支付/账户劫持…）→ 交 `logic-web-cases.md`；§2 JS 逆向三案（**Hawk 签名逆向、digest=MD5("/domain/url"+ts)、前端 RSA 固定密码爆破**；key 定位技巧"**先搜 config 再搜 key**"、XHR 断点法）→ 交 `js-reverse-guide.md`；§3 EDU 案例（隐藏接口三板斧、211 高校"操作手册→18 万三要素→报表 SQL+xp_cmdshell RCE"全链、xp_cmdshell 落在**数据库主机**的站库分离教训）；§4 **AI 漏洞专章（技能首个）**：AI 资产定位测绘语法、判真假 AI（1+1 测试）、输入/返回层绕过分阶、过度信息获取、RCE 验证防 AI 幻觉、公众号 AI 注入新入口 |
| `知识库/subkb-netsec-cases.md` | **ima 订阅库「网络安全知识库」1616 项定向开垦**（第 2 个订阅库，不全量翻：实读 5 篇 + 顶层 ≈30 项简介级）：§1 **金融 SRC 场景全谱**（开户"删组件绕过校验/证件缓存复用多开户/request_id 遍历三要素"、支付"并发提现·负值反冲·**int64 金额溢出**·手续费参数篡改"、优惠券"券码爆破按响应长度判存在·无锁重复核销"、查询"**隐藏参数 fuzz** + **ToC/ToB 网关混用导 a.com 管理端 history 去 b.com 重放**"、存储/SSRF 白名单域名绕过、第三方"JWT 硬编码密钥/运维 curl 拉密码后门"）；§2 **Fastjson"不看版本看依赖"打法**（DNS/延时/报错三招探依赖，**`{"@type":"java.lang.Character","@type":"java.lang.Class","val":"类名"}` 存在即回显 `can not cast to char`**，据此定 BCEL/CCK1/CB 链，CC 3.2.1+ 需 `enableUnsafeSerialization` 故转 CB）；§3 **LLM 辅助审计工作流**（Fiddler 导出 Raw + KillWxapkg 解包 → LLM 还原签名 + 出报告 → 人工复现；Prompt 三段式 角色/约束/JSON 输出；**脱敏与防幻觉两条红线**）；§4 **Electron 客户端 RCE**（Markdown `<img onerror>` → `process.binding('process_wrap')` → `spawn cmd.exe`）；§5 未读清单 + 排除项 |
| `知识库/subkb-airedteam-cases.md` | **ima 订阅库「AI红队指南攻防知识库」1474 项定向开垦**（第 3 个订阅库，实读 5 篇 + 普查 ≈95 项）：§1 **MCP 服务未授权 → 直接 RCE**（新资产面：hunter `header.server=="uvicorn" && status_code=="404" && header="text/plain"` 约 2789 条 → 逐个验 `/sse` → `list_tools()` 拿到 `python_code_execution`/`execute_sql`/`navigate_click` 即 RCE·拖库·SSRF，作者据此真挖到某 SRC 边缘服务器 RCE）；§2 **MCP 协议攻击面 5 类**（工具投毒 TPA / 地毯式骗局 Rug Pulls / **影子攻击 Shadowing——不调用也能改写可信工具行为** / 命令注入 / 供应链·越狱·API KEY 窃取 + 协议 6 大缺陷 + A2A `/.well-known/agent.json` 泄露面）；§3 **ForcedLeak 链式提示注入**（Salesforce Agentforce，9.4 分，多步调用上下文接力污染，"AI 时代的 XSS"）；§4 **输入侧新手法**（**Unicode Tags Block 不可见字符走私** U+E0000–U+E007F——UI 不渲染 LLM 能解析，可隐藏注入/反向外带/利用 Human-in-the-Loop；字体投毒；攻击增强三分类编码类/单次类/对话类）；§5 **LLM 红队维度与工具**（五大风险类别、OWASP LLM Top10 2025 编号、Garak/DeepTeam/FuzzyAI）；§6 **Java 写文件→RCE：SO 劫持**（`System.loadLibrary` 路径顺序、**已加载的库改写会 SIGBUS 崩溃**、`/proc/pid/maps` 枚举、首选 `libawt.so`、so→触发类对照表、JNI 重写 native 方法优雅落地、ojdbc `heteroxa21`、JDK 路径未知时 fastjson DNS 链与 awt 白名单）→ 交 `cmd-injection-cases.md` / `file-upload-cases.md` |
| `知识库/archive-inventory.md` | **「其他」归档清单与副本对照（2b/2c）**：科普 102 / HW 18 / 电子书 16 / 制度 8 / EduSRC 单点归档 56 的完整留档；**明确副本可删对照** + **标题同但 size 不同（不可判重）警示** + 图片碎片 49 的处理建议（含已被哪个案例覆盖）。不精读，只留档与给删副本依据 |
| `知识库/other-census.md` | **案例库「其他」762 份构成调研（P1-4 结论）**：不是漏洞类型，而是未归位附件倾倒口。Web 547 构成表 + EduSRC 185 教育行业归档特征 + App/小程序方法链路 + 去重（762→≈562）+ 6 条完整攻防链（EDR 二次认证文件删除绕过 / 域渗透 dcsync / DNS 隧道 / AC Host 白名单绕过 / 泛微三层 URL 编码 / K8s etcd→Pod 逃逸）+ 安卓加固对抗（改 SM4 key 表）+ **三分法处置建议** |
| `知识库/open-redirect-test.md` | **URL 跳转 / 重定向**（成篇）：参数名速查（`url`/`redirect`/`next`/`returnUrl`/`callback`…）+ 服务端 sink 与前端 sink + 白名单/协议/编码绕过 + 与 OAuth·登录态组合论证升档（案例见 `logic-web-cases.md` §9）|
| `知识库/ghost-bits-cast-test.md` | **Java char→byte 窄化（Ghost Bits / Cast Attack）**：`char`(16bit) 转协议字节时的截断特性，用于走私 / 邮件头 / 路径 / RESP 等 8bit 边界绕过；公式 `chr((k<<8)\|T)` |
| `知识库/el-injection-test.md` | **EL / SpEL / OGNL 表达式注入**：`${7*7}` `#{7*7}` 多语言探针 → 引擎识别 → 沙箱逃逸 → RCE（Java 系后台、报表、模板常见）|
| `知识库/insecure-scm-test.md` | **源码与配置泄露**：`.git` / `.svn` / `.idea` / `.DS_Store` / `WEB-INF` 等路径速查与还原手法（属信息泄露子类，单独成篇）|
| `知识库/crlf-injection-test.md` / `hpp-test.md` / `http2-attacks-test.md` | **几乎不交**：纯 CRLF、参数污染、HTTP/2 各自不写；导致越权/注入按那个洞走 `idor-test.md` / `injection-test.md`，走私走 `http-smuggling-test.md` |
| `知识库/csv-formula-injection-test.md` / `dangling-markup-test.md` / `dependency-confusion-test.md` / `email-header-injection-test.md` / `xslt-injection-test.md` | **几乎不交 / 无入口 N/A**：CSV 公式、悬空标记、依赖混淆、邮件头注入、XSLT 各自默认不写；导出越权走 `idor-test.md`，现场 XSS 走 `xss-test.md`，模板转换口按现场 SSTI/XXE 打 |

---

## 白盒

用户给出项目路径或源码时，按 `rules/researcher-blackbox-whitebox.md` Phase 0～6。本技能不另抄一套。

黑盒 SRC 正式报告只认 `rules/vuln-report-format.md`。

---

## 与 Grok 版的差异（移植说明）

| 项 | Grok 原版 | 本移植版 |
|---|---|---|
| 规则加载 | `~/.grok/rules/` 全部常驻 | 需按上文「启动必读」主动读取 |
| 浏览器 | `playwright-dual-slot.mjs` 双槽 Playwright MCP | 内置 `agent-browser` 技能 |
| FOFA 资产搜索 | `~/.grok` 无（原靠 MCP） | **fofa.info 网页手动跑**（语法见 `知识库/recon-methodology.md` + 各案例库）；无 key 可用，无配额走 DNS+HTTP+crt 兜底 |
| 路径引用 | `~/.grok/...` | 已全部改写为本技能根目录绝对路径 |

用法、目录说明与红线见 `README.md`。
