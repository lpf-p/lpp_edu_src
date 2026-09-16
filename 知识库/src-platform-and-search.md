# SRC 平台目录 & 搜索技巧

> 定位：本篇解决两件事——**「去哪找目标 / 交报告」**和**「怎么搜（文章 / 泄露 / 资产）」**。
> 具体打法在各自模块；报告写法见 `src-case-study.md`（七字段）+ `report` skill（DOCX）。
> 红线：dork / GitHub 搜到的资产，**只在授权范围（SRC 收录范围 / 众测项目范围）内测**；非授权目标、他校、无关企业一律不碰（对齐 `edge-asset-hunting.md` §0）。

---

## 一、搜索技巧

### 1.1 Google Hacking / Dorks（找资产 · 找泄露 · 找报告）

| 指令 | 用途 | 示例 |
|---|---|---|
| `site:` | 限定站点 | `site:<目标域>` |
| `filetype:` / `ext:` | 限定文件类型 | `site:x.edu.cn filetype:xlsx` |
| `inurl:` / `allinurl:` | URL 含词 | `inurl:admin`、`inurl:api` |
| `intitle:` / `allintitle:` | 标题含词 | `intitle:"index of"` |
| `intext:` | 正文含词 | `intext:"默认密码"` |
| `related:` | 相似站 | `related:target.com` |

高价值组合（**仅对授权目标**）：
- 后台 / 登录：`site:target inurl:admin OR login OR manage`
- 敏感文档：`site:target filetype:pdf OR xlsx OR docx 手册 OR 账号 OR 密码`
- 目录列目录：`intitle:"index of" site:target`（打法见 `artifact-intel-guide.md` G 组）
- 配置泄露：`site:target filetype:env OR ini OR conf OR yml`
- API 文档：`site:target inurl:swagger OR api-docs OR graphql`
- 报错泄露：`site:target intext:"SQL syntax" OR "Warning: mysql"`
- 找思路（搜历史报告）：`site:freebuf.com SRC 逻辑漏洞`、`site:xz.aliyun.com 越权`

资源：GHDB（Google Hacking Database，`exploit-db.com/google-hacking-database`）、GitHub `awesome-google-dorks`。
注：`cache:` 已被 Google 弃用，看历史快照改用 `web.archive.org`。

### 1.2 GitHub Dorking（找泄露的密钥 / 配置）

- 手动语法：`org:xxx`、`filename:.env`、`path:config`、`extension:json`、`"AKIA"`、`"BEGIN RSA PRIVATE KEY"`
- 工具：GitDorker、trufflehog、gitleaks
- 高价值目标：`.env`、`config.json`、`application.yml`、CI 配置、备份 / 部署脚本
- 与 `js-reverse-guide.md` §流程六（硬编码凭据正则清单）是**同一「找钥匙」思路的两个入口**——GitHub 是外部源码面，JS 是前端产物面
- 红线：找到的密钥先判归属；不在 SRC 范围 / 非本目标的，**不测不交**

### 1.3 组合关键词（找文章 / 经验）

- 模板：`SRC 漏洞挖掘 实战`、`企业SRC 报告`、`越权 挖掘思路`、`逻辑漏洞 案例`、`教育SRC 经验`
- 加年份收窄：`2026 逻辑漏洞`
- 平台内搜：FreeBuf / 先知 / 安全客 站内搜索

---

## 二、SRC 平台目录

### 2.1 国内企业自建 SRC

| 平台 | 地址 |
|---|---|
| 腾讯 TSRC | security.tencent.com |
| 阿里 ASRC | asrc.alibaba.com |
| 百度 BSRC | bsrc.baidu.com |
| 字节跳动安全中心 | security.bytedance.com |
| 美团安全应急响应中心 | security.meituan.com |
| 京东 JSRC | security.jd.com |
| 哔哩哔哩 SRC | security.bilibili.com |
| 携程 SRC | sec.ctrip.com |
| 网易 / 新浪 / 金山办公 / 智联招聘 / 哈啰出行 | 各有独立漏洞收集页 |

### 2.2 国内众测平台（第三方）

| 平台 | 地址 | 备注 |
|---|---|---|
| 补天（奇安信） | butian.net | 老牌，教育 / 企业都收 |
| 漏洞盒子 | vulbox.com | |
| 漏洞银行 | bugbank.cn | |
| 火线安全平台 | huoxian.cn | 企业 SRC 运营服务 |
| 360 漏洞云众包 | src.360.net | |
| 360 漏洞云（开源） | loudongyun.360.cn | 开源 / 供应链漏洞 |

### 2.3 教育行业（EDUSRC）

| 平台 | 地址 | 备注 |
|---|---|---|
| **EDUSRC 教育漏洞报告平台** | **src.sjtu.edu.cn** | 上海交大承办的**高校**漏洞平台，教育行业主战场 |
| EDUSRC 演习专栏 | vulsrc.sjtu.edu.cn | 常态化漏洞挖掘演习，需邀请码注册 |

> ⚠️ **常见误标**：`src.sjtu.edu.cn` 常被误写成「上海交大自己的 SRC」，实际是**教育行业平台**。上海体育大学属教育行业 → 走 EDUSRC 提交。

### 2.4 国际漏洞赏金

| 平台 | 地址 |
|---|---|
| HackerOne | hackerone.com |
| Bugcrowd | bugcrowd.com |
| Open Bug Bounty | openbugbounty.org |

### 2.5 安全社区与文章

| 社区 | 地址 | 特点 |
|---|---|---|
| 先知社区（阿里云） | xz.aliyun.com | 企业级安全研究，质量高 |
| 安全客（360） | anquanke.com | 资讯 + 技术文章 |
| FreeBuf | freebuf.com | SRC 实战技巧多 |
| CSDN | blog.csdn.net | 从业者分享多 |

### 2.6 官方漏洞库与基础设施

| 名称 | 地址 | 用途 |
|---|---|---|
| CNVD | cnvd.org.cn | 国家级漏洞共享平台 |
| CNNVD | cnnvd.org.cn | 中国信息安全测评中心 |
| CNCERT/CC | cert.org.cn | 应急响应协调 |

---

## 三、提交与报告

- 报告七字段模板 → `src-case-study.md`
- DOCX 成稿 → `report` skill
- 定级只认 → `rules/vuln-report-format.md`

---

## 四、红线

- dork / GitHub 搜到的资产**只在授权范围内测**
- 非授权目标、他校、无关企业一律不碰（`edge-asset-hunting.md` §0）
- 不社工 / 不钓鱼 / 不买号 / 不截真实个人数据

---

## 五、SRC 挖洞方法论精选（ima 案例库 57 条 → 精读 18 份）

> 来源：个人 ima 知识库 `src`（`7492290188703512`）「其他/Web」的「SRC/众测挖洞方法论」57 条，去重后精读 18 份高价值文档（优先「第 N 更」系列、平台/行业挖掘思路、众测厂商案例）。**仅作威胁认知与防守复盘，SRC 一律不做**；与本篇 §四 红线、`edge-asset-hunting.md` §0 一致——非授权目标、他校、无关企业绝不碰。⚠️ 文中出现的社工/钓鱼/买卖账号内容一律标注红线，仅用于识别攻击手法、加固防守。

### 5.1 选目标与优先级（哪些厂商/资产值得打、赏金与接收率）

- **教育 SRC 选"冷门校"定点打穿**：优先选漏洞少、通报少、安全意识低的高校；弱口令/默认口令进门后逐个系统测，一天可上 80+ rank，日拱一卒比盲扫高效。（来源：第一更《教育src如何日刷百分》）
- **国内 SRC 最看重"业务安全"**：非普通用户权限（商家/合作方/签约作者）与新上线业务是两大富矿；新业务常内测不严、一上线就是漏洞。（来源：国内SRC漏洞挖掘技巧与经验分享）
- **盯"更新"捡漏**：用 GSIL 类或自写脚本监控目标业务 URL 变动，新业务/新模块一上线就第一时间去挖，比重复扫老业务划算。（来源：挖洞技巧-业务监控之捡漏洞）
- **简单逻辑漏洞"送钱"**：并发签到/重复提交类（如小程序并发签到刷积分）门槛极低，拼的是耐心与细心而非技术。（来源：水一篇众测的漏洞报告；转转漏洞挖掘从无到有的副本）
- **"时间差"打法**：先弱口令进后台记录目标，后学对应框架（如 Dcat Admin 插件写马）再回头 getshell 拿赏金。（来源：漏洞挖掘-机缘巧合获取高额赏金）→ ⚠️ 仅防守复盘用。
- **思维层面（长期价值）**：跳出"代码实现层"到框架/组件/配置/运维层；把功能当第一性，漏洞是功能的副产物；系统是动态运行的；专注 + 学挖结合。（来源：挖洞思维_思想建设）

> ⚠️ **红线提醒**：《第七更：SG的常见方法》整篇为**伪装交友/表白墙套取账号、冒充官方运维、购买账号**等社工与买卖账号手法，属红线，仅作攻击手法识别与防守加固，**严禁在 SRC/众测中实施**；《国内SRC经验》中"用简单社工拿商家权限"亦为红线，勿用。

### 5.2 信息收集与接口发现（子域 / JS / 小程序 / APP / API / 历史资产 / 通杀）

- **子域与历史资产**：SSL 证书查询（censys/crt.sh）优于枚举；Github 登录态搜索返回更多三级域/测试代码；CNNIC 按网络名称反查厂商 IP 段；大字典来自开源源码的目录/脚本名/参数/js 名，入库按命中计数降序复用。（来源：国内SRC漏洞挖掘技巧与经验分享）
- **JS/接口是越权第一入口**：翻 Burp HTTP 历史与 F12 网络，找页面看不到的 `?sid=`/`?values=` 等鉴权缺失接口；某证书大学通过接口泄露全校师生身份证、工号、密码 md5。（来源：第三更《接口漏洞实战》）
- **从 JS 找隐藏接口与逻辑 0day**：不看 jquery 等第三方库，专看 `app.*.js`/`config.*.js`，搜 `api/url/path/ajax/username/password`；操作手册常泄露初始密码，翻 `ajax` 直接构造密码重置。（来源：第四更《对Js接口的继续探讨》；通用型漏洞挖掘思路）
- **通杀/同源资产**：学校多用同套二开源码，凭"页面不像自研"直觉 + `inurl` + favicon（鹰图 icon 检索）找同类站点；一处漏洞可横扫多校。（来源：通用型漏洞挖掘思路）
- **JS API 批量 Fuzz 工作流**：`ffuf`+SecLists 扫目录 → FindSomething 提取 JS 接口 → Yakit 批量发请求看状态码/长度；`xx/config` 加 `token:1` 曾泄露阿里云 OSS 临时 key 接管 bucket。（来源：安服仔挖洞记录；分享挖洞中遇到有趣的漏洞）→ ⚠️ 接管 bucket 危害大，仅防守认知。
- **越权 Fuzz 技巧**：`/getUser?userId=` 类参数试中文姓名拼音/工号可遍历人员数据；任意用户登录（存在该用户即免密拼 URL 进后台）+ 任意文件读取(`filePath=/etc/passwd`)常伴生。（来源：安服仔挖洞记录）
- **小程序/APP/伪协议**：APP 证书锁定用 SSL Unpinning 解除抓包；伪协议 `app://jump?url=` 未校验可任意域跳转；jsonp 加 `callback=` 把 json 变 jsonp 劫持订单/凭证。（来源：国内SRC经验；转转漏洞挖掘）
- **源码审计反打**：登录框无弱口令时读源码，DOM XSS → Struts2（`.mob` 也是 struts 后缀）S2-045/046/020 RCE 直接 `system`。（来源：对一次登陆系统的漏洞挖掘）

### 5.3 提交与沟通（怎么写报告、被拒怎么办、重复规避、危害论证升档）

- **重复/被拒是常态**：京东案例显示提交后常收到"已被其它白帽子提交""超出系统理解范围自动关闭"——先查是否已收录，报告写清复现步骤+截图降低误判。（来源：挖洞技巧-业务监控之捡漏洞）
- **危害论证升档**：单点越权影响小，组合"jsonp 劫持拿到越权所需 id + 越权读取"形成组合拳；审核问"是否影响大量用户"时补 App 端利用或加批量证据。（来源：转转漏洞挖掘）
- **凭证劫持类报告模板**：OAuth `redirect_uri` 未校验 → token 外带；第三方登录 `RedirectUrl` 劫持 → `ST` 票据；`service` 白名单用图片 referer 绕过拿 ticket——统一按"授权流程缺陷导致用户登录凭证泄露"写。（来源：漏洞挖掘之众测厂商 4 篇）
- **报告七字段 + 脱敏**：按 `src-case-study.md` 模板；截图与数据一律脱敏，案例库文档本身多标"（不打码）"，提交前务必打码真实个人数据。（来源：安服仔挖洞记录等）
