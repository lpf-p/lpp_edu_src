# 越权 / 未授权 实战案例深挖（ima 案例库）

> **回查原文** → `ima-retrieval-index.md` §2.2（章节 → 检索式：ima `src报告/越权/Web` + 关键词 + 报告名直搜）。

> **来源**：ima 个人知识库 `src` → `src报告/越权/`（Web 120、EduSRC 47、小程序 1，共 168 条）。
> **去重结果**：168 条 → **112 份唯一**（Web 70 + EduSRC 42；小程序那 1 条＝Web 的重复）。详见 `_work/unique-list-idor.md`。
> **本轮精读**：6 批评读稿 `_work/deep-idor-a.md` ~ `deep-idor-f.md`（约 106 份有效精读，含跨目录重复跳过与读取失败）。
> **配套手册**：`idor-test.md`（越权+业务接口未授权的系统化打法）。**本文件是"实战案例与增量"，手册是"方法论"**，配合使用。
> **平台维度**：EduSRC 42 份已按业务场景并入 `edusrc-cases.md` §2.8，本文件只保留教育行业的索引与跨引。

---

## 一、本批构成盘点（先分流，别当报告读）

越权目录**不是纯实战报告**，混了三类内容，处理方式不同：

| 类别 | 条数 | 代表 | 处理 |
|------|------|------|------|
| **教程 / 方法论**（京东 JSRC 安全小课堂 7 篇 + 乌云总结 + 越权漏洞系列 + 角色权限 + 刷越权思路 + K8s） | ≈12 | `04-企业级未授权访问漏洞防御实践.pdf`、`77-聊聊越权的那些事.pdf`、`99-web漏洞挖掘之未授权访问漏洞.pdf` | **只取增量**（→ §二） |
| **CNVD / CNCERT 通报**（设备指纹） | 6 | 星网锐捷路由器、HP M226dw、锐捷 RG-NBR800GW、共济科技动环、网心云 | **只取指纹**（→ §二 B） |
| **企业实战报告** | ≈40 | 麦当劳、平安、腾讯、百度商城、Fairdesk、用友 NC… | **重点**（→ §三） |
| **EduSRC 42 份** | 42 | 同济、上海交大、兰大、南开、清华、浙大… | **并入 `edusrc-cases.md` §2.8** |
| **跨目录已覆盖重复** | 9 | 上海交大 3 份、同济 5 张、小程序 1 份 | **跳过**，引用 `logic-web-cases.md` / `edusrc-cases.md` |

> **一句话**：越权目录的**真增量在"实战报告的接口与参数"**，教程类大多被 `idor-test.md` 覆盖，只有 6 篇教程 + 8 份设备通报值得抽取。

---

## 二、教程与 CNVD 的增量（只记新的）

### A. 教程类：相对 `idor-test.md` 的真增量（6 篇有料）

| 来源 | 增量手法 | 怎么用 |
|------|---------|--------|
| **W5 聊聊越权的那些事** | ① **空值处理**：多参数匹配查询时把部分参数（如 `userIDcard`）置空/删除，或清空时间范围参数，绕过限定实现遍历；② **签名绕过**：签名参数置空；或分析签名 key 来源（常取自上一响应包），**改上游响应里的 key** 让 API 替你调用 | 接口被"必须带全参数"卡住时，先试删参；有签名机制时先找 key 从哪来 |
| **W6 web漏洞之越权漏洞挖掘** | ① 隐藏 URL（菜单藏特权地址，靠 Google Hacking/前端路由/路径扫描）；② 含 id 参数未校验归属；③ **顺序流程阶段越权**（找回密码第二阶段不再校验用户真实性）；④ **`X-Forwarded-For: 127.0.0.1` 加请求头绕过 403 验证逻辑**；⑤ **POST 参数 `verifycode2` 换成 `verifycode` 绕过验证码登录** | XFF 伪造本地、验证码**参数名替换**是两枪便宜而有效的绕过 |
| **W7 web漏洞挖掘之未授权访问** | ① **系统服务未授权 17 种**（Redis/Jenkins/MongoDB/ZooKeeper/Elasticsearch/Memcache/Hadoop/CouchDB/Docker/Varnish/proxool/nfs/samba/influxdb/Rsync/Cassandra/Resin）；② Web 未授权三分（后台 / RESTful API / webservice）；③ 找接口思路（静态文件+JS 解密、逆向 app、开放平台、`site:`/`inurl:`、`robots.txt`、django debug 泄露 url）；④ 组合利用（SSRF 打内网 MySQL 未授权→RCE、未授权+XXE、Memcache 放大） | **端口类只在有安全网关时可打**；清单本身稀缺，作为组件发现索引 |
| **W26 角色权限缺陷逻辑** | 把"角色 / 模式"当成**可篡改的用户属性参数**：`role`/`mode`/`switch` 类参数往往单参数控权。案例：百度青少年模式 `POST /appui/user/setteenagerinfo` 改 `teenagerSwitch=0` 即解除 | 见到 `mode`/`role`/`switch`/`teenager` 就抓包试改 |
| **W28 K8s API Server 未授权命令执行** | 完整链：`kubectl -s http://IP:8080 get pods` 探活 → `/api/v1/namespaces/kube-system/secrets/` 读 dashboard-admin token（base64 解一次）→ 建特权 pod 挂宿主 `/` 到 `/mnt` → 写 `/mnt/root/.ssh/authorized_keys` 或 `/mnt/var/spool/cron/root` 反弹，或 `chroot /mnt`。端口 **8080**（insecure，1.20+ 已禁用）/ **6443**（靠 `system:anonymous` 误绑 cluster-admin） | 云原生独立利用链，技能库稀缺 |
| **W65 之前的刷越权思路** | **后台路径 + fuzz 参数**：看似"跳登录"的后台路径别放弃，补 GET/POST 参数 + fuzz 参数名，可能命中未鉴权的数据接口。案例：jd.com 后台路径加 `?check=1` 并 fuzz，返回业务数据（含用户 org/注册号） | 隐蔽、重复率极低；比前端可见越权点更值钱 |

**无增量的 6 篇**：W1（企业级未授权防御实践）、W2（越权泄露隐私）、W3（另一角度看越权）、W4（Redis 未授权）、W49（乌云越权总结）、W56（越权漏洞·小米案例）——均为「越权=缺失的艺术 + 差分 + ID 枚举 + 四动作 + 多账号矩阵」的初级定义或例证。仅极边角补充：**交叉越权**（ID 与权限同变）、**uuid 代理主键**代替业务 id 防遍历、**nginx 代理 JS 混淆**防扫描器。

### B. CNVD / CNCERT 通报：设备指纹速查表（并入指纹库）

| 设备 / 系统 | FOFA / 鹰图语法 | 端口 | 未授权接口 / POC | 泄露 |
|------------|----------------|------|-----------------|------|
| **星网锐捷 NBR 系列路由器** | `title="锐捷网络" && port="9999" && country="CN"` | 9999 | `http://IP:9999/index.data?opt=err&_=1663068005` | 内网 `wan_ip`/`wan_gw`/`mac` |
| **锐捷 RG-NBR800GW** | 鹰图 `web.icon="a45883b12d753bc87aff5bddbef16ab3" && web.body="RG-NBR800GW"` | 9999 | 同上 `/index.data?opt=err` | 同上 |
| **HP LaserJet Pro MFP M226dw** | 无语法，直访 | 631/8080/443 | `/device/set_config_webServices.html?tab=WebServices&menu=WebServicesConfig` | 打印机 Web Services 配置可改 |
| **HP Officejet Pro 251dw** | `app="HP-OfficeJet-Printer" && product="HP-Officejet-Pro-251dw-Printer"` | 80/8080/9100 | EWS 首页直进设置/网络/密码/备件页 | 设备状态、ePrint 配置 |
| **共济科技 XBROTHER 动环监控** | `app="XBROTHER-动环监控系统"` | 30001 | ① `/xbreport/attachment/*.pdf`（`Cookie: USER_ID=1` 读后台日报）② `/api/v3/system/version/info` ③ `/api/v2/license/info`（SN）④ `/api/v3/system/version/history`（POST，需头 `check: cd5c55d62866d0061cc12d462f83f66b`） | 温湿度报表、版本、序列号 |
| **网心云设备** | `app="网心云设备" && country="CN"` | 9999（个别 8882） | 访问根路径直接进后台 | 设备 SN / 激活码 / MAC / 内网 IP |
| **H3C ER6300 路由器** | `"H3C" && title=="ER6300系统管理"` | 5555/8080 | 全站无鉴权，命令经 `CMD` 参数分发：`GET /ER6300_SYSLOG.log` 下日志；`POST /goform/aspForm` `CMD=SYS_LOG` / `CMD=SetExpiretime&vld_disable_flag=1` 关验证码 / `CMD=IDS` 关 IDS | 系统日志、可关安全功能 |
| **福建科立讯 指挥调度管理平台** | `app="指挥调度管理平台"` | 7080/8088/8443 | 默认 `admin/admin` → IMEI管理→导入→抓 `GET /app/extensions/imei_import.csv`，换浏览器匿名重访即未授权下载 | 模板/导出文件 |

> **打法**：`FOFA 指纹 → 默认口令只试一次 → 找"模板/导出/日志"下载接口 → 退出会话匿名重访该 URL`。设备类多给中危（信息泄露+可改设置），路由器/调度平台被控可到高。

---

## 三、企业实战 · 按打法分组（核心章节）

### 3.1 【对象 ID 替换】最基础的一枪

> 把请求里的**资源对象 ID**（订单号/单据号/资产 id/媒体 id）换成他人的，服务端不校验归属。

- **W53 越权查看他人购买的音乐包**：`GET /products/{id}` 遍历 id（如 `128508`/`121517`）→ 拿到他人已购音乐包。Intruder 遍历返回 200 即命中，"我的已购/我的资产"详情页是通用入口。
- **W55 Fairdesk 交易所越权查资产**：`GET /user/v1/private/saving/summary?userId=254854`，遍历 `userId`（`251577`）→ 读他人 USDT/BTC 余额与利息。**带 `/private/` 路径却用可遍历 `userId` 当查询参数**是水平越权高发点，返回含 `totalValueInUsdt`。
- **W57 / W62 百度商城越权改他人订单收货地址**（同源两版）：账号 A 下单 `4721205586`、账号 B 下单 `4721207746`；B 抓 `PUT /api/orders/4721207746/address/v1?timestamp=…`，把订单号改成 A 的 → B 填的地址写进 A 的订单。**电商"改地址"只校验登录态不校验订单归属**即中招；需两账号对照。
- **W9 / W10 好看视频（haokan）冒用他人视频发布**（同源两版）：作者发布页 `/author/upload` 请求体含 `mediald`（视频 mad）；改成**他人视频 mad** 即可用自己的账号发布别人的视频。发布/编辑/删除类接口以对象 ID 定位资源且无所有权校验。
- **W70 麦当劳门店"周转物返空出库"单据越权**（被拒收）：`/store/#/store/outbound/tray/return/list/view?id=3e3857c6-…`，把 URL 中 UUID 换成其他门店单据 id → 读他店出库单。SPA 单据详情以 URL id 定位、后端不校验门店归属。

### 3.2 【用户标识参数替换】从"读"到"顶号/接管"

> 比对象 ID 更值钱：替换的是**用户身份标识**（`userId`/`unionId`/`loginUuid`/`memberId`/`uid`），能做改他人资料、顶号登录、接管账号。

- **W32 平安微互动小程序任意用户登录（顶号）**：`GET /padelm/chat/login?unionId=o8stus…`，服务端以 `unionId` 当身份凭证。先从排行榜接口响应拿他人 `UNION_ID`，替换后直接以他人身份登录，回显手机号/昵称。**凡以 unionId/openId 当登录态的小程序**，排行/分享接口就是 ID 来源。
- **W43 腾讯原创馆越权改信息 + 登录任意账号**：`PUT /my/profile` 体含 `userId`/`username`/`password`。改 `userId` 为他人即改他人资料；因 **`userId` 与 QQ 号绑定**，把他人 userId 绑到自己 QQ 即可登录他人账号。头带 `X-Token`/`X-Source: ycg.qq.com`。
- **W54 越权查看聊天记录**：先抓"搜索联系人"包 `fromAccid=s-15205***44` 换他人 → 看联系人列表；再抓"搜索聊天记录"包（含 `fromAccid` + `toAccid`）换 `fromAccid` → 看他人会话。IM 消息接口常带 from/to 双 id，替换其一即可。
- **W58 麦当劳小程序越权改他人支付密码**：新账号设支付密码抓 `POST /api`，`funcode=A1.AC003`，体含 `memberId`（如 `MEDDY1899…`）+ `encryptData`；取老用户 `memberId` 替换 → 把老用户支付密码改成已知密码（老用户原密码失效、新密码可进）。字段还有 `familyId`/`accountNature`/`cooperator=C7777`。
- **W59 小米游戏中心越权改他人帖子**：`POST …/posts` 体含 `loginUuid`（`1410617498`）+ `viewpointId`（文章 id）；双改 → 改他人帖子。参数还有 `circleId`，头带 `_SW01_…`。
- **W52 越权撤回他人评论**：撤回请求体含 `"userId":"u62c7e9b1…"` 与 `"id":"1a182ecc…"`，双改即可撤回/删除别人评论，返回 `{"code":0,"msg":"success"}`。
- **W36 上海交大就业小程序越权读毕业去向**（EduSRC，跨引）：`/newcareer/main/jygl/xs/byqx/view/{id}?qxid=XwGA…` 与 `POST /selectByXsid`（体 `qxid=`），替换 `qxid` → 回显他人姓名/学号/身份证/生源地。

### 3.3 【响应包篡改】前端信任返回包 ⇒ 服务端没二次校验

> 登录态或权限若由**返回包字段**决定，改包即越权。这是最高性价比的一枪。

- **W67 麦当劳"水晶盾"垂直越权到超管（高危）**：`http://crystalshield.mcd.com.cn:9091`，账号 `11111111111`/验证码 `888` 登录，抓 `POST /api-crystal/auth/mobile/login` 返回包，把四个布尔权限位全改 `1`（`isMip`、`isOnlineCaseCenter`、`isMarketCity`、`isAdmin`）→ 越权超管，刷新仍有效，可见全国门店案件数据。**SRC-2022-439，+40 积分 +400 安全币（已修复）**。
- **W63 用友 NC 文件服务器未授权进控制台**：`POST /fs/console`（`operType=login&username=root&password=…`），把返回包 `"login":"false"` 改成 `"login":"true"` → 绕过认证进 `/fs/console.html` 控制台（可见服务器 IP/存储路径）。
- **W68 麦当劳"云鼎智能"任意用户登录**（被拒收）：先 `/api/sys/loginByName` 用 admin 登录复制其 `userInfo`（含 id/username/role），再随便输账号密码 `POST /api/sys/login`，把返回包 `result.userInfo` 替换成 admin 数据 → 登入后台"切换用户"选任意角色。**拒收理由：服务器为供应商资产、域名解析有误，第三方公司系统不在奖励范围**。
- **W27 长春理工"生产车间执行系统"响应包 `success` 篡改**（兼任意改密）：`POST /updatePassword` 参数 `loginId=111234&password=Admin123&value1=123`，`value1`（原密码）校验不严、填错也成功；把响应 `success:false` 改 `true` 可绕过提示，重置他人密码。

### 3.4 【Cookie / token 缺陷】

- **W11 宝马用户后台 Cookie 越权**：Cookie 为 MD5 串，解出结构 `随机值 + 账户识别码(如 43S579) + 随机值`；注册第二账号得识别码 `59KI893`，按同结构重构 Cookie 后 MD5 → 以 `43S579` 身份越到 `59KI893` 资料页。分两段校验随机值、仅回显识别码对应信息。**Cookie 含可识别用户标识且整体可逆 ⇒ 重构他人标识段即水平越权**。
- **W69 麦当劳供应商/商家 token 未授权 + 可解密遍历**（被拒收）：`datajson` 明文返回 account/password/token；请求头把 token 名改成 `SCToken`、URL 的 `login` 改 `index` 直接访问 → 未授权进库存页；token 为 Base64（解出"餐厅user1:餐厅:0-*/*"）可遍历 id 伪造登录，商户名/tokenid 乱改仍有效。定级"无影响"。
- **W33 圈友分享·企业网盘任意密码重置**：重置链接 `code = 用户id + reset + 时间戳`。先从他人分享页的 **4 位访问密码**（无错误锁定）爆破拿到 `ownerId`，再从注册接口返回包拿 `register` 时间戳；拼 `/netdisk-api/usercenter/updateStatus?code=用户id_reset_时间戳`，对最后 4–5 位时间戳 Intruder 爆破 → 命中 302 跳重置页设新密码。同源还暴露任意用户注册。

### 3.5 【删参 / 改排序 / 号段放行】把"范围过滤"打没了

> 接口本来用业务维度（班级/学期/号段）限定数据范围，**删掉范围参数或改排序字段**就可能退化成全表查询。

- **W8 兰州大学研究生综合业务系统成绩查询**：`GET /lzuyjs/cjlr/xkxsldex?id=…&pkxq=…`，`jsbld`（教学班）+ `xqcode`（学期）是数据范围维度；**删掉这两个参数**并把 `sort=card,asc` 改成 `sort=id,asc` → 服务端不再按班级隔离，直接返回全校学生姓名/手机/身份证/家庭住址/父母身份证及手机。
- **W29 兰大研究生系统（yjscs，同主题另一接口）**：`GET /api/xs/stuxkjgVo?page=0&size=15&sort=card,asc&jsbld=…&xqcode=…`（头带 `Authorization: Bearer <JWT>`），同样删 `jsbld`/`xqcode` + 改 `sort=id.asc` → 全量。**注意：带 Bearer 鉴权仍可能缺对象级校验**。
- **W60 / W61 某通讯营业厅缴账单查询越权**（同源两版）：查询订单本有"密码 + 验证码"双限制，但**手机号填指定地区号段（如 1788…）时限制失效**；再爆破手机号后四位批量拉他人账单（`mobileNo`/`bills`/`billOrgName`）。运营商账单接口对特定号段放行是典型缺陷。
- **W35 任意用户注册（弱约束）**：注册短信验证码仅 **4 位、有效期 15 分钟、无频控/无锁定**，Intruder `0000-9999` 全空间爆破 → 任意手机号注册并登录（响应 `{"status":"SUCCESS","describe":"register succeed"}`）。弱注册常是后续越权的前置。

### 3.6 【路径替换 / 直访受限 URL / 废包】

- **W41 陕西学前师范学院 OA 越权读他人卡片**：本人卡片用 `/cardPersonal/`、他人卡片用 `/cardInfo/`（不含身份证）。把他人卡片 URL `.../main/hrm/card/cardInfo/5?key=tuiht9` 的 `/cardInfo/` **替换为 `/cardPersonal/`** → 泄露他人身份证、婚姻状况、家庭联系方式，通讯录共 14861 条可遍历。**同类资源存在 `/info`（公开）与 `/personal`（敏感）两套路径时，换路径即越权**。
- **W37 上海交大电工电子实验中心虚拟仿真平台（越权新思路）**：① **改名越权登录**：测试账号 `10001/10001` 登录，把用户名改成 `zhangfeng` 即越权登录为「张峰」老师，出现课程库/教学课程管理，可增删改课程与助教；② **直访受限 URL**：普通学生账号直接访问 `/tcoursesite/listCourseLibrary?currpage=1`、`/listSelectCourse?currpage=1` 即用教师功能。**前端菜单隐藏 ≠ 后端鉴权**；后端为 Gvsun 教学平台，自述中危 Rank5。
- **W12 丁香园 BBS 未授权读受限版块**：访问受限帖 `GET /bbs/newweb/post/detai?postId=20516161&…&sign=…` 提示无权限；在 Burp 中**逐一丢弃（废包）权限校验子请求**，定位到可被废掉的那一个 → 校验流程被跳过，即可打开帖子、上传附件、发内容。**受限资源带签名/权限校验子请求时，逐个 drop 找可废的那一个**。
- **W65 后台路径 + fuzz 参数**（教程，见 §二 A）：对"看似跳登录"的后台路径补参数 + fuzz 参数名，命中未鉴权数据接口。

### 3.7 【客户端鉴权】前端 / 隐藏字段说了算

- **W25 某招生就业系统 JS 跟踪未授权**：跟踪 `/js/custom/login.min.js`，登录逻辑 `$.post("/framework/login_login.do",{loginId,password,verifycode})`，JS **仅依据返回 `a=="true"` 就跳转** `/framework/login_toManage.do`；**实际只校验 loginId 是否存在，密码不参与鉴权**。输入已存在用户名（如 admin），密码错也显示"密码错误"，**手工直接访问后台框架 URL 即拿到该用户全部权限**（微信管理、用户管理、全部用户 7188 条）。前端判成败 + 自行跳后台 URL ⇒ 直接访问后台地址即绕过。
- **W22 i春秋论坛虚拟马甲越权发帖 → 冒充任意用户**：发帖页有隐藏字段 `<input name="kl3wguisepostuserid" type="hidden" value="46921">` 指定发布者 UID，**仅前端校验**。改成目标用户 UID（如超管"阿蛋" `77972`）即可用其身份发帖（thread-30131），实现控制任意账号（可升级到冒充管理员钓鱼）。漏洞 ID rosectow，2017-12-08；利用前须先获授权马甲。

### 3.8 【垂直越权 / 提权】

- **W34 中国电信安徽分公司防控通行监管系统平台垂直越权**：`https://47.111.13.153:8010`，弱口令/自注册进普通用户后，刷新个人信息触发 `POST /prod-api/wuyu/user/get_user_info`（体 `{"uid":"m3hqmws2k"}`）；把 `uid` 改成 `admin` → 响应 `displayName:"系统管理员"`、菜单多出权限管理/用户管理，成功提权超管（可增删用户、下载 apk）。提权路径 `uid=m3hqmws2k`（普通）→ `uid=admin`（超管）；头带 `Access_token`/`Authtoken`，Vue 前端 `/app.bf2b1749.js` 暴露注册接口。
- **W27 长春理工"生产车间执行系统"垂直越权 + 任意改密**：登录框无验证码，爆破出 `123/123456`（302 长度 445 为成功，存在用户枚举）；`POST /getUserMsg?loginId=123` 把 `loginId` 改成 `1960347` → 拿到"超级管理员"信息并成功以其登录；`POST /updatePassword` 参数 `loginId=111234&password=Admin123&value1=123`，原密码字段 `value1` 校验不严 + 响应 `success:false→true` → 重置他人密码。密码 bcrypt `$2a$10$…`。**用户查询/改密接口以 `loginId` 为对象且无权限校验 ⇒ 垂直越权**。
- **W67 麦当劳水晶盾垂直越权**（响应包篡改，详见 3.3）。

### 3.9 【未授权访问】业务接口 / 后台 / 组件

- **W51 某文件服务后台管理系统（青峰软件 lx-files）未授权文件操作**：未登录直接访问 `/portal/fileinfos/toFileInfosPage` 列出全部文件（路径/上传人/下载次数）；`/portal/fileinfonew/add` 可未授权传文件；删除以 `id` 参数控制，**遍历 id 可删全部文件**。文件存 FastDFS `M00/00/00/…`，上传人字段可写任意名。
- **W66 麦当劳供应商/门店数字化后台未授权进后台（低危）**：未登录直接访问 `https://scdigital.mcd.com.cn/supplier/#/supplier/index` 与 `/store/#/store/index` 即进后台看货品库存。**SPA 仅靠前端路由隐藏、接口缺鉴权时，直访 `#/xxx` 内部路径即未授权**。SRC-2022-330，+2 积分 +20 安全币。
- **W64 福建科立讯指挥调度管理平台未授权文件下载**：FOFA `app="指挥调度管理平台"` 定位（7080/8088/8443），默认 `admin/admin` 登录 → IMEI管理→导入→下载模板，抓 `GET /app/extensions/imei_import.csv`；**退出或换浏览器直接访问该 URL**，匿名下载成功。后台"模板/导出下载"类接口常缺鉴权。
- **W18 H3C ER6300 路由器未授权**：全站无鉴权，命令经 `CMD` 参数分发；日志 `GET /ER6300_SYSLOG.log` 或 `POST /goform/aspForm`（`CMD=SYS_LOG`）、关验证码 `CMD=SetExpiretime&vld_disable_flag=1`、关 IDS `CMD=IDS`。证明案例 `http://125.68.138.105:12345/home.asp` admin/admin。
- **W21 HP Officejet Pro 251dw 打印机未授权**：直访 EWS 首页（80/8080/9100）即进设置/网络/工具/密码/备件/恢复页，暴露 ePrint 配置（主机名 `HPCA5A6`/`HPCA87DD`）与无线信息。纯资产/指纹型未授权。
- **组件未授权 17 种 + K8s 链**：见 §二 A（W7、W28）。

### 3.10 【任意密码重置 / 账号接管】越权的钱袋子

| 案例 | 手法关键词 | 要点 |
|------|-----------|------|
| **W30 大尚国际（DUSUN）任意密码重置** | `mn` 字段 | 找回时把"重置手机号"换成自己的号收码；填新密码时抓包，请求 `mn` 字段显示被重置账号手机号 → 改回受害者手机号（`identifyingCode=882969&action=valRegCode&pwd=admin123`），**一次性把两个账号密码都重置**——重置动作绑定的是请求中的手机号标识而非验证码归属 |
| **W33 圈友分享·企业网盘** | `code=用户id_reset_时间戳` | 4 位分享密码爆破拿 ownerId + 注册包拿时间戳 → 爆破时间戳 → 改任意密码（详见 3.4） |
| **W31 逻辑漏洞——任意密码重置案例合集（9 厂商）** | 9 类缺陷 | ①4/5 位验证码前端刷新可暴破（当当 `verify_fp.php`）；②验证码明文回显响应包（走秀 `/ajax/sms.php?action=user_reset&verifycode=2807`）；③返回包泄露加密手机号+验证码有规律可构造字典（新浪）；④重置 token 基于时间可猜（中兴 `reSetPwdCheck.action?startClickTime=…`）；⑤登录态改他人 `userIdCard` 绑自己邮箱再找回（彩票 `bindMobileOrEmail.action`）；⑥`step` 跳步（电信 `step=4`）；⑦响应包 `flag` 篡改（OPPO `{"flag":-4}`→`{"flag":1}`）；⑧注册竞态改 admin 密码（中铁）；⑨同浏览器链接+他人账号错位的会话混淆（聚美） |
| **W27 长春理工** | `loginId` + `success` | 详见 3.8 |
| **W38 上海交大任意用户密码重置** | OCR 不完整 | 仅得线索"创建 `admin`→已注册→改 `admin111` 注册并抓包"，完整重置利用步骤缺失，建议回源图复核 |

> **通用打法**：任意密码重置 = 找"验证码可暴破/回显、token 可猜、step 可跳、响应 flag 可改、身份字段可替换、会话可混淆"六类薄弱点之一。与 `password-reset-test.md` 交叉。

### 3.11 【多租户 / 通杀】一套系统多站复用

- **W42 通杀1·上海甲鼎就业信息服务平台（多校共用）**：雇主编辑职位 `GET /Enterprise/PositionEdit.aspx?PosiID=55055`，把 `PosiID` 改成其他公司职位 ID（Intruder 爆破后两位）即篡改他人职位。案例三家：华东理工 `career.ecust.edu.cn`、上海理工 `91.usst.edu.cn`、上海商学院 `jiuye.sbs.edu.cn`，均用 `Admin123456` 登录后通杀。**同一平台多租户以对象 ID 定权且无租户隔离 ⇒ 批量打同厂商站点**。鹰图语法 `title="就业" && body="甲鼎"` 定位同平台资产。
- **同厂商横向套用**：与教育行业是同一种思路（epay/依能/南软"打通一个横向刷分"，见 `edusrc-cases.md`）。

---

## 四、按功能点的排查 Checklist

### A. 有会话（登录后）——对象图 / 换 id
1. [ ] 抓"我的资产/订单/单据/简历/资料"详情请求，**换对象 id**（数字自增 / UUID / mad / qxid）；
2. [ ] 请求里有没有**用户身份参数**（`userId`/`uid`/`unionId`/`loginUuid`/`memberId`/`fromAccid`/`usercode`）？换成他人试；
3. [ ] 有没有**双参数**（用户 id + 对象 id 同时可控，如 W52/W59）？
4. [ ] 数据接口是不是带**范围维度**（`jsbld`/`xqcode`/班级/门店/租户）？**删掉范围参数** + 改 `sort` 排序字段试全量；
5. [ ] 带 `/private/` 却用可遍历 id 作查询参数 ⇒ 重点；
6. [ ] Cookie 结构可逆（MD5/Base64）？含用户标识段能否重构他人值？
7. [ ] token 是否明文/仅 Base64？能否遍历/乱改字段？
8. [ ] 有签名机制？签名参数置空；或找签名 key 是否取自上一响应包（改上游包）。

### B. 无会话 / 弱会话
1. [ ] SPA 后台的 `#/xxx` 内部路径直访是否跳登录？换 `curl -i` 看不跟随的响应体（未必真鉴权）；
2. [ ] 后台路径补参数 + **fuzz 参数名**（`?check=1` 类）；
3. [ ] 登录接口只校验用户名？JS 判成败 + 跳后台 URL ⇒ 直访后台地址；
4. [ ] 前端隐藏字段决定操作主体（`*userid` 类）？改值试；
5. [ ] 设备/组件 FOFA 指纹 → 默认口令 → 找"模板/导出/日志"下载接口 → 匿名重访；
6. [ ] 端口类组件（17 种）是否裸奔（需有安全网关语境）。

### C. 响应包 / 前端信任
1. [ ] 登录返回包是否有 `login:false` / `status` / `SignId` / `role` / 布尔权限位（`isAdmin`/`isXxx`）？改成"成功/高权"试；
2. [ ] 返回包是否携带完整 `userInfo`？替换成高权用户数据试；
3. [ ] 操作类响应的 `success`/`flag` 改值能否绕过前端提示（不改后端）。

### D. 找回密码 / 改密（越权的钱袋子）
1. [ ] 接收验证码的"手机/邮箱"与"被重置账户"是否**分离且可分别篡改**（`mn`/`hone` 类）？
2. [ ] 重置 token/链接是否 = `用户id + 动作 + 时间戳` 且无签名？爆破时间戳；
3. [ ] 改密/改资料接口的目标用户由 URL 参数/Cookie 决定？替换 id；
4. [ ] `step` 参数能否跳步？响应 `flag` 能否篡改？
5. [ ] 交叉 `password-reset-test.md`。

### E. 提权
1. [ ] 个人信息/会话接口（`/api/*/me`、`/api/v1/sessions`）的 `uid` 参数改 admin？
2. [ ] 用户查询接口（`getUserMsg?loginId=`）改 id 拿超管？
3. [ ] 改密接口原密码字段校验是否严格？

---

## 五、案例索引表（Web 70 份唯一 → 本文件章节）

| 序号 | 标题（简称） | 目标 | 归入章节 |
|------|------------|------|---------|
| W1–W4、W49、W56 | JSRC 小课堂 04/37/38/46、乌云总结、越权漏洞系列 | — | §二（无增量） |
| W5 | 77-聊聊越权的那些事 | — | §二 A（空值/签名） |
| W6 | 94-web漏洞之越权漏洞挖掘 | — | §二 A（XFF/验证码参数/阶段越权） |
| W7 | 99-web漏洞挖掘之未授权访问 | — | §二 A（17 组件清单） |
| W8 | 兰大越权（成绩查询，OCR） | `lzuyjs` | 3.5 |
| W9 / W10 | 不安全对象直接调用2（同源） | 好看视频 | 3.1 |
| W11 | cookie越权 | 宝马 | 3.4 |
| W12 | 丁香园未授权访问 | `dxy.cn` | 3.6 |
| W13–W17 | CNVD 通报（锐捷×2/HP/共济/网心云） | 设备 | §二 B |
| W18 | H3C ER6300 未授权 | 路由器 | 3.9 / §二 B |
| W19 | 华东理工接口未授权中危（**读取失败**） | — | §七 |
| W20 | 好看视频不安全对象直接调用（**读取失败**） | — | §七 |
| W21 | HP Officejet Pro 251dw 未授权 | 打印机 | 3.9 / §二 B |
| W22 | i春秋论坛越权控制阿蛋账号 | `bbs.ichunqiu.com` | 3.7 |
| W23 / W24 | 交大-越权（截图，OCR 碎片） | 上海交大 | `edusrc-cases.md` §2.8 |
| W25 | Js跟踪之未授权访问 | 招生就业系统 | 3.7 |
| W26 | 角色权限缺陷逻辑 | — | §二 A |
| W27 | 记一次逻辑越权漏洞 | 长春理工 | 3.3 / 3.8 / 3.10 |
| W28 | K8s API Server 未授权命令执行 | — | §二 A |
| W29 | 兰大越权（yjscs，OCR） | `yjscs.lzu.edu.cn` | 3.5 |
| W30 | 逻辑cookie任意密码重置 | 大尚国际 | 3.10 |
| W31 | 逻辑漏洞--任意密码重置（9 厂商） | 多家 | 3.10 |
| W32 | 平安任意用户登录 | 平安微互动小程序 | 3.2 |
| W33 | 圈友分享-企业网盘任意密码重置 | 企业云盘 | 3.4 / 3.10 |
| W34 | 中国电信防控通行监管系统平台垂直越权 | `47.111.13.153:8010` | 3.8 |
| W35 | 任意用户注册 | — | 3.5 |
| W36 | 上海交大越权 | 交大就业小程序 | 3.2 / `edusrc-cases.md` |
| W37 | 上海交大 越权新思路 | `vlab.sjtu.edu.cn` | 3.6 |
| W38 | 上海交大-任意用户密码重置（**OCR 不完整**） | `.sjtu.edu.cn` | 3.10 / §七 |
| W39 | 上海交通水平越权 | 交大知行安泰小程序 | `edusrc-cases.md` §2.8 |
| W40 | 上海理工接口未授权（**读取失败**） | — | §七 |
| W41 | 陕西学前越权 | `oa.snsy.edu.cn` | 3.6 |
| W42 | 通杀1 | 甲鼎就业平台（多校） | 3.11 |
| W43 | 腾讯原创管可越权修改信息并登录任意账号 | `ycg.qq.com` | 3.2 |
| W44–W48 | 微信图片（同济 5 图，与 EduSRC 逐字节同） | 同济大学 | `edusrc-cases.md` §2.8 |
| W49 | 乌云越权总结 | — | §二（无增量） |
| W50 | 新疆交通1（**读取失败**） | — | §七 |
| W51 | xxxx有限公司存在未授权文件操作 | lx-files | 3.9 |
| W52 | 越权撤回评论 | 音频/讨论平台 | 3.2 |
| W53 | 越权查看别人购买的音乐包 | 音乐商城 | 3.1 |
| W54 | 越权查看聊天记录 | 社交/IM | 3.2 |
| W55 | 越权查看他人资产 | Fairdesk | 3.1 |
| W56 | 越权漏洞（小米案例） | 小米 | §二（无增量） |
| W57 / W62 | 越权修改地址 / 越权（一）（同源） | 百度商城 | 3.1 |
| W58 | 越权修改支付密码 | 麦当劳小程序 | 3.2 |
| W59 | 越权修改 | 小米游戏中心 | 3.2 |
| W60 / W61 | 越权 / 越权_(1)（同源） | 通讯营业厅 | 3.5 |
| W63 | 用友文件服务器未授权 | 用友 NC | 3.3 |
| W64 | 指挥调度中心-未授权访问漏洞3 | 科立讯 | 3.9 / §二 B |
| W65 | 之前的刷越权思路 | jd.com | §二 A / 3.6 |
| W66 | [低危] 麦当劳存在未授权访问漏洞 | scdigital | 3.9 |
| W67 | [高危] 麦当劳水晶盾垂直越权到超管 | crystalshield | 3.3 / 3.8 |
| W68 | [忽略] 麦当劳云鼎智能任意用户登录 | mcdchina | 3.3（拒收） |
| W69 | [忽略] 麦当劳供应商/商家 token 未授权 | scdigital | 3.4（拒收） |
| W70 | [忽略] 麦当劳商家/供应商越权 | scdigital | 3.1（拒收） |

---

## 六、厂商定级尺度实录

| 案例 | 定级 | 奖励 / 结果 |
|------|------|-----------|
| McDonald's W67 水晶盾垂直越权到超管 | **高危** | SRC-2022-439，**+40 积分 +400 安全币**（已修复） |
| McDonald's W66 scdigital 未授权进后台 | **低危** | SRC-2022-330，**+2 积分 +20 安全币** |
| McDonald's W68 云鼎智能任意用户登录 | **忽略** | 拒收：**"服务器为供应商资产，且此系统与麦中无关，域名解析有误，第三方公司系统不在奖励范围内"** |
| McDonald's W69 token 未授权遍历 | **忽略** | 定级"无影响"；疑与 W66 同源 + token 类重复提交 |
| McDonald's W70 门店单据越权 | **忽略** | 定级"无影响"；与 W66/W69 同源域名 |
| Shanghai Jiao Tong W37 vlab 越权 | 中危 **Rank5** | — |
| 上海交大科艺 IDOR 改密（教育） | 中危 | — |

> **三条经验**：① 同厂商多份同类漏洞会被判"重复提交"（麦当劳 W69/W70）；② **资产归属不清（供应商/第三方）是拒收重灾区**——提交前先确认域名/系统在 SRC 范围内；③ **"越权到超管 + 影响全国数据"是拿高额奖励的关键**（W67），单纯"读一条别人数据"常判低危或无影响。

---

## 七、素材缺口（需在 ima 客户端补）

| 项 | 情况 | 待补 |
|---|------|------|
| W19 `华东理工接口未授权中危（已看）.doc` | 两次返回空（`{"content":"8\n"}`） | 打开原文件补录 |
| W20 `好看视频不安全对象直接调用.docx` | `code:220030` 两次失败 | 疑与 W9/W10 同系列"上一章"，待比对 |
| W40 `上海理工接口未授权.doc` | 两次返回空 | 打开原文件补录 |
| W50 `新疆交通1.png` | `code:220030` 两次失败 | 建议 ima 内查看 |
| W38 `上海交大-任意用户密码重置（打码）.png` | OCR 碎片，仅"创建 admin→已注册→admin111" | 回源图补全重置链路 |
| W23/W24 `交大-越权.png`×2 | 纯截图，OCR 碎片 | 内容由 E22–E24（越权打包）覆盖 |
| W8/W29 兰大 | OCR 不完整，URL/参数名以域名+关键字为准 | 已提取核心动作（删参改 sort） |

---

## 八、交叉引用

- **方法论** → `idor-test.md`（越权+BOLA/BFLA+业务接口未授权；核心认知、四动作、ID 枚举三法、Autorize/AuthMatrix）
- **密码重置** → `password-reset-test.md`（§3.10 的六类薄弱点体系化）
- **登录绕过** → `login-bypass-playbook.md`（十枪：删参数/改响应/默认凭据/JWT）
- **响应包状态值** → `password-reset-test.md`、`logic-web-cases.md`
- **教育行业** → `edusrc-cases.md` §2.8（EduSRC 越权 42 份按业务场景重组）
- **组件/中间件未授权** → `middleware-unauth-test.md`、`info-leak-test.md` §五
- **逻辑漏洞实战** → `logic-web-cases.md`
- **资产测绘（设备指纹）** → `recon-fingerprint-cdn-wildcard.md`、`edge-asset-hunting.md`
- **案例库总进度** → `ima-corpus-progress.md`
