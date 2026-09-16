# 移动端（App / 小程序 / 公众号）实战案例与打法（ima 案例库深挖）

> **回查原文** → `ima-retrieval-index.md` §四（ima `其他/App` + `其他/小程序` + `其他/EduSRC` 移动端条目；关键词见该表）。

> 来源：ima 知识库 `src` → `src报告/其他/App`（20 条）+ `其他/小程序`（10 条）+ `其他/EduSRC`（185 条中筛出移动端）+ 各漏洞类型目录下 App / 小程序 子格（逻辑漏洞 / 越权 / 信息泄露 / 命令注入 / SQL注入），**去重后共 28 份唯一，实读 28 份，读取失败 0 份**。
> 定位：技能包移动端**从 0 到 1 的打法底座**——抓包链路 → 反编译 → 动态调试 → 登录态与改包 → 客户端校验绕过 → 云资产接管。
> 生成日期：2026-09-14

> ⚠️ **本文件仅作威胁认知与防守复盘，SRC 一律不做：不社工、不钓鱼、不买卖账号、不触碰真实个人隐私数据。**
> 素材原文中的真实账号口令、手机号、身份证号、车牌、姓名、OpenID、邮箱等内容**一律未抄录**，涉及处仅保留手法骨架。逐处红线已在正文以 `⚠️ 红线` 标注。

---

## 一、抓包链路（Android / iOS / PC 微信各版本）

### 1. Android 模拟器直连（首选，最省事）
- 模拟器装 Burp CA 时要进 **设置 → 安全 → 从 SD 卡安装 → 凭据用途选「VPN 和应用」**（选"仅限软件/用户凭据"不够，Android 7+ 起 App 默认不信任用户证书）。
- 模拟器 WLAN → 代理 → 手动，填 **宿主机内网 IP + Burp 监听端口**（`ipconfig` 查网卡，Burp 里同时保留 `127.0.0.1:8080` 与本机内网监听）。

### 2. 模拟器开着代理 APP 就打不开 → Proxifier 转发（关键绕过）
App 检测到「系统代理/Wi-Fi 代理」会拒连或数据异常时：
- Burp 照常监听；**模拟器内代理关掉，改由 Proxifier 转发**；
- Proxifier → 配置文件 → 代理服务器填 Burp 地址端口；代理规则里添加模拟器进程：
  `nox.exe; NoxVMSVC.exe; MultiPlayerManager.exe; NoxVMHandle.exe`
  （必须点"浏览"取进程真实路径，否则抓不到包；规则自上而下匹配，末尾兜底规则务必是 `Direct`，否则流量出不去。）
- 实测对加固类 App、游戏类 App 效果好，抓到的包仍带 `.sign=` 之类签名参数，需转第三节。

### 3. SSL Pinning / 双向认证 → Xposed + JustTrustMe
- 夜神 **Android 5** 版本 + Xposed Installer（Framework v89）+ `JustTrustMe` 模块，可突破证书校验与部分双向验证（高版本 Android 上该组合成功率下降，需换 Frida 脚本或 sslunpinning 方案）。
- 真机方案（Android / iOS 均适用）：装 Burp 证书 + 系统/全局代理；**iOS 必须走完整两步**——下载描述文件安装 → **通用 → 关于本机 → 证书信任设置 → 对 PortSwigger CA 启用完全信任**，否则抓不到 TLS。
- iOS 抓非浏览器 App：WiFi 里配置代理的同时，用 Shadowrocket 建一个 **HTTP 类型节点**（地址=Burp IP，端口=Burp 端口）并选中该节点出站。

### 4. PC 微信 / PC 微信小程序抓包（最稳，推荐优先）
- 微信 3.x 的 XWeb 内核走私有网络栈，**默认不走系统代理**。解法：新建 bat 删除抓包障碍 runtime（**退出微信后运行**）：
  `del /f /s /q %APPDATA%\Tencent\WeChat\XPlugin\Plugins\WMPFRuntime\*.*`
  重新登录微信 → 开系统全局代理（127.0.0.1:8080）→ 小程序流量即进 Burp。
- 或走 Proxifier，进程写 `WeChat.exe; WeChatAppEx.exe; WeChatPlayer.exe; WeChatBrowser.exe; WeChatAppEx*.exe`（`WeChatAppEx.exe` = 小程序宿主，`WeChatBrowser.exe` = 内置浏览器）。任务管理器右键"打开文件所在位置"可确认进程真实路径。

### 5. 小程序流量在 Burp 里的识别特征（省大量时间）
小程序请求头几乎恒定带这组特征，可直接在 Burp 里做过滤器：
```
User-Agent: ... MicroMessenger/7.0.20.1781(0x6700143B) NetType/WIFI
            MiniProgramEnv/Windows  WindowsWechat/WMPF  XWEB/8323
Xweb_xhr: 1
Referer: https://servicewechat.com/<appid>/<版本号>/page-frame.html
```
- `Referer` 里的 **appid** 就是资产抓手（见第二节 `get-domains.py`）；
- 响应头里出现 `Access-Control-Allow-Origin: https://xxx` + `Allow-Credentials: true` 时，**这是白送的另一个域名**——SRC 里经常从这里翻出没做防护的旁站。

### 6. 常见失败与排查顺序
| 现象 | 原因 | 处置 |
|---|---|---|
| 浏览器能抓、App 不能 | 证书装在用户凭据 | 改装到系统凭据 / 用 Xposed+JustTrustMe |
| 握手失败、App 白屏 | SSL Pinning | 脱壳定位校验点 / Frida hook / 改 so |
| 代理一开 App 就报错 | 判代理（环境检测） | 关系统代理 + Proxifier 转发进程 |
| 抓到包但重放无效 | 请求体/头带签名（`.sign=`、`Ql-Auth-Sign`、`Ql-Auth-Timestamp`、`Token`） | 先扒签名算法，别急着 fuzz |
| 小程序无流量 | XWeb 私有栈 + WMPFRuntime | 删 WMPFRuntime + 系统全局代理 |

---

## 二、小程序逆向三件套

### 1. 落盘位置（拿到 wxapkg）
| 平台 | 路径 |
|---|---|
| Windows 微信 | `WeChat Files\Applet\wx********\<版本号>\__APP__.wxapkg`（主包）；同目录还有 `_pages_common_.wxapkg` 等分包 |
| Android | `/data/data/com.tencent.mm/MicroMsg/{用户ID}/appbrand/pkg/` |
| iOS | `/var/mobile/Containers/Data/Application/{UUID}/Library/WechatPrivate/{用户ID}/WeApp/LocalCache/release/{小程序ID}/` |
| 支付宝小程序（iOS） | `.../Documents/NAMAPP_UNZIP/{随机ID}/`（内含 `.tar` + `CERT.json` / `Manifest.xml` / `SIGN.json`） |

- 触发下载技巧：**删掉 `Applet\wx*` 目录后重新打开该小程序**，会重新拉取并落盘。
- wxapkg 结构：头 `0xBE`、尾 `0xED`，中间是「索引段（文件名 / 偏移 / 数据长度）+ 数据段」，可自行写脚本解析。

### 2. 解密 + 反编译
- 解密：`UnpackMiniApp`（一键解密，**必须从原始目录选择** `__APP__.wxapkg`，自动判断是否加密），输出到 `wxpack\`。
- 反编译：`CrackMinApp`（拖进 `wxapkg` 目录即点即用）或 `wxappUnpacker`。
- **主包与分包要分别编译，先主包后分包**：
```bash
node wuWxapkg.js <主包>.wxapkg
node wuWxapkg.js <__WITHOUT_MULTI_PLUGINCODE__>.wxapkg -s=<分包>.wxapkg
```
- 产物形态要注意：**wxml/wxss 已被编译变形**——wxml 进了 `page-frame.html`（`$gwx` 模板函数），wxss 变成 `setCssToHead([...])` 的 JS 数组；业务逻辑集中在 `app-service.js` / `app.js`。支付宝小程序则是 `axml` / `acss` / `appConfig.json`。
- 反编译后源码常有缺失，**能跑起来是少数**，实战中"能用 IDE 全局搜索"就够，不必强求可运行。

### 3. 开 F12 动态调试（WeChatOpenDevTools）
- 原理：hook 微信的偏移地址，把小程序窗口当浏览器挂上 DevTools，需要**按微信版本匹配偏移**（版本一升级偏移就变）。已知可用组合示例：
  | Windows 微信 | 小程序版本 |
  |---|---|
  | 3.9.9.43_x64 | 8555_x64 |
  | 3.9.8.25_x64 | 8531 / 8529 / 8519 / 8501 / 8461 / 8447_x64 |
- 用法（WeChatOpenDevTools-Python，先 `pip3 install -r requirements.txt`）：
  - `python main.py -x` → 注入 `WeChatAppEx.exe`，开小程序 F12
  - `python main.py -c` → 开**微信内置浏览器** F12（公众号 H5、网页授权链路靠这个）
- 限制：小程序**显式禁用调试模式**时该法失效；**有封号风险，用小号**。

### 4. 资产测绘（把"一个小程序"扩成"一套资产"）
- `get-miniapps.py`：关键词（如"XX大学"）→ 批量返回小程序名 + **appid**（需要微信 Cookie）。
- `get-domains.py`：输入 appid → 返回该小程序请求过的**全部业务域名**（需要 `X-WECHAT-UIN` / `X-WECHAT-KEY`）。这一步等价于"零成本拿到后端资产清单"，是移动端信息收集的最高性价比动作。
- 配合微信客户端「搜一搜 → 小程序」按主体名搜索，可把同一单位的公众号 / 服务号 / 小程序一起捞出来（归属证明也顺手拿到了）。

---

## 三、加固与反调试对抗

### 1. 加壳识别与代际
- Android 加壳大致四代：① 整体 dex 加壳隐藏 → ② 防调试 / 防 Dump → ③ 方法体抽离 → ④ VMP 加壳 / so 加壳。
- **核心判断：无论哪一代，运行时必然解密**，所以第 4 代也能从内存里把完整 dex 修出来。
- 厂商清单：免费 360 / 百度 / 腾讯乐固 / 网易盾 / 阿里聚安全；收费 爱加密 / 梆梆 / 娜迦 / 几维 / 顶象。爱加密已到 **双 VMP（dex + so）** 且支持防模拟器、防截屏、防界面劫持、本地数据强加密、防内存 Dump、协议加密。
- **坑**：MT 管理器给出的加固类型会误判（案例里报"娜迦加固"，实际不是），不要被工具结论带偏。

### 2. 脱壳：从"自定义加固"里捡现成 dex
真遇到自研壳时，先看壳的 java/smali 实现：
- 搜索 `copyAssets` / `getCipherValue` 这类**自实现解密函数**；判断依据是文件头 magic——`{100,101,120,10}` 即 ASCII `dex\n`，命中就把头写回；
- 解出的 dex 通常被写到 **`<app dataDir>/.cache/`**（或 `XDATA/YDATA/MDATA` 之类自建目录），App 跑起来后直接去该目录取原生 dex，拉进 IDA 分析，省掉整套 dump 工具。

### 3. native 层定位加密算法
- IDA 打开 so，先搜 `JNI_OnLoad`（**常未混淆**），里面是动态注册表，能直接看到 java 方法名 ↔ native 函数名映射（如 `getNativeSM4EncryptValue` ↔ `_Z10getSMValue...`）。
- 顺藤摸瓜看加密装配（真实银行 APP 案例）：
  - `SM4-ECB` 加密业务密文（ECB 无 IV，省事）；
  - key 是**每次启动随机生成**的 32 字节（`srand(time())` + 从 62 字符表 `byte_18703A` 取随机字符）；
  - 再用 **SM2 公钥加密这个随机 key**（私钥只在服务端，所以服务端能还原）；
  - 再用 `HMAC/SM3` 算签名；
  - 最后 `snprintf(dst, "%s|%s|%s", sm2Key, sm4Cipher, hmac)` 拼成一串 → **这就是请求体里那两个 `|` 的来源**；
  - 请求头 `X-Madp-Encrypted: 1` 是"已加密"标记。

### 4. 「改密钥表而不是改算法」——本批素材最省力的一招
不要去实现 SM2、也不要伪造服务端：
- 把 `.rodata` 里的字符表 `byte_18703A`（key 的候选池）**全部 patch 成 `0x41`（大写 A）**；
- 于是每次启动生成的 key 恒为 **32 个 A**；
- 之后本地直接用「32 个 A」做 SM4 解密/加密，就能任意构造与篡改请求。
- patch 落地：IDA → `Edit → Patch program → Apply patches to input file...` 保存 so → 覆盖 `/data/app/~~xxxxxxxx==/lib/arm/` 下的 so → 重启 App 抓包。

### 5. 其他要点
- so 混淆后函数名会变成 `p5FA8948A02401A1B...` 这类无意义串，还常配合 `libsecmain.so` fork + exec 做"专职监护人"进程与反调试（检查 `TracerPid`、命令行里的 `gdb/gdbserver/android_server`）。
- 部分加固在做反调试时还会**校验代码运行时间**来判断是否被单步调试；字符串全加密（两段数据解密还原），靠字符串猜逻辑的路子被堵死。
- **防御侧提示（写报告/做防守复盘可用）**：自实现字符串加密（`a.c("JAoHL...")` 这类）+ 逻辑打散，虽不能防死逆向，但能显著拉高时间成本。

---

## 四、客户端校验绕过（改包重放 / 本地时间校验 / 前端金额与数量 / 前端抽奖概率 / 返回值篡改）

| 类型 | 手法 | 真实案例 |
|---|---|---|
| **返回值篡改（最高频）** | 改响应包里的身份/状态字段，让客户端认为"我已认证/我已登录" | 小程序 `POST /grad/account/authUserInfo` 返回体里改 `phone` → 直接登入他人账户；`/wx/login.php` 返回体把 `hasLocalAccount` 由 `0` 改 `1` → 跳过"必须绑定校内账号"步骤，未授权进入 |
| **前端假象** | UI 提示"不可查看"，但响应体已经带全量字段 | 小程序点他人名片提示"不可查看校友名片"，同一响应的 JSON 里已含姓名/单位/身份证/手机 → 只看响应体，不看界面 |
| **本地时间校验** | 活动"不在举办时间"、按钮置灰，实际不校验服务端 | 小程序抽奖提示"抽奖不在举办时间"，抓包把 POST 参数（次数）由 `1` 改成 `10` 即多次抽奖 |
| **前端文件类型/大小校验** | 只校验 `Content-Type: image/*` 或后缀名 | 上传接口 `/upload` 前端限"必须为照片"，改包 Content-Type 为 `image/jpeg`、文件名 `x.jsp` → jsp 马落地 `/upload/2021-05-10/` → getshell |
| **前端金额/数量** | 数量、单价、件数等可改字段直接信任 | 与"改包重放"同源，规矩是"凡是前端算的、服务端不复核的都能改" |
| **手势密码绕过（免 root 九式）** | ① 启动页广告点击后返回绕过；② **多重启动**（手势页 → Home → 应用市场"打开" → 二次启动绕过）；③ 错误 5 次上限弹框**不点确认**、强停后重开 → 又给 5 次 → 循环爆破；④ 清理数据只清了手势文件没清登录态；⑤ 启动瞬间狂点内页；⑥ 点通知栏推送直达主页；⑦ 手势页自带设置入口无校验；⑧ 点"忘记手势密码"→ 登录页 → 返回桌面强停 → 重开直接登录态进主页；⑨ iOS 手势页左右滑动滑进主页 | 京东安全小课堂 81 期（剑影） |
| **手势密码绕过（root 四式）** | ① 分析组件后用 ADB 制造拒绝服务让手势 Activity 提前退出 → 跳下一 Activity（主页）；② 改 `shared_prefs` 下 XML **文件权限**（去掉读权限，App 误判为"需设置手势"）或**文件内容**（清空/替换成"关闭状态"的值）；③ 同法改 `databases` 下 SQLite（`code:14` 打不开时把库复制到 sdcard 再改）；④ 改 `files` 目录文件/目录权限。**关键坑**：改文件前必须强停 App，否则写入不生效 | 同上 |

> ⚠️ 红线（第四类"多重启动/手势绕过"）：这类手法需要**拿到他人已解锁手机**才有意义，属物理接触攻击，纯防守复盘用，不做。

**找手势密码存哪儿的通用技巧**：改一次手势密码 → 过 1 分钟再改一次 → 按文件修改时间做差集筛选；只保留参数少、且随开关手势而清空/变化的那个文件。目录时间不动但**目录内文件时间跟着变**，要逐层看。

**开发侧修复项（可直接抄进报告建议）**：合理启动方式（防多重启动）、手势校验加服务端票据、手势密码被修改时**自动清除登录态**。

---

## 五、移动端高价值漏洞场景

### 1. 云存储 AK/SK 与 bucket 接管（小程序侧最大惊喜）
反编译源码里搜 `OSS_CONFIG` / `accessKeyId` / `accessKeySecret` / `bucket`，命中即用 OSS 工具接管：
```javascript
window.OSS_CONFIG = { region:'oss-cn-xxx', accessKeyId:'LTAI...', accessKeySecret:'...', bucket:'xxx' }
```
- 注意：**2022 年 6 月后的小程序开发工具会检测 AppSecret 泄露**，新项目命中率在下降；
- 兜底正则扫源码：`https?://`、`phone`、`token`、`key`、`sdk`，再写脚本遍历接口，常有意外收获。

### 2. 未授权接口 / 垂直&水平越权
- **放大 pageSize 一次拉全量**：`pageNum=1&pageSize=19214` → 单请求拖走 1.9 万条；
- **ID 遍历**：`/app/visitor/getVisitorInfo?viId=1`、`/mp/server/sjtu/user/info` 里改 `friend_id` 用 Intruder 跑 → 批量拉身份证/手机/单位；
- **未授权 ≠ 越权，分开算分**：一个未授权接口若额外存在任意文件下载，**分两个漏洞交**（`GET /fileUrl=/etc/group`）。

### 3. 未授权 Swagger 直接给全套接口
- 小程序访客登录后暴露"专属 API host"，fuzz 目录命中 **`/v2/api-docs`** 未授权 → 本地起 Swagger 挂载 → 拿到全部后端接口与参数定义，后续按图索骥。

### 4. 公众号 / 服务号的隐藏入口（常被忽略）
- 子域被挖干净、无内网 VPN 时，"去公众号 / 服务号里翻一遍"是性价比极高的第二战场；
- 关注后拿到的 H5 登录页目录 + **F12 看 JS** → 从 JS 里拼出隐藏接口 → 未授权接口 → 再翻下一个 JS 找到 `/upload` 上传接口 → getshell；
- 服务号里常见"通用查询接口"（`/api/apiquery`），参数如 `TableCatalog` / `TableName` / `UniqueId` / `ExtraExpression` / `OrderBy` / `OrderDir` **全是查表拼接**，是 SQL 注入的富矿（见案例索引）。

### 5. 登录态与 token 缺陷
- **token 刷新时序坑**：某政务系统登录后 token 会刷新，下一次登录必须用上一次的 token，否则一直"口令无效"——排查登录失败时不要轻易放弃；
- **网关不校验完整身份**：小程序只要 `Bearer` token + 自研头（`QI-Client-Id` / `QI-Auth-Sign` / `QI-Auth-Timestamp` / `Ql-Auth-Nonce`），一旦某个头不校验就是绕过点。

### 6. 客户端组件导出为客户端 RCE
- **CSV 注入 → 客户端 RCE**：任何"用户可控字段 → 导出 CSV/Excel → 客户端打开"的链路都成立。PC 微信账单导出即一例（可控参数是**微信用户名**）。
  > ⚠️ 红线：该攻击需先把昵称改成恶意代码、再诱导受害者收款并打开账单，属**社工诱导**，仅作认知，禁止实操。
- 同理适用于：客户端阅读器解析恶意文件（本批素材另有 NeatReader EPUB/TXT 解析命令执行，见 `未精读清单`）、各类"导入/导出"功能。

### 7. 第三方与供应链
- 小程序生态第三方面：一键生成平台、后台管理平台、管理插件、端插件/端 SDK、开发账号授权；
- 第三方建站模板（如微擎 / 微赞模块）可用空间测绘（`title="小程序后台"`）找 1day；
- 客户端侧供应链：**GitHub 泄露**——`site:xxx.com username` 搜前端仓库，命中 SMTP `MAIL_CONFIG` 的 username/password 明文，即"从 App 摸到 Web 后台邮箱账号"。
  > ⚠️ 红线：命中的口令与个人信息一律不记录、不外传，仅作为"存在泄露"的证明。

### 8. 设备指纹 / 风控绕过
- 设备指纹用于**设备绑定、异地登录二次校验、防撞库刷单**，是账号安全与风控核心；
- 已知弱点：Android 山寨机共用 IMEI/MAC、**模拟器设备信息可任意伪造**、指纹算法一旦被掌握可 **hook 伪造指纹**；指纹"只识设备、不识环境、不识人"。
- 攻击面：多账号养号、风控绕过、设备绑定绕过。

### 9. App 合规检测（加分维度，非漏洞）
`app违法违规检查步骤.xlsx` 给出六类 20+ 判定项，可直接当作"App 合规检测"SOP：未公开收集规则 / 未明示目的方式范围 / 未经同意收集 / 违反必要原则 / 未经同意向第三方提供 / 未提供删除更正注销与投诉举报渠道。关键判点：`targetSdkVersion > 23`（否则动态权限不合规）、首次运行是否有弹窗、隐私政策进入是否需 >4 次点击、是否默认勾选同意、第三方 SDK 是否逐一列举、注销功能是否有障碍。

---

## 六、案例索引

| # | 报告名 | 平台 | 目标/类型 | 核心手法 | 结果/定级 |
|---|---|---|---|---|---|
| 1 | 微信小程序渗透测试指北（附案例） | 小程序 | 众测 ×3：信息泄露 / 弱口令 / 未授权 | Proxifier 抓包 → UnpackMiniApp+CrackMinApp 反编译 → 源码搜 `OSS_CONFIG` 拿 AK/SK 接管 OSS；域名拎出来开浏览器撞管理后台（验证码复用+找回密码用户枚举）；未授权站从 `Access-Control-Allow-Origin` 翻出第二个域名，405 为地域限制，换省出口可通 | 多漏洞打包 |
| 2 | 小程序抓包流程 | 小程序 | 方法论 | Burp 监听 + Proxifier 代理规则走 `WeChatAppEx.exe; WeChatBrowser.exe` | 方法论 |
| 3 | pc微信小程序抓包 | 小程序 | 方法论 | `del /f /s /q ...\WMPFRuntime\*.*` 后走系统全局代理 | 方法论 |
| 4 | 小程序反编译 | 小程序 | 方法论 | Applet 目录取 `__APP__.wxapkg`（主包+分包）→ UnpackMiniApp → wxappUnpacker 先主包后分包 `-s=`；插件包 `plugin-private:` | 方法论 |
| 5 | 安恒信息：红队视角下…小程序 | 小程序 | 方法论 | appid→域名（`get-miniapps.py`/`get-domains.py`）；wxapkg 结构；**CMRF 跨小程序请求伪造**（分享 pagepath 传参 + 已登录身份，点一下改密码）⚠️红线：诱导点击/社工；`getUserInfo` 的 `signature = sha1(rawData + "$" + session_key)` 服务端不校验即可伪造；第三方一键生成平台/微擎模块面 | 方法论 |
| 6 | 【HVV回顾】小程序打点案例分享 | 小程序 | 某政务 / 某县医院 / 某中学访客 | 弱口令进后台（token 刷新时序坑）；前台接口 debug 未关爆库账密；后台 `category/selectpage` 延时注入；Fastadmin 在线命令插件 `/command?ref=addtabs` 一键生成 API 文档写冰蝎马 → 提权拿 root；公众号挂号处患者 ID 注入（MSSQL，sqlmap 需指定 MSSQL 才出结果，DBA 权限但 `xp_cmdshell` 被防护）；`/app/visitor/getIntervieweeList` 未授权 + `getVisitorInfo?viId=1` 遍历 | 严重→高危（未授权/注入/getshell） |
| 7 | 新浪小程序抽奖——前端校验（打码） | 小程序 | 抽奖活动 | "不在举办时间"置灰 → 抓包把 POST 次数参数 `1` 改 `10` | 逻辑漏洞 |
| 8 | 同济大学1弹 | 小程序 | 校友服务平台未授权 | `POST /grad/account/authUserInfo` 拦截改返回体 `phone` → 登入他人账户 | 未授权（中高危） |
| 9 | 新疆交通职业技术学院（docx + pdf 同案） | 公众号/小程序 | 口袋交院（第三方 handschool.cn） | 留言/输入框提交 `<script>alert('xss')</script>` → 重新进入"我的大学"弹窗，存储型 XSS | 中危 |
| 10 | 浙江大学 | 小程序 | 科创中心访客预约系统 | 访客登录暴露专属 API host → fuzz 到 `/v2/api-docs` 未授权 Swagger → `pageSize=19214` 一请求拉全量 | 严重（⚠️红线：约 1.9 万条真实身份证/车牌/手机，未记录） |
| 11 | 山东理工大学 | 公众号 | "温暖理工"人事系统 | 子域挖空后转公众号 → F12 翻 JS 拼出 `POST /commonServlet` 的 `fromflag=querySection` / `queryWorkUserBySectionId` → **未授权拿科室电话与人员工号**（爆破身份证后六位失败）→ 再翻 `appointment.js` 找到 `/upload` → 前端只校验 Content-Type，改包传 jsp 马落 `/upload/日期/` → 菜刀 getshell | 高危/getshell |
| 12 | 上海交大小程序——逻辑漏洞（打码） | 小程序 | 校园健康打卡小程序 | 抓 `GET /wx/login.php?o=...` 返回包，`hasLocalAccount` 由 `0` 改 `1` → 绕过"必须绑定 jAccount"| 未授权 |
| 13 | 上海交大——交大知行安泰小程序——越权（不打码） | 小程序 | 校友小程序 | UI 提示"不可查看校友名片"，但 `POST /mp/server/sjtu/user/info` 响应已含全量字段；对 `friend_id` 用 Intruder 遍历 → 水平越权批量拉校友信息（⚠️红线：真实身份证/手机，未记录） | 中危 |
| 14 | 某酒店app信息泄露 | App | 酒店 App（SOAP 接口） | Burp 抓到请求里泄露**真实 IP** → 直连 IP 发现**目录遍历**（服务器配置错误） | 信息泄露 |
| 15 | (微信app rce | App（PC 客户端） | PC 微信 | 账单导出 CSV 含**可控的微信用户名** → CSV 注入 → Excel 打开触发命令执行 ⚠️红线：需社工诱导，仅作认知 | 客户端 RCE |
| 16 | 常熟理工小程序sql注入 | 公众号/服务号 | 理工微门户 `/api/apiquery` | 查表参数全拼接，**5 处注入**：`ExtraExpression` 直接拼 where（报错注入）；`OrderDir=asc,1/(convert(int,user))`、`1/db_name()`、`1/@@version` 报错回显；`OrderBy=dictionary_sort,1-user` 逗号闭合；`ExtraExpression=... and user like 'dbo%'` 读库名 | 高危 SQL 注入（MSSQL） |
| 17 | 渗透测试 记一次安卓渗透流量被加密的解决思路 | App | 银行 App（加壳 + 流量加密） | MT 管理器加固类型误判；反编译定位 `copyAssets`，magic `dex\n` → dataDir`.cache` 捡原生 dex；IDA 搜未混淆的 `JNI_OnLoad` 找动态注册表 → 定位 `getSMValue`；装配为 **SM4-ECB(数据) + SM2(key) + HMAC/SM3 + `%s\|%s\|%s` 拼接**；**改密钥字符表 `byte_18703A` 全为 0x41，key 恒为 32 个 A**；Patch input file 后替换 `/data/app/~~xxx==/lib/arm/` 下 so，重启抓包 | 加密对抗成功 |
| 18 | APP抓包心得 | App | 方法论（四法） | ① 模拟器+Burp 证书（凭据用途「VPN和应用」）；② 模拟器判代理 → Proxifier 转 `nox.exe; NoxVMSVC.exe; MultiPlayerManager.exe; NoxVMHandle.exe` 并关模拟器代理；③ 夜神 Android5 + Xposed + JustTrustMe 破双向认证；④ 真机 Android/iOS + 证书完全信任；抓到包含 `.sign=` 签名参数 | 方法论 |
| 19 | burp ios直接抓包 | App（iOS） | 方法论 | 描述文件安装 → 通用-关于本机-证书信任设置-完全信任 PortSwigger CA → WiFi 配代理（与 Burp 一致）→ Shadowrocket 建 HTTP 节点挂代理 | 方法论 |
| 20 | 82-移动安全之APP加固 | App | 加固理论 | 加壳四代（dex 隐藏→防调试防 Dump→方法体抽离→VMP/so 加壳）；运行时必然解密 → 内存可修完整 dex；iOS 侧靠 Xcode 插件混淆/扁平化；加固两类（客户端本体 + 业务安全）；措施：加壳/文件校验/封包验签/时间戳/SSL 校验/敏感数据不落地/手势密码全局 FLAG/设备绑定多因子；厂商清单 | 理论 |
| 21 | 28-APP安全加固技术的讨论 | App | 加固原理 | 加固 = 二进制中植入优先取控制权的代码（dex 加密存 apk，运行时壳先跑再解出 dex/so）；实现几乎都走 `DexClassLoader` 动态加载 → 必配反调试（混淆、文件特征检查、**代码运行时间检测**）；案例拆解阿里 `libmobisecx/y/z.so`（字符串全加密、反射调用、检查 `TracerPid`/`gdb`/`android_server`）；so 函数名混淆成 `p5FA8948...`；`libsecmain.so` fork+exec 做监护人；自实现字符串加密 `a.c("...")` 提高逆向成本 | 理论 |
| 22 | 81-APP手势密码安全 | App | 手势密码绕过 | 免 root 九式 + root 四式（见第四节表）；定位手法：改密码→等 1 分钟→再改，按修改时间差集筛选 `shared_prefs`/`databases`/`files`；坑：改文件前必须强停 App；修复：合理启动方式 + 服务端校验 + 改手势清登录态 | 高危（数量级大） |
| 23 | 64-移动端设备指纹 | App | 设备指纹/风控 | 设备指纹 = 设备绑定识别信息，用于异地登录二次校验、反撞库刷单、精准营销；弱点：山寨机共用 IMEI/MAC、模拟器可伪造、掌握算法可 hook 伪造、只识设备不识环境不识人 | 理论/风险面 |
| 24 | 27-聊聊app手工安全检测 | App | 检测流程 | Android：看壳 → 脱壳 → 反编译/反汇编（apktool + dex2jar + jd-gui）→ 特征定位 → 结合上下文 → 必要时动态调试；iOS：无法反编译，用 IDA + （越狱后）idb/class-dump，动态 hook 关注加解密/HTTP/文件系统/剪切板/日志/keychain/UIWebView；工具：drozer / androguard / jadx / jeb / IDA / dexhunter / 盘古 janus；强调**自动化只给风险点，必须手工确认** | 方法论 |
| 25 | app违法违规检查步骤 | App | 合规检测 | 六类 20+ 判定项 SOP（见第五节第 9 条） | 合规 |
| 26 | 通过github找到某知名app数据库账号密码 | App（供应链） | GitHub 信息泄露 | `site:xxx.com username` 搜到前端仓库 `shareDP-web`，`MAIL_CONFIG` 里 SMTP username/password 明文 ⚠️红线：口令未记录 | 信息泄露 |
| 27 | 补天-漏洞…IoT APP漏洞_移动… | App（平台归类错位） | 某普法志愿者后台 | 弱口令 `admin/admin123` 登入后台 → 导出 2.2 万条志愿者真实信息 ⚠️红线：真实姓名/手机/身份证，未记录；虽挂在"APP漏洞_移动"标签下，实为 Web 后台 | 高危（弱口令） |

> 实读份数说明：第 9 条 docx 与 pdf 为**同案两种格式**（文件大小不同，按去重规则各算一份、均已实读）；其余各条均已逐份实读，**无读取失败**。

---

## 七、按场景的排查 Checklist（拿到 App / 小程序后按什么顺序做）

**A. 小程序（0 → 出洞）**
1. 抓包打通：PC 微信删 WMPFRuntime + 系统代理；或 Proxifier + `WeChatAppEx.exe`
2. Burp 过滤小程序流量（`Xweb_xhr: 1` / `Referer servicewechat.com/<appid>`），**记下 appid 与所有业务域名**
3. `get-domains.py` 用 appid 扩域名 → 域名直接浏览器打开，撞弱口令 / 管理后台
4. 取包：`WeChat Files\Applet\wx*` → UnpackMiniApp → CrackMinApp / wxappUnpacker（主包 + 分包 + 插件包）
5. 源码搜：`OSS_CONFIG` / `accessKeyId` / `accessKeySecret` / `token` / `phone` / `key` / `https?://` → 云资产接管
6. 源码搜接口路径 → 提取所有 API 清单 → 逐条试未授权（去掉 Cookie/Token 重放）
7. 试 `/v2/api-docs`、`/swagger-ui.html`、`/doc.html`、`/actuator` → 未授权 Swagger
8. 对分页接口**放大 pageSize**，对 ID 类参数做 Intruder 遍历
9. 抓"我的 / 个人信息 / 名片 / 看过谁"等页 → 对比**响应体与 UI**，找前端假象与水平越权
10. 改返回体字段（`hasLocalAccount` / `phone` / `role` / `vip` / `isAuth`）测登录态绕过
11. 活动类功能：改前端校验参数（时间、次数、金额、数量）
12. 上传点：改 Content-Type / 后缀（前端只校验 image 时才有效）
13. 需要动态调试时：WeChatOpenDevTools `-x` 开 F12（小号！）
14. 挖空后转公众号 / 服务号：关注 → H5 → F12 翻 JS → 隐藏接口 → 未授权 → 上传 → getshell

**B. App（0 → 出洞）**
1. 抓包打通：模拟器 + Burp 证书（VPN 和应用）→ 不通就 Proxifier 转发进程（关模拟器代理）
2. Pinning / 双向认证：夜神 Android5 + Xposed + JustTrustMe；或 Frida 脚本
3. 真机：Android 装系统凭据；iOS 描述文件 + 完全信任 + Shadowrocket HTTP 节点
4. 抓包看请求体/头：有 `.sign=`、`Ql-Auth-Sign`、`X-AuthToken-Local`、`X-Madp-Encrypted` 就先解决签名，别 fuzz
5. 反编译：apktool + dex2jar + jd-gui / jadx；先看是否加壳，加壳再脱
6. 脱壳：自定义壳逆 `copyAssets` 取 `.cache` 下 dex；商用壳用通用脱壳/Frida dump
7. native：IDA 搜 `JNI_OnLoad` → 动态注册表 → 加密函数 → 判断算法（SM4/AES + SM2/RSA + HMAC）
8. **改密钥表而非改算法**：patch key 字符表为固定值 → 固定 key 加解密 → 可任意改包
9. 客户端逻辑：手势密码绕过、本地 `shared_prefs`/`databases`/`files` 明文与权限问题、备份文件
10. WebView / H5 混合页：按 Web 手法全测一遍
11. 内嵌引用第三方 SDK / 域名：拉出来一起测（App 常在后端暴露未防护接口）
12. 泄露面：抓包找真实 IP → 直连测目录遍历 / 未授权；GitHub `site:主域 username` 搜前端仓库

---

## 八、未精读清单（标题级归类）

以下为去重后**未纳入精读**或**非移动端**的条目，按标题归档，供后续按需回捞：

| 类别 | 条目 | 说明 |
|---|---|---|
| 非移动（平台归类错位） | 补天-漏洞…IoT APP漏洞_移动…（含 `_(1)` 等重复副本） | 实为 Web 后台弱口令（见案例 27），已读，标签归属不准 |
| 移动端理论（App 目录内） | 各项与 `82/81/64/28/27` 期的重复副本（`_(1)`~`_(4)`、`_202105062140xx` 后缀） | 内容与已精读稿完全同源，仅文件名重复 |
| App 目录内 Web/通用条目 | `app违法违规检查步骤.xlsx` 的同类合规表，以及 App 目录中被误归入的 Web 类报告 | 与本次移动端主线弱相关 |
| EduSRC 内移动端候选（弱相关） | 同济大学2弹、同济大学(1)、同济大学 2弹、同济大学-存在万能验证码、同济大学外网 | `同济大学外网` 为 API 改包（偏 Web）；万能验证码属认证逻辑；均与"移动端专属打法"重叠度低，未精读 |
| 各类型子格（无移动端子目录） | SSRF / XSS / XXE / 弱口令 / 文件上传 / 文件包含 / CSRF | 经枚举，这些类型目录下**只有 EduSRC 与 Web 两个子格，无 App/小程序 子格** |
| 客户端解析类（未纳入） | 北京高知图新 NeatReader 命令执行（EPUB/TXT 解析 RCE） | 属"客户端文件解析"面，与第五节第 6 条同源，建议后续单列 |
| 供应链/凭据类 | 通过 github 找到某知名 app 数据库账号密码（已读，短） | 已并入第五、六节 |

---

## 九、素材缺口（技能包移动端还缺什么）

1. **iOS 逆向链路整体缺失**：本批只有 iOS 抓包（描述文件 + 信任 + 节点），没有 `class-dump`/`frida-ios-dump`/`Keychain` 导出、越狱环境搭建、`Mach-O` 分析、Swift 符号恢复。
2. **Frida / Objection 实操缺失**：素材里 SSL Pinning 靠 Xposed + JustTrustMe 这种"上古方案"，没有 Frida 脚本（hook 加解密、hook 设备指纹、hook 越权参数）与 `objection` 一键绕过。
3. **脱壳工具链缺失**：只有"自定义壳逆 copyAssets 捡 dex"，缺 FRIDA-DEXDump / frida-unpack / Youpk / BlackDex / 虚拟化壳（VMP）从内存重建 dex 的完整流程与常见坑。
4. **小程序动态调试版本适配缺失**：只有一张偏移表，缺"版本升级后如何自行定位偏移"的方法与失败特征。
5. **路由/框架层对抗缺失**：缺 `ContentProvider`/`Activity` 导出、`Intent` 重定向、`WebView` `addJavascriptInterface`、DeepLink 劫持、`PendingIntent` 等"组件级"漏洞的检测方法。
6. **风控/反欺诈对抗缺失**：设备指纹只讲到"可 hook 伪造"，缺 hook 点定位、Xposed 模块写法、风控策略探测（同设备多账号、代理 IP 池）。
7. **App 自动化扫描缺失**：MobSF / 移动端 DAST 的落地流程与结果如何转化为可交的漏洞。
8. **服务端 API 侧配套缺失**：移动端拿到 API 后如何与 Web 侧方法论（未授权/越权/SQL 注入）打通，缺"移动端 API 专项测试清单"（签名、重放、时间戳、幂等、越权矩阵）。
9. **公众号 / 服务号链路偏薄**：素材仅两条案例，缺"公众号 → H5 → JSSDK → 网页授权（snsapi_base/userinfo）→ 用户信息接口"的完整攻击面梳理。
10. **合规检测仍需模板化**：`app违法违规检查步骤` 是纯判定项表，缺可直接交付的检测报告模板与取证截图要求（且**取证不得留存真实个人数据**）。
