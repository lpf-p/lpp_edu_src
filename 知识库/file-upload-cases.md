# 文件上传实战案例（ima 案例库深挖）

> **回查原文** → `ima-retrieval-index.md` §三（ima `src报告/文件上传/` folder_id + 关键词 + 报告名直搜）。

> 来源：ima 知识库 `src` → `src报告/文件上传/`（40 条 → 去重后 32 份唯一，实读 18 份，读取失败 3 份）
> 定位：**真实上传点、真实绕过 payload、真实定级**；方法论与绕过清单见 `file-upload-test.md`，本文件补充真实案例与厂商尺度。
> 生成日期：2026-09-14

> ⚠️ **红线声明**：本报告仅作威胁认知与防守复盘，**SRC 一律不做**社工 / 钓鱼 / 免杀 / 买卖账号 / 真实个人隐私数据。SRC 上传验证止于无害证明（如传 `1.jsp` 输出固定字符串），不落地后门、不接管服务器。来源报告中出现的"免杀马 / 落地后门"均属授权演练复盘，实战 SRC 不得复现。

---

## 一、绕过手法全景（按"防护层级"重组）

### 1. 前端 JS 校验
- **原理**：仅 `<script>` 内 `checkFile()` 校验后缀（如 `allow_ext='jpg|png|gif'`），未过服务端。
- **payload**：禁用 JS 或直接 Burp 改包，`filename="shell.php"` 重放即可。
- **代表案例**：`php代码审计之文件上传`、`22-谈谈上传漏洞`、`96-web漏洞挖掘之上传漏洞`。

### 2. MIME 与 Content-Type
- **原理**：后端用 `$_FILES['type']` 或请求头 `Content-Type` 判断类型，值可控。
- **payload**：`Content-Type: application/octet-stream` 配 `filename="x.jsp"`；好视通 / 华智慧园区均靠此绕过。
- **代表案例**：`好视通云会议 upLoad2.jsp`、`华智慧园区文件上传RCE`、`UEditor .net`（远程 `content-type` 可控）。

### 3. 后缀黑名单
- **原理**：禁止 `php/jsp/asp` 但放过变体或系统特性后缀。
- **payload**：
  - Windows ADS：`phpinfo.php::$data` 绕过黑名单且被解析为 php（艰难打点 bypass）。
  - 黑名单漏网：`phps`、`.phtml`、`.jspx`、`.ashx`、`.asmx`、`.soap`。
  - 大小写 / 空格 / 点 / `0x00` 截断（老版）。
- **代表案例**：`实战攻防-艰难打点之bypass绕过文件上传`、`某徽工业大学`（`.jsp` 在黑名单内却放行）、`华南农业大学`（`.jspx`）。

### 4. 后缀白名单 + 可控文件名
- **原理**：扩展名限定但**保存文件名由其他参数决定**，可注入后缀或跨目录。
- **payload**：上传 `s2s.jsp` → 返回 `xxx.jpg`；改 `str` 参数为 `xxx.jsp` 即落地；`fileName=../../test.jsp` 跨目录写入（分享几个实战）。
- **代表案例**：`分享几个实战中遇到的文件上传案例`（EDU 后台可控文件名 + 跨目录）。

### 5. 内容检测与 WAF
- **原理**：校验文件头（GIF89a/PNG）、关键字（Runtime / FileOutputStream）、云 WAF 正则。
- **payload**：
  - 图片马：`copy /b small.jpg + phpinfo.php/a phinfo.jpg`，正文嵌 php。
  - **WAF 绕过**：
    - boundary 后加 **TAB** 打断云 WAF 解析（某 OA `MobileFileUpload.ashx`）。
    - 文件名 `jsp` 后加**换行符**、`FileOutputStream` 后加换行符绕过关键字检测（长安大学 ⚠️ 红线：含 WAF 绕过+落地后门，SRC 仅止于无害上传证明）。
    - `filename` 不闭合双写：`filename="2222."` + 下一行 `filename="2222.php"`（长亭雷池绕过）。
    - `.net` 用 `a?s?m?x` / `.soap` 后缀畸变绕过安全狗正则。
- **代表案例**：`某oa文件上传绕过`、`长安大学`、`分享几个实战`、`实战攻防-艰难打点bypass`。

### 6. 二次渲染 / 解析配置
- **原理**：图片二次渲染会清除图片马；可用 `.htaccess` / `.user.ini` 改写解析、NTFS ADS 残留。
- **payload**：`.user.ini: auto_prepend_file=1.jpg` 让同目录 php 包含图片马。
- **代表案例**：`22-谈谈上传漏洞`、`96-web漏洞挖掘之上传漏洞`（理论为主，未见实案例）。

### 7. 解析配置与别名映射（中间件 / 编辑器）
- **IIS**：`*.asp;.jpg`、`*.asa`、`web.config` 允许执行脚本（安全狗场景）。
- **Apache**：`.phtml`/`.php.x` 仍按 php 解析；`AddHandler` 解析漏洞。
- **Nginx**：`*.php/x.jpg` 解析漏洞。
- **UEditor .net**：`/ueditor/net/controller.ashx?action=catchimage` 的 `source[]` 不校验后缀，只认远程 `content-type` → 自架 apache 返回 `image/jpeg` for `.asp` 即可落地。
- **Weblogic**：`/ws_utc/config.do` 改 Work Home Dir 上传 jsp（见下）。

### 8. 上传路径与文件名可控（跨目录 / 覆盖）
- **原理**：`key` / `fileName` / `str` 等参数决定最终路径，未做目录穿越过滤。
- **payload**：
  - `key=../../mdpic/pic/.../xxx.jpg` 覆盖系统图片 / logo（跨目录文件上传危害提高）。
  - COS `key=1.html` 把带 `<script>` 的 html 覆盖上传并解析 XSS（易车）。
  - `fileName=../../test.jsp` 跨目录写 shell（分享几个实战）。
- **代表案例**：`跨目录文件上传危害提高`、`易车文件上传覆盖漏洞`、`分享几个实战`。

---

## 二、组件与编辑器上传点速查表

| 组件/系统 | 上传路径与参数 | 可用手法 | payload / 文件名 | 来源案例 |
|---|---|---|---|---|
| 好视通云会议 | `POST /fm/systemConfig/upLoad2.jsp`，参数 `file` | 未授权任意上传 | `filename="dudesuite.jsp"`，落点 `/fm/upload/dudesuite.jsp` | 好视通 POC |
| 华智慧园区 | `POST /emap/devicePoint_addImgIco?hasSubsystem=true`，参数 `upload` | 任意上传 RCE | `filename="dude.jsp"`，响应 200 | 华智慧园区 POC |
| UEditor .net | `/ueditor/net/controller.ashx?action=catchimage`，`source[]` | catchimage 不校验后缀 | 远程 `.asp` + apache `mime.types` 返回 `image/jpeg` | UEditor .net getshell |
| 某 OA（.net） | `MobileFileUpload.ashx`（FileUpload.ashx 有云 WAF） | boundary 后加 TAB 绕过 WAF | `Content-Type: ...; boundary=<TAB>...` 传 `.aspx` | 某oa文件上传绕过 |
| Weblogic | `/ws_utc/config.do` Work Home Dir | 相对路径 `servers/AdminServer/tmp/_WL_internal/.../war/css` | 上传 jsp，结合 IIOP / XXE 取绝对路径（CVE-2018-2894） | Weblogic 不知绝对路径 |
| 金航网上阅卷系统 | `upload.jsp` | 直接传 jsp 木马 | `shell.jsp` → `ROOT/upload/shell.jsp` | 四川省教育厅 |
| 校师通校本资源平台 | 个人中心"上传资源/头像" | 弱口令 admin/admin 后传 php | `shell.php` → `uploads/myFileUpload/.../shell.php` | 云南省教育厅 |
| 某工业大学平台 | `POST /xupload/uploadUserImg?fileType=1` | 黑名单含 jsp 却放行 | 返回 `userimg/...jsp` | 某徽工业大学 |
| 师范人人通空间 | 更换头像（`file`，无限制） | 任意 aspx | 哥斯拉 `123.aspx` | 某徽工业大学 |
| 长安大学招标系统 | "公司信息修改"扫描件 | jsp + 换行符绕过 WAF ⚠️ | `xxx.jsp`（`FileOutputStream` 后换行） | 长安大学 |
| 华南农业大学监督系统 | 用户管理→用户信息 头像 | `.jspx` 免杀过渡写马 ⚠️ | 读 `f` 参数写文件的 jspx | 华南农业大学 |
| 明道/文件助手类 | `key` 参数控制对象名 | 跨目录覆盖 | `key=../../mdpic/.../x.jpg` | 跨目录文件上传危害提高 |
| 易车摩卡小程序 | COS `key` 路径（反馈上传） | 改名 `1.html` 覆盖+解析 XSS | `<script>alert(1)</script>` 的 `1.html` | 易车文件上传覆盖 |

---

## 三、上传后利用链

1. **拿路径 → 解析 → getshell**
   - 好视通 / 华智慧园区：返回即给出 webshell URL，蚁剑直连。
   - 金航阅卷：`{"success":true,...,"C:\...\ROOT\upload/shell.jsp"}` → 蚁剑连 `shell.jsp`。
2. **跨目录写 shell / 覆盖配置**
   - `分享几个实战`：EDU 后台 `fileName=../../test.jsp` 写 web 根目录 → getshell（Win Server 2012，tomcat）。
   - `跨目录文件上传危害提高`：覆盖系统 logo / 图片，可改界面、投毒。
3. **中间件落地（Weblogic）**
   - 改 Work Home Dir 相对路径上传 jsp，再结合 IIOP/报错/XXE 取绝对路径；响应返回时间戳拼接 URL。
4. **SOAP/asmx 曲线救国（.net）**
   - 传 `.soap` → 其 WebService 落 `p.asmx` 到根目录 → SOAP UI / AWVS 发 `shellInject` 执行命令（绕安全狗黑名单）。
5. **内容侧后续**
   - 易车：上传 html 覆盖 → 存储型 XSS（钓 cookie / 水坑）。
   - 某徽工业大学：上传 getshell 后进入后台，发现 SQL 注入（MSSQL error-based）→ 拖库。
6. **提权 / 内网**
   - `信息收集到getshell`：base64 图片上传落 php → 读数据库配置 → fofa 同指纹扩刷 3 个 shell。
   - `艰难打点bypass`：Windows Defender 进程链查杀 → 用大马 / 免杀马 ⚠️ 上线 CS（SRC 仅止于证明，不接管）。

---

## 四、按功能点的排查 Checklist

- [ ] **头像 / 个人资料上传**：改 `filename` 后缀、改 `Content-Type`、图片马；关注 `.jspx/.ashx/.aspx/.soap` 变体。
- [ ] **附件 / 反馈 / 资源上传**：是否有 COS `key` 或 `fileName` 可控 → 跨目录 / 改名 html 打 XSS / 覆盖。
- [ ] **富文本编辑器**：UEditor / KindEditor / ewebeditor / fckeditor / 帝国 / 通达 → 找 `catchimage`、上传接口、未授权 ashx/aspx。
- [ ] **后台任意上传页**：遍历 `*.aspx/*.ashx`；某 OA 类先找未授权上传再找 WAF 绕过（boundary 加 TAB）。
- [ ] **文件名 / 路径参数**：`str`/`key`/`fileName`/`saveUrl` 是否决定后缀或路径 → 注入 `../../` 与 `.jsp`。
- [ ] **base64 内联图片**：`data:image/php;base64,...` 前缀决定扩展名（自写 `validateImg` 不归一化）。
- [ ] **WAF / 云防护**：双写 `filename` 不闭合、boundary 插 TAB、换行符插后缀、后缀畸变 `a?s?m?x`。
- [ ] **中间件特性**：IIS `*.asp;.jpg`、Apache `.phtml`、Nginx `x.php/y.jpg`、Weblogic `ws_utc`、Tomcat 任意写。
- [ ] **教育 / 政务系统**：弱口令进后台（admin/admin 常见）→ 上传点；学工 / 教务 / 阅卷 / 资源平台重点。

---

## 五、案例索引

| # | 报告名 | 平台 | 目标/系统 | 上传点 | 绕过手法 | 结果/定级 |
|---|---|---|---|---|---|---|
| 1 | 好视通云会议 upLoad2.jsp 任意文件上传 | Web | 好视通云会议 | `/fm/systemConfig/upLoad2.jsp` | 未授权 + octet-stream 传 jsp | 任意文件上传/RCE |
| 2 | 华智慧园区文件上传 RCE | Web | 华智慧园区 | `/emap/devicePoint_addImgIco` | 参数 `upload` 任意 jsp | RCE |
| 3 | UEditor .net getshell | Web | UEditor .net | `controller.ashx?action=catchimage` | `source[]` 不校验后缀 | getshell |
| 4 | 某oa文件上传绕过 | Web | 某 OA(.net) | `MobileFileUpload.ashx` | boundary 后加 TAB 绕云 WAF | getshell（高危） |
| 5 | Weblogic 不知绝对路径拿 shell | Web | Weblogic | `/ws_utc/config.do` | 相对路径 + IIOP/XXE 取路径 | CVE-2018-2894 利用 |
| 6 | 实战攻防-艰难打点bypass | Web | apache+php Win | 后台签名上传 | 图片马 + `php::$data` + 免杀 ⚠️ | getshell |
| 7 | 分享几个实战文件上传案例 | Web | 多系统 | 编辑器/后台/反馈 | catchimage 不出网、a?s?m?x、可控文件名跨目录、雷池双写 | 多手法合集 |
| 8 | 跨目录文件上传危害提高 | Web | 明道/文件助手 | `key` 参数 | `../../` 跨目录覆盖 | 覆盖 logo/图片 |
| 9 | 易车文件上传覆盖漏洞 | Web | 易车摩卡小程序 | COS `key` 路径 | 改名 `1.html` 覆盖+解析 | 高危（XSS） |
| 10 | 22-谈谈上传漏洞 | Web | 通用 | 通用 | JS 校验/0x00/解析漏洞 | 方法论 |
| 11 | 96-web漏洞挖掘之上传漏洞 | Web | 通用 | 通用 | MIME/内容/后缀/系统特性 | 方法论 |
| 12 | php代码审计之文件上传 | Web | 通用 | 通用 | 前端 JS 绕过 + 审计思路 | 方法论 |
| 13 | 信息收集到getshell（同CMS） | Web | thinkphp 站点 | `/index/jpgsave` base64 | `data:image/php;base64` 决定后缀 | getshell + 扩刷 |
| 14 | 四川省教育厅 任意文件上传通杀 | Web(教育) | 金航网上阅卷 | `upload.jsp` | 直接传 jsp | 严重 |
| 15 | 云南省教育厅 任意文件上传通杀 | Web(教育) | 校师通资源平台 | 上传资源/头像 | 弱口令 admin + 传 php | 高危 |
| 16 | 长安大学 文件上传+get shell | EduSRC | 招标报名系统 | 公司信息修改扫描件 | jsp+换行符绕 WAF ⚠️ | 高危 |
| 17 | 华南农业大学 文件上传+get shell | EduSRC | 廉洁监督系统 | 用户头像 | `.jspx` 免杀过渡写马 ⚠️ | 高危(6) |
| 18 | 某徽工业大学+能源学院+师范 | EduSRC | 工业大学/师范平台 | 头像/更换头像 | 黑名单放行 jsp / 无限制 aspx | getshell + SQLi |

> 读取失败（如实标注，未臆造）：`文件上传篡改图标.docx`（220030）、`四川省双流中学getshell.doc`（220030）、`同济大学-getshell.doc`（空返回）。

---

## 六、未精读清单（标题级归类）

> 共 11 份唯一稿未精读（去重后 32 − 实读 18 − 失败 3 = 11）。多数为"getshell"但主题偏离纯上传（Shiro/Redis/Exchange/信息泄露），或图片类低信息量。

- **方法论/检测向**：`52-详谈webshell检测.pdf`（webshell 检测，防守侧，与内容检测相关）。
- **图片类（低信息量）**：`兰州getshell.png`、`兰州getshell_(1).png`（两张不同体积，疑似 SQL 注入+上传截图，未展开）。
- **非上传主题 getshell（仅标题，供交叉引用）**：
  - `未授权redis+getshell.docx`（Redis 未授权 → 写公钥/计划任务，非上传）。
  - `攻防打点-0day(信息泄漏)到getshell.pdf`（aspx 站 + 目录扫描，疑似上传，未确认）。
  - `实战---记一次攻防Exchange艰难getshell.pdf`（Exchange CVE 链，非上传）。
  - `一次艰难曲折的getshell.pdf`（主题不明）。
  - `【实战经验】从shiro权限绕过getshell.pdf`（Shiro，非上传）。
  - `[攻防实战]爽文一把梭getshell.pdf`（Shiro/源码泄露/oa.zip，非上传）。
  - `成都市职业学院getshell.pdf`（EduSRC，简介为 Shiro 反序列化，非上传）。
  - `广州市教育局getshell.doc`（EduSRC，手法未确认）。

---

## 七、厂商定级尺度观察

- **严重**：教育厅级"任意文件上传 getshell 通杀"（如四川省教育厅 `upload.jsp` 直接落 jsp，定级"严重"）。
- **高危**：高校/职校系统弱口令进后台 + 传 shell（长安大学、华南农业大学、云南/某徽工业定"高危"，Rank 0~6）；带 WAF 绕过的 getshell、云会议/园区 RCE 多归高危。
- **中危/低危**：仅能上传 html 造成存储型 XSS（易车"覆盖用户文件 + 解析 XSS"定"高危"，因可覆盖+解析；若仅普通 XSS 多为中危）；跨目录覆盖图片/logo 通常中危（取决于能否解析）。
- **厂商共性**：教育/政务系统对"直接 getshell"宽容度低、定级高；纯 XSS/覆盖多为中危；白帽常因"通杀多所高校同系统"拿 Rank。

---

## 八、素材缺口

1. **具体组件 POC 偏少**：仅好视通、华智慧园区、UEditor .net、某 OA、Weblogic 有可抄路径；ewebeditor/kindeditor/帝国/通达/宝塔等编辑器/面板案例缺失。
2. **Nginx / Apache 解析漏洞实案例缺失**：素材多为理论（22/96 期），无真实 `x.php/y.jpg` 实战。
3. **`.htaccess` / `.user.ini` 包含链缺失**：无图片马→配置包含的真实案例。
4. **二次渲染绕过缺失**：无 GD/imagecreatefromjpeg 二次渲染后保留 payload 的实例。
5. **教育侧独立增量有限**：EduSRC 6 份中 3 份读取失败、1 份为 Shiro 非上传，有效上传案例仅长安/华南农/某徽 3 份（见 `edusrc-upload-add.md`）。
6. **读取失败 3 份**：建议至 ima 内补读 `文件上传篡改图标.docx`、`四川省双流中学getshell.doc`、`同济大学-getshell.doc`。
