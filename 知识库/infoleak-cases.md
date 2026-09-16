# 信息泄露实战案例（ima 案例库深挖）

> **回查原文** → `ima-retrieval-index.md` §三（ima `src报告/信息泄露/` folder_id + 关键词 + 报告名直搜）。

> 来源：ima 知识库 `src` → `src报告/信息泄露/`（75 条 → 去重后 44 份唯一，实读 26 份，读取失败 1 份）
> 定位：**真实泄露源、真实路径、真实判定与定级**；方法论见 `info-leak-test.md`。
> 生成日期：2026-09-14

> ⚠️ **红线声明**：本报告仅作威胁认知与防守复盘之用，SRC 上报一律不做社工/钓鱼/免杀/买卖账号行为。涉及真实个人隐私数据（师生身份证号、手机号、密码明文等）的素材**只做"可获取师生身份证/手机号"类描述，不抄录任何真实身份证号、手机号、密码明文**。凡标题标注"（不打码）"的教育侧报告，均按此原则脱敏处理。

## 一、泄露源分类（按"泄露载体"重组）

### 1. 配置文件泄露
- **去哪儿 train 站**：访问 `https://hao123.train.qunar.com/build.xml` 直接下载 Ant 构建文件，内含 SSH 部署账号 `hao.lin`、密码、目标服务器路径与数据库相关敏感信息。可拿去扫端口/连服务器。
- **用友 NC**：路径遍历读配置 `/portal/docctr/open/word.docx?disp=/WEB-INF/web.xml`，返回完整 `web.xml`（filter、listener、context-param 全暴露），可定位后台路径与组件。多个 IP 通杀（案例一/三命中）。
- **芋道 yudao 项目（证书站）**：Vue 前端按 JS 路径回溯 GitHub 源码，确认是开源"芋道"项目；拼接 `/api/admin-api/infra/file-config/page` 未鉴权返回 OSS 的 `accessKey`/`accessSecret`、endpoint、bucket，定级**高危**。

### 2. 调试端点（heapdump / actuator / Swagger）
- **北京教委 中小学学籍云平台**：`/api/actuator/heapdump` 未授权下载，heapdump_tool 解密出 redis 密码、`oracle` 数据连接密码等大量服务口令；8848 端口 `nacos/nacos` 弱口令登入，可删服务致业务崩溃。
- **从 API 到 RCE（综合信息平台）**：扫出 8010/9010 端口，`/jeecg-boot/actuator` 暴露，其中 `httptrace` 留存登录 cookie（含 JWT）；改成 POST 触发 SpringBoot Whitelabel 报错确认框架；最终用 jeecg-boot 已知 ndady（jmreport 接口 Freemarker RCE）打穿，并复用泄露手机号+弱口令 123456 接管账号。
- **Swagger 另类绕过**：`/swagger-ui/index.html`、`/v3/api-docs` 被删/权限不足时，访问 `/actuator/mappings` 取 `patterns` 字段拿到全部路由，写脚本提取后批量打未授权接口，泄露大量业务数据。

### 3. 备份与临时文件 / 目录列举
- **熵基 ZKTeco 门禁**：`/tmp/`、`/file/` 目录列举，暴露 `center_202209xx.txt` 日志、`人员2022xxxx.xls`（员工姓名/卡号/部门/职务/指纹数）、`实时监控记录*.xls`（姓名/卡号/出入时间/门点）、`SvcZKECOBackupDB.log` 等。Web 资产测绘 `app="zkteco-门禁管理系统"` 可通杀。
- **软件著作商后台**：`dirsearch` 扫出 `/upload/` 列目录，下载 `.xlsx` 含多所高校（浙大、西交、西工大、大连理工、广东工大等）前台/后台地址+账号+密码；多数已改密，浙大仍可登录。
- **十堰 阳光心健**：`admin/userfiles/2018在校生综合信息查询.xls` 列目录直接下载，初始账号即学籍号。
- **某酒店 App**：Burp 抓包暴露真实 IP `124.127.125.70`，访问 IP 发现目录遍历（服务器配置错误）。

### 4. 前端 JS 与硬编码密钥
- **同程旅行 App**：jadx 反编译 `AndroidManifest.xml`，在 `meta-data` 拿到百度语音 `APP_ID/API_KEY/SECRET_KEY`；用官方 OAuth 换 `access_token` 后调用付费"人脸识别/身份证核验"接口，传入姓名+身份证号可验证是否匹配，造成付费能力被白嫖。
- **麦当劳 etraining**：`https://etraining.mcd.com.cn:5501/js/Data.js` 暴露内部题库/配置（评分项、证照管理、安全检查表等运营细节），定级低危。

### 5. 接口未授权 / 返回包明文 / 前端脱敏失效
- **ehall 帆软报表（四川建院）**：`/xsfw/sys/frReport2/show.do?reportlet=com.fr.JZ&cpt=...&wid=学号` 改 `wid` 遍历，**泄露全校学生身份证号**；并可用泄露账号登录统一身份认证。⚠️ 红线（原文含真实姓名+身份证，已脱敏）。
- **电子科技大学**：登录统一身份认证后多处业务系统接口（教职工体检预约、出国证明等）返回 `sfz` 等敏感字段。
- **交大 预约咨询接口**：返回包直接带用户敏感信息（标题"不打码"）。
- **唯品会 注册电话枚举**：忘记密码处对已/未注册手机号返回不同响应，且返回 `pid`/`selectid` 可被另一包利用，造成账号信息泄露（中危）。
- **马士兵教育 意见反馈**：`/api/edu-im/user/random10VipStudent?userId=` 可遍历随机 VIP 用户；把 `userId` 改为他人 ID 经 `findMySession`/改资料接口读取并篡改他人资料（越权+信息泄露）。
- **前端脱敏/明文传输**：评论区、播报栏、排行榜、转账、提现、客服处，前端打 `*` 但返回包为明文身份证/银行卡/手机号；提现账户 `bankCard` 明文可读。按厂家属低危或中危。
- **前端校验绕过**：资讯帖对游客前端屏蔽"客户专享"，但对应数据包未鉴权，直接拿全文。
- **匿名用户定位**：匿名评论的返回包带 `uid`，拼 `uid.html` 可反查真人头像与账号。

### 6. 报错回显 / 物理路径
- **甲鼎就业平台（通杀）**：IIS 站 `https://域名/1` 触发 404 详细错误，回显物理路径 `E:\haishi\1`、`D:\tianhua\1`、`D:\shlg\1` 等；鹰图语法 `title="就业"&&body="甲鼎"` 通杀上海多所高校就业网（海事/天华/理工/上大等）。为后续攻击提供路径信息。

### 7. 数据库与服务端口
- 见 §2 北京教委（nacos/redis/oracle）、§5 各类未授权接口库。端口类泄露多与 heapdump/弱口令叠加。

## 二、高价值泄露点速查表

| 泄露点/指纹 | 探测方式与 URL | 可获取内容 | 危害 | 来源案例 |
|---|---|---|---|---|
| SpringBoot heapdump | `/actuator/heapdump`、`/api/actuator/heapdump` | redis/oracle/数据库密码、内部 token | 高（可连库/进内网） | 北京教委 |
| Nacos 弱口令/未授权 | `:8848/nacos` `nacos/nacos` | 服务列表、配置、可删服务 | 高 | 北京教委 |
| Swagger / api-docs | `/swagger-ui/index.html`、`/v3/api-docs`、`/actuator/mappings` | 全量 API 路由与参数 | 中-高 | Swagger绕过、API→RCE |
| 用友NC web.xml 遍历 | `/portal/docctr/open/word.docx?disp=/WEB-INF/web.xml` | web.xml 组件与后台路径 | 中（信息） | 用友NC |
| build.xml / 构建文件 | `/build.xml` | SSH 账号密码、服务器路径 | 高 | 去哪儿 |
| 开源框架配置文件接口 | `/api/admin-api/infra/file-config/page` 等 | OSS key/secret、数据库配置 | 高 | 芋道证书站 |
| 帆软报表 wid 遍历 | `frReport2/show.do?...&wid=` | 全校学生身份证号 | 高（隐私） | ehall四川建院 |
| 门禁/系统 /tmp、/file/ | `IP:端口/tmp/`、`/file/` | 员工名册、考勤、进出记录 | 中-高 | 熵基 |
| 上传/备份目录列举 | `/upload/`、`admin/userfiles/` | xlsx 含账号密码、学生信息 | 高 | 软件著作商、十堰 |
| App 硬编码密钥 | 反编译 AndroidManifest `meta-data` | 第三方 API key/secret | 中（滥用付费） | 同程 |
| 接口返回明文隐私 | 评论/播报/转账/提现返回包 | 身份证/银行卡/手机号明文 | 低-中 | 前端脱敏失效 |
| IIS 报错物理路径 | `域名/1` 触发 404 详细错误 | 网站真实物理路径 | 低（助攻） | 甲鼎通杀 |
| 注册/忘记密码枚举 | 响应差异 + pid/selectid | 账号是否存在、用户标识 | 中 | 唯品会 |
| userId 越权读资料 | 改 `userId` 参数 | 他人资料、可篡改 | 中-高 | 马士兵 |

## 三、按功能点的排查 Checklist

- **资产与框架识别**：确认 SpringBoot / 用友NC / 芋道 / jeecg-boot / 帆软 / ZKTeco 等，先打对应调试端点与默认路径。
- **调试端点**：`/actuator`、`/heapdump`、`/swagger-ui`、`/v3/api-docs`、`/actuator/mappings`、`/env`、`/configprops`。
- **配置文件**：`/build.xml`、`/WEB-INF/web.xml`、`/.env`、`/application.yml`、`.properties`、源码仓库 `.git/config`、`.svn/entries`。
- **目录列举**：`/upload/`、`/tmp/`、`/file/`、`/admin/userfiles/`、`/backup/`、年份日志 `.txt`、`.xls/.xlsx` 备份。
- **前端 JS / 小程序**：抓包看真实 API 域名；反编译 App 查 `meta-data`/`string` 硬编码；`Findsomething` 插件捞 JS 内路径与 key。
- **返回包审计**：评论区、播报、排行榜、转账、提现、客服、个人中心——前端打码 ≠ 传输加密，必看响应体。
- **越权+遍历**：带 `userId`/`wid`/`xh`/`id` 的接口尝试改值；学号/工号可枚举的报表重点测。
- **报错信息**：IIS/SpringBoot/Tomcat 详细错误是否回显物理路径、SQL、堆栈。
- **教育侧专项**：统一身份认证后业务系统接口、帆软/正方 xgxt 报表、学工系统遍历参数。

## 四、案例索引

| # | 报告名 | 平台 | 目标/系统 | 泄露点 | 泄露内容量级 | 结果/定级 |
|---|---|---|---|---|---|---|
| 1 | 从API接口信息泄露到挖掘出一个RCE | Web | 综合信息平台(jeecg-boot) | actuator/httptrace+API文档未授权 | 全平台师生信息→RCE | 通杀多站 |
| 2 | ehall学生端帆软报表打印处信息泄露 | Web | 四川建院 ehall | frReport2 wid 遍历 | 全校学生身份证 | 高(隐私) |
| 3 | 去哪儿信息泄露 | Web | qunar train | /build.xml | SSH/DB 密码 | 中 |
| 4 | 用友nc信息泄露 | Web | 用友NC 多IP | web.xml 遍历 | 后台路径/组件 | 中(通杀) |
| 5 | 赏金猎人针对Swagger的另类绕过 | Web | 某Spring项目 | /actuator/mappings | 全路由→未授权数据 | 中-高 |
| 6 | 高危（芋道证书站） | Web | 某.edu.cn 芋道 | file-config/page 未鉴权 | OSS key/secret | 高危 |
| 7 | 交大-返回包敏感信息泄漏 | Web | 交大预约系统 | 返回包明文 | 用户敏感信息 | 中 |
| 8 | 前端脱敏导致的信息泄漏 | Web | 金融/通用 | 评论/提现明文 | 身份证/银行卡 | 低-中 |
| 9 | 中信银行硬编码信息泄露(同程) | Web/App | 同程旅行App | AndroidManifest meta-data | 百度API key→付费接口 | 中 |
| 10 | 用户注册电话枚举加信息泄露 | Web | 唯品会 | 注册枚举+pid | 账号标识 | 中 |
| 11 | 意见反馈处信息泄露+越权 | Web | 马士兵教育 | userId 越权 | 他人资料可改 | 中-高 |
| 12 | 通杀2（甲鼎） | Web | 多高校就业网 | IIS 报错物理路径 | 真实路径(通杀) | 低(助攻) |
| 13 | 熵基科技股份有限公司 | Web | ZKTeco 门禁 | /tmp//file/ 列举 | 员工名册/考勤 | 中-高 |
| 14 | 如何从软件著作商处获取敏感信息 | Web/Edu | 某软件商后台 | /upload/ 列目录 | 多校账号密码 | 中 |
| 15 | 匿名用户导致的用户泄露 | Web | 某站评论 | uid 反查 | 匿名→真人 | 低-中 |
| 16 | 前端校验导致的绕过访问 | Web | 某资讯站 | 游客态数据包未限 | 专享全文 | 低-中 |
| 17 | 麦当劳etraining信息泄露 | Web | 麦当劳etraining | /js/Data.js | 内部题库/配置 | 低危 |
| 18 | 北京教委信息泄露（EduSRC pdf） | EduSRC | 北京中小学学籍云 | heapdump+nacos | redis/oracle 密码 | 高 |
| 19 | 电子科技大学信息泄露 | EduSRC | 电子科大统一身份后系统 | 多处接口 | sfz 等 | 中 |
| 20 | 陕西师范大学 正方xgxt | EduSRC | xgxt.snnu.edu.cn | 任意密码重置 | 4.6万条学生信息 | 严重(8) |
| 21 | 十堰高级职业学校 阳光心健 | EduSRC | 阳光心健 | 列目录+未授权+s2 | 在校生信息→getshell | 高危(8) |
| 22 | 湘潭大学 正方xgxt | EduSRC | xgxt.xtu.edu.cn | 越权遍历 | 学生敏感信息 | 中危(4) |
| 23 | 某酒店app信息泄露 | App | 某酒店App | 真实IP+目录遍历 | 服务器路径 | 中 |
| 24 | 北京教委信息泄露（已看）.doc | Web | 北京教委 | （读取失败，仅标题） | — | 读取失败 |

## 五、未精读清单（标题级归类）

以下 17 份按"标题级"归类未精读（多为信息收集/方法论通识文档，或重复版本），不计入实读：

- **方法论/信息收集通识（Web）**：`06-信息泄露之配置不当`、`49-网站安全检测之信息收集类工具`、`87-web漏洞挖掘之前期信息收集`、`91-web漏洞之敏感信息漏洞挖掘`、`CTFSHOW-web入门-信息搜集`、`第二更：信息收集`、`第一更：信息收集`、`钓鱼网站分析(主要是信息收集)`、`github信息收集`、`关于人的信息搜集`、`论src漏洞挖掘的前期信息收集`（ppt 两个版本）、`渗透测试信息搜集.xmind`、`信息收集.pdf`+`信息收集.docx`集群、`一次通过信息搜集打点`。
- **重复/相近版本（已以唯一份代表）**：`信息泄漏（—）.docx` 集群（前端明文，与"前端脱敏"同源不同版）、`匿名用户导致的用户泄露` 与 `信息泄露(1)` 集群（已合并为#15）、`前端校验导致的绕过访问` 与 `信息泄露.docx` 集群（已合并为#16）、`麦当劳名下子公司存在信息泄露`（robots.txt，与#17 同源）。
- **EduSRC 已读但列于此备查**：`edusrc敏感信息搜集.txt`（google dork 搜身份证，已读，方法见 §3 教育侧）。

## 六、厂商定级尺度观察

- **只能定"信息泄露（低）"的场景**：前端打码但明文返回（评论/提现）、App 硬编码非核心 key、内部题库/配置（`Data.js`）、注册枚举仅泄露"账号是否存在"、IIS 物理路径（无直接数据）。
- **可升中危**：返回包带可定位真人的标识（uid/头像）、游客态绕过拿全文、userId 越权读他人资料、唯品会式 pid 利用。
- **可升高危/严重**： heapdump 泄露数据库密码、OSS key 泄露、帆软 wid 遍历全校身份证、芋道配置接口未鉴权、nacos 弱口令可删服务。
- **教育侧偏高**：正方 xgxt 任意密码重置→严重(8)；阳光心健列目录+未授权+s2→高危(8)；越权遍历学工→中危(4)。教育侧因涉及**大量师生身份证/手机号/家庭地址**，即便"只是信息泄露"也常因量级大被抬到中/高危。
- **关键抬级因素**：① 数据量级（全校/全平台）；② 是否含 credential（密码/key）；③ 是否可进一步利用（RCE/接管/进内网）；④ 是否涉个人隐私（身份证/人脸）。

## 七、素材缺口

- **缺专属移动端深度案例**：App 平台仅 2 条（去重后 1 条：某酒店真实IP+目录遍历），且为"信息收集"而非典型 App 隐私泄露；同程 App 硬编码归在 Web 标题下。建议补充：Andoird/iOS 抓包泄露 token、小程序逆向、分享链接受损等。
- **缺云存储/OSS 公网 bucket 直接列举案例**：现有 OSS 泄露来自配置接口，无"阿里云 OSS bucket 可匿名列举/下载"的实战样本。
- **缺 .git/.svn 源码泄露专项**：本目录无典型 `.git` 泄露案例（用友NC 为 web.xml 遍历，非源码仓）。
- **缺日志文件大段泄露**：熵基有日志但属门禁记录；通用 Web 访问日志/报错日志泄露样本不足。
- **教育侧"不打码"原始报告**（陕西师范/十堰/湘潭/交大/电子科大）含真实隐私，已脱敏，无法作为可复现 POC 细节沉淀，仅保留技术与定级。
