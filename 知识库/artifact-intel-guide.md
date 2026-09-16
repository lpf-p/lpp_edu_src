# 前端产物情报提取（JS 之外还能挖什么）

> 定位：**情报提取层**，不是漏洞类型层。本篇回答两件事——① JS 里除了 API 和硬编码还能拿什么；② 还有哪些**跟 JS 同性质、能直接下载下来读**的东西。
>
> **分工（细节只在一处，不复制）：**
>
> | 已有 | 管什么 |
> |---|---|
> | `js-reverse-guide.md` | JS 逆向：接口发现、签名复现、sourcemap、硬编码凭据、影子 API |
> | `info-leak-test.md` §2.1 | **服务端**敏感路径：`.git`/`.env`/`web.config`/备份包/Swagger/Actuator |
> | `insecure-scm-test.md` | 源码仓库泄露（`.git`/`.svn`/`.hg`）的深度利用 |
> | `middleware-unauth-test.md` | 中间件未授权面 |
> | **本篇** | **前端可下载产物**：构建清单、配置、客户端包、元数据、协议文件 |
>
> 冲突以 `rules/src-value-hunting.md` 与 `rules/vuln-report-format.md` 为准。

> **实战案例（双向引用）** → `infoleak-cases.md` §4 前端 JS 与硬编码密钥（麦当劳 `etraining` 的 `/js/Data.js` 暴露内部题库与运营配置）+ §1（芋道 yudao：按 JS 路径回溯 GitHub 源码 → 拼出未鉴权 `/api/admin-api/infra/file-config/page` 拿到 OSS AK/SK）；`attack-chain-cases.md` §2.2（`*.js.map` + reverse-sourcemap 还原源码、`.ds_store` + **DS_Walk** 还原目录）；`ima-case-corpus.md` §1.4（Vue 站 → JS 路径去 GitHub 搜源码 → 认出框架 → 官方演示站抓包拿接口路径 → 拼回目标）。

---

## 1. JS 里除了「接口 + 硬编码」还能拿什么

按性价比排序（前 6 项最容易变成实际漏洞）：

| # | 能拿什么 | 拿到后怎么用 |
|---|---------|------------|
| 1 | **业务对象模型 / 字段名** | 响应里没有、但 JS 里写了的字段 → **Mass Assignment 隐藏可写字段**（`role`/`isAdmin`/`verified`/`tenantId`/`balance`）。见 `idor-test.md` |
| 2 | **加密 ID 的公钥 / 算法** | JSEncrypt 的 `modulus`/`exponent` 写死 → 自己加密邻号换 id。见 `idor-test.md`「密文 ID」 |
| 3 | **对象图：哪些 id 能换** | `userId`/`orderId`/`tenantId`/`orgId` 出现的位置 = 换 id 的候选面（`dig-scope` §4.2.3） |
| 4 | **错误码表 / 状态码常量** | 枚举出「用户不存在」「已注册」等分支码 → 账号枚举的判定依据 |
| 5 | **i18n 语言包** | 未上线功能的文案、内部术语、模块名 → 反推隐藏接口 |
| 6 | **功能开关 feature flag** | `isTest`/`enableMock`/`__DEV__` 打开时走的另一套接口 |
| 7 | 内部域名 / 内网 IP / 网关拓扑 | 进本站队列，配合 SSRF 再打 |
| 8 | 第三方集成配置 | OAuth `clientId`、支付 `appId`、IM SDK 配置 → 换票/代调面 |
| 9 | 框架与组件版本 | `package.json` / 版本号字符串 → 定向已知 CVE |
| 10 | 构建信息 | commit hash、构建时间、分支名 → 配 `.git` 泄露还原源码 |
| 11 | 风控 / WAF 行为特征 | 前端对哪些字符做了转义、哪些接口走了滑块 |
| 12 | 过期但仍存在的旧接口 | 老版本 chunk 里的 path → 影子 API |

---

## 2. 跟 JS 同性质、能直接下载下来读的东西

这类东西的共同点：**浏览器能取到，服务端常常没加鉴权**。

### A. 构建与依赖清单（定向 CVE 最快）

| 文件 | 能拿到什么 |
|---|---|
| `package.json` | 依赖与版本范围 |
| `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` | **精确版本** → 直接对 CVE |
| `composer.json` / `composer.lock` | PHP 依赖 |
| `requirements.txt` / `Pipfile.lock` / `poetry.lock` | Python 依赖 |
| `pom.xml` / `build.gradle` / `gradle.lockfile` | Java 依赖 |
| `go.mod` / `go.sum` | Go 依赖 |

**打法**：SPA 的 `package.json` 常常能被直接 GET（前端项目误把整个目录当静态根）。拿到精确版本后对照 CVE，比盲扫有效得多。

### B. 构建与环境配置

| 文件 | 价值 |
|---|---|
| `webpack.config.js` / `vue.config.js` / `vite.config.js` | 代理目标（**内网后端地址**）、环境变量 |
| `.env` / `.env.production` / `.env.local` | 接口地址、密钥占位、第三方 key |
| `config.js` / `config/index.js` / `env.js` | baseURL、环境切换 |
| `Dockerfile` / `docker-compose.yml` | 内网服务拓扑、端口、账号 |
| `.gitlab-ci.yml` / `.github/workflows/*.yml` / `Jenkinsfile` | 部署目标、仓库地址、**CI 变量** |

> 服务端侧的配置路径（`.env`/`web.config`/`application.yml`）见 `info-leak-test.md` §2.1，本篇不重复。

### C. 前端运行时产物

| 产物 | 能拿什么 |
|---|---|
| `*.js.map` | **原始源码**（`js-reverse-guide.md` 流程五） |
| **Service Worker JS** | 离线缓存清单 = **几乎全量接口列表**，且含页面不一定调用的路径 |
| `manifest.json`（PWA） | `start_url`、图标、应用结构 |
| **CSS 文件** | 背景图路径、未上线模块的样式、内部 class 命名（反推业务模块名） |
| **iconfont / 图标库 JSON** | 内部图标命名 → 未上线的功能模块名 |
| i18n 语言包 JSON | 见 §1 第 5 项 |

**Service Worker 是被忽略最多的一个**——它必须提前声明所有要缓存的资源，所以里面常常有完整路由表。

### D. 客户端包（有客户端时）

| 包 | 说明 |
|---|---|
| 小程序 `.wxapkg` | 可反编译出完整前端代码。**见 `miniprogram-security` skill** |
| Electron 应用 `asar` | 可解包，含完整源码 |
| APP `apk` / `ipa` | 用户不做移动端时跳过；需要时见 `aboutsecurity-master` 的 `android-app-pentesting` |

### E. 文档与元数据（最容易被漏）

| 对象 | 能拿什么 |
|---|---|
| **PDF / Office 元数据** | 作者、单位、**内部文件路径**（如 `D:\项目\上海体育\...`）、内部主机名 |
| **图片 EXIF** | GPS 坐标、拍摄设备、**软件版本** |
| `robots.txt` | 禁止收录的路径 = 后台/管理入口线索 |
| `sitemap.xml` | 全站 URL 清单（含未链出的） |
| `security.txt` / `.well-known/security.txt` | 联系方式、披露政策 |
| `crossdomain.xml` / `clientaccesspolicy.xml` | 跨域策略（Flash/Silverlight 遗留，偶有宽松配置） |
| **目录列目录（Nginx autoindex）** | 整站文件树 → 备份包、日志、配置一眼全见 |

**打法（元数据）**：
```bash
# PDF / Office 元数据
exiftool target.pdf
# 或用 python
python -c "import zipfile;print(zipfile.ZipFile('a.docx').read('docProps/core.xml').decode())"

# 图片 EXIF
exiftool img.jpg
```

### F. API 规范（比 Swagger 页面更好用）

| 对象 | 说明 |
|---|---|
| `openapi.json` / `swagger.json` / `api-docs` | 完整接口+参数+字段（见 `info-leak-test.md` §2.1 路径表） |
| **GraphQL introspection** | `POST {"query":"{__schema{types{name,fields{name}}}}"}` → 全量类型与字段 |
| Postman collection 导出（`.json`） | 偶尔被误传到静态目录 |
| Protobuf / Thrift 定义 | 罕见但价值极高 |

### G. 目录列目录（Nginx autoindex / Apache Indexes）★ 用户点名

**形态**：访问一个路径直接看到该目录下的文件列表。**这是性价比最高的一类**——一眼看到全站文件树，后面的备份包、文档、配置全在眼前。

**识别签名**（命中任一）：
```
Index of /xxx                       Nginx / Apache
<a href="../">                      Apache 父目录链接
Parent Directory                    Apache
[To Parent Directory]               Apache 老版本
Directory listing for /             Python SimpleHTTPServer
<h1>Directory:                      Tomcat 列目录（需 listings=true）
```

**探测目录字典**（按命中率排序）：
```
/ /static /assets /upload /uploads /uploadfile /upfile /files /file /data
/doc /docs /download /downloads /backup /bak /tmp /temp /log /logs
/images /img /css /js /public /web /old /test /manual /help /guide
/attachment /attach /export /report /resources /media /archive
/software /soft /apk /app /ueditor /kindeditor /ueditor/net
/admin /manage /console /webroot /site /db /sql
/资料 /下载 /文件 /文档
```

**找到列目录后翻什么**（按价值排序）：
1. **备份包**：`*.zip` `*.tar.gz` `*.sql` `*.bak` —— 一个包就是全站源码
2. **文档**：见下方 H 组
3. **日志**：`*.log` —— 含请求参数、报错栈、偶有 token
4. **配置**：`*.yml` `*.properties` `*.conf` `.env`
5. **上传目录**：证件照、简历、合同 —— **告警：含大量个人信息，只取能证明危害的最小片段，禁止下载全量**
6. 版本目录：试邻近日期 / 旧版本号拿旧包

**打法**：
```bash
# 检测
curl -s --noproxy '*' -k "https://target.com/upload/" | grep -iE 'Index of|Parent Directory|<a href="\.\./'
# 批量（见 §3 脚本 probe 思路：hosts × dirs 并发，20 线程）
```

**假点**：
- 返回是**自定义 404/403 页面**恰好含 `Index of` 字样 → 不是列目录，看有没有 `<a href=` 文件行
- 只列出静态资源（css/js 正常文件）→ 信息价值低，通常不收
- 空目录 → 无价值

### H. 文档与表格泄露 ★ 用户点名（EDU/企业 SRC 高分）

**为什么值钱**：使用手册 / 操作说明 / 培训材料里常直接印着——**初始密码规则、默认账号、内部拓扑、业务流程图、接口地址**。拿到「初始密码规则」就能把「枚举」变成「可算」，威力极大。

**文件名字典**：
```
中文手册类：
使用手册.pdf 用户手册.pdf 操作手册.pdf 操作说明.pdf 使用说明.pdf
说明书.pdf 帮助.pdf 培训材料.pptx 培训.pptx 部署文档.docx 部署说明.docx
运维手册.docx 安装说明.docx 系统说明.docx 说明.txt

表格类（最敏感）：
账号.xlsx 密码.xlsx 账号密码.xlsx 初始密码.txt password.txt account.txt
通讯录.xlsx 名单.xlsx 联系人.xlsx users.xls
学生名单.xlsx 教师名单.xlsx 考生名单.xlsx 录取名单.xlsx

英文通用：
manual.pdf guide.pdf help.pdf readme.txt README.md
```

**在哪找**：
1. 先找到**目录列目录**（G 组）→ 直接翻
2. 站点自己的**下载中心 / 帮助中心 / 通知公告**栏目 → 挂的附件
3. `site:` 搜索（对齐 `password-reset-test.md` §七）：
   ```
   site:目标域名 filetype:pdf 使用手册 操作说明
   "目标域名" help.pdf OR 初始密码 OR 使用帮助
   "目标单位" 学号 密码 工号 泄露
   ```
4. 对象存储的公开桶（见 `file-upload-test.md`「桶策略对匿名全开」）
5. 老版本目录 / 备份包里

**拿到后干什么**：
- **初始密码规则** → 直接生成候选口令，配合 `password-reset-test.md` 与登录口（**注意：登录表单弱口令不当必做，见 `dig-scope` §4.1.1**；这里是用规则缩小范围，不是跑字典）
- **内部拓扑 / IP** → 进队列配 SSRF
- **接口地址** → 回 `src-value-hunting` §3 矩阵
- **名单（姓名+手机/证件）** → 属个人信息泄露，可交；**但只取能证明危害的最小片段**

**假点**：
- 手册是**对外公开**的产品说明书 → 不收
- 名单是脱敏的 / 公开公示的 → 不收
- 文档里的账号口令是**示例占位**（`test/123456` 且不可用）→ 不收

### I. 「能直接看到目录/文件」的同类面（家族清单）

用户问的「目录列目录」只是其中一支。同类还有：

| 面 | 在哪篇 |
|---|---|
| 目录穿越 / LFI（`../` 读任意文件） | `path-traversal-lfi-test.md` |
| 静态根映射了整个仓库根（`package.json` 可 GET） | `path-traversal-lfi-test.md`「仓库根当静态」 |
| Nginx `alias` 缺斜杠（`/static../`） | `path-traversal-lfi-test.md` |
| 备份 / 打包文件（`www.zip`、`db.sql`） | `info-leak-test.md` §2.1 |
| 版本控制泄露（`.git`/`.svn`/`.hg`） | `insecure-scm-test.md` |
| **对象存储桶列目录**（S3/OSS `ListBucket`） | `file-upload-test.md`「存储代理 sign key=/」 |
| 上传组件自带文件管理页（ueditor/kindeditor） | `middleware-unauth-test.md` §2 + 本组字典 |
| 中间件默认示例目录（Tomcat `examples`、Jenkins `script`） | `middleware-unauth-test.md` §2 |
| 调试控制台目录（Druid `/druid/...`、Actuator） | `middleware-unauth-test.md` §2 |
| **匿名 FTP / 网盘 / 文件共享** | 本组 G 的字典同样适用 |
| 公网编辑器/IDE 的文件树（VS Code 系） | `path-traversal-lfi-test.md`「公网 VS Code 系读进程环境」 |

**统一打法**：都是「找一个能列/能读的入口 → 翻出值钱文件」。字典复用 G 组的目录字典 + H 组的文件名字典。

---

## 3. 提取流程（批量化）

```bash
# 1) 先拿页面里的全部资源引用（不只是 script）
curl -s --noproxy '*' -k "https://target.com" \
  | grep -oE '(src|href)="[^"]+"' | sed -E 's/.*="([^"]+)"/\1/' | sort -u > assets.txt

# 2) 相对路径补全（同 js-reverse-guide 流程六 §1）

# 3) 逐个探「JS 同族产物」
BASE="https://target.com"
for p in package.json package-lock.json yarn.lock composer.json requirements.txt \
         manifest.json sw.js service-worker.js robots.txt sitemap.xml \
         .env .env.production webpack.config.js vue.config.js Dockerfile \
         .gitlab-ci.yml crossdomain.xml security.txt; do
  c=$(curl -s -o /dev/null -w "%{http_code}" --noproxy '*' -k --max-time 8 "$BASE/$p")
  [ "$c" = "200" ] && echo "HIT  $p"
done

# 4) 探目录列目录（autoindex）
for d in /static /assets /upload /files /backup /doc /download /tmp; do
  c=$(curl -s --noproxy '*' -k --max-time 8 "$BASE$d/" | grep -ciE 'Index of|<a href="\.\./|Directory listing')
  [ "$c" -gt 0 ] && echo "AUTOINDEX  $d/"
done

# 5) GraphQL introspection
curl -s --noproxy '*' -k -X POST "$BASE/graphql" -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name}}}"}' | head -c 300
```

**命中后的处理**：出依赖清单 → 对 CVE；出内网地址 → 进队列配 SSRF；出接口清单 → 回 `src-value-hunting` §3 矩阵；出凭据 → 假值对照 + 只读例（`src-value-hunting` §2）。

### 3.1 去伪（批量必做，否则命中全是垃圾）

批量探测会把 200 都当命中，但 200 有三种假象：

| 假象 | 怎么排除 |
|---|---|
| **SPA catch-all**：所有路径返首页 | 候选文件 md5 / `Content-Length` **与首页比对**；再看 `Content-Type` 是否匹配扩展名 |
| **统一 404 页返 200** | 比对一个必然不存在的随机路径（`/zzz_random_9x7`）的响应，一致即假 |
| **WAF 拦截页返 200（最阴险）** | 有些 WAF/上网行为管理对**已知敏感路径**（`swagger-ui.html`、`actuator`、`/admin`）返回 **HTTP 200 + 「访问禁止」页面**，而不是 403/404。实测某高校：`/swagger-ui.html` → 200/911B 拦截页，`/swagger-resources` → 200 拦截页，而**随机路径 → 404**。判定：① 内容里搜 `访问禁止` `Blocked` `拒绝访问` `请联系` 等；② **拿随机路径做对照**——随机路径 404 而候选路径 200 且内容像拦截页，就是假的；③ 别只看状态码 |

```bash
# 基准：随机不存在路径
BASE_LEN=$(curl -s --noproxy '*' -k "$H/zzz_random_9x7" | wc -c)
# 候选文件与基准、与首页都不同的才算命中
```

**脚本要并发**：串行 `for` 循环会被工具超时截断（hosts × dirs 轻松上百请求）。用 `ThreadPoolExecutor(max_workers=20)`，别用 shell 串行。

---

## 4. 假点

- ⚠️ **SPA catch-all 假阳性（最高频，必查）**：前端 SPA 常把**所有未知路径** fallback 到首页，于是 `password.txt`/`README.md`/`manual.pdf` **全都返 200 且内容=首页**。判定：拿候选文件的 `Content-Length` / md5 **跟首页比**——一致即假阳性。真实文件 `Content-Type` 也该对（`application/pdf` 不是 `text/html`）。**批量脚本必须内置这一步**，否则命中全是垃圾
- `package.json` 200 但**是第三方库的**（jquery/element-ui）→ 不是目标的
- 依赖版本能读到但**没有对应 CVE** 且无未授权面 → 不是洞，只是指纹
- EXIF 里只有拍摄参数、无位置无内部信息 → 通常不收
- PDF 元数据作者是「Administrator」/打印机名 → 价值低，多数平台不收
- `robots.txt` 只有 `Disallow: /admin` 一行 → 弱线索，单独不交
- GraphQL introspection 被禁（返回错误）→ 正常加固
- 拿到的 `sw.js` 只缓存静态资源 → 无接口清单价值
- **「能下载到」不等于「是漏洞」** —— 多数这类发现是**佐证**，要写进主报告的「攻击链佐证」（见 `password-reset-test.md` §八）

---

## 5. 红线

- **只读**：GET 下来看，不改、不传、不删
- 目录列目录看到了也**不要**下载全站备份包（体量大、可能含大量个人信息）
- 拿到含个人信息的文档（证件照、名单）→ **只取能证明危害的最小片段**，不外传
- 依赖清单对出 CVE → **只在有 PoC 且不影响线上时验证**，禁止打生产
- 源码/配置**不全量贴进报告**，只引用必要片段

---

## 6. 自检

- [ ] 除了 `<script>`，是否也把 `href`（CSS/图标/manifest）纳入了？
- [ ] 是否探了 **Service Worker**（`sw.js` / `service-worker.js`）？
- [ ] 是否探了 `manifest.json`？
- [ ] 是否批量探了 `package.json` / lock 文件 / 各语言依赖清单？
- [ ] 是否探了 `.env` / `webpack.config.js` / `Dockerfile` / CI 配置？
- [ ] 是否探了**目录列目录**（autoindex）？
- [ ] 是否看了 `robots.txt` / `sitemap.xml`？
- [ ] 有 GraphQL 是否试了 introspection？
- [ ] 有 PDF/Office/图片是否查了**元数据**？
- [ ] 命中的是**目标自己的**文件，还是第三方库的？
- [ ] 有没有把「能下载到」直接当漏洞报？（多数只能当佐证）

---

## 7. 一句话

**JS 之外先探 Service Worker 与 manifest，再批量探 lock 文件 / `.env` / CI 配置 / Dockerfile；查目录列目录、robots、sitemap、GraphQL introspection；PDF 与图片查元数据；拿到的多是佐证不是洞——写进主报告的攻击链，别单独交。**
