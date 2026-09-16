# 代码审计与漏洞专题实战案例（ima 案例库深挖）

> **回查原文** → `ima-retrieval-index.md` §四（ima `src报告/其他/Web` 中"代码审计专题"115 条；关键词与项目名见该表）。

> 来源：ima 知识库 `src` → `src报告/其他/Web`（547 条中"漏洞类型与代码审计专题"约 115 条，按标题关键词筛出代码审计/具体漏洞类型条目，去重（去 `(n)`/`_(n)`/`_2021xxxx` 后缀 + size 相同）后唯一 **41 份**，原始含副本约 95 条；精读 **23** 份；读取失败 **0** 份）
> 定位：**白盒审计的真实切入点、危险函数与利用链**；方法论见 `researcher-blackbox-whitebox.md`，本文件补"真实项目里的样子"。
> 生成日期：2026-09-14
> 说明：全部案例均取自 SRC/授权评估语境，仅作威胁认知与防守复盘，未授权目标一律不做；其中红队演练类（见案例索引 #23）涉及权限维持，属授权复盘，非 SRC 众测手法。

## 一、代码审计切入点清单（按语言/框架）

### 1.1 Java（Spring / SSM / 通用 Mapper / 反序列化 / SpEL / 文件操作 / 权限注解缺失）

- **MyBatis `${}` 拼接 → SQL 注入**：全局搜 `*.xml` 中 `${`，重点看 `like`/`order by`/`in`/动态表名。案例 `(java代码审计)某后台管理系统` 中 `DictMapper.xml` 写 `AND di.dict_name like CONCAT('%',${dictName},'%')`，逆向追踪 `nickName` 参数 → `UserController` → `DictDao`，sqlmap 跑出 time-based blind。来源：某后台管理系统。
- **权限注解缺失 / 水平越权**：`@PreAuthorize` 缺失或 `userId` 取自请求体即危险。某后台管理系统 `deleteUser` 仅 `checkUserAllowed` 校验但 `userId` 可遍历批量删；因酷 `updateUser` 实现类无任何身份校验，改 `user.userId` 即可改他人资料。来源：某后台管理系统 / 因酷网校。
- **SpringSecurity 放行配置 → 未授权**：`web.ignoring().antMatchers("/actuator/**")` 把监控页放行，未登录即可访问 `/actuator/env`、`/heapdump` 拖配置与口令。来源：某后台管理系统。
- **验证码绕过**：`VerifyCodeFilter` 把校验逻辑注释掉、仅判 `captcha` 非空即放行；或验证码不过期/可复用。来源：某后台管理系统 / `44-在线验证码的安全隐患`。
- **文件上传（后缀前端可控）**：因酷 `VideoUploadController` 收 `fileType` 参数仅比对文件名后缀，改 `fileType=jsp` 传 jsp 马即 getshell。来源：因酷网校。
- **反序列化**：`ObjectInputStream.readObject`、`JSON.parseObject(fastjson)` 等，看 `pom.xml` 是否引入 `commons-collections 3.1` 等危险版本，结合 ysoserial/marshalsec。来源：Java安全编码基础（某后台管理系统 pom 含 fastjson 1.2.56 但未用 parseObject）。
- **SpEL 注入 → RCE**：`SpelExpressionParser.parseExpression(el)` 中 `el` 外部可控即 RCE（CVE-2018-1260 同类）。来源：Java安全编码基础。
- **XXE**：`SAXReader`/`DocumentBuilder` 等未 `disallow-doctype-decl`，外部实体读 `file:///etc/passwd`。来源：Java安全编码基础。
- **Autobinding（自动绑定）**：`@SessionAttributes("user")` + `@ModelAttribute` 在密码找回流程中可往 session 对象注入 `answer=hehe` 改安全问题。来源：Java安全编码基础。
- **第三方组件**：`pom.xml` 查 `fastjson`/`Struts2`/`Commons Collections`/`Spring Boot` 版本与配置；低版本 Struts2、Commons Collections 反序列化最易利用。来源：41-谈一谈java代码审计。

### 1.2 PHP（框架 ThinkPHP/CI/Laravel、文件上传与包含、命令与代码执行、SQL 拼接）

- **phpMyAdmin 多点**：`js/get_scripts.js.php?scripts[]=../../flag` 任意文件读取；`index.php?copyright=ls` 代码执行；`index.php?target=/flag` 文件包含（需登录）；`import.php` 用 `select ... into outfile` 写 webshell。来源：9_phpmyadmin 漏洞报告。
- **调试环境搭审计台**：`phpstorm + xdebug`（phpstudy 起服务、配 `xdebug.remote_host/port`、路径映射、断点）对 ThinkPHP 等做动态跟踪，比纯静态快。来源：phpstorm xdebug 调试php代码。

### 1.3 其他（.NET、前端 JS / REST）

- **.NET 反编译审计**：`dnSpyx`/`ILSpy`/`dotPeek` 反编译 `*.Web.dll` 导出入 Rider，全局搜"上传"定位 `HttpPostedFileBase`；`System.IO.File.Delete(path)` 任意文件删除可删 `web.config` 让 webshell 恢复执行；另有任意文件读取。来源：记一次红队攻防中.Net代码审计（⚠️ 属授权演练复盘，删 config/权限维持非 SRC 众测手法）。
- **REST API / 前端**：从 Swagger 文档拿全量接口，用 AppSpider+Swagger 或手工 `PUT /api/user/1` 改 `first_name` 测 SQLi/XSS；关注 `Authorization: Token` 校验。来源：Restful-API安全测试。

## 二、危险函数 / 危险关键字速查表

| 语言/框架 | 搜什么关键词 | 危险原因 | 常见利用方式 | 来源案例 |
|---|---|---|---|---|
| Java/MyBatis | `${` 在 `*.xml` | 字符串拼接非预编译 | SQL 注入（like/in/order by） | 某后台管理系统、因酷网校 |
| Java | `ObjectInputStream.readObject` / `JSON.parseObject` | 反序列化用户输入 | 借助危险三方库 RCE | Java安全编码基础 |
| Java | `SpelExpressionParser.parseExpression` | SpEL 表达式外部可控 | SpEL 注入 RCE | Java安全编码基础 |
| Java | `SAXReader`/`DocumentBuilder`/`XMLReader` | 外部实体未禁用 | XXE 读文件 | Java安全编码基础 |
| Java | `@SessionAttributes`+`@ModelAttribute` | 请求参数绑到 session 对象 | Autobinding 改关键字段 | Java安全编码基础 |
| Java | `Runtime.getRuntime().exec`/`ProcessBuilder` | 命令参数用户可控 | 命令执行 | Java安全编码基础 |
| Java | `MultipartFile`/`getOriginalFilename` | 后缀校验不严/前端可控 | 上传 jsp/webshell | 因酷网校 |
| Java | `new URL(url).openConnection` | URL 未白名单 | SSRF | Java安全编码基础 |
| Java | `@PreAuthorize` 缺失 / 请求取 userId | 无权限校验 | 水平/垂直越权 | 某后台管理系统、因酷网校 |
| PHP | `get_scripts.js.php?scripts[]` / `index.php?target=` | 路径拼接可控 | 任意文件读/包含 | 9_phpmyadmin |
| .NET | `HttpPostedFileBase` / `File.Delete` | 上传/删除路径可控 | 上传马、删 web.config | .NET代码审计 |
| 通用 | `pom.xml` / `composer.json` 依赖版本 | 低版本组件 | 组件漏洞利用 | 41-谈一谈java代码审计 |
| JWT | `alg:none` / 弱密钥 | 签名可置空/可爆破 | 伪造管理员 token | JWT的攻击面、Jwt攻击 |

## 三、漏洞专题实操要点

- **JWT 攻击面**：① `alg:none` 置空签名伪造 administrator；② `jwt_tool`/`hashcat -m 16500` 爆破弱 key（字典 jwt.secrets.list）；③ 水平越权改 `sub`、垂直越权改 `sysadmin:Y`；④ 把 `SQLi`/`命令执行`/`文件读取`/`SSRF` payload 塞进 JWT 业务字段。来源：JWT的攻击面 / Jwt攻击。
- **REST API 安全**：先抓 Swagger `swagger.json` → AppSpider（Swagger Utility）半自动扫；手工 `PUT` 改 `first_name` 验注入/XSS；重点测未授权接口与 `Authorization` 缺失。来源：Restful-API安全测试。
- **文件覆盖 / 任意后缀上传**：判断后缀白名单是否前端可控（如 B站专栏商品图像上传可传任意后缀，BVE-2021047360 高危/200 币）。抓包改 `fileType`/`Content-Type` 验证。来源：任意文件覆盖上传-b站。
- **人脸识别绕过**：账户注销等人脸校验点，先本人验证看返回 `{"verified":"true"}`，再拿他人请求把返回包 `verified:false`→`true` 替换放包即通过。来源：绕过人脸识别-2。
- **越权与不安全对象调用**：① 付费视频 `id` 遍历 + F12 拿 mp4 直链 + 迅雷下载（不安全对象调用案例）；② 小程序练习馆 `rightcode` 替换绕过"建设中"拿积分（脱敏不安全资源调用）；③ 青少年模式 `teenagerSwitch=0`→`1` 解除限制（角色权限缺陷逻辑）。本质是"对象引用/开关参数服务端未校验归属"。来源：三篇对应报告。
- **短信与验证码**：① 验证码与手机号未绑定 → A 发码 B/C/D 复用注册（银行私测中危）；② 验证码不过期/可复用/识别插件 98% 成功率/滑块拼图底图有限可对比破解。来源：逻辑业务漏洞 / 44-在线验证码。
- **支付逻辑**：下单接口 `总金额=单价×数量` 且单价由前端提交，改 `price` 7980→0.01、数量×3 实付 0.03 下单成功。所有价格/数量/折扣必须服务端重算。来源：支付原理与案例。
- **组件 / 未授权**：Redis 默认 6379 未授权（`info` 探测脚本批量扫 FOFA 教育资产，提交 CNVD）；GlassFish 4848 `%c0%ae` 目录穿越读 `admin-keyfile` 拿账号哈希。来源：redis漏洞批量挖掘 / 中间件漏洞--GlassFish。

## 四、案例索引

| # | 报告名 | 类型 | 目标/系统 | 核心漏洞点 | 审计或利用手法 | 结果/定级 |
|---|---|---|---|---|---|---|
| 1 | (java代码审计)某后台管理系统 | 白盒审计 | RefiningStone-RBAC(SSM) | `${}`拼接/越权/actuator未授权/验证码 | 全局搜xml `${}`→sqlmap；userId遍历删；放行/actuator；注释掉验证码逻辑 | 多漏洞实战复盘 |
| 2 | (java代码审计)某商城系统 | 白盒审计 | 某商城系统 | 同类 SSM 审计 | 同框架手法（未精读，超大7MB） | — |
| 3 | 因酷网校在线教育系统JAVA代码审计 | 白盒审计 | 因酷网校(Spring MVC+MyBatis) | XSS/越权/SQLi/上传 | EL未转义；updateUser无校验；deleteArticleByIds `${value}`；fileType可控jsp马 | 高危可getshell |
| 4 | 某菠菜代码白盒审计 | 白盒审计 | 某菠菜系统 | 综合审计 | 框架级（16MB未精读） | — |
| 5 | Java安全编码与代码审计基础 | 审计教材 | 通用 | XXE/反序列化/SpEL/SSRF/上传/Autobinding/命令执行/越权 | 逐漏洞给危险函数+修复示例 | 方法论 |
| 6 | 73-白盒安全测试 | 方法论 | 通用 | 白盒测试分类 | 静态/动态/运行环境审计；工具Fortify/RIPS/Taint | 方法论 |
| 7 | 41-谈一谈java代码审计 | 方法论 | 通用 | Java审计重点 | 关注SQLi/上传/未授权/垂直越权+低版本组件 | 方法论 |
| 8 | 记一次红队攻防中.Net代码审计 | .NET审计 | 某XXX系统 | 上传/任意文件删/读 | dnSpyx反编译→搜"上传"；`.cer`绕WAF；`File.Delete`删web.config | ⚠️授权演练复盘 |
| 9 | phpstorm xdebug调试php代码 | 环境 | ThinkPHP等 | PHP动态调试 | phpstudy+xdebug 断点跟踪 | 环境搭建 |
| 10 | 9_phpmyadmin 漏洞报告 | 组件 | phpMyAdmin | 任意读/包含/代码执行/写马 | `scripts[]=../../flag`；`?copyright=ls`；`into outfile` | 漏洞报告 |
| 11 | JWT的攻击面 | 漏洞专题 | JWT应用 | key爆破/越权/注入 | jwt_tool爆破；sub/sysadmin改值；字段塞payload | 高危 |
| 12 | Jwt攻击 | 漏洞专题 | JWT应用 | alg:none/弱密钥 | hashcat -m 16500；portswigger靶场 | 高危 |
| 13 | Restful-API安全测试 | 漏洞专题 | REST API | 注入/XSS/未授权 | Swagger+AppSpider；PUT测参 | 方法论 |
| 14 | 中间件漏洞--GlassFish | 组件 | GlassFish 4848 | 目录穿越/任意读 | `%c0%ae` 读 win.ini/admin-keyfile | 高危 |
| 15 | redis漏洞批量挖掘 | 组件 | Redis 6379 | 未授权 | FOFA搜+socket脚本批量`info`探测 | 提权/CNVD |
| 16 | 不安全对象调用案例 | 逻辑/越权 | 某教育视频SRC | 付费资源未授权 | F12拿mp4直链+迅雷下载 | 中~低危 |
| 17 | 脱敏不安全资源调用 | 逻辑 | 某小程序 | 开关/code绕过 | rightcode替换绕过"建设中"拿积分 | 低危 |
| 18 | 任意文件覆盖上传-b站 | 上传 | BILISRC专栏 | 任意后缀上传 | 商品图可传任意后缀 | 高危/200币 |
| 19 | 绕过人脸识别-2 | 生物识别 | 某App注销 | 返回包替换 | verified:false→true绕过人脸 | 中危 |
| 20 | 阿里某处referer绕过案例 | 逻辑 | 阿里jsonp | referer校验绕过 | `www.qq.com&@qishi.sm.cn`劫持 | jsonp劫持 |
| 21 | 宇视科技视频监控main-cgi密码泄露 | 信息泄露 | Uniview摄像机 | main-cgi泄露 | `cmd:255` 下载Config.xml拿账号密码 | 高危POC |
| 22 | 44-在线验证码的安全隐患 | 漏洞专题 | 通用 | 验证码绕过 | 识别插件/不过期/滑块可破解 | 科普 |
| 23 | 逻辑业务漏洞 | 逻辑 | 某银行私测 | 短信验证码未绑定 | A发码B/C/D注册 | 中危/10币 |
| 24 | 角色权限缺陷逻辑 | 越权 | 百度全民小视频 | 青少年模式开关 | teenagerSwitch改1绕过 | 低危/10币 |
| 25 | 支付原理与案例 | 逻辑 | 某支付 | 单价前端可控 | price 7980→0.01 实付0.03 | 高危(已修复) |

## 五、未精读清单（标题级归类）

- **Java/PHP 审计环境类（与已读重复或环境向）**：(java代码审计)某商城系统（7.2MB，同框架）、1.java安全-环境操作（671KB，环境配置）、1_某友的0day挖掘机（7.6MB，偏工具）。
- **组件/中间件（可补）**：Apache详解及漏洞复现（3.1MB）、74-NFC支付安全（2MB）。
- **逻辑/支付（同类已读代表，余下作交叉样本）**：逻辑支付（PPT）、逻辑支付之直接关系、使用其他支付方式购买合作优惠商品、百度平台商家爱番番：支付原理与案例、美团商城逻辑对抗逻辑之十块钱变十万、滴滴仓库逻辑支付、支付原理与案例（v2，size 1326217 不同版本）、水一篇众测的漏洞报告、国家市场监督管理总局存在权限认证缺陷。
- **人脸/资源副本**：绕过人脸设别（367KB，与"绕过人脸识别-2"不同 size 视为另一版本，未读）。
- **科普系列（非本专题，仅列名）**：33-零基础如何挖漏洞、58-勒索软件解析（一）（归"安全科普"类，不纳入本文件）。

## 六、不纳入项

- **CORS.pdf**（技能包红线"不挖"）——本文件不纳入，仅保留认知：CORS 配置缺陷（ACAC:true +  Origin 校验不严谨）可劫持账户，但 SRC 打点范围不含。
- **SRC挖掘经验-cors劫持账户.docx、亿速云官网的cors挖掘历程.docx** —— 均属 CORS 红线范畴，不纳入。
- **JWT 已有 `oauth-jwt-test.md` 覆盖**攻击面与测试；本文件仅补 `JWT的攻击面`/`Jwt攻击` 两篇的实战利用链，不重复方法论。

## 七、厂商定级尺度观察

- **组件/未授权类**（Redis、GlassFish、宇视 main-cgi）：若影响核心资产可报 CNVD/高危；SRC 侧通常中~高危。
- **上传/解析类**（B站任意后缀、因酷 jsp 马）：高危，B站给 200 安全币，属打点硬货。
- **逻辑/支付类**（短信未绑定、支付改价、青少年模式）：普遍中~低危但批量刷分利器；支付类涉资金通常高危（本文"已修复"）。
- **越权/不安全对象调用**（付费视频、练习馆积分）：中低危，看是否可实质冒用/获利。
- **人脸绕过**：中危为主，取决于能否冒用他人身份完成业务。
- **JWT/算法缺陷**：高危（可伪造管理员），但需证明实际影响面。
- 观察：厂商对"可自动化批量"的逻辑漏洞（验证码复用、积分、注册）定级偏保守（低危/少量币），对"直接 getshell/未授权核心数据"定级慷慨。

## 八、素材缺口

- ~~缺独立**反序列化实战专题**（仅 Java安全编码基础 理论 + 某后台管理系统 fastjson 提及"未实际使用"）~~ ✅ **已由他处覆盖（2026-09-15 核实，不再单列）**：`deserialization-test.md`（CC/CB/Spring/JDK 链 + 版本兼容矩阵）、`jndi-injection-test.md`（JNDI + JNDIExploit 回显）、`subkb-netsec-cases.md` §2（"不看版本看依赖"探测四步）。**本文件真正的缺口是"从源码定位到反序列化入口"的审计视角**（搜什么 sink、怎么看 `parseObject` 的参数来源），那才是该补的。
- ~~缺 **Shiro**（rememberMe 反序列化）、**ThinkPHP 具体版本 RCE** 实战~~ ✅ **部分覆盖**：`nday-watchlist-2026.md`（认版本核 Nday）+ `attack-chain-cases.md`（Shiro 默认 key 实战链）。
- 缺 **SSTI/模板注入、XXE** 真实案例（仅理论）→ **XXE 已由 `lfi-xxe-cases.md` 覆盖**；**SSTI 仍只有 `ssti-test.md` 方法论、无真实案例，本条成立**。
- 缺更多**厂商支付/逻辑**交叉样本以校准定级。
- ⚠️ **结构性提醒**：本段写于「其他」目录普查之前，未与后来新建的 `deserialization-test.md` / `jndi-injection-test.md` / `nday-watchlist-2026.md` / `lfi-xxe-cases.md` 对账，**6 条里 3 条已作废**。全库共 14 个「素材缺口」段存在同一毛病（各自孤立、互不知情）——建议统一对账，或收敛进 `ima-corpus-progress.md` 一份总台账。
- CORS 按红线不纳入，JWT 由 `oauth-jwt-test.md` 覆盖，本文件已注明不重复。
- 超大文件（某商城 7.2MB、某菠菜 16MB、Apache 3.1MB）仅作框架级标注，建议后续按需抽读关键章节。
