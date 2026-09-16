# 中间件 / 框架未授权面 + 影子 API

> 定位：`src-value-hunting.md` §3 的「弱口令 / 默认口」「敏感路径」两行的**正文**。`info-leak-test.md` §2.1 只列了几个常见路径，本篇是**逐个组件的未授权面**。
> 衔接：`cloud-ide-codex-rce-chain.md`（编程台）、`api-gateway-test.md`（网关）、`recon-methodology.md`（怎么找）。
> 冲突以 `rules/src-value-hunting.md` 与 `rules/vuln-report-format.md` 为准。

> **实战案例（双向引用）** → `infoleak-cases.md` §2 调试端点（北京教委 `/api/actuator/heapdump` 未授权下载，解密出 redis / oracle 连接密码；**Swagger 被删时走 `/actuator/mappings` 取 `patterns` 拿全量路由**）；`cmd-injection-cases.md` §二打法分类 5（Nacos 2.3.2/2.4.0 配置接口 RCE、K8s 8080 未鉴权 `exec`、WebLogic `_async`/`wls-wsat` XMLDecoder）；`vendor-system-cases.md` §1（浙江计量院 actuator、贵州电网 heapdump、某保险云 `actuator/env` 泄露 OBS AK/SK → 接管 37 台）；`weak-password-cases.md` §一（Druid `/druid/login.html`）；`mobile-cases.md` §3（小程序 fuzz 到 `/v2/api-docs` 未授权 Swagger，本地挂载拿全套接口）。

---

## 0. 为什么这一类性价比高

- **不依赖业务账号**，不依赖登录态
- 未授权配置接口常直接给**数据库密码 / 云密钥**，一步到高危
- 中间件版本暴露本身就是佐证，能定向到已知 CVE

**但注意**：只开 `health` / `info` 的 Actuator 单独交会被判「无意义信息泄露」。**要么跟到凭据，要么当佐证并入主链**（见 `password-reset-test.md` §八「佐证合并」）。

---

## 1. 先识别：怎么知道有中间件

| 手段 | 做法 |
|---|---|
| 特征路径 | 直接试下表里的路径，看 200 / 302 / 401 的差异 |
| 响应头 | `Server` / `X-Powered-By` / `X-Application-Context` |
| 错误页 | 默认错误页自带组件名与版本 |
| favicon hash | 算 favicon 的 mmh3 hash，比对指纹库 |
| FOFA 语法 | 见 `recon-methodology.md` 文首（**节奏仍认 `dig-scope`**） |

**别停提示**：403 不等于没有——换路径、换大小写、加/去尾斜杠、换 METHOD 再试一次。

---

## 2. 逐个组件的未授权面

| 组件 | 端口 | 未授权 / 默认口 | 打通后跟什么 |
|---|---|---|---|
| **Nacos** | 8848 | `/nacos/v1/auth/users?pageNo=1&pageSize=9`（列用户）、`/nacos/v1/console/namespaces`、`/nacos/v1/cs/configs?dataId=&group=&pageNo=1&pageSize=100&tenant=`；默认 `nacos/nacos` | 配置里常含**数据库密码 / 云 AK** |
| **Spring Actuator** | 应用端口 | `/actuator` `/actuator/env` `/actuator/configprops` `/actuator/mappings` `/actuator/heapdump` `/actuator/httptrace` `/actuator/jolokia/list`；老版本 `/env` `/mappings` | heapdump 用 MAT 挖密码；jolokia 可到 RCE |
| **Swagger / OpenAPI** | 应用端口 | `/swagger-ui.html` `/swagger-ui/index.html` `/v2/api-docs` `/v3/api-docs` `/swagger-resources` `/doc.html`（knife4j） | **反推全部接口** → 喂给 `src-value-hunting` §3 矩阵 |
| **Druid** | 应用端口 | `/druid/index.html` `/druid/sql.html` `/druid/websession.html` | 监控台可见 SQL、URI、**Session**；弱口令 `admin/admin` |
| **Jenkins** | 8080 | `/api/json` 列任务、`/script` Groovy 控制台、`/manage` | 未授权脚本控制台 → RCE |
| **GitLab** | 80/443 | 开放注册、`/explore` 公开项目、`/api/v4/projects` | 内部源码 → 硬编码凭据 |
| **Elasticsearch** | 9200 | `/_cat/indices?v` `/_search?pretty` `/_nodes` `/_cluster/health` | 全量数据泄露 |
| **Kibana** | 5601 | `/app/kibana` `/app/home` `/api/status` | 索引数据 + 老版本 Timelion RCE |
| **MinIO** | 9000/9001 | `/minio/health/live` 探活、`/minio/bootstrap/v1/verify`；默认 `minioadmin/minioadmin` | 对象存储全量读写 |
| **Consul** | 8500 | `/v1/kv/?recurse` `/v1/agent/self` `/v1/catalog/services` `/v1/acl/list` | 服务拓扑 + 配置（含凭据） |
| **etcd** | 2379 | `/v2/keys/?recursive=true`、`/v3/kv/range`（POST base64 key） | K8s 全量 Secret |
| **RabbitMQ** | 15672 | 管理台默认 `guest/guest`、`/api/overview` | 队列消息正文 |
| **Redis** | 6379 | 未授权 `INFO` / `CONFIG GET` | 见下方红线，**只读** |
| **Docker API** | 2375 | `/version` `/containers/json` `/images/json` | 可起容器挂宿主 → 高危 |
| **Zookeeper** | 2181 | 四字命令 `envi` `dump` `cons` `stat` | 节点数据 |
| **Grafana** | 3000 | `/api/health` 探活；默认 `admin/admin`；`/public/plugins/<plugin>/../../../../etc/passwd` | 数据源配置（含数据库账密） |
| **Prometheus** | 9090 | `/api/v1/targets` `/api/v1/status/config` `/api/v1/query?query=up` | 全部被监控目标 |
| **XXL-JOB** | 8080 | `/xxl-job-admin` 默认 `admin/123456` | 执行器命令执行 |
| **Eureka** | 8761 | `/eureka/apps` | 内网服务清单 |
| **Hystrix** | 应用端口 | `/hystrix.stream` | 内部接口调用详情 |
| **Sentinel** | 8080 | 默认 `sentinel/sentinel` | 流控规则 |
| **Solr** | 8983 | `/solr/admin/cores?wt=json` | 索引数据；老版本 Velocity RCE |
| **Harbor** | 80/443 | `/api/v2.0/projects` `/api/v2.0/systeminfo` `/api/v2.0/health`；默认 `admin/Harbor12345`；未授权拉镜像 | 内部镜像 → 源码 |
| Harbor **去伪**（必看，否则必误报） | — | 匿名能列项目 **不等于漏洞**：看 `metadata.public`。**`public=true` 时匿名可读是 Harbor 设计行为，不是洞**。真洞的判据是：① 匿名能列到 `public=false` 的私有项目 ② `/v2/<repo>/tags/list` 匿名 200（能真 pull 到层）③ `self_registration=true`（可自注册进私有项目）。三条都不满足就**别交**。`/api/v2.0/users` `/statistics` `/configurations` 返 401 = 鉴权正常，是正常的 | 只拿到镜像名/tag/大小清单 = 情报，不是洞 |
| **Tomcat** | 8080 | `/manager/html` `/host-manager/html` 弱口令 | 部署 war → RCE |
| **Weblogic** | 7001 | `/console` 默认 `weblogic/Oracle@123` | 多个反序列化 CVE |
| **Nexus** | 8081 | 默认 `admin/admin123`；`/service/rest/v1/repositories` | 内部制品 |
| **APISIX** | 9080 | `/apisix/admin/routes` 默认密钥 `edd1c9f034335f136f87ad84b625c8f1` | 路由改写 → SSRF/RCE |
| **Skywalking** | 8080 | `/graphql` 未授权 | 链路数据（含参数） |
| **Jolokia** | 应用端口 | `/jolokia/list` `/jolokia/exec/` | JMX → 多种 RCE |

**别停提示**：
- Actuator 只开 `health` **别停** —— 逐个试 `/env` `/heapdump` `/jolokia`，可能没在根路径而是在 `/manage/` 前缀下
- Nacos 列用户接口在新版本已加鉴权，**别停** —— 试 `User-Agent: Nacos-Server`（老版本绕过）与默认口令
- ES 返回 401 **别停** —— 试 `/_cat/indices` 与 `/_search`，鉴权可能只挂在部分路径

---

## 3. 影子API / 影子接口 / 未授权 API 资产

中间件之外，「没人调用但还活着」的接口是另一个高产面。

| 形态 | 打法 |
|---|---|
| 版本并存 | `/api/v1` 有鉴权 → 试 `/api/v2` `/api/v0` `/api/beta` `/api/internal` |
| 环境前缀 | `/test` `/dev` `/uat` `/pre` `/staging` `/gray` |
| 内部前缀 | `/internal` `/admin` `/manage` `/console` `/actuator` `/debug` |
| JS 里没被页面调用的接口 | 从 `js-reverse-guide.md` 抽出的清单里，挑**页面没调过**的打 |
| Swagger 反推 | 文档里全部接口，逐个去掉鉴权头打一遍 |
| 老域名 / 老端口 | 同 IP 的其他端口、`old.` / `new.` / `test.` 子域 |

**关键**：影子 API 常常**只有前端没接、后端照跑**，鉴权往往没跟上。

---

## 4. 打通后跟什么（别停在这一步）

1. **出接口清单** → 回 `src-value-hunting` §3 类型矩阵，逐个过一遍
2. **出配置 / 环境变量** → 找数据库账密、云 AK/SK、JWT secret
3. **出凭据后** → 按 `src-value-hunting` §2：**假值对照**证明生产认这个钥 → 认钥枪须带出身份或列表 → 再打**不影响线上的只读例**
4. **出内网地址** → 进本站队列（`dig-scope` §4.1.3），配合 SSRF 再打

**抄到凭据就停手交报告 = 禁止**（对齐 `src-value-hunting` §2）。

---

## 5. SRC 红线

- **只读**：`INFO` / `CONFIG GET` / `_cat` / `/v1/kv` 这类读接口可以打
- **禁止**改配置（`CONFIG SET`、`/actuator/env` POST、Nacos 改配置）
- **禁止**删数据、清索引、drop 库
- **禁止**重启 / 关停服务
- **禁止**用 Redis 写文件落地 webshell、用 Docker API 起容器挂宿主
- 默认口令**只试一次**，不跑字典爆破（对齐 `dig-scope` §4.1.1：登录表单弱口令不当必做）

---

## 6. 假点

- 只有**默认错误页**，没有实际接口 → 只是指纹，不是洞
- Actuator 只开 `health`，无任何其他端点 → 单独交会被判「无意义信息泄露」，**当佐证**
- 中间件版本号能读到但**无未授权接口**且**无对应 CVE** → 不是洞
- 组件在内网、你的请求根本打不到 → 不是这站的问题
- 默认口令页面存在但登录被拦（验证码 / IP 白名单）→ 停，别磨

---

## 7. 自检

- [ ] 是否逐个试过下表的**未授权路径**，而不只看首页？
- [ ] 403 / 401 是否**换路径、换大小写、换 METHOD** 再试过？
- [ ] Actuator 只开 `health` 时，是否试过 `/env` `/heapdump` `/jolokia` 与 `/manage/` 前缀？
- [ ] Swagger 出了接口清单，是否**回 §3 矩阵逐个过**（不是只截图交报告）？
- [ ] 影子 API（版本并存 / 环境前缀 / 内部前缀）是否试过？
- [ ] 拿到凭据后是否做了**假值对照 + 只读例**，而不是抄到就停？
- [ ] 有没有改配置 / 删数据 / 重启服务 / 写文件落地？
- [ ] 只开 `health` 的发现，是否当**佐证**并入主链而不是单独交？

---

## 8. 一句话

**先识别再逐路径试；403 换路径换方法；Actuator 别停在 health；Swagger 出了清单就回矩阵；拿到凭据必做假值对照与只读例；只读、不改、不删、不重启。**
