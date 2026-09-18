> **免责声明**：本仓库内容整理自公开安全研究资料与 SRC 实战沉淀，仅供**已授权**的安全测试、SRC 漏洞挖掘与防御研究学习使用。
> 严禁用于任何未授权目标或违法用途；使用者须自行遵守所在地法律法规与目标平台授权范围，一切后果由使用者自行承担。

# lpp_edu_src

SRC 挖洞 + 白盒 0day 审计的技能包（WorkBuddy skill 格式）。

---

## 一、它是做什么的

一句话：**把「挖什么 → 怎么挖 → 怎么写成能过审的报告」这套流程固化成可复用的规则与知识库**，让 Agent 接手后按流程跑，而不是每次临时发挥。

### 三块能力

| 能力 | 解决什么问题 |
|---|---|
| **黑盒 SRC 挖洞**（主） | 给一个目标（集团名 / 域名 / URL），从资产测绘、指纹识别、按目标特征选打法，一路做到落报告 |
| **白盒 0day 审计** | 给一份源码（Linux Kernel / Chromium / Laravel / Spring / Django 等），按 Phase 0～6 找开发者认知盲区 |
| **实战案例知识库** | 90 份专题文档，其中 18 份是 ima 案例库 1300+ 份真实报告的去重提炼——不是教程，是「别人真交过、真收了」的打法 |

### 它特别适合的场景

- **教育行业 / EDUSRC**：统一身份认证（金智 wisedu）、WebVPN（网瑞达）、图书馆资源代理（创文 ERMS）等入口类资产有专门的指纹判据与打法表
- **模糊目标**：只知道集团名、没有 URL 清单 —— 有「自由跳」节奏规则，自己找资产边找边挖
- **批量目标**：多资产 / 一份 zip 几十份报告要鉴定 —— 有假阳性控制规则 + 批量探根脚本

### 它不是什么（重要）

- ❌ **不是扫描器**：不自动扫漏洞，`nuclei` 只在需要已知 CVE 时当辅助，禁止「全量模板扫一遍」当进度
- ❌ **不捆绑任何 key**：不依赖 fofa MCP，FOFA 语法在 fofa.info 网页手动跑；无配额时走 DNS+HTTP+crt 活筛兜底
- ❌ **不替代判断**：知识库给的是「这类目标通常打什么」，具体打不打、打没打中，仍要现场取证

---

## 二、怎么用

### 安装

放到用户主目录的 skills 下（各机器按各自用户名）：

```
~/.workbuddy-ai/skills/lpp_edu_src
```

放好即可，无需配置、无需 key。

### 触发

技能自动匹配。说这些就会命中：

> `挖 xxx 集团` / `帮我测一下这个站` / `这个平台有没有漏洞` / `挖 src` / `越权测试` / `JS 逆向找接口` / `WAF 绕过` / `写漏洞报告` / `代码审计` / `审计这个项目`

注意：**「挖」后面跟集团/品牌名，没给 URL 也算** —— 会走自由跳流程自己找资产。

### 一次任务的流程

| 步 | 做什么 | 对应文件 |
|---|---|---|
| 0 | **授权与范围**：确认目标在 SRC 公布范围内 / 自有资产 / 有书面授权。三者都不成立就停 | `rules/security-research-context.md` |
| 1 | **资产测绘**：起手落盘种子队列（业务名 + SRC 范围域 + 全资子公司域，禁止只有一条）；一种子闭环，挖完再换 | `rules/dig-scope-workflow.md` §1.0.1 |
| 1.5 | **判存在性**（锁面有资产清单时必做）：厂商公布的清单里**混着空壳 / 默认页 / 泛记录**。逐台「响应体 `sha1` vs 同批实时双基线」定论，**状态码不可信**；逐台落资产账本 | `rules/asset-existence-and-coverage.md` |
| 2 | **进站指纹**：每个种子都要过 —— 认指纹 / 判 CDN / 判泛解析。**不做这一步就开打 = 闭眼扔飞镖** | `知识库/recon-fingerprint-cdn-wildcard.md` |
| 3 | **选模块打**：按目标特征查 `SKILL.md` 的「对得上再开」表，命中哪个开哪个文件 | `知识库/*.md`（见 `SKILL.md` 知识库目录表） |
| 3.5 | **功能点过 12 维**（反查）：对登录 / 支付 / 审批 / 上传 / 权限 / 报表这类**有业务逻辑的功能点**，逐条问 12 个维度并**自己命威胁名**，补上类型矩阵漏掉的形态 | `rules/dig-scope-workflow.md` §4.1.4 |
| 4 | **落报告**：中危及以上确认即落 `报告/` | `rules/vuln-report-format.md` |
| 5 | **收工自查**：资产账本判定列无空缺 + 种子队列 pending = 0 + 确证存在的逐个有矩阵记录 + **功能点 12 维过完、`coverage_note` 三问已答、报告里无「疑似」、每条 `not_vulnerable` 都带 `unruled_out`** | `rules/asset-existence-and-coverage.md` §6 + `rules/verdict-states.md` |

### 三条最容易用歪的纪律

1. **规则不会自动加载。** Grok 版会把 `~/.grok/rules/` 全部常驻，WorkBuddy 只加载 `SKILL.md`。所以 `SKILL.md` 里列了「启动必读」清单 —— **进站前**读 `dig-scope-workflow.md` + `src-value-hunting.md`，**写报告前**读 `vuln-report-format.md`。不读 = 技能只加载了个目录。
2. **自由跳不许停工问。** 模糊目标且用户没叫停时，禁止问「要不要继续？」「其他品牌要不要也挖？」。一轮搜完 ≠ 任务结束，种子队列还有 pending 就不能以问句收尾。
3. **报告版式只有一个来源。** 正式报告只认 `rules/vuln-report-format.md`（含 EDUSRC 特别条款），不要用自己习惯的模板。
4. **技能没出现在 skill 列表里，先查目录入口，别急着说"技能不存在"。** 实体放在 `~/.workbuddy-ai/skills/` 而会话只加载 `~/.workbuddy/skills/` 时，技能**静默不加载**（不报错、不提示）。修法：把关键 skill 用 **Windows 目录联接**接入当前目录，一份实体两个入口（`cmd /c 'mklink /J "<当前目录>\skills\<name>" "<原目录>\skills\<name>"'`）；**新建/联接后需重开会话**才会出现在列表里。

### tools/ 批量脚本（可选）

入口类资产（统一认证 / WebVPN / 资源代理）批量识别三步。判据表外置在 `fingerprint_markers.py`，加新指纹只改这一个文件。

```bash
# 1) 探根：hosts.txt 每行一个 host 或 host:port → result.tsv + _raw/
python tools/probe_roots.py hosts.txt --out-dir ./sweep_out

# 2) 分类：出统计报告（特征命中 / Server 分布 / Cookie 分布 / 厂商归属 / 未定性清单）
python tools/classify_results.py ./sweep_out/result.tsv --raw-dir ./sweep_out/_raw --top 30

# 3) 跟一跳：挑 root 301/302 且体积 <300 的站跟跳（≤4 次）后重新分类
#    实测：root 未定性的站跟一跳后 44% 直接拿到判据
python tools/follow_redirects.py ./sweep_out/result.tsv --raw-dir ./sweep_out/_raw --max 30 --out follow_report.txt
```

纪律：**只发 GET、不带凭据、不爆破、不碰利用**，目标必须是已授权范围内的资产。详见 `tools/README.md`。

---

## 三、目录结构

```
lpp_edu_src/
├── SKILL.md                    # 入口：路由表 + 红线 + 规则速查表（唯一自动加载的文件）
├── rules/                      # 15 份运行时规则（流程与纪律，不常驻，按「启动必读」主动读）
├── 知识库/                     # 90 份专题：打法 + 案例库提炼 + 厂商系统速查
├── tools/                      # 批量探根 / 指纹分类 / 跟一跳验证脚本（判据表外置）
├── check_desensitize.py        # push 前自检：公开版是否残留未打码的活目标
├── mcp-servers/                # 本机 MCP 能力索引（本地专用，不进公开版）
└── reference/                  # 仅存档，不参与运行
```

**rules 与 知识库 的分工**：rules 管「流程与纪律」（怎么排队、什么时候换资产、报告什么版式），知识库管「具体怎么打」（这类目标打什么、payload 长什么样）。两者冲突时 **以 rules 为准**。

---

## 四、红线

- 越权验证用**读/列表差分**优先；写越权可测但顺序是「先添加 → 再删自己刚加的那条」，不改别人已存在的订单/地址/密码/角色；禁止批量、禁止真资损
- **禁止登出/注销**操作（用户提供登录态后，全程不得调用 `/logout`、`/revoke`，不得测「退出后会话还有效」）
- **CORS 永久不挖**
- 禁止破坏性利用、禁止留后门、禁止拖库
- 不索取/留存真实敏感数据（身份证、手机号、成绩、支付信息），验证做到「能证明存在」即止

**关于公开版脱敏**：本仓库的知识库做过合规脱敏 —— 我们自己实测发现的**活目标**一律打码（`webvpn.**.edu.cn` 形态）或泛化（「某高校」「多所双一流高校」），方法论、厂商判据、实验设计保持完整。案例类文档（`*-cases.md`）里的域名与 IP 来自**已公开收录的 SRC 报告**，属公开信息二次整理，故保留原文。改动后 push 前跑一次：

```bash
python check_desensitize.py .                    # 退出码 0 = 无活目标、无新增，可 push
python check_desensitize.py . --update-baseline  # 首次 / 大改后定基（基线仅本地，已 gitignore）
```

脚本内置两道护栏，防止「往案例文件里补自己的实测记录」被文件名豁免静默放过：一是案例文件若出现自建实测标记（如「2026-09-16 实测」）即取消豁免；二是与基线比对，命中数增长即报。两道都只对**基线之外的新增**报错，不会把公开报告里原有的域名翻出来刷屏。

---

## 五、最近更新

- **2026-09-19**：**新增 `tools/probe_existence.py`**（第 -1 步 判存在性：双轨四象限 + **门闸页四联征排除**；配套 `asset-existence-and-coverage.md`，10 台真机验证）。**`asset-existence-and-coverage.md` 增第 4 条禁令**——由一次实战假阳性总结：**9 台主机（`www` + 8 个院系/职能站）状态 200、SHA1 两两各异，初判"确证存在"，实为同一套 WAF JS 挑战页**（`_0x…` 混淆 + `navigator.webdriver` + `Server: ******` + 无 `<title>`）。据此：判定表「异形」**降级为候选**、判定列**增第 5 个允许值「存在但被门闸挡住」**、§3 由三条禁令扩为四条、§0 一句话与 §10 时间线同步。**核心一句：`sha1` 各异 ≠ 有后端 —— 门闸页按 Host 定制，故意让每台都看着"异形"。**
- **2026-09-18（补）**：**新增 `rules/verdict-states.md`**（判定状态词五个 + 三层确认门 + 反早闭 `unruled_out`）+ **`dig-state.json` 断点续跑**（`desktop-task-folder` §1.2）+ **功能点 12 维反查**（`dig-scope-workflow` §4.1.4）。来源：对标一个外部的授权渗透工作台 skill 后吸收，补上本技能原来缺的**假阴性那一半** —— `batch-verify-discipline` 管「别把假的当成真的」（假阳性），`verdict-states` 管「**别把真的漏了、还当测完了**」（假阴性）。同步：`vuln-report-format` §二 增「判定状态 / 盲区去哪」两行、明确**只有 `confirmed` 落盘**；`desktop-task-folder` 开新任务必须建 `dig-state.json`（⛔ 凭据实值不进）；`hunt-iter` 明确判定类产出同样**不受漏洞门槛约束**；`dig-scope-workflow` §4.3 加两条换站下限 + §5 自检两条。**核心一句：一个点测完只有五种说法，只有 `confirmed` 进报告正文，标 `not_vulnerable` 必须先写 `unruled_out`。**
- **2026-09-18**：**新增 `rules/asset-existence-and-coverage.md`**（资产存在性判据「双轨四象限」+ 覆盖率账本 + 判据留痕制度 + 范围判定）—— 由一次十四轮实战被动总结：历轮最值钱的产出全在**判据层**，却因 `hunt-iter` 门槛只收"已落报告的高危/严重"而**一条都进不了库**，导致"用了 skill 反而更浅"。据此同步：`hunt-iter` 明确**判据类产出不受漏洞门槛约束**；`dig-scope-workflow` §4.0 增「第 -1 步 判存在性」+ §0.1「锁面必建资产账本」+ §5 自检两条；`batch-verify-discipline` §1.1 增**主机级基线**；`知识库/recon-fingerprint-cdn-wildcard.md` §2.5 新增「认平台只看 CNAME 后缀」+ §3.2/§3.3 升级为双轨四象限。**核心一句：状态码完全不可信（403/404/200 各被骗一次），只认响应体 `sha1` 与同批实时双基线的比对结果。**
- **2026-09-16**：新增 `tools/` 四个脚本（批量探根 / 指纹分类 / 跟一跳验证，判据表外置到 `fingerprint_markers.py`）；`知识库/recon-fingerprint-cdn-wildcard.md` §1.3 补入 30 站实测校准的入口类判据——**root 只回 301/302 时厂商信息在跳转后的登录页上，必须跟一跳**（实测未定性站跟跳后 44% 拿到判据，但仍不充分）；补金智三个新判据、`Server: Server` = 同一款国产 SSL VPN 的硬判据。
- **2026-09-15**：新增 `rules/batch-verify-discipline.md`（批量探测假阳性控制，实测把 24 条假阳压到 1 条）；`vuln-report-format.md` 增补 EDUSRC 特别条款（定性纪律 / 佐证合并不拆分 / 平台 15 条忽略规则自检）。

---

*源自 Grok Build 身份包 `clown-src-6k-skill`，2026-09-13 移植到 WorkBuddy 并持续实战迭代。*
