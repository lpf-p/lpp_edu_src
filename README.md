> **免责声明**：本仓库内容整理自公开安全研究资料与 SRC 实战沉淀，仅供**已授权**的安全测试、SRC 漏洞挖掘与防御研究学习使用。
> 严禁用于任何未授权目标或违法用途；使用者须自行遵守所在地法律法规与目标平台授权范围，一切后果由使用者自行承担。

# lpp_edu_src — 移植说明

从 Grok Build 身份包 `clown-src-6k-skill` 移植到 WorkBuddy 的 SRC 挖洞技能。

## 来源

| 项 | 值 |
|---|---|
| 源包 | `D:\src_tools\skill\clown-src-6k-skill`（原始版，规则完整） |
| 参考包 | `D:\src_tools\skill\src-6k-security-research-skills-main`（第三方 jiker666 重构版，仅取其 fofa_MCP 补丁） |

> 注：两个包原位于 `D:\src_tools\` 根下，2026-09-13 19:41 被移入 `D:\src_tools\skill\` 子目录。
| 移植日期 | 2026-09-13 |
| 目标 | `~/.workbuddy-ai/skills/lpp_edu_src`（用户主目录下，各机器按各自用户名放置） |

## 目录结构

```
lpp_edu_src/
├── SKILL.md                    # 入口：路由 + 红线 + 规则速查表
├── rules/                      # 12 份运行时规则（原 ~/.grok/rules/ + 1 份新增）
├── 知识库/                     # 专题手法（原 skills/skill/知识库/）
└── reference/                  # 仅存档，不参与运行
    └── grok-config.toml        # 原 Grok config.toml（MCP 定义参考）
```

## 做了什么改动

1. **路径改写**：16 处 `~/.grok/...` 硬编码引用全部改写为本技能根目录绝对路径。
   - `~/.grok/rules/` → `<root>/rules/`
   - `~/.grok/skills/skill/知识库/` → `<root>/知识库/`
   - `~/.grok/mcp-servers/` → `<root>/mcp-servers/`
   - `~/.grok/config.toml` → `~/.workbuddy-ai/mcp.json`
2. **浏览器规则重写**：`rules/playwright-browser-mcp.md` 从 Grok 双槽 Playwright MCP 改为 WorkBuddy 内置 `agent-browser` 技能。
3. **修复源包缺陷**：`rules/researcher-blackbox-whitebox.md` 原文件**头部 1–43 行被 `playwright-browser-mcp.md` 内容整段覆盖**，导致白盒 Phase 0 与表格前两行丢失（第 44 行只剩 `） | 不可信输入最密集 |` 残片）。本版已移除重复块并重建 Phase 0。
   - 已**同时回修源包** `D:\src_tools\skill\clown-src-6k-skill\rules\researcher-blackbox-whitebox.md`，原损坏件备份为 `researcher-blackbox-whitebox.md.bak-head-clobbered`。
   - D1 重构包的归档副本 `docs/legacy-rules/researcher-blackbox-whitebox.md` **仍是坏的**（未改动，保持第三方原件原样）。
4. **FOFA 资产搜索改为网页手动跑**：本技能**不捆绑 fofa MCP、不要求任何 key**。把案例库里的 FOFA 语法直接抄进 fofa.info 搜索框即可；无配额时走 `dig-scope` §2.1.4 的 DNS+HTTP+crt 活筛兜底。（原 jiker666 重构版的 fofa_MCP 补丁已不再随包分发。）

## 规则加载机制差异（重要）

Grok 把 `~/.grok/rules/*.md` **全部常驻**进上下文；WorkBuddy 只加载 `SKILL.md`。
因此 `SKILL.md` 里加了两节补足：

- **启动必读**：进站前先读 `dig-scope-workflow.md` + `src-value-hunting.md`；写报告前读 `vuln-report-format.md`。
- **规则速查表**：把 `dig-scope`、`src-value`、`hunt-iter` 等裸短名映射到具体文件，避免解析失败。

## 还没做的

- 本技能**不依赖 fofa MCP、不需要任何 key**：FOFA 查询在 fofa.info 网页手动跑（语法散见各案例库 + `知识库/recon-methodology.md` 文首）；无配额时走 `dig-scope` §2.1.4 兜底。
- 本机 `~/.grok` 仍不存在，Grok Build 版未安装（不影响本技能运行）。

