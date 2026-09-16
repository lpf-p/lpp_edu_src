# 浏览器工具路由 — 一律走 agent-browser

本规则适用于**每次会话**。原 Grok 版依赖 `~/.grok/bin/playwright-dual-slot.mjs` 双槽 Playwright MCP；WorkBuddy 环境**没有**该 MCP，改用内置的 `agent-browser` 技能。

## 强制路由

凡属下列任务，**禁止**用 shell 里的 `npx playwright`、curl 硬凑、裸 CDP，也不要拿 `WebFetch` 当交互式浏览器的替代：

- 打开 / 操控真实浏览器
- 点击、输入、滚动、填表、提交
- 对活页面截图 / 取快照
- 多步 Web 流程导航
- 提取需要 JS 渲染或登录态的内容
- 页面转 PDF
- 浏览器端 QA / 冒烟验证

**一律：**

1. 先调用 `Skill` 工具，`skill: "agent-browser"`，按其说明执行。
2. 需要 JS 渲染、登录态、抓包重放时，用浏览器拿到真实请求后再交给 curl / Burp 复现。
3. 页面结构理解优先用可访问性快照；需要视觉确认时再截图。
4. 多步任务保持同一浏览器会话，不要反复重启。

## 何时不用浏览器

- 纯静态 HTTP 读取公开 URL → `WebFetch` / `WebSearch` 足够。
- 本地文件编辑、git、终端、代码分析 → 内置工具。
- `agent-browser` 不可用 → 明确说明并降级到 curl，不要默默放弃。

## 自查清单

在只用文字或 shell 回答浏览器类需求之前：

- [ ] 我加载 `agent-browser` 了吗？
- [ ] 我真的用它做了操控，而不是编 bash 一行流？
- [ ] 需要登录态的页面，我拿到真实会话了吗？

任一项不满足且任务确实需要真实浏览器 → **停下，先加载技能**。

## 会话预期

`agent-browser` 是 WorkBuddy 的内置技能，随时可用，不需要用户每次重新启用。Grok 版的双槽 Playwright 脚本仅作历史参考，见 `reference/`。
