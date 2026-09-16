# XSS 实战案例（ima 案例库深挖）

> **回查原文** → `ima-retrieval-index.md` §三（ima `src报告/XSS/` folder_id + 关键词 + 报告名直搜）。

> 来源：ima 知识库 `src` → `src报告/XSS/`（96 条 → 去重后 51 份唯一，实读 30 份：29 成功 + 1 份读取失败）
> 定位：**真实触发点、真实 payload、真实绕过与定级**；方法论见 `xss-test.md`。
> 类型目录 folder_id：`folder_7492581009159778`；平台子目录：Web=`folder_7492581009141111`（92 条）、EduSRC=`folder_7492581013334279`（4 条）。无 App / 小程序子目录。
> 生成日期：2026-09-14

> ⚠️ **红线提示**：本报告仅作威胁认知与防守复盘，**SRC 一律不做**社工/钓鱼/水坑/免杀/买卖账号/窃取真实个人隐私数据。素材中 `上交大 xss.png`（`2813488062@qq.com/xqs566`）与 `上海交大xss.docx`（`17683971365/Admin123` 及身份证/银行卡照片）含**真实账号与个人隐私**，下文仅保留其 XSS 技术点（上传改名 html），**如实标注 ⚠️红线、不落地、不推荐其作为可用手法**。

## 零、精读案例摘要（120~200 字/份）

1. **07-XSS之攻击与防御（京东安全小课堂）**：系统梳理 XSS 分类——反射型、存储型（含 DOM）、服务端/客户端跨站，及 mXSS（innerHTML 畸变）、UBB（`[img]javascript:...[/img]`）等特殊跨站。结论：存储型危害最大，反射型数量最多；self-xss 配 CSRF 可放大。防御侧：Java filter 统一输入拦截、前端 JS 检测 DOM-XSS、CSP+report 机制。Dete: 纯方法论，无具体目标。（Web/方法论）

2. **95-web漏洞之XSS漏洞挖掘（gainover）**：实战挖掘心法——结合输出点与 WAF 规则黑盒摸索（先判过滤的是符号/标签/属性/关键字）。拓展场景：XSS 打 redis、内网信息收集、借浏览器漏洞远控；盲打用 xss platform / beef（websocket 实时、模块复用）；React/Angular 高度封装时"避开框架照样有漏洞"；UXSS 属浏览器漏洞非 Web 漏洞。（Web/方法论）

3. **a标签xss（丁香医生 app 客服聊天）**：iOS 丁香医生"我的-在线客服"功能，发送系统提示超链接 `<a href="https://www.baidu.com">点击这里</a>`，在 App 内直接跳转外部站，可钓鱼。补天定级**低危**，奖金 ¥100。说明超链接型存储 XSS 在 IM/客服场景迷惑性强、但厂商普遍给低危。（Web/存储型·超链接）

4. **爱奇艺上传xss（爱奇艺知识）**：`iqknow.iqiyi.com` 收益结算"上传身份证"处，抓包将文件名改为 `.html`（如 `Snipaste_2023-06-23_21-18-13.html`），对后缀无过滤，返回地址 `static-s.iqiyi.com/lequ/...html` 被当作 HTML 解析执行 `<script>alert('XSS')</script>`。属任意文件上传→存储型 XSS。（Web/文件类XSS）

5. **不常规xss（延迟/间接触发）**：在"用户名"等个人信息处插入 `<script>alert("1")</script>` 保存后**不立即弹窗**，但访问其它会加载该头像/姓名的页面（如商品推荐页 `ProductSearch`）时自动触发。提示：个人信息类 XSS 常因渲染上下文不同而不在提交页弹窗，需遍历引用点。（Web/存储型·延迟触发）

6. **百度 ueditor 编辑器 xss（getContent）**：ueditor 的 `getContent.php/.asp/.jsp/.ashx` 取 `myEditor` 参数后**直接输出**，php 版虽用 `htmlspecialchars` 过滤输入，却在第 14 行输出时用 `htmlspecialchars_decode` 反转义。payload：`myEditor=<script>alert(document.cookie)</script>`（E 必须大写）。属富文本编辑器反射 XSS。（Web/编辑器与富文本）

7. **bypass-xss（base64 object→iframe 绕 WAF）**：发文章抓包，将 `content` 替换为绕 WAF poc：先 `<object data=data:text/html;base64,PHNjcmlwdD5hbGVydCgneXVlcWl1Jyk8L3NjcmlwdD4=></object>` 再整体 base64 塞进 `<iframe src="data:text/html;base64,...">`。利用 data URI + 双层 base64 规避关键字/标签过滤。案例域名 `luban.m.qq.com`。（Web/WAF绕过）

8. **存储XSS（线上剧本平台·超链接 hover）**：剧本平台验证码登录后，"新增线上剧本"的角色信息/主持人手册处插入超链接 payload，保存后**鼠标悬停**即触发；提交审核后商家/购买者浏览也会中招，可打商家 cookie。典型"超链接 + onmouseover/hover"存储 XSS。（Web/存储型·超链接）

9. **hgame2023 Designer XSS 外带 token（CTF 盲打）**：题目 `/button/preview` 用 `"` 闭合属性后 `<script>` 弹窗；`/button/share` 用 puppeteer 本地访问预览并带出 localStorage token。盲打平台用 bluelotus，接收端 PHP 写文件，JS 用 `XMLHttpRequest` 先 `/user/register` 注册 admin 再带 token 请求 `/user/info`。完整演示"XSS 外带敏感数据"。（Web/盲打·外带）

10. **京东 SELF-XSS 蠕虫**：函数计算"创建函数"处 `nickName` 未转义为 SELF-XSS；将 CSRF 改为 GET 方式，构造 `function/create?nickName=<script>alert(21)</script>&...` 的存储型 URL；再借京东论坛 IMGURL 外链批量植入，统一登录下实现大规模蠕虫。定级视角：self→worm 危害陡增。（Web/SELF-XSS·蠕虫）

11. **鸡肋 DedeCMS 反射型 xss（ShowMsg）**：DedeCMS ≤5.7.106 的 `ShowMsg($msg,$gourl)` 把第二个参数 `$gourl` 直接拼进 `<a href="$gourl">`，未过滤。`/plus/vote.php` 第 26 行 `$ENV_GOBACK_URL` 取自 `HTTP_REFERER` 无限制，改 Referer 为 `x"><script>alert(1)</script>` 即弹窗。近 20 处同类点，但需登录投票、较鸡肋。（Web/反射型·CMS）

12. **论坛xss（/action/=javascript: 绕过）**：某手游助手论坛发帖"行内代码"，WAF 拦 `javascript:`，绕过思路在 `action` 前加 `/`：`action/=javascript:`；组合 poc `<iframe src/="data:text/html;base64,PHNjcmlwdD5hbGVydCgieHNzIik8L3NjcmlwdD4=">`。草稿箱打开亦弹窗，证明存储可达。（Web/WAF绕过·论坛）

13. **某厂家相册 bypass-xss（base64 object→iframe）**：与 #7 同源手法，手机端注册后发图文，将 `content` 用 object base64 再包 iframe base64 绕过 WAF，预览页 `spread/previewArticle` 执行。证明"data:text/html;base64 + 双层编码"是通用绕 WAF 套路。（Web/WAF绕过·相册）

14. **某厂家邮箱 xss（formaction + 注释拼接）**：邮箱附件上传 HTML，富文本中 `formaction` 事件未过滤但直接插不行；发现 `</:` 会被解析为注释，利用 `<img src=http://baidu.com x="" ></:>1><button formaction=alert(1)>` 经注释吞掉中间、拼接出可执行 `formaction`。属存储型 XSS 的非常规解析绕过。（Web/存储型·邮箱富文本）

15. **某DN搜索框 xss（搜索历史触发）**：某 SDN 搜索框本身不弹窗，但**搜过 XSS payload 后，payload 被写入搜索历史**，点击搜索框自动加载历史即触发。同类还有淘宝/当当/亚马逊的 URL 参数型搜索 XSS。提示：搜索历史、热词回显是易漏的 DOM/存储触发点。（Web/反射·DOM·搜索历史）

16. **php 代码审计之 xss**：归纳三类——反射（`echo $_REQUEST['xss']`）、存储（insert 不过滤 + select 后 echo）、DOM（`document.getElementById` 取参拼进 `href` 用 `'` 闭合）。审计重点关注 `echo/print/printf/sprintf/die/var_dump` 等输出函数及过滤逻辑。推荐 pikachu、xss_labs 靶场。（Web/代码审计）

17. **全球华人某社区鸡肋 XSS（天涯 api）**：天涯 `bbs.tianya.cn/api?method=bbs.ice.getHotArticleList&params.pageSize=40&var=<ScRiPt>alert(1)</ScRiPt>` 反射弹窗，靠 F12 看 XHR 找到可疑 api 参数。大小写混淆 `<ScRiPt>` 绕过简单过滤。危害低但说明"看网络请求找隐藏参数"是挖反射 XSS 的常用手法。（Web/反射·API参数）

18. **上海交大 xss（上传改名 html）** ⚠️红线：登录 `sac.sjtu.edu.cn/ktgl`（报告含真实账号 `17683971365/Admin123` 及身份证/银行卡照片，**隐私不落地**），"修改个人信息-上传银行卡"抓包将 `filenames` 改为 `.html`，上传 `GIF89a?<script>alert('xss')</script>`，访问 `upfile/.../personalInfo/...html` 执行。技术点=上传点改后缀解析为 HTML，但凭据属红线不推荐。（Web/文件类XSS）

19. **私信 XSS（javascript: 绕过 WAF）**：发私信先传图，发布时抓包把 `image_url` 替换为 `javascript:window['al'+'ert']('xss')`，拆分 `alert` 绕过 WAF 关键字拦截（返回 403 原被拦）。证明 WAF 拦 `<script>` 时可转向 `javascript:` URI + 字符串拼接。（Web/WAF绕过·私信）

20. **通达 OA xss（窃取 admin）**：2013/2015 版通达 OA 发邮件、问题问答处前端过滤、抓包插 payload 后服务端又过滤事件，用 `<img src=x onerror=eval(atob('...'))>`（atob 编码绕事件名过滤）打管理员，可获取他人/admin 账号权限。属 OA 存储型 XSS 接管会话。（Web/存储型·OA）

21. **微博两个反射 xss（ting + 广告 ad-data）**：①`ting.weibo.com/list` 歌单名直接插 `<script>alert(/hacked by/)</script>`；②首页广告 `ad-data` 的 `adid` 参数回显，改 `adid=<script>alert(/xss/)</script>` 触发。说明子域爆破+dirsearch 找边缘功能、以及前端 DOM 属性回显都是反射 XSS 高发点。（Web/反射·子域/广告）

22. **文件上传 html 嵌套 xss（挂黑页·中危）**：营业执照/合作页上传点只能传图不解析，改传含 `<script>alert("testxss")</script>` 的 HTML，访问返回 html 即解析。众测定级**中危、赏金 ¥800**；同手法另一 SRC 中危 ¥100。说明"不能传马就传 html"是 SRC 高频中危项。（Web/文件类XSS）

23. **文件上传 xss（open.sto.cn 任意上传→存储）**：`open.sto.cn` 图片上传点，Burp 改 `filename=1.html`、`Content-Type:text/html`、内容 `<sCriPt>alert(/xss/)</sCriPt>`，直传阿里云 OSS 返回 `open-server-img.sto.cn/...html` 并解析。任意文件上传点皆可试 html 触发存储 XSS。（Web/文件类XSS）

24. **西安明德理工 xss（上传 pdfxss）**：`xnfz.mdit.edu.cn` 虚拟仿真实验平台"实验报告-插入链接/本地文件"上传 `pdfxss.pdf`（内容含 XSS），返回 `vlab_files/.../p8he.pdf` 被解析弹窗；同法 `gixf.zjnu.edu.cn`（浙江师大）亦中。教育站点 summernote 富文本+文件上传是重灾区。（Web→Edu 关联/文件类XSS）

25. **信呼 OA 储存型 xss（X-Forwarded-For 日志）**：信呼 OA 1.9.0-1.9.1 登录失败写日志，日志 IP 取自 `X-Forwarded-For` 未过滤；发 `X-Forwarded-For: <script>alert(1)</script>` 登录失败，后台"日志查看"渲染弹窗。再用 xss 平台打 cookie（注意需 `//` 防被注释截断）。属 HTTP 头注入→后台存储 XSS。（Web/存储型·OA·HTTP头）

26. **xss报告2（机构信息上传改名 html）**：机构后台"基本信息填写"上传 logo，抓包发现后缀为空、返回 png；将 `filename` 改为 `blob.html` 并插入 `<sCript>alert(1)</sCriPt>`，返回 `...ED16B7A8D3C4E47AAA5B41DDF76A2FC.html` 解析。通用套路：上传点改后缀+改 Content-Type 为 text/html。（Web/文件类XSS）

27. **同济大学 存储型 xss（附件导入改名 html）** ⚠️隐私关联：EduSRC `cscy.tongji.edu.cn/kycgfwptweb` 人工收引证明，"我的委托-附件导入"先传 `.txt` 再抓包改后缀 `.html`、内容 `<script>alert('xss')</script>`，下载路径 `/media/wits/attachment/...html` 解析弹窗。注入点=附件上传改名，教育侧向"附件/证明文件上传"集中。（EduSRC/文件类XSS）

28. **上交大 xss（EduSRC）** ⚠️红线：报告 `weijegou.sjtu.edu.cn/SignUp/Attender/Index` 附件上传改名 html 触发，但原文**明文写出账号密码 `2813488062@qq.com/xqs566`**，属真实个人隐私，**不落地、不推荐**。技术点与 Web 侧上海交大/同济"上传改名 html"完全一致，无独立增量。（EduSRC/文件类XSS）

29. **YCCMS 3.4 反射型 xss（大小写绕过）**：`/admin/?a=html&art=<sCrIpT>alert(ian)</sCrIpT>&m=arts`，用大小写混合 `<sCrIpT>` 绕过对 `<script>` 的精确匹配过滤。典型"大小写/双写"绕过入门案例。（Web/反射·大小写绕过）

> 读取失败（如实标注，未合并、未臆造）：
> - **YouDianCMS 8.0 Storeage XSS.docx**：`fetch_media_content` 返回 `code:220030 该文件获取失败`，未取得内容。已知线索仅标题——POST `/index.php/Admin/wx/saveSubscribeReply` 存储型 XSS。建议后续在 ima 内补读。

## 一、打法分类

- **反射型**：DedeCMS ShowMsg/Referer（#11）、天涯 api 参数（#17）、微博 ting/广告（#21）、YCCMS 大小写（#29）、某DN 搜索历史（#15，边界偏 DOM）。触发靠诱点访问带 payload 的 URL/参数。
- **存储型**：丁香医生超链接（#3）、剧本平台 hover（#8）、邮箱 formaction（#14）、通达 OA（#20）、信呼 OA 日志（#25）、同济/上交大附件（#27/#28）、机构信息上传（#26）。触发靠受害浏览已存数据。
- **DOM 型**：搜索历史自动加载（#15）、微博广告 `ad-data` 属性回显（#21）、各类取参拼 DOM 属性（#16）。
- **SELF / 蠕虫**：京东函数创建 self→GET-CSRF→论坛蠕虫（#10）。
- **盲打 / 外带**：hgame token 外带（#9）、xss platform/beef（#2）。
- **编辑器与富文本**：百度 ueditor getContent（#6）、summernote 文件上传（#24）、邮箱富文本（#14）。
- **文件类 XSS**：爱奇艺/sto.cn/营业执照/机构信息/同济/上交大——上传点改后缀或 Content-Type 为 html 触发解析（#4/#22/#23/#26/#27/#28）。
- **WAF / 过滤绕过**：base64 data-URI 双层（#7/#13）、`/action/=javascript:`（#12）、`javascript:`+字符串拆分（#19）、`</:` 注释拼接（#14）、大小写（#29）、atob 编码事件（#20）、`//` 防注释截断（#25）。
- **HTTP 头注入 XSS**：信呼 OA `X-Forwarded-For` 进日志（#25）。

## 二、WAF/过滤绕过与 payload 实战表

| 场景/指纹 | 绕过手法 | 可用 payload | 来源案例 |
|---|---|---|---|
| 拦 `<script>`/关键字 | data:text/html;base64 双层（object→iframe） | `<iframe src="data:text/html;base64,PG9iamVjdC...">` | #7 #13 |
| 拦 `javascript:`（富文本/私信） | 字符串拆分 + javascript: URI | `javascript:window['al'+'ert']('xss')` | #19 |
| 拦 `action=`/`javascript:`（论坛） | 在 action 前插 `/` | `action/=javascript:...` + iframe base64 | #12 |
| 拦事件名（OA） | atob 编码整段 JS | `<img src=x onerror=eval(atob('...'))>` | #20 |
| 富文本 formaction 被吞 | `</:` 变注释拼接 | `<img ...></:>1><button formaction=alert(1)>` | #14 |
| 精确匹配 `<script>` | 大小写混合 | `<sCrIpT>alert(1)</sCrIpT>` | #29 #11 同源 |
| 后台日志渲染 | HTTP 头注入 + `//` 防截断 | `X-Forwarded-For: <script>alert(1)</script>` | #25 |
| 上传点只收图 | 改后缀 .html + Content-Type: text/html | 文件体 `<script>alert(/xss/)</script>` | #4 #22 #23 #26 #27 |
| 输出进 `<a href>` 未过滤 | 闭合属性 + 标签 | `x"><script>alert(1)</script>`（Referer 注入） | #11 |

## 三、按功能点的排查 Checklist

- **用户资料/头像/昵称**：保存不弹、访问引用页才触发（#5）；遍历所有回显点。
- **客服/IM/私信**：超链接、图片 URL、富文本（#3 #19）；注意 App 内跳转钓鱼。
- **论坛/评论/发帖/歌单**：行内代码、附件、草稿箱（#12 #21）；保存草稿验证存储。
- **上传点（身份证/营业执照/logo/附件/证明文件）**：先试传 `.html`、改 `filename` 后缀、改 `Content-Type`（#4 #22 #23 #26 #27）；不解析就换名。
- **富文本编辑器**：ueditor/getContent、summernote、腾讯/相册图文（#6 #24 #13）；看是否 decode 反转义。
- **搜索框/热词/历史**：URL 参数 + 历史回显（#15）。
- **OA/后台（邮件、问答、日志）**：HTTP 头、登录失败日志、邮件正文（#20 #25）。
- **CMS 后台/前台参数**：DedeCMS/YouDian/YXCMS/Yunucms/Zzzcms 等 `col`/`art`/`backurl` 参数（#11 #29 及未精读）。
- **API/JSON 回显**：抓 XHR 找隐藏参数（#17 #21）。

## 四、案例索引

| # | 报告名 | 平台 | 目标/系统 | 类型 | 注入点 | payload/手法 | 结果/定级 |
|---|---|---|---|---|---|---|---|
| 1 | 07-XSS之攻击与防御 | Web | 通用 | 方法论 | — | 分类/mXSS/UBB/CSP | 知识 |
| 2 | 95-web漏洞之XSS挖掘 | Web | 通用 | 方法论 | — | 盲打/beef/框架 | 知识 |
| 3 | a标签xss | Web | 丁香医生 app | 存储·超链接 | 客服聊天系统提示 | `<a href=...>` 跳转 | 低危 ¥100 |
| 4 | 爱奇艺上传xss | Web | 爱奇艺知识 | 文件类 | 上传身份证点 | 改名 .html 解析 | 存储XSS |
| 5 | 不常规xss | Web | 通用商城 | 存储·延迟 | 用户名/头像 | `<script>` 引用页触发 | 存储XSS |
| 6 | 百度ueditor xss | Web | ueditor | 编辑器 | getContent myEditor | decode 反转义 | 反射XSS |
| 7 | bypass-xss | Web | luban.m.qq.com | WAF绕过 | 文章 content | object→iframe base64 | 绕WAF |
| 8 | 存储XSS | Web | 线上剧本平台 | 存储·hover | 角色/主持手册超链接 | 悬停触发 | 可打cookie |
| 9 | hgame Designer XSS | Web | CTF | 盲打·外带 | preview/share | xss平台外带token | 演示 |
| 10 | 京东SELF-XSS蠕虫 | Web | 京东函数计算 | SELF→蠕虫 | nickName | GET-CSRF+论坛IMGURL | 蠕虫 |
| 11 | 鸡肋DedeCMS反射 | Web | DedeCMS≤5.7.106 | 反射 | ShowMsg/Referer | `x"><script>` | 鸡肋 |
| 12 | 论坛xss | Web | 手游助手论坛 | WAF绕过 | 发帖行内代码 | `action/=javascript:` | 存储可达 |
| 13 | 某厂家相册bypass | Web | 相册 | WAF绕过 | 图文 content | object→iframe base64 | 绕WAF |
| 14 | 某厂家邮箱xss | Web | 邮箱 | 存储 | 附件HTML富文本 | `</:` 注释拼接 formaction | 存储XSS |
| 15 | 某DN搜索框xss | Web | 某SDN | 反射/DOM | 搜索历史 | 历史自动加载 | 鸡肋 |
| 16 | php代码审计之xss | Web | 通用 | 审计 | echo/输出函数 | 三类归纳 | 方法论 |
| 17 | 天涯鸡肋XSS | Web | bbs.tianya.cn | 反射 | api 参数 var | `<ScRiPt>` 大小写 | 鸡肋 |
| 18 | 上海交大xss ⚠️ | Web | sac.sjtu.edu.cn | 文件类 | 上传改名html | `.html` 解析 | ⚠️隐私不落地 |
| 19 | 私信XSS | Web | 通用 | WAF绕过 | 私信 image_url | `javascript:`+拆分 | 绕WAF |
| 20 | 通达oa xss | Web | 通达OA | 存储·OA | 邮件/问答 | `<img onerror=eval(atob)>` | 接管admin |
| 21 | 微博两个反射xss | Web | weibo(ting/广告) | 反射 | 歌单名/adid | 直接 `<script>` | 反射 |
| 22 | 文件上传html嵌套 | Web | 众测厂商 | 文件类 | 营业执照上传 | 传 html 挂黑页 | 中危 ¥800 |
| 23 | 文件上传xss | Web | open.sto.cn | 文件类 | 图片上传 | 改 html+text/html | 存储XSS |
| 24 | 西安明德理工xss | Web | mdit/zjnu 仿真 | 文件类 | 实验报告上传pdfxss | pdf/html 解析 | 教育关联 |
| 25 | 信呼oa 储存型 | Web | 信呼OA 1.9.0-1.1 | 存储·HTTP头 | X-Forwarded-For日志 | 头注入后台 | 后台XSS |
| 26 | xss报告2 | Web | 机构后台 | 文件类 | logo上传改名 | blob.html | 存储XSS |
| 27 | 同济大学存储型 ⚠️ | EduSRC | cscy.tongji.edu.cn | 文件类 | 附件导入改名 | `.html` 解析 | Edu中危 |
| 28 | 上交大 xss ⚠️ | EduSRC | weijegou.sjtu.edu | 文件类 | 附件改名 | 同上+真实账号红线 | ⚠️隐私 |
| 29 | YCCMS 3.4 反射 | Web | YCCMS 3.4 | 反射 | admin?a=html&art | `<sCrIpT>` 大小写 | 反射 |
| — | YouDianCMS 8.0 | Web | YouDianCMS | 存储 | /Admin/wx/saveSubscribeReply | 未读到(220030) | 读取失败 |

## 五、未精读清单（标题级归类，21 份唯一/Web）

> 与已精读技术高度重合的同类副本、基础教程、CMS 单点，按标题归类列出，未逐份实读（size 相同者视为同内容；size 不同者已如实保留为独立唯一份）。

- **上传改名 html 同类**：`文件上传html嵌套xss语句.docx`（905008 版）、`腾讯相册bypass-xss.docx`（与 #13 同手法）、`某鹅邮箱xss.docx`（与 #14 同手法，mail.qq.com 内部域名）。
- **剧本平台/机构信息存储同类**：`存储XSS_(1)`组(664549)、`xss报告1.docx`(664549)、`xss报告2_(1)`(459987)、`xss漏洞.docx`(459987)、`xss上传html.docx`(499756)、`xss-2.pdf`(186788)——均"上传/信息填写插入 XSS"，与 #8/#26 同。
- **私信/论坛 WAF 绕过同类**：`xss-3.docx`(488679/487146)、`xss-3.pdf`(428777)、`xss-4.doc`(1010688)、`xss-4.pdf`(692106)——与 #12/#19 同。
- **基础教程**：`xss基础与练习.docx`(44817)、`xss-1.pdf`(290485)。
- **DedeCMS 另一版本**：`鸡肋DedeCMS V5.7.106 反射性xss.pdf`(428644)——与 #11 同源不同文件。
- **其它 CMS 单点（反射/存储）**：`Yunucms v2.0.7 后台xss.docx`、`YXCMS 1.4.7储存型xss.docx`(col 参数)、`Zzzcms 1.75 xss漏洞.docx`(backurl onmouseover)、`YouDianCMS 8.0`（读取失败，见上）。
- **上海交大图片组**：`上海交大xss漏洞.png`(打码/不打码 3 份同 size)、`上海交大xss_(1).docx` 组(642424)——与 #18 同技术，含真实凭据 ⚠️。

## 六、厂商定级尺度观察

- **低危**：超链接型/客服聊天 XSS（丁香医生 ¥100）、纯反射且需诱点、鸡肋 CMS 反射（DedeCMS/天涯）。
- **中危**：文件上传→HTML 解析挂黑页（众测 ¥800/¥100）、存储型可打 cookie（剧本平台/邮箱/通达 OA）、教育站附件上传存储。
- **高危少见**：本批 96 条里几乎没有给高危的 XSS，说明厂商普遍把"非接管/非规模化"的 XSS 压在中低危；只有 self→worm（京东）这类可规模化才被高看。
- **教育侧（EduSRC）**：同济/上交大均为存储型文件上传 XSS，通常中危；但 edu 报告易夹带**真实学号/账号/身份证**，提交时务必打码，避免红线。

## 七、素材缺口

- **CSP 绕过实案例缺失**：方法论提到 CSP+report，但 96 条中无一份真正"绕过 CSP"的实战（仅爱奇艺响应头带 `upgrade-insecure-requests`，非 CSP 绕过）。建议补 CSP bypass 专项。
- **DOM XSS 深度案例少**：多为搜索历史/广告属性回显，缺 `script gadget`、Angular/React 模板注入等现代框架 DOM-XSS 实战。
- **mXSS / UXSS 仅方法论提及**，无实战样本。
- **盲打平台实操仅 hgame(CTF) 一份**，缺真实 SRC 盲打收菜案例。
- **YouDianCMS 8.0 读取失败**，需补读；其余 CMS 单点（Yunucms/YXCMS/Zzzcms）未精读，可择一补细节。
- **定级样本偏中低危**，缺"XSS→账号接管/蠕虫"的高危完整报告（京东 #10 最接近但偏自述）。
