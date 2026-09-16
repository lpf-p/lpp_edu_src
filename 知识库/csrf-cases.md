# CSRF 实战案例（ima 案例库深挖）

> **回查原文** → `ima-retrieval-index.md` §三（ima `src报告/CSRF/` folder_id + 关键词 + 报告名直搜）。

> 来源：ima 知识库 `src` → `src报告/CSRF/`（43 条 → 去重后 35 份唯一：Web 33 + EduSRC 2，其中 7 份为截图证据；实读文档 21 份，未精读以标题级归类，读取失败 0 份）
> 定位：**真实利用场景、PoC 写法、厂商定级现实**；方法论见同级 `csrf-test.md`。
> 生成日期：2026-09-14
> ⚠️ 本文仅作威胁认知与防守复盘。**CSRF PoC 只做授权环境自测复现，不得用于攻击真实用户**。EduSRC 案例中出现的"测试账号"为提交者自建复现账号，非真实个人隐私数据。

## 一、打法分类

### 1. GET 型 CSRF
- **判定条件**：敏感操作走 GET，且参数全在 URL（如 `?act=del&id=1`）；或接口仅校验 cookie 不校验来源。
- **PoC 模板**：`<img src="https://target/admin/del?id=1">` 或 `<a href="...">点我</a>`。
- **代表案例**：PbootCMS 删除用户 `GET /admin.php/User/del/ucode/10004`；PhpMyAdmin 4.9.0 用 `<img>` 触发 `tbl_sql.php?sql_query=...` 执行 SQL；华为 WS331a 重启/恢复出厂 `POST /api/service/reboot.cgi`（无参即触发）。

### 2. POST 表单型 CSRF（最常见）
- **判定条件**：后台/会员中心敏感表单（改资料、加管理员、删用户）无 token 或 token 未校验。
- **PoC 模板**：自动提交表单（见第二节）。
- **代表案例**：EyouCMS 1.4.3 添加管理员、Zzcms 8.3 添加管理员、74cms v5.0.1 添加管理员、FineCMS 5.4 改管理员密码、YzmCMS v3.6 添加管理员、CatfishCMS 后台改角色、Seacms 后台添加视频。

### 3. JSON / fetch 型（无 token + CORS 宽松）
- **判定条件**：前端用 `fetch/ajax` 发 `application/json`，后端仅靠 cookie 鉴权，且**无 CSRF token**；若响应带 `Access-Control-Allow-Origin:*` 且 `SameSite` 缺省则更易打。
- **PoC 模板**：见第二节 `fetch + credentials`。
- **代表案例**：基础漏洞csrf挖掘 中百度 AI Studio 改头像接口（`Access-Control-Allow-Origin:*`、仅 `X-Requested-With` 头、cookie 完整发送）→ 把头像字段替换为退出链接实现"退出登录 CSRF"。

### 4. 登录与授权 CSRF（高价值，易被忽略）
- **判定条件**：第三方绑定/快捷登录回调仅依赖一次性 `code`，绑定动作无二次确认或 state 可被攻击者预置。
- **代表案例**：某厂商 OAuth2.0 微博绑定劫持——攻击者先拿自己微博 `code`，构造 `callback?state={"can_transfer":true}&code=...` 发给受害者，受害者点开即把自己的账号绑定到攻击者微博，攻击者随后可用微博登录接管受害者账号。

### 5. 登出 / 降权 CSRF
- **判定条件**：退出登录接口无防护。
- **代表案例**：百度 AI Studio `logout` 链接可被埋入评论区头像 `src`，其他用户访问即被强制登出（影响业务连续性，企业 SRC 中危）。

### 6. 文件上传 / 管理后台型
- **判定条件**：中间件/设备/CMS 管理接口无 CSRF 防护。
- **代表案例**：RabbitMQ Web 管理 `<3.7.6` 添加管理员 `POST /api/users/rootadmin`；各类 CMS 后台添加管理员。

### 7. 编辑器 / 富文本 / BBCode 型（CSRF→XSS）
- **判定条件**：后台可编辑 BBCode/模板且缺防护，导入后在前台渲染执行。
- **代表案例**：phpBB 3.2.7 编辑 BBCode 的 CSRF（`$submit` 未传则不走 `check_form_key`）→ 新增 `[xss]{TEXT}[/xss]` BBCode 致存储 XSS；Ninja Forms `<3.4.24.2` 通过 `admin-ajax.php?action=ninja_forms_ajax_import_form` 导入恶意表单覆盖原表单 → 表单 XSS。

### 8. 多步操作链（CSRF 升格为 RCE）
- **判定条件**：CSRF 能写入可控内容，且下游有缓存/反序列化/SQL 执行可利用。
- **代表案例**：
  - **CatfishCMS 4.5.7 getshell**：前台评论插 XSS → 诱管理员访问 → XSS 自动发 CSRF（写文章含 `<?php eval`，清缓存，访问前端重新生成缓存）→ 缓存 PHP 文件落地 webshell。
  - **CatfishCMS 4.6.15 getshell**：作者加了 `verification` 参数防 CSRF，但因可先 XSS 读取 `verification` 再构造 CSRF 而绕过；随后 CSRF 建页面触发文件包含图片马 → getshell。
  - **PHPOK 5.5 getshell**：CSRF 改 `api_code`（后台站点设置无防护）→ 已知 key 可伪造 token → 反序列化 `cache` 类 `__destruct` 调用 `file_put_contents` → `php://filter` 去 `exit()` 写马。

### 9. 设备 / 路由器管理型
- **判定条件**：IoT/路由器管理页仅 cookie 鉴权，操作接口无 token。
- **代表案例**：华为 WS331a 重启、恢复出厂（恢复后 `admin/admin` 可连）。

## 二、PoC 模板库

```html
<!-- POST 表单自动提交 -->
<form action="https://target/admin/add" method="POST">
<input type="hidden" name="user" value="att"><input type="hidden" name="pass" value="att">
</form><script>document.forms[0].submit()</script>
```
```html
<!-- GET 型 -->
<img src="https://target/admin/del?id=1">
```
```html
<!-- 隐藏 iframe 静默触发 -->
<iframe src="//evil/csrf.html" style="display:none"></iframe>
```
```js
// JSON / fetch 型（需目标无 token 且 SameSite 缺省）
fetch('https://target/api/modify',{method:'POST',credentials:'include',
headers:{'Content-Type':'application/json'},
body:JSON.stringify({field:'evil'})});
```
```html
<!-- OAuth 绑定劫持：把预置 code 的回调链接发给受害者 -->
<a href="https://target/auth/weibo/callback?state={%22can_transfer%22:true}&code=ATTACKER_CODE">点我领福利</a>
```
```html
<!-- 退出登录 CSRF：替换为头像/资源 src -->
<img src="https://target/logout">
```

## 三、绕过防护的手法汇总

1. **无 token / token 未校验**：多数 CMS 后台整站表单无 token（Zzcms、EyouCMS、74cms、FineCMS、YzmCMS、Seacms）。
2. **token 可预测 / 可获取**：CatfishCMS 4.6.15 的 `verification` 可由 XSS 先读取再带入 CSRF；PHPOK `api_code` 被 CSRF 改写后攻击者即可推算 token。
3. **Referer 校验可绕**：某电商收藏接口校验 Referer，但把恶意请求拼到可信域登录回调 `redirect_url=` 后，Referer 变为信任域；或利用论坛（DZ）图片 `src` 可任意改，把收藏请求当图片插入帖子中刷量。
4. **SameSite 缺失**：JSON/fetch 类与 cookie 鉴权接口在 `SameSite=Lax/None` 缺省时可直接跨站带 cookie。
5. **仅靠 sid 防护但 sid 泄露**：phpBB 把 session id 放 URL，管理员从后台切前台时 sid 进入 `Referer` 被远程头像窃取，再用 BBCode CSRF 接管。
6. **校验逻辑可被绕过（参数触发缺失）**：phpBB 编辑 BBCode 仅当 POST 含 `submit` 才 `check_form_key`，不带 `submit` 即跳过 → CSRF 成功。
7. **仅前端校验**：修改密码/资料接口前端有提示但后端不校验来源（同济大学招聘系统改密接口）。

## 四、按功能点的排查 Checklist

- [ ] 后台：添加/删除管理员、改密码、改权限、插件/模板/SQL 执行、缓存清理
- [ ] 会员中心：改资料、改绑手机/邮箱、改头像、退出登录
- [ ] 交易/订单：下单、改收货、退款、转账（GET 尤其危险）
- [ ] 第三方绑定/快捷登录：绑定/解绑回调是否校验 state 与二次确认
- [ ] 文件/设备管理：上传、用户管理、设备重启/恢复出厂
- [ ] 富文本/编辑器：BBCode、自定义 HTML、表单导入
- [ ] 通用：所有写操作是否带随机 token 且**服务端校验并绑定用户会话**；是否校验 `Origin`/`Referer`；cookie 是否 `SameSite=Lax`；JSON 接口是否允许跨站 `fetch credentials`

## 五、案例索引

| # | 报告名 | 平台 | 目标/系统 | 触发点 | 缺少的防护 | 定级 | 是否被接收 |
|---|---|---|---|---|---|---|---|
| 1 | 001-CatfishCMS后台csrf | Web | CatfishCMS 后台 | `POST modifymanage` 改角色 | 仅 `verification`，可预测 | CVE/公开 | — |
| 2 | 002-PbootCMS csrf | Web | PbootCMS | `GET User/del/ucode` 删用户 | 无 token，GET 即删 | CVE/公开 | — |
| 3 | CatfishCMS 4.5.7 csrf getshell | Web | CatfishCMS 4.5.7 | 评论XSS→CSRF写文章→缓存落马 | 后台无 CSRF token | 高危链 | — |
| 4 | CatfishCMS 4.6.15 csrf getshell | Web | CatfishCMS 4.6.15 | XSS读verification→CSRF建页→包含图片马 | verification 可获取绕过 | 高危链 | — |
| 5 | csrf绕过 | Web | 某电商 | 收藏接口 JSONP/Referer 可绕 | Referer 校验可被登录回调绕 | 中危 | — |
| 6 | Eyoucms 1.4.3 csrf漏洞 | Web | EyouCMS 1.4.3 | `admin_add` 添加管理员 | 无 token 校验 | CVE/公开 | — |
| 7 | XDCMS 1.0 csrf漏洞 | Web | XDCMS 1.0 | `member&f=edit` 改资料+改 Cookie userid 越权 | 无 token/referer | CVE/公开 | — |
| 8 | YzmCMS v3.6 csrf | Web | YzmCMS v3.6 | `admin_manage/add` 添加管理员 | 无 token（另含 SQL 执行 getshell） | CVE/公开 | — |
| 9 | RabbitMQ Web管理csrf | Web | RabbitMQ <3.7.6 | `POST /api/users/rootadmin` | 管理接口无 CSRF | CVE/公开 | — |
| 10 | Seacms V6.61 后台csrf | Web | SeaCMS 6.61 | `admin_video.php?action=save` 添加视频 | 无 token | CVE/公开 | — |
| 11 | Zzcms 8.3 csrf | Web | ZZCMS 8.3 | `adminadd.php?action=add` 添加管理员 | 全后台无 token | CVE/公开 | — |
| 12 | Finecms 5.4 CSRF | Web | FineCMS 5.4 | `admin.php?c=member&m=edit` 改管理员密码 | 无 token | CVE/公开 | — |
| 13 | 74cms v5.0.1 CSRF | Web | 74CMS 5.0.1 | `admin&a=add` 添加超级管理员 | 无 token | CVE/公开 | — |
| 14 | Phpmyadmin CSRF (CVE-2019-12616) | Web | phpMyAdmin ≤4.9.0 | `tbl_sql.php?sql_query=` GET 触发 | 仅 cookie 鉴权 | CVE/公开 | — |
| 15 | 华为WS331a CSRF (CVE-2016-6158) | Web | 华为 WS331a | `reboot.cgi`/`restoredefcfg.cgi` | 管理接口无 token | CVE/公开 | — |
| 16 | PhpBB session→CSRF→XSS (CVE-2019-13376) | Web | phpBB 3.2.7 | 编辑BBCode（不带submit跳过校验）+ sid 泄露 | check_form_key 触发条件缺陷 | CVE/公开 | — |
| 17 | Ninja Forms CSRF→XSS (CVE-2020-12462) | Web | WordPress Ninja Forms <3.4.24.2 | `admin-ajax.php?action=ninja_forms_ajax_import_form` | 仅校验权限无 token | CVE/公开 | — |
| 18 | PHPOK 5.5 csrf+反序列化 getshell | Web | PHPOK 5.5 | `admin.php?c=all&f=save` 改 api_code | 站点设置无 CSRF | 高危链 | — |
| 19 | 漏洞挖掘之OAuth2.0绑定劫持 | Web | 某厂商（匿名） | 微博绑定回调 code 预置 | state/绑定无二次确认 | 高危（登录劫持） | — |
| 20 | 基础漏洞csrf挖掘 | Web | 百度AI Studio 等 | 改头像/退出登录 JSON 接口 | 仅 X-Requested-With，无 token | 中危（登出） | — |
| 21 | 同济大学（CSRF） | EduSRC | 同济大学招聘系统 `kh.tongji.edu.cn` | `savePassword.do` 改密码 | 无 token/referer（仅前端校验） | 中危/低危 | 接收 |

## 六、未精读清单（标题级归类）

- **方法论/重复变体（未单独精读）**：`10-CSRF的攻击与防御.pdf`、`92-web漏洞之CSRF漏洞挖掘.pdf`（JSRC 小课堂，通用方法论）；`基础漏洞csrf挖掘 (1).docx`/`_(1)`/`_(2)` 与 `_(1).docx`/`_(2).docx`（与已读 `基础漏洞csrf挖掘.docx` 同主题不同体积，未逐一读）；`CatfishCMS后台csrf.docx`、`PbootCMS csrf.docx`（与已读同名 .md 同源）；`同济大学2.pdf`、`同济大学——CSRF（不打码）.pdf`、`同济大学2——CSRF（不打码）.pdf`（与已读 `同济大学.pdf` 同内容）。
- **截图证据（7 张 PNG，未精读）**：`15889446053876/15889446138818`（Catfish 后台）、`15892011150891/15892011232050/15892011480196/15892011546305/15892011637086`（PbootCMS 请求与页面截图），均为对应报告的过程截图。

## 七、厂商定级尺度观察（CSRF 常被忽略或判低危，重点记录"怎么论证危害才能升档"）

1. **单点改资料/删用户常被判低危**：纯"改自己资料""删一个用户"若无连锁危害，SRC 多判低危甚至忽略。
2. **升档论证路径**：
   - **改成"添加管理员/改管理员密码"** → 直接后台接管，至少中危，常升高危。
   - **登录 CSRF / 账号绑定劫持** → 可接管他人账号，论证"账号资产+数据泄露"，判中~高危（OAuth 绑定劫持案例即高危）。
   - **退出登录 CSRF** 在"高频交互场景（评论/论坛）"论证"可批量踢下线、干扰业务"，企业 SRC 可到中危。
   - **CSRF→XSS / CSRF→getshell / CSRF→SQL执行** 形成利用链 → 直接按最终危害（RCE/存储 XSS）定级，远超普通 CSRF。
   - **设备/路由器重启恢复出厂** → 论证"可用性破坏+恢复后无鉴权可入侵"，中危起。
3. **被接收的关键叙述**：把"我能做什么"量化——受影响用户规模、是否涉及资金/个人敏感信息、是否无需受害者配合（静默 iframe）、是否可批量。避免只说"理论上可伪造请求"。

## 八、素材缺口

- 缺少**CORS+CSRF 组合**的独立完整案例（现有 JSON 型仅为 `Access-Control-Allow-Origin:*` 宽松，未展示"带自定义头触发预检失败"的边界）。
- 缺少**Flash/JSON hijacking（307 重定向）** 类历史手法素材。
- 缺少**SameSite 绕过（Lax+Top-Level-POST、客户端漏洞配合）** 的新近案例。
- EduSRC 侧仅 1 个有效案例（同济大学），样本不足，难以归纳教育行业共性规律。
- 多数 Web 案例为公开 CVE/CMS 复现，缺"在真实 SRC 中从低危沟通到升档"的厂商回复原文。
