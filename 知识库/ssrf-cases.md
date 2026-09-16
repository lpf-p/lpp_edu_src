# SSRF 实战案例（ima 案例库深挖）

> **回查原文** → `ima-retrieval-index.md` §三（ima `src报告/SSRF/` folder_id + 关键词 + 报告名直搜）。

> 来源：ima 知识库 `src` → `src报告/SSRF/`（SSRF `folder_id=folder_7492581013355331`；Web `folder_7492581013333313` 14 条 + EduSRC `folder_7492581017549786` 2 条，共 16 条 → 去重后 10 份唯一，实读 10 份，其中 1 份（兰州大学-存在ssrf.doc）空返回读取失败、同报告 PDF 已覆盖）
> 定位：**真实 SSRF 参数点、协议利用、内网探测与云元数据链、真实定级**；方法论见 `ssrf-test.md`。
> 生成日期：2026-09-14

> ⚠️ **红线声明**：本报告仅作威胁认知与防守复盘，**SRC 一律不做**。SSRF 验证止于证明服务端可发起请求（dnslog/回显/时间差证明可达），不深入内网横扫、不读取真实业务数据、不搭建钓鱼网站。下文凡涉及社工/钓鱼之处均逐处标注 `⚠️ 红线`。

## 一、SSRF 参数点速查表

| 业务场景/系统 | 参数名 | 可利用协议 | 能做什么（探测/读文件/打内网/云元数据） | 来源案例 |
|---|---|---|---|---|
| 360 众测产品 zcfy.cc（文章抓取） | `url`（POST `/original/capturepage`） | http + `@` 拼接 | 内网探测、回显 nginx 指纹 | 360产品一处ssrf内网侦测 |
| 阿里云开发者社区（提问"添加网页链接"） | 链接地址字段 | http / dnslog / nc 监听 | 打到内网 `192.168.*` | 阿里云开发者社区某处存在ssrf漏洞 |
| 百度 share 子站 `api.share.baidu` | `url`（fuzz 出 `chack.jsp`） | http + `@` | 内网探测 | 百度某ssrf挖掘过程 |
| 百度 campus（Discuz 3.2x） | `message=[img]...[/img]`（`forum.php?mod=ajax&action=downremoteimg`） | http（可扩 gopher/ftp） | 内网端口批量探测、CEYE dnslog | 百度一处SSRF |
| 头像保存功能 | `avatar` | http / dnslog | 无回显确认 + 时间差判定内网 | 无回显SSRF(脱敏) |
| 兰州大学 jsoa 协同办公 | `url`（`/jsoa/GetRawFile?url=`） | http | 任意 URL 读取、内网端口探测 | 兰州大学-存在ssrf |
| 京东"添加网站"业务点 | 网站地址 | http | 内网地址可达性判定 | SSRF深入挖掘 |

## 二、绕过过滤的手法汇总

1. **`@` 符号混淆**：`http://www.baidu.com@10.121.95.65` —— 让解析命中内网 IP，绕过"禁止内网地址"校验（360、百度案例均中）。
2. **短网址 / 302 跳转**：21 份报告仅靠重定向即绕过；`985.so` 等短链服务把内网目标藏进跳转。
3. **DNS rebinding**：3 份报告用于绕过地址过滤器；难点在 TTL 与解析时机，修复成本高（研究报告统计）。
4. **xip.io / DNS 解析**：`10.0.0.1.xip.io` 或自托管域名指向 `127.0.0.1`，再用域名请求绕过 IP 黑名单。
5. **进制与短写法 IP**：`0177.0.0.1`=127.0.0.1、`3232235777`(十进制)、`013451347312`(八进制)、`0x7f000001`(十六进制)。
6. **协议切换**：`file://`（读 `/etc/passwd`）、`dict://`（探测端口/服务）、`gopher://`（打 Redis/MySQL/FastCGI）、`sftp://`、`ftp://`。
7. **`#` 注释截断**：无回显场景用 `#` 截掉后端拼接的后续路径，只发 `avatar=http://dnslog#`。
8. **IPv6 与特殊地址**：2 份报告用 IPv6 绕过；`[::1]`、`http://[::]:port`。
9. **混淆符号**：`https://[your_domain]\@jobs[.]googleapis[.]com` 一类符号歧义绕过（11 份）。

## 三、云环境利用链

本批 16 条**无直接云元数据实战案例**，但 `ssrf研究报告.png` 汇总 360+ 报告给出尺度参考：

- **云元数据读取 29 份**（最常见影响）：AWS `169.254.169.254/latest/meta-data/iam/security-credentials/`、阿里云 `100.100.100.200/latest/meta-data/`、腾讯云 `metadata.tencentyun.com`、华为云 `169.254.169.254` 差异。
- 链路：SSRF 可达元数据 → 取临时 AK/SK → `AssumeRole` 横向 → 接管 OSS/COS/对象存储/控制台。
- 技能包打法：发现 SSRF 后优先打 `169.254.169.254` / `100.100.100.200`，命中即高危；本批缺样本，建议从 `ssrf-test.md` 补通用 payload。

## 四、按功能点的排查 Checklist

（源自 `ssrf研究报告.png` 对 360+ 报告的统计，按出现频次排序）

1. **URL 导入/远程加载资源**（22 份，最常见，多为图片）— 重点
2. **文件上传**（17 份：7 XXE + 6 ffmpeg CVE + SVG/PDF/Office）— 含 XXE、ffmpeg 读本地文件
3. **headless 浏览器 / HTML 渲染**（9 份，7 个 full-read）— 影响大、难防，**重点方向**
4. **webhooks / 检查服务器状态**（8 份，Google 单笔 3 万美金）
5. **代理 / 路由相关**（8 份，多半用 `url` 参数）— **重点方向**
6. **安全机制 / 库问题**（7 份，多半 blind）
7. **文件存储集成**（7 份：Google Drive / S3，Dropbox 高额）
8. **Sentry 集成**（4 份）、**路由二级上下文路径遍历**（3 份）、**Host 头**（2 份 blind）、**邮件配置**（2 份 blind）、**首请求行**（1 份 8000+ 美金）
9. **易遗漏参数字典**：`url` `u` `src` `endpoint` `srcURL` `remote_attachment_url` `q` `link` `import_url` `images` `image[src]` `image`，以及路径型 `xxx.com/path/SSRF-PAYLOAD/` 与 `Host`/`X-Forwarded-For` 头。

## 五、案例索引

| # | 报告名 | 平台 | 目标/系统 | 参数点 | 利用方式 | 结果/定级 |
|---|---|---|---|---|---|---|
| 1 | 31-浅谈SSRF漏洞 | Web | 通用科普 | — | 成因/危害/防御/绕过综述；提及 Discuz SSRF→Redis getshell、WP pingback | 教育科普 |
| 2 | 360产品一处ssrf内网侦测 | Web | zcfy.cc 文章抓取 | `url`(POST `/original/capturepage`) | `@` 绕过打 `10.121.95.*`，回显 nginx | 内网探测确认 |
| 3 | 阿里云开发者社区某处ssrf漏洞 | Web | help.aliyun.com 提问 | 添加链接地址 | dnslog + nc 监听收到 `192.168.*` 连接 | 内网可达证明 |
| 4 | 百度某ssrf挖掘过程 | Web | api.share.baidu | `url`(`chack.jsp`) | fuzz 目录 + `@` 绕过打 `10.121.95.222` | 内网探测 |
| 5 | 百度一处SSRF（附 poc） | Web | campus.baidu.com Discuz 3.2x | `message=[img]`(`downremoteimg`) | CEYE dnslog 收 `180.76.155.81`；Python 批量探内网端口 | 高危 / **已忽略，0 积分** |
| 6 | SSRF深入挖掘 | Web | 通用方法论 | 多 | 三分法+验证(回显/时间/dnslog/字节数)+绕过+后续利用 | 方法论 |
| 7 | ssrf研究报告 | Web | 360+ 报告统计 | — | 功能点/参数/绕过/影响量化 | 统计综述 |
| 8 | 无回显SSRF(脱敏) | Web | 头像保存 | `avatar` | dnslog 确认 + `#` 截断 + 时间差判内网(127.0.0.1≈1.1s，192.168 段≈6s+) | 盲打确认 |
| 9 | 兰州大学-存在ssrf | EduSRC | oa.lzu.edu.cn 九思 jsoa | `url`(`/jsoa/GetRawFile?url=`) | 任意 URL 回显百度；探 `127.0.0.1:80` 开放、`81` 500；VPS 确认公网出口 `202.201.13.77`；⚠️ 红线：文中提及"用钓鱼网站钓取用户名密码" | 教育侧报告（交大 SRC 模板） |

> 注：#9 的 `.doc` 版空返回读取失败，内容以 `.pdf` 版为准。

## 六、未精读清单（标题级归类）

去重剔除的 6 条重复副本（同标题剥离后缀 + 同 `file_size`，不再实读）：
- `31-浅谈SSRF漏洞_20210506214051.pdf`（= #1，1872189 字节）
- `阿里云开发者社区某处存在ssrf漏洞(1)_(1).docx`（= #3，427225 字节）
- `无回显SSRF(脱敏)_(1)~(4).docx`（= #8，各 32750 字节）

读取失败（照实标注，内容由同报告另一格式覆盖）：
- `兰州大学-存在ssrf.doc`：fetch 返回空（`{"content":"8\n"}`），判定为**读取失败（空返回）**；同报告 `兰州大学-存在ssrf.pdf` 已成功读取，内容完整覆盖，不重复计入缺失。

## 七、厂商定级尺度观察

- **百度（SRC）**：`百度一处SSRF` 标"高危"但状态"已忽略"、奖励积分 0 —— 通用型 Discuz 漏洞、内网探测未造成实质数据泄露时，大厂常忽略或低酬，盲打/无实质影响的 SSRF 定级偏低。
- **教育侧（EduSRC / 交大 SRC 模板）**：`兰州大学` 案例走标准教育 SRC 提交流程（含资产确认、漏洞详情、修复建议），对"可探内网端口 + 可确认公网出口"即认定为有效 SSRF，尺度较宽、重在修复。
- **影响权重**：能回显 / 打到云元数据 / 升级 RCE 才易拿高定级；纯内网端口探测多为中危，云元数据读取普遍高危。

## 八、素材缺口

1. **云元数据实战**：本批无 `169.254.169.254`/`100.100.100.200` 直接案例，仅研究报告统计提及，需在 `ssrf-test.md` 补通用打法。
2. **gopher 打 Redis/MySQL/FastCGI**：仅在综述里出现，无逐步 payload 实战样本。
3. **XXE→SSRF、ffmpeg CVE 读文件**：研究报告统计有 8/6 份，本批无专门案例。
4. **DNS rebinding 实操**：仅统计 3 份，缺可复现步骤。
5. **App / 小程序平台**：SSRF 类型目录无 App、小程序平台样本（仅 Web + EduSRC），相关排查 checklist 待其他类型目录补充。
