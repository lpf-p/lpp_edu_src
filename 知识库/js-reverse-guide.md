# JS 逆向配合接口挖掘指南

> 进站强制步骤见 `dig-scope` §4.1：**不只抽 `/api/` path**。盐、密文 id 公钥、hidden/admin 路由、写死的演示号有就进清单，没有写「无」。演示号当钥匙，不是登录框字典。

> **实战案例（双向引用）** → `ima-case-corpus.md` §1.4（**Vue 站 → JS 路径去 GitHub 搜源码 → 认出芋道框架 → 官方演示站抓包拿接口路径 → 拼回目标 `/api/admin-api/infra/file-config/page`**）；`other-census.md` §6.2（安服仔挖洞记录：从 JS 发现登录成功后跳 `#/dashboard`，**直接拼 URL 绕过登录**）+ §6.3（招生系统注册关闭 → 翻 JS 找到 `zsUserCount.action`/`sendSMS.action`/`resetPassword.action`）；`attack-chain-cases.md` §2.4（**读源码发现「假白名单」**：`123.jsp$.jpg` 被拦 → 源码里是假校验，可直接传 `test_*.jsp`）；`mobile-cases.md` §6（抓到包但重放无效 → 带 `.sign=`/`Ql-Auth-Sign` 时**先扒签名算法，别急着 fuzz**）。

## 使用场景

- 页面接口有加密参数，无法直接用 curl 重放
- 需要从前端 JS 发现隐藏 API 接口
- 需要了解签名/token 生成逻辑以构造任意请求
- 路由表里 hidden/admin、webpack 异步 chunk、写死演示号/测试租户
- **有 `.map` sourcemap → 还原原始源码（流程五，SRC 高分项）**
- **找硬编码凭据：AK/SK、私钥、JWT、Webhook、签名盐、演示号（流程六）**
- **找隐藏路由 / 页面没调用过的接口 = 影子 API（流程七）**

**冲突以 `rules/src-value-hunting.md` §2 为准**：抄到凭据后必须**假值对照**证明生产认这个钥，再打**不影响线上的只读例**；抄到就停手交报告 = 禁止。

---

## 流程一：接口发现

### 1. 查看网络请求

使用 js-reverse MCP 工具（浏览器已打开目标页面时）：

```
操作: list_network_requests()
筛选: resourceTypes=["xhr", "fetch"]
关注: 含用户数据的接口（/user/, /api/, /order/, /account/）
```

### 2. 从 JS 源码批量提取接口

```javascript
// 在 evaluate_script 中执行，提取页面所有 XHR 路径
() => {
  const scripts = Array.from(document.querySelectorAll('script[src]'))
    .map(s => s.src);
  return scripts;
}
```

```bash
# 下载所有 JS 文件，grep 接口路径
for url in $(cat js_files.txt); do
  curl -s "$url" | grep -oP '"(/api/[^"]+)"' | tr -d '"'
done | sort -u > discovered_apis.txt

# 关键词搜索
grep -E "(userId|uid|token|sign|order|payment)" discovered_apis.txt
```

### 3. 使用 search_in_sources 搜索

```
search_in_sources("userId")          // 找用户ID相关接口
search_in_sources("/api/")           // 找所有 API 路径
search_in_sources("Authorization")   // 找 token 设置位置
search_in_sources("signature")       // 找签名参数
```

---

## 流程二：加密参数分析

适用于请求中有 `sign`/`_token`/`x-sign` 等加密参数。

### Step 1: XHR 断点定位

```
1. break_on_xhr("/api/target-endpoint")
2. 在页面触发对应操作
3. 执行暂停后: get_paused_info()
4. 查看调用栈，找到设置加密参数的函数
```

### Step 2: 分析调用栈

```
get_paused_info() 返回示例:
  Frame 0: setRequestHeader (XMLHttpRequest)
  Frame 1: signRequest (utils.js:342)     ← 关注这里
  Frame 2: sendApiRequest (api.js:89)
  Frame 3: onClick (page.js:234)
```

定位到 Frame 1，读取源码：

```
get_script_source(url="utils.js", startLine=335, endLine=355)
```

### Step 3: 提取签名逻辑

常见签名算法模式：

```javascript
// 模式 1: 参数排序 + MD5
function signRequest(params) {
  const sorted = Object.keys(params).sort().map(k => `${k}=${params[k]}`).join('&');
  return md5(sorted + SECRET_KEY);
}

// 模式 2: timestamp + nonce + HMAC
function sign(data) {
  const ts = Date.now();
  const nonce = Math.random().toString(36).substr(2);
  return hmacSha256(ts + nonce + JSON.stringify(data), APP_SECRET);
}

// 模式 3: 固定 salt 拼接
const sign = md5(userId + ':' + timestamp + ':' + SALT);
```

### Step 4: 在浏览器中执行签名函数

```javascript
// evaluate_script 直接调用页面内的签名函数
() => {
  // 如果函数在全局作用域
  return window.signRequest({userId: "victim_id", action: "getInfo"});
}
```

### Step 5: Python 复现签名

```python
import hashlib
import hmac
import time
import random
import string

# MD5 签名复现
def sign_request(params: dict, secret_key: str) -> str:
    sorted_str = '&'.join(f"{k}={params[k]}" for k in sorted(params.keys()))
    return hashlib.md5((sorted_str + secret_key).encode()).hexdigest()

# HMAC-SHA256 签名复现
def sign_hmac(data: str, app_secret: str) -> str:
    ts = str(int(time.time() * 1000))
    nonce = ''.join(random.choices(string.ascii_lowercase, k=8))
    msg = ts + nonce + data
    return hmac.new(app_secret.encode(), msg.encode(), hashlib.sha256).hexdigest()

# 验证：Python 结果应与浏览器 JS 执行结果一致
```

---

## 流程三：隐藏接口发现

### 从 Webpack chunk 中提取

```bash
# 找 chunk 文件
curl -s "https://target.com" | grep -oP 'chunk\.[a-z0-9]+\.js'

# 下载所有 chunk
for chunk in $(curl -s "https://target.com" | grep -oP '"/static/js/[^"]+\.js"' | tr -d '"'); do
  curl -s "https://target.com$chunk" >> all_js.txt
done

# 提取路径
grep -oP '"(/[a-z]+){1,5}"' all_js.txt | sort -u | grep -v node_modules
```

### 从路由配置提取

```bash
# Vue/React 路由配置
grep -oP 'path:\s*["\x27][^"'\'']+' all_js.txt
grep -oP '"route":\s*["\x27][^"'\'']+' all_js.txt

# Axios 基础 URL
grep -oP 'baseURL:\s*["\x27][^"'\'']+' all_js.txt
grep -oP 'BASE_API\s*=\s*["\x27][^"'\'']+' all_js.txt
```

---

## 流程四：API 参数枚举

发现接口后，枚举参数找越权/注入点：

```python
import requests

# 对发现的接口逐个测试
discovered_apis = [
    "/api/v1/user/info",
    "/api/v1/order/list",
    "/api/v2/account/profile",
]

session = requests.Session()
session.headers.update({"Authorization": "Bearer YOUR_TOKEN"})

for api in discovered_apis:
    r = session.get(f"https://target.com{api}")
    print(f"[{r.status_code}] {api} - {len(r.text)} bytes")
    if r.status_code == 200:
        # 记录响应中的 ID 字段，用于后续越权测试
        data = r.json()
        print(f"  响应字段: {list(data.keys()) if isinstance(data, dict) else 'array'}")
```

---

## 流程五：Sourcemap 还原原始源码（SRC 高分项）

**为什么值钱**：打包后的 JS 被压缩混淆，但 `.map` 里的 `sourcesContent` 是**完整原始源码**——含注释、TODO、测试接口、内部域名、没上线的路由、硬编码配置。一份 map 常常抵几十条接口。

### 1. 发现

```bash
# JS 文件末尾的声明
curl -s "https://target.com/static/js/app.xxxx.js" | tail -c 200 | grep sourceMappingURL
# //# sourceMappingURL=app.xxxx.js.map

# 直接猜（webpack 默认同名 + .map）
curl -s -o /dev/null -w "%{http_code}\n" "https://target.com/static/js/app.xxxx.js.map"

# 批量：把所有 js 拼 .map 探一遍
for u in $(cat js_files.txt); do
  c=$(curl -s -o /dev/null -w "%{http_code}" "$u.map")
  [ "$c" = "200" ] && echo "HIT $u.map"
done
```

**别停**：`//# sourceMappingURL=` 只是最常见的一种。老项目可能是 `//@ sourceMappingURL=`，也可能挂在响应头 `SourceMap:` / `X-SourceMap:`。

### 2. 还原

```bash
# 拿到 map 后看结构
python -c "
import json
m=json.load(open('app.js.map'))
print('sources:', len(m.get('sources',[])))
print('有 sourcesContent:', bool(m.get('sourcesContent')))
"
```

- **有 `sourcesContent`** → 直接把原始源码写出来，最省事
- **只有 `sources` 没有内容** → 需要配合 `webpack://` 路径自己重建；价值低很多
- 工具：`npx source-map-unpack` / `reverse-sourcemap` / `shuji`；手工解析 JSON 也行

### 3. 还原后优先看什么

| 看什么 | 为什么 |
|---|---|
| 注释里的 TODO / FIXME / 临时 | 常带未完成接口与内部说明 |
| 环境配置 `dev` / `test` / `prod` 分支 | 测试环境域名、开关 |
| 路由表 `hidden: true`、`meta.roles` | 隐藏管理页 |
| 请求封装里的 `baseURL` 变体 | 影子 API 前缀（`/internal` `/admin` `/v0`） |
| 常量文件 `constants.js` / `config.js` | 硬编码配置 |
| 加解密工具 `encrypt.js` / `crypto.js` | **盐、公钥、算法** |

### 4. 假点

- `.map` 404 → 没开，停
- 有 map 但 `sourcesContent` 为空 → 只有路径清单，价值低，别当还原成功
- 生产构建已剥离调试信息 → 正常，不是洞
- 拿到的是第三方库的 map（jquery/element-ui）→ 不是目标的，扔掉

**红线**：源码只用于找漏洞，**不外传、不全量贴进报告**；报告里只引用必要片段。

---

## 流程六：硬编码凭据提取（正则清单）

> 与 `info-leak-test.md` §3 分工：那边是**已确认的具体案例**；这里是**可复用的正则与流程**。
> 抄到后按 `src-value-hunting.md` §2：假值对照 → 认钥枪须带出身份或列表 → 只读例。

### 1. 先把 JS 全下下来

```bash
# 从页面抽 script src（含动态 chunk 的父包）
curl -s "https://target.com" | grep -oE 'src="[^"]+\.js[^"]*"' | sed 's/src="//;s/"$//' | sort -u > js_files.txt

# 相对路径补全 + 下载
while read u; do
  case "$u" in
    http*) full="$u" ;;
    //*)   full="https:$u" ;;
    /*)    full="https://target.com$u" ;;
    *)     full="https://target.com/$u" ;;
  esac
  n=$(echo "$full" | md5sum | cut -c1-8)
  curl -s --noproxy '*' -k "$full" -o "js/$n.js"
done < js_files.txt
```

**注意**：SPA 的 chunk 是**懒加载**的，首页只拿到入口包。要拿全必须：① 从入口包的 `webpackChunkName` / 数字 chunk 映射表推出全部 chunk；② 或用浏览器把各路由都点一遍（走 `agent-browser`）。

### 2. 凭据正则清单

```bash
# 云厂商 AK/SK
grep -rnoE 'AKIA[0-9A-Z]{16}' js/                      # AWS
grep -rnoE 'LTAI[A-Za-z0-9]{12,24}' js/                # 阿里云
grep -rnoE 'AKID[A-Za-z0-9]{32}' js/                   # 腾讯云

# 私钥 / 证书
grep -rnoE '\-\-\-\-\-BEGIN [A-Z ]*PRIVATE KEY\-\-\-\-\-' js/

# JWT（写死的令牌）
grep -rnoE 'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}' js/

# 代码托管 PAT
grep -rnoE 'gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}' js/

# 第三方服务
grep -rnoE 'AIza[0-9A-Za-z_-]{35}' js/                 # Google API
grep -rnoE 'xox[baprs]-[A-Za-z0-9-]{10,}' js/          # Slack
grep -rnoE 'qyapi\.weixin\.qq\.com/cgi-bin/webhook/send\?key=[A-Za-z0-9-]+' js/   # 企业微信机器人
grep -rnoE 'oapi\.dingtalk\.com/robot/send\?access_token=[A-Za-z0-9]+' js/        # 钉钉机器人

# 数据库 / 中间件连接串（带密码的）
grep -rnoE '(mongodb(\+srv)?|jdbc:mysql|jdbc:postgresql|postgres(ql)?|redis|amqp)://[^"'"'"' ]{8,80}' js/

# 通用键值对
grep -rnoiE '(password|passwd|pwd|secret|token|apikey|api_key|apiKey|access_key|accessKey|secret_key|secretKey|appSecret|app_secret|private_key)\s*[:=]\s*["'"'"'][^"'"'"']{6,60}["'"'"']' js/

# 签名盐（前端算 md5/sha 时最常见）
grep -rnoiE '(salt|signKey|sign_key|secretSalt)\s*[:=]\s*["'"'"'][^"'"'"']{4,40}["'"'"']' js/

# RSA 公钥（JSEncrypt 写死时）
grep -rnoE '\-\-\-\-\-BEGIN PUBLIC KEY\-\-\-\-\-|"modulus"\s*:|"exponent"\s*:' js/

# 内部域名 / 内网 IP
grep -rnoE 'https?://(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)[^"'"'"' ]*' js/
grep -rnoE 'https?://[a-z0-9.-]+\.(internal|corp|local|lan|intranet)[^"'"'"' ]*' js/
```

### 3. 演示号 / 测试租户（当钥匙，不是字典）

```bash
grep -rnoiE '(demo|test|guest|样例|示例|演示)[^"'"'"']{0,10}(user|account|tenant|账号|租户)[^"'"'"']{0,20}' js/
grep -rnoE '(username|account)\s*[:=]\s*["'"'"'][^"'"'"']{2,20}["'"'"']' js/ | grep -iE 'demo|test|admin|guest'
```

**用法**：`src-value-hunting` §1.1 明确「JS/页里写死的演示号、测试租户当钥匙用」——拿它去打业务口，不是拿去撞登录框。

### 4. 前端签名算法（能自己算签 = 绕过一层）

```bash
grep -rnoE 'md5\(|sha1\(|sha256\(|HmacSHA|CryptoJS\.|JSEncrypt' js/ | head
```
定位到算法后，看盐从哪来（常量？接口下发？时间戳拼接？）。细节见本文件流程二「加密参数分析」。

### 5. 假点

- 值明显是占位符：`YOUR_KEY` `xxx` `test` `123456` `placeholder` → 不是洞
- 是**公开**的前端 key（如高德/Mapbox 前端 key、Firebase 配置）→ 本来就该在前端，通常不收
- 密钥过期 / 被吊销 → 假值对照时真假返回一致 → N/A
- 只能打测试环境、生产拒 → 如实写，别虚报
- **手机号加解密钥不当钥匙**（`src-value-hunting` §2）

---

## 流程七：隐藏路由 / 未调用接口（影子 API）

> 与 `middleware-unauth-test.md` §3 影子 API 互补：那边从**路径前缀**找，这边从**前端代码**找。

### 1. 路由表

```bash
# Vue Router / React Router
grep -rnoE 'path\s*:\s*["'"'"'][^"'"'"']{2,60}["'"'"']' js/ | sort -u
grep -rnoE 'name\s*:\s*["'"'"'][a-zA-Z0-9_-]{2,40}["'"'"']' js/ | sort -u

# 隐藏 / 需权限的路由（重点）
grep -rnoE 'hidden\s*:\s*(true|1)' js/
grep -rnoE '(roles|permission|auth|requiresAuth)\s*:\s*\[?[^]]{0,80}' js/
grep -rnoE 'meta\s*:\s*\{[^}]{0,120}\}' js/ | grep -iE 'admin|role|auth|hidden'
```

**打法**：拼出完整 URL 直接访问。`hidden: true` 的页面常常**后端没加权限**（前端藏了菜单而已）。

### 2. 动态 import 的 chunk

```bash
grep -rnoE 'import\(["'"'"']\.[^"'"'"']+["'"'"']\)' js/          # 相对路径 chunk
grep -rnoE 'webpackChunkName:\s*["'"'"'][^"'"'"']+' js/
grep -rnoE '\(\d+\s*:\s*["'"'"'][0-9a-f]{6,}["'"'"']\)' js/      # 数字 → chunk hash 映射
```
拿到 chunk 列表后逐个下载，**里面常常有页面没加载的管理模块**。

### 3. 未被页面调用的接口（最容易被漏的一类）

**做法**：
1. 从 JS 抽出**全部**接口字符串 → `all_apis.txt`
2. 用浏览器把主要路由走一遍，记录**实际发出**的请求 → `used_apis.txt`
3. `comm -23 all_apis.txt used_apis.txt` = **定义了但没调用**的接口

```bash
sort -u all_apis.txt -o all_apis.txt; sort -u used_apis.txt -o used_apis.txt
comm -23 all_apis.txt used_apis.txt
```

**为什么值钱**：`打穿短表.md` 第 76 行那条「列表过滤详情不闸」就是这类——**前端没接，后端照跑，鉴权常常没跟上**。

### 4. 版本目录 / 环境开关

```bash
# 静态资源目录带日期或版本号（如 /authserver/sus_20250410/）
grep -rnoE '/[a-z]+_?[0-9]{6,8}/' js/ | sort -u
# → 试着改邻近日期、旧版本号，可能拿到旧版 JS（旧接口 + 旧漏洞）

# 环境与调试开关
grep -rnoE '(NODE_ENV|__DEV__|VUE_APP_[A-Z_]+|isTest|isDebug|debug\s*:\s*true|enableMock)' js/ | sort -u
```

### 5. 假点

- 路由 `hidden: true` 但访问被后端 403 → 权限是对的，不是洞
- chunk 里是第三方库代码 → 不是目标的
- 未调用接口访问返回 404 / 已下线 → N/A
- 旧版本目录依然存在但内容没变 → 不是洞

---

## 自检（JS 逆向这摊）

- [ ] 是否探过 `.js.map`（sourcemap），而不只下打包后的 JS？
- [ ] 有 map 时是否确认了 `sourcesContent` 有没有内容？
- [ ] JS 是否**下全了**（含懒加载 chunk），而不是只下首页那几个？
- [ ] 凭据正则是否跑了**云 AK / 私钥 / JWT / PAT / 连接串 / 通用键值对 / 盐** 这几类？
- [ ] 抄到的凭据是否做了**假值对照 + 只读例**，而不是抄到就停？
- [ ] 是否把**占位符**当真密钥报了？
- [ ] 路由表里 `hidden: true` / `roles` 的隐藏页面是否拼 URL 访问过？
- [ ] 是否算过「JS 里有但页面没调」的接口（影子 API）？
- [ ] 版本目录是否试了邻近日期 / 旧版本号？
- [ ] 演示号是当**钥匙打业务口**了，还是拿去撞登录框了？（后者禁止）

---

## 一句话

**先探 `.js.map` 拿原始源码，再下全 JS（含 chunk）跑凭据正则；抄到凭据必做假值对照与只读例；路由表找 hidden/roles 隐藏页，diff 出「有定义没调用」的影子接口；演示号当钥匙不打登录框。**
