# -*- coding: utf-8 -*-
"""入口类资产指纹判据表（唯一来源，probe/classify/follow 三脚本共享）。
加新指纹只改这里。规则：
- SERVER_EXACT：Server 头**精确匹配**（避免 none 之类误伤）。
- SUBSTR：正文 / URL / Cookie 的结构性子串；(marker, 名称, 大小写不敏感?)。
"""

SERVER_EXACT = {
    "wisedu": "金智 wisedu（Server 头）",
    "Sangine": "Sangine 网关（Server 头）",
    "none": "网关默认值 none（字面量）",
    "Server": "Server 头写错（字面量 Server）",
    "WVS": "泛微 e-cology（Server: WVS）",
    "RUMS": "RUMS 图书馆",
    "rums/b": "RUMS 图书馆",
    "rump/c": "RUMS 图书馆",
    "seProxy/1.21.6": "seProxy 代理",
    "BigIP": "F5 BigIP 负载均衡",
    "appframe": "WebVPN(appframe) · Server头",
    "******": "兰州大学 WebVPN（Server 通配屏蔽）",
}

SUBSTR = [
    # 网瑞达 WebVPN
    ("77726476706e69737468656265737421", "网瑞达 · IV硬编码", True),
    ("/wengine-auth/", "网瑞达 · /wengine-auth/", True),
    ("wengine", "网瑞达 · wengine", True),
    ("wrdvpn", "网瑞达 · wrdvpn", True),
    ("aes-js", "网瑞达 · aes-js库", False),
    ("fromUrl=", "网瑞达 · fromUrl 参数", True),
    # Sangine 网关
    ("/controller/v1/public/verify", "Sangine · verify接口", True),
    # 金智 wisedu
    ("/authserver/", "金智 · /authserver/", True),
    ("lyuapServer", "金智 · lyuapServer", True),
    ("jziotlogin", "金智 · jziotlogin", True),
    ("/jwapp/sys/", "金智 · jwapp教务", True),
    ("/rsfw/sys/", "金智 · rsfw人事", True),
    ("wisedu", "金智 · wisedu", False),
    ("ehall", "金智 · ehall", False),
    ("请选择证书", "金智 · USB Key证书组件文案", False),
    ("组件版本号", "金智 · USB Key组件版本号", False),
    ("/build/ecodesdk/", "金智 · /build/ecodesdk/", True),
    # 北京创文（图书馆电子资源 ERMS）
    ("/ermsLogin/", "创文科技 · /ermsLogin/", True),
    ("CWJSESSIONID", "创文科技 · CWJSESSIONID", True),
    ("北京创文", "创文科技 · 页脚署名", False),
    # 「Server: Server」款国产 SSL VPN（2026-09-16 硬判据，6 站同套）
    ("/com/64sys.js", "SSL VPN(S:S) · /com/64sys.js", True),
    ("is_old_solution", "SSL VPN(S:S) · is_old_solution", True),
    ("g_midatk", "SSL VPN(S:S) · g_midatk", True),
    ("selectline_timeout", "SSL VPN(S:S) · selectline_timeout", True),
    ("SSL Strip", "SSL VPN(S:S) · 中间人告警文案", False),
    # appframe WebVPN
    ("/vpn/theme/auth_home.html", "WebVPN(appframe) · auth_home", True),
    # .NET OIDC 自建统一认证
    ("Discovery Document", ".NET OIDC · Discovery Document", False),
    ("/Home/SetLanguage", ".NET OIDC · /Home/SetLanguage", True),
    # 教务 / 认证 / SSO
    ("zftal", "正方 · zftal", True),
    ("logincas", "CAS · logincas", True),
    ("/cas/login", "CAS · /cas/login", True),
    ("login.jsp?service=", "CAS · login.jsp?service=", True),
    ("serviceValidate", "CAS · serviceValidate", False),
    ("org.jasig.cas", "CAS · Apereo", False),
    ("/gate/login", "认证 · /gate/login", True),
    ("/users/sign_in", "Astraeus WebVPN(ROR)", True),
    ("_astraeus_session", "Astraeus WebVPN(cookie)", True),
    ("/vpn_key/update", "自研WebVPN · vpn_key", True),
    ("/go?http", "自研WebVPN · /go?http", True),
    ("/auth/oauth/login", "SSO · /auth/oauth/login", True),
    ("/oauth/authorize", "SSO · OAuth2授权码", True),
    ("LoginSSO.aspx", "SSO · ASP.NET LoginSSO", True),
    ("?code=0x", "SSO · code=0x 模式", True),
    ("/tpass/", "认证 · /tpass/", True),
    ("/tp_up/", "认证 · /tp_up/", True),
    ("/tp_fp", "认证 · /tp_fp", True),
    ("/new/index.html", "金智 ehall · /new/index.html", True),
    ("gwroute-casp-portal", "网关 · gwroute-casp-portal", True),
    ("/xsfw/sys/", "学工系统 · /xsfw/sys/", True),
    ("/xggzptapp", "学工系统 · xggzptapp", True),
    # 第三方
    ("chaoxing", "超星 chaoxing", False),
    ("kdocs.cn", "WPS 金山文档", False),
    ("dd.SessionId", "钉钉 SSO", True),
    ("ecology_JSessionid", "泛微 e-cology", True),
    ("/wui/", "泛微 · /wui/", True),
    ("atrust", "深信服 aTrust", False),
    ("Sangfor", "深信服", True),
    # 配置错误类信息泄露（单 GET / 被动可确认；详见 rules/test-scope-boundary.md §三/§八）
    ("<title>Index of", "目录列表 · Index of", False),
    ("Traceback (most recent call last)", "Debug泄露 · 堆栈跟踪", False),
    ("SECRET_KEY", "Debug泄露 · SECRET_KEY", False),
    ("phpinfo()", "信息泄露 · phpinfo", False),
    # 未授权后台泄露（3xx/2xx 响应体含后台页面 —— 后置鉴权缺陷，body 已随包发出）
    ("重置管理员密码", "未授权后台泄露 · 管理员密码重置", False),
    ("找回管理员密码", "未授权后台泄露 · 管理员密码找回", False),
    ("修改管理员密码", "未授权后台泄露 · 修改管理员密码", False),
    ("管理员登录", "未授权后台泄露 · 管理员登录字样", False),
    ("后台管理中心", "未授权后台泄露 · 后台管理中心", False),
    ("系统管理后台", "未授权后台泄露 · 系统管理后台", False),
    ("超级管理员", "未授权后台泄露 · 超级管理员字样", False),
]


def scan(hay, markers=None):
    """返回 hay 命中的判据名列表。markers 默认 SUBSTR。"""
    if markers is None:
        markers = SUBSTR
    out = []
    for mk, name, ci in markers:
        h = hay.lower() if ci else hay
        n = mk.lower() if ci else mk
        if n in h:
            out.append(name)
    return out


def classify(srv, body="", locs=(), cks=()):
    """按 Server 头 + 正文 + Location + Cookie 名综合判据，去重保序。"""
    hits = []
    if srv in SERVER_EXACT:
        hits.append(SERVER_EXACT[srv])
    hits += scan(body or "")
    hits += scan(" ".join(locs))
    hits += scan(" ".join(cks))
    seen, out = set(), []
    for h in hits:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


# 厂商归属优先级（取首个命中关键词）
PRIORITY = [
    ("网瑞达", "网瑞达WebVPN"), ("Sangine", "Sangine网关"),
    ("Astraeus", "Astraeus WebVPN"), ("自研WebVPN", "自研WebVPN"),
    ("金智", "金智wisedu"), ("正方", "正方"), ("泛微", "泛微"),
    ("RUMS", "RUMS图书馆"), ("学工系统", "学工系统"), ("创文科技", "创文科技ERMS"),
    ("SSL VPN(S:S)", "SSL VPN(Server:Server)"), ("WebVPN(appframe)", "WebVPN(appframe)"),
    ("CAS", "CAS系"), ("SSO", "SSO(OAuth/CAS模式)"), ("认证 ·", "其他认证"),
    (".NET OIDC", ".NET OIDC自建"), ("超星", "超星"), ("WPS", "WPS"), ("钉钉", "钉钉"),
    ("深信服", "深信服"), ("兰州大学", "兰大WebVPN"),
    ("网关默认值", "网关(Server:none)"), ("Server 头写错", "网关(Server:Server)"),
]


def vendor(hits):
    for kw, v in PRIORITY:
        if any(kw in h for h in hits):
            return v
    return "未定性"
