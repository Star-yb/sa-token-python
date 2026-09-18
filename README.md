# sa-token-python

<p align="center">
  <img src="docs/community.png" alt="加入讨论群" width="220" />
</p>
<p align="center">扫码加入讨论群</p>

轻量级、**有状态** 的 Python 认证鉴权框架，灵感来源于 [Sa-Token](https://sa-token.cc/)（Java）。

同族实现：[sa-token-go](https://github.com/sa-tokens/sa-token-go) · [sa-token-rust](https://github.com/sa-tokens/sa-token-rust) · [xlt-token](https://github.com/xiaoLangtou/xlt-token)（Node.js）

**核心不依赖任何 Web 框架。** 脚本、定时任务、gRPC、FastAPI、Flask、Django 共用同一套登录 / 踢人 / 权限语义。

```python
token = await StpUtil.login(user_id)
```

---

## 特性

- 🔐 **认证** — 登录 / 登出 / 双 Token 刷新，多端登录，踢人与顶号带明确原因
- 🛡️ **鉴权** — 权限与角色，支持通配符（`user:*`）和 AND / OR
- 🛣️ **路径鉴权** — Ant 风格规则表，可按 GET / POST / PUT / DELETE 区分
- 🧯 **防重放** — 服务端 Nonce、Refresh family 重放检测、Temp Token 原子消费
- 🚫 **封禁** — 临时 / 永久，按服务、按等级
- 🔒 **二级认证** — 已登录仍需短时确认，适合支付、改密
- 💾 **Session** — 账号级与 Token 级 KV 会话
- 🎨 **Token 风格** — uuid / random / hash / timestamp / tik / 有状态 JWT
- 📦 **存储可插拔** — Memory（开发）/ Redis（生产）/ 自定义 `SaStorage`
- 🎧 **事件** — 登录、登出、踢人、封禁等，载荷只带 token 指纹
- 🌐 **框架适配** — FastAPI 优先；Starlette / Flask / Django 基础适配
- 🎫 **OAuth2** — 授权码 + PKCE + client_credentials + introspection + 吊销
- 🔑 **SSO** — 一次性 ticket、HMAC 签名与统一登出
- 👥 **在线用户** — FastAPI WebSocket 鉴权、按设备推送、踢人即断连

---

## 安装

Python 3.10+。两个发行名，导入均为 `sa_token`。

```bash
pip install sa-token-python                     # 核心 + Redis / JWT（不含 Web 框架）
pip install "sa-token-python[fastapi]"          # 再加上 FastAPI / Starlette
pip install "sa-token-python[flask]"            # 再加上 Flask
pip install "sa-token-python[django]"           # 再加上 Django
pip install "sa-token-python[full]"             # Redis / JWT / 全部框架适配

pip install sa-token-python-core                # 轻量：核心 + 内存存储
pip install "sa-token-python-core[redis]"       # Redis 存储
pip install "sa-token-python-core[jwt]"         # JWT token 风格
pip install "sa-token-python-core[fastapi]"     # FastAPI / Starlette
pip install "sa-token-python-core[flask]"       # Flask
pip install "sa-token-python-core[django]"      # Django
pip install "sa-token-python-core[full]"        # 与 pip install "sa-token-python[full]" 相同
```

也可按需组合 extras，例如 `"sa-token-python-core[redis,jwt,fastapi]"`。

从源码安装：

```bash
pip install "git+https://github.com/Star-yb/sa-token-python.git"
pip install "sa-token-python-core[fastapi] @ git+https://github.com/Star-yb/sa-token-python.git"
```

---

## 快速开始（原生，无 Web 框架）

这是主路径。没有中间件，没有 Request，脚本里直接可用。

```python
import asyncio
from sa_token import SaToken, StpUtil
from sa_token.storage import MemoryStorage


async def main() -> None:
    SaToken.builder().storage(MemoryStorage()).timeout(7200).build()

    token = await StpUtil.login("10001", device="cli")
    await StpUtil.set_permissions("10001", ["user:read", "order:*"])
    await StpUtil.set_roles("10001", ["admin"])

    assert await StpUtil.is_login(token)
    assert await StpUtil.has_permission("10001", "order:delete")  # order:* 命中

    await StpUtil.kickout("10001")
    assert not await StpUtil.is_login(token)


asyncio.run(main())
```

```python
from sa_token.storage import MemoryStorage, RedisStorage

SaToken.builder().storage(MemoryStorage()).timeout(7200).build()
SaToken.builder().storage(RedisStorage.from_url("redis://127.0.0.1:6379/0")).timeout(7200).build()
```

被踢之后拿到的是明确原因，而不是笼统的「未登录」：

```python
from sa_token import NotLoginException, NotLoginType

try:
    await StpUtil.check_login(token)
except NotLoginException as exc:
    assert exc.type is NotLoginType.KICK_OUT   # 还可以是 BE_REPLACED / TOKEN_TIMEOUT / ...
```

---

## 异步与同步

**内核默认是异步。** 所有核心方法都是 `async`：

```python
token = await StpUtil.login(10001)
login_id = await StpUtil.check_login(token)
```

FastAPI / Starlette 直接 `await`。Flask、Django 同步视图、没有事件循环的脚本，用同步桥接：

```python
from sa_token.sync import StpUtilSync

token = StpUtilSync.login(10001)          # 没有 await
login_id = StpUtilSync.check_login(token)
```

`StpUtilSync` **不是第二份鉴权实现**，只是把同一套 `StpLogic` 放到后台事件循环里跑。

命名约定（避免和常见缩写搞混）：

| 名字 | 含义 | 使用场景 |
| --- | --- | --- |
| `StpUtil` | 异步 API（`async` / `await`） | FastAPI、脚本 `asyncio.run`、任何已有事件循环的环境 |
| `StpUtilSync` | 同步 API。`Sync` = English **synchronous**（同步） | Flask、Django 同步视图、普通函数 |

已经在事件循环里时不要调用 `StpUtilSync`，会明确报错，请直接 `await StpUtil.xxx()`。

---

## 核心 API

### 认证

```python
token = await StpUtil.login(1000)
token = await StpUtil.login("user123", device="mobile")
token = await StpUtil.login(1000, token_value="legacy-token")  # 迁移旧系统

tokens = await StpUtil.login_with_refresh(1000, device="web")
new_tokens = await StpUtil.refresh_access_token(tokens.refresh_token)

await StpUtil.is_login(token)
await StpUtil.check_login(token)          # 失败抛 NotLoginException
await StpUtil.get_login_id(token)

await StpUtil.logout(1000)
await StpUtil.logout_by_token(token)
await StpUtil.kickout(1000)               # 下次请求 type=KICK_OUT
await StpUtil.kickout_by_token(token)      # 只踢指定终端，保留原因
await StpUtil.replaced(1000)              # 下次请求 type=BE_REPLACED
await StpUtil.get_offline_reason(token)
```

### Nonce / Temp Token

```python
# 服务端签发；绑定用户与业务，消费时原子删除
nonce = await StpUtil.issue_nonce("10001", purpose="change-password")
await StpUtil.consume_nonce(nonce, "10001", purpose="change-password")

# 邀请、重置密码、邮箱验证等一次性链接
temp_token = await StpUtil.create_temp_token(
    {"user_id": "10001"}, 300, namespace="reset-password"
)
payload = await StpUtil.consume_temp_token(
    temp_token, namespace="reset-password"
)
```

`consume_nonce` 与 `consume_temp_token` 在并发请求中只允许一次成功。Nonce 不是
验证码，也不能代替登录校验；它用于阻止有效请求被重复提交。

### 权限 / 角色

```python
await StpUtil.set_permissions(1000, ["user:read", "user:write", "admin:*"])
await StpUtil.has_permission(1000, "admin:delete")          # 通配符命中
await StpUtil.has_permissions_and(1000, ["user:read", "user:write"])
await StpUtil.has_permissions_or(1000, ["admin", "super"])
await StpUtil.check_permission(1000, "order:delete")        # 失败抛 NotPermissionException

await StpUtil.set_roles(1000, ["admin", "manager"])
await StpUtil.has_role(1000, "admin")
await StpUtil.check_role(1000, "admin")
```

已有 RBAC 表时，实现 `StpInterface`（`get_permission_list` / `get_role_list`），不要把权限再抄一份进 Redis。

### Session / 封禁 / 二级认证

```python
session = await StpUtil.get_session(1000)
await session.set("nickname", "alice")

await StpUtil.disable(1000, seconds=3600)                   # 临时
await StpUtil.disable(1000, seconds=-1)                     # 永久
await StpUtil.disable(1000, 3600, service="comment", level=2)
await StpUtil.untie(1000)

await StpUtil.open_safe(token, "pay", 300)
await StpUtil.check_safe(token, "pay")
await StpUtil.close_safe(token, "pay")
```

### 多端查询

```python
await StpUtil.get_terminal_list(1000)
await StpUtil.get_token_value_list_by_login_id(1000, device="web")
await StpUtil.search_token_value("abc")     # 管理端扫描，不要放进热路径
await StpUtil.search_session("user")        # 扫描 Account-Session ID
```

---

## 配置

```python
SaToken.builder() \
    .storage(MemoryStorage()) \
    .token_name("Authorization") \
    .timeout(86400) \
    .token_style("uuid") \
    .is_concurrent(True) \
    .is_share(False) \
    .auto_renew(True) \
    .build()
```

| 配置 | 默认 | 说明 |
| --- | --- | --- |
| `token_name` | `Authorization` | Header / Cookie / Query 键名 |
| `timeout` | `2592000` | token 有效秒数，`-1` 永久 |
| `active_timeout` | `-1` | 活跃超时，超时未访问则冻结 |
| `auto_renew` | `True` | 校验成功后续期 |
| `token_style` | `uuid` | 生成风格 |
| `token_prefix` | `Bearer ` | 读取时剥离，不带前缀也接受 |
| `is_concurrent` | `True` | 是否允许多端同时在线 |
| `is_share` | `True` | 多端是否共享同一 token |
| `max_login_count` | `12` | 最大同时在线数，`-1` 不限制 |
| `refresh_token_timeout` | `2592000` | 登录态 Refresh Token 有效期 |
| `refresh_token_rotate` | `True` | 刷新时轮转 Refresh Token |
| `refresh_token_reuse_detection` | `True` | 旧值重放时吊销整个 family |
| `nonce_timeout` | `60` | 服务端 Nonce 有效秒数 |
| `is_write_cookie` | `False` | FastAPI 显式调用写 Cookie 助手时是否生效 |
| `storage_key_prefix` | `satoken:` | 所有存储键前缀 |
| `jwt_secret_key` | `None` | JWT 风格时必填 |

Token 读取顺序全局唯一：**Header → Authorization 兜底 → Cookie → Query**。各框架禁止自己再解析一遍。

### 多端登录语义

| `is_concurrent` | `is_share` | 行为 |
| --- | --- | --- |
| `False` | 忽略 | 新登录顶掉旧登录（银行 App） |
| `True` | `True` | 同设备类型复用同一 token |
| `True` | `False` | 每端独立 token，互不影响 |

---

## 路径鉴权（按 HTTP 方法区分）

Java 里可以 `SaRouter.match(SaHttpMethod.POST, "/user/**")`。本项目同样支持：规则表里用 `methods=`，匹配时同时看路径和请求方法。

`methods` 省略或空列表 = 匹配该路径的**所有方法**。

```python
from sa_token.adapter import PathAuthConfig
from sa_token.integration.fastapi import SaTokenMiddleware

path_auth = (
    PathAuthConfig()
    .ignore("/login", "/docs", "/openapi.json")
    .ignore("/article", methods=["GET"])                       # 公开阅读
    .permission("/article", "article:write", methods=["POST", "PUT", "DELETE"])
    .permission("/order/**", "order:*", methods=["DELETE"])
    .role("/admin/**", "admin")
    .login("/**")                                              # 其余全部要登录
)

app.add_middleware(SaTokenMiddleware, path_auth=path_auth)
```

对应关系：

| Java | 本项目 |
| --- | --- |
| `SaRouter.match("/user/**").check(r -> StpUtil.checkLogin())` | `.login("/user/**")` |
| `SaRouter.match(SaHttpMethod.GET, "/article")` | `.ignore("/article", methods=["GET"])` 或 `.login(..., methods=["GET"])` |
| `SaRouter.match(SaHttpMethod.POST, "/article").check(perm)` | `.permission("/article", "article:write", methods=["POST"])` |

注意：`ignore` 优先级最高。如果写成 `.ignore("/article")`（不限方法），后面的 `.permission("/article", ..., methods=["POST"])` 对 POST 也不会生效。要「GET 公开、POST 鉴权」，必须给 ignore 也加上 `methods=["GET"]`。

路径匹配是 Ant 风格：`*` 单层，`**` 任意层。

装饰器 / Depends 场景不需要规则表——路由本身已经绑定了方法（`@app.delete` 只对 DELETE 生效）。规则表适合网关、不想给每个路由挂注解的情况。

---

## FastAPI（主要适配框架）

各框架统一用注解鉴权。FastAPI 的标准写法与 Flask / Django 相同：

```python
from fastapi import FastAPI, Response
from sa_token import SaToken, StpUtil
from sa_token.storage import MemoryStorage, RedisStorage
from sa_token.integration.fastapi import SaTokenFastAPI, set_token_cookie

SaToken.builder().storage(MemoryStorage()).set_option(is_write_cookie=True).build()
SaToken.builder().storage(RedisStorage.from_url("redis://127.0.0.1:6379/0")).set_option(is_write_cookie=True).build()

app = FastAPI()
sa = SaTokenFastAPI(app)


@app.post("/login")
async def login(user_id: str, response: Response) -> dict:
    tokens = await StpUtil.login_with_refresh(user_id, device="web")
    set_token_cookie(response, tokens.access_token)
    return tokens.to_dict()


@app.get("/user")
@sa.check_login
async def user_info() -> dict:
    return {"id": sa.login_id()}


@app.delete("/order/{order_id}")
@sa.check_permission("order:delete")
async def delete_order(order_id: str) -> dict:
    return {"deleted": order_id}
```

作为主要适配框架，FastAPI 额外提供 `Depends` / `Annotated`（`LoginId`、`BearerLoginId`），语义与注解相同：

```python
from fastapi import Depends
from sa_token.integration.fastapi import LoginId, BearerLoginId, check_permission


@app.get("/profile")
async def profile(login_id: LoginId) -> dict:
    return {"id": login_id}


@app.get("/me")
async def me(login_id: BearerLoginId) -> dict:
    return {"id": login_id}


@app.get("/order/{order_id}")
async def get_order(order_id: str, _: str = Depends(check_permission("order:read"))) -> dict:
    return {"id": order_id}
```

### FastAPI WebSocket

```python
from fastapi import WebSocket
from sa_token.integration.fastapi import authenticate_websocket

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    login_id, token = await authenticate_websocket(websocket)
    await websocket.accept()
```

浏览器 WebSocket 不能自定义 Header 时可使用
`/ws?Authorization=<token>`。生产代码应再用 `OnlineManager.register` 登记连接，
并在心跳、断开时调用 `heartbeat` / `unregister`。

完整的登录刷新、Cookie、权限、Nonce、WebSocket 示例见
[`examples/fastapi/main.py`](examples/fastapi/main.py)。

---

## Flask

Flask 没有事件循环，用 `StpUtilSync`。鉴权与 FastAPI、Django 一样使用注解。

```python
from flask import Flask
from sa_token import SaToken
from sa_token.storage import MemoryStorage, RedisStorage
from sa_token.integration.flask import SaTokenFlask
from sa_token.sync import StpUtilSync

SaToken.builder().storage(MemoryStorage()).build()
SaToken.builder().storage(RedisStorage.from_url("redis://127.0.0.1:6379/0")).build()

app = Flask(__name__)
sa = SaTokenFlask(app)


@app.post("/login")
def login():
    return {"token": StpUtilSync.login("10001")}


@app.get("/user")
@sa.check_login
def user_info():
    return {"id": sa.login_id()}


@app.delete("/order/<order_id>")
@sa.check_permission("order:delete")
def delete_order(order_id):
    return {"deleted": order_id}
```

完整示例见 [`examples/flask/main.py`](examples/flask/main.py)。

---

## Django

Django 自带 `django.contrib.auth`（Session + User 模型）。本库**不是**去替换它，而是给 **纯 API / DRF** 项目提供与 FastAPI、Flask 一致的 Token 鉴权。模板站点继续用 Django Auth 即可。

安装：`pip install "sa-token-python[django]"` 或 `pip install "sa-token-python-core[django]"`。Django 是同步 WSGI，一律走 `StpUtilSync`。

### 1. 启动时初始化

在某个 App 的 `AppConfig.ready()` 里构建一次 Manager（只做一次，不要在每个请求里 `build()`）：

```python
# myapp/apps.py
from django.apps import AppConfig

class MyappConfig(AppConfig):
    name = "myapp"

    def ready(self) -> None:
        from sa_token import SaToken
        from sa_token.storage import MemoryStorage, RedisStorage

        SaToken.builder().storage(MemoryStorage()).timeout(86400).print_banner(False).build()
        SaToken.builder().storage(RedisStorage.from_url("redis://127.0.0.1:6379/0")).timeout(86400).print_banner(False).build()
```

### 2. 注册中间件

```python
# settings.py
MIDDLEWARE = [
    # ... Django 自带中间件 ...
    "sa_token.integration.django.SaTokenDjangoMiddleware",
]
```

默认行为与 FastAPI 中间件相同：**只解析 token**，挂到 `request.sa_token` / `request.sa_login_id`，不强制登录。未登录访问公开接口不会 401。

鉴权异常会被中间件翻成 JSON：`{"code": 401, "message": "...", "error": "NotLoginException", "type": "NOT_TOKEN"}`。

### 3. 登录 / 登出视图

```python
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from sa_token.sync import StpUtilSync

@csrf_exempt
def login(request):
    # 这里自己查数据库校验账号密码，通过后：
    user_id = "10001"
    token = StpUtilSync.login(user_id, device="web")
    StpUtilSync.set_permissions(user_id, ["user:read", "order:*"])
    StpUtilSync.set_roles(user_id, ["admin"])
    return JsonResponse({"token": token})

def logout(request):
    StpUtilSync.logout_by_token(request.sa_token)
    return JsonResponse({"ok": True})
```

客户端之后在 Header 带 `Authorization: Bearer <token>`。Cookie / Query 同样能读到（由核心 `token_io` 统一处理）。

### 4. 视图装饰器

与 FastAPI、Flask 相同，使用注解：

```python
from django.http import JsonResponse
from sa_token.integration.django import check_login, check_permission, check_role

@check_login
def me(request):
    return JsonResponse({"login_id": request.sa_login_id})

@check_permission("order:delete")
def delete_order(request, order_id):
    return JsonResponse({"deleted": order_id})

@check_role("admin")
def admin_panel(request):
    return JsonResponse({"ok": True})

@check_permission("user:read", "user:write", mode="AND")
def update_user(request):
    return JsonResponse({"ok": True})
```

装饰器失败时直接返回 401 / 403 JSON，不会进到视图函数。

### 5. 路径规则表（可选）

不想给每个 view 挂装饰器时，在初始化之后给模块级 `PATH_AUTH` 赋值，中间件就会按规则表强制鉴权：

```python
# 建议放在 AppConfig.ready() 里，build() 之后
from sa_token.adapter import PathAuthConfig
from sa_token.integration import django as sa_django

sa_django.PATH_AUTH = (
    PathAuthConfig()
    .ignore("/api/login", "/api/health")
    .ignore("/api/article", methods=["GET"])
    .permission("/api/article", "article:write", methods=["POST", "PUT", "DELETE"])
    .role("/api/admin/**", "admin")
    .login("/api/**")
)
```

### 6. 与 DRF 一起用

中间件仍然生效。DRF ViewSet 上继续套同一个装饰器，或在 `initial()` / permission 类里调用 `StpUtilSync.check_login(request.sa_token)`。不要在 DRF 里再写一套 Header 解析。

取当前用户：

```python
login_id = request.sa_login_id          # 中间件或装饰器已经校验过时
# 或
login_id = StpUtilSync.get_login_id(request.sa_token)
```

### 7. 不要和 Django Auth 混用同一套会话

| | Django Auth | sa-token-python |
| --- | --- | --- |
| 凭证 | `sessionid` Cookie | Token（Header / Cookie / Query） |
| 用户模型 | `AUTH_USER_MODEL` | 只认 `login_id` 字符串 |
| 踢人 | 清 session / 改密码未必立刻失效 | `kickout` 立刻生效 |
| 适用 | 模板站点、Admin | 纯 API、多端、需要踢人封禁 |

两套可以并存（Admin 继续用 Django Auth，API 用本库），但不要让同一个接口两套都校验。

---

## 存储

```python
from sa_token import SaToken
from sa_token.storage import MemoryStorage, RedisStorage

SaToken.builder().storage(MemoryStorage()).timeout(7200).build()
SaToken.builder().storage(RedisStorage.from_url("redis://127.0.0.1:6379/0")).timeout(7200).build()
SaToken.builder().storage(RedisStorage.from_url("redis://:your_password@127.0.0.1:6379/0")).timeout(7200).build()
SaToken.builder().storage(RedisStorage.from_url("redis://user:your_password@127.0.0.1:6379/1")).timeout(7200).build()
SaToken.builder().storage(RedisStorage.from_url("rediss://:your_password@redis.example.com:6379/0")).timeout(7200).build()
```

```python
from redis.asyncio import Redis
from sa_token.storage import RedisStorage

client = Redis(host="127.0.0.1", port=6379, db=0, password="your_password", decode_responses=True)
SaToken.builder().storage(RedisStorage(client)).build()
```

自定义存储实现 `SaStorage`：`get` / `set` / `delete` / `expire` / `ttl` / `set_if_absent` / `compare_and_set` / `scan`。

---

## Token 风格

`uuid`（默认）、`simple-uuid`、`random32` / `random64` / `random128`、`hash`、`timestamp`、`tik`、`jwt`。

JWT 是**有状态 JWT**：token 自带 claims，校验仍查存储。踢人、顶号、封禁继续有效。不要把它理解成「签发后服务端不管」。

```python
SaToken.builder().storage(MemoryStorage()).token_style("jwt").jwt_secret_key("至少32字节的密钥").build()
```

---

## 事件

```python
from sa_token import Event, EventData, SaToken
from sa_token.storage import MemoryStorage

def on_event(data: EventData) -> None:
    print(data.event, data.login_id, data.token_fingerprint)

SaToken.builder().storage(MemoryStorage()).on(Event.ALL, on_event).build()
```

事件包括 `LOGIN` / `LOGOUT` / `KICKOUT` / `REPLACED` / `DISABLE` / `UNTIE` / `RENEW` 等。载荷只有 token 指纹，不会把原始 token 打进日志。监听器异常不影响主流程。

---

## 扩展模块

全部框架无关，可在单测里不起 HTTP 服务跑通。

**OAuth2**（授权码 + PKCE + 原子 refresh 轮转 + client_credentials）：

```python
from sa_token.oauth2 import OAuth2Client, OAuth2Server, generate_pkce_pair

server = OAuth2Server(manager)
await server.register_client(OAuth2Client(
    client_id="web-app",
    client_secret="secret",
    redirect_uris=["https://app.example/callback"],
    scopes=["read"],
))
code = await server.create_authorization_code(
    client_id="web-app", login_id="10001", redirect_uri="https://app.example/callback",
)
tokens = await server.exchange_code_for_token(
    code=code.code, client_id="web-app", client_secret="secret",
)
```

FastAPI 可直接挂载标准 `/token`、`/introspect`、`/revoke`：

```python
from sa_token.integration.fastapi_oauth2 import create_oauth2_router

app.include_router(create_oauth2_router(server))
```

授权页是否同意属于业务决策，不会由库自动放行；用户确认后调用
`authorization_redirect`。

**SSO**：配置 `SsoConfig(secret_key="...")` 后使用
`create_signed_ticket` / `validate_ticket(..., signature=...)`；ticket 一次性且绑定
service。`SsoServer.logout` 返回待通知客户端列表，HTTP 或消息队列由应用选择。

**在线用户 / WebSocket**：`OnlineManager` 支持心跳、按用户或设备推送、按设备
断开和过期连接清理。通过 `StpUtil.kickout` / `replaced` 触发核心事件时，本进程
连接会自动关闭。跨 worker 的连接对象不能放进 Redis，跨进程广播需由部署层接入
Redis Pub/Sub 或消息总线。

---

## 异常

| 异常 | HTTP | 含义 |
| --- | --- | --- |
| `NotLoginException` | 401 | 未登录 / 无效 / 超时 / 被踢 / 被顶 / 冻结，看 `exc.type` |
| `NotPermissionException` | 403 | 权限不足 |
| `NotRoleException` | 403 | 角色不足 |
| `DisableException` | 403 | 账号封禁 |
| `NotSafeException` | 403 | 二级认证未通过 |
| `SecurityException` | 400 | Nonce / Refresh / Temp Token 安全流程失败，看 `exc.code` |
| `SaTokenException` | 500 | 其它内部错误 |

`NotLoginException.type`：`NOT_TOKEN` / `INVALID_TOKEN` / `TOKEN_TIMEOUT` / `TOKEN_FREEZE` / `BE_REPLACED` / `KICK_OUT`。

框架适配只做异常 → HTTP 的翻译，不在适配层重新发明错误码。

---

## 项目结构

```
src/sa_token/
├── stp_logic.py          # 认证鉴权的唯一实现
├── stp_util.py           # 异步静态门面
├── sync.py               # 同步桥接 StpUtilSync
├── adapter/              # HttpContext + 路径规则 + 统一管道
├── integration/          # FastAPI / Flask / Django / Starlette（只做适配）
├── storage/              # Memory / Redis
├── strategy/             # Token 生成风格
├── security/             # Nonce / 登录 Refresh / Temp Token
├── oauth2/  sso/  online/
```

依赖方向只能从上到下：`integration` 可以依赖 core，core 绝不能 import FastAPI / Flask / Django。

示例见 [examples/](examples/)。

---

## License

Apache-2.0
