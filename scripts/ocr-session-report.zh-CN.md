# sa-token-python 中断扫描的审查意见（中文）

来源：`C:\Users\starcwm\.opencodereview\sessions\D_.A-Project-sa-token-python\dfec471d-ad3d-4711-82fe-6fb18a26cc9c.jsonl`

这是 `scripts/ocr-session-report.md` 的中文译本。代码块保持原样，只翻译说明文字。

已提交意见 117 条。其中 96 条来自中断前的会话，21 条来自后来对未完成文件的补扫（`scripts/ocr-rescan/`）。

- **严重**: 1
- **高**: 27
- **中**: 53
- **低**: 36
- **补扫后无意见**: `src/sa_token/strategy/base.py`、`src/sa_token/token_io.py`

## 高

### `src/sa_token/adapter/path.py`

- **缺陷**

命中的多条规则被收成同一个 `mode`，而且只要有一条是 AND，就会一直粘在 AND 上。`run_auth_flow` 会把 `rule.mode` 同时用在 `check_permission` 和 `check_role` 上，于是一条 AND 规则会悄悄改掉其它本该按 OR 判断的规则。例如 `.permission("/x", "a", "b", mode="OR")` 再加上 `.role("/x", "r1", "r2", mode="AND")`，权限 `["a", "b"]` 也会按 AND 判断，只拥有 `a` 的用户会被拒绝。模式应该按每条规则、每一组列表单独保存（例如分别保留 `(permissions, mode)` 和 `(roles, mode)`，各组独立判断），不要合并成一个开关。

```
merged = PathRule(path, require_login=any(rule.require_login for rule in matched))
        for rule in matched:
            merged.permissions.extend(rule.permissions)
            merged.roles.extend(rule.roles)
            if rule.mode == "AND":
                merged.mode = "AND"
        return merged
```

### `src/sa_token/integration/django.py`

- **缺陷**

身份上下文绑定在 PATH_AUTH 分支会丢失。`run_path_auth`/`run_auth_flow` 内部通过 `set_current(token, login_id)` 写入 contextvars，但 `run_sync` 是把协程投递到 sa-token 的后台事件循环线程执行的，contextvars 的修改只作用于那个 Task 的上下文副本，不会回传到当前 Django 请求线程。结果是：走了 PATH_AUTH 的请求，视图里 `StpUtil.get_token_value()` / `StpUtil.get_login_id_from_context()` 恒为 `None`；而 PATH_AUTH 为 None 的分支因为直接在本线程调用 `resolve_token`，却是能取到 token 的——两种配置行为不一致。建议拿到结果后在请求线程里重新绑定。

```
run_sync(run_path_auth(ctx, manager, PATH_AUTH))
```

建议改成：

```
result = run_sync(run_path_auth(ctx, manager, PATH_AUTH))
                set_current(result.token, result.login_id)
```

### `src/sa_token/integration/fastapi.py`

- **缺陷**

无条件追加一个仅关键字参数，会在接口已经声明了 `**kwargs` 时生成非法签名。`inspect.Signature` 要求参数顺序固定：可变关键字参数后面不能再跟仅关键字参数。于是 `Signature.replace(...)` 会在装饰阶段抛出 `ValueError: wrong parameter order`。也就是说，任何写成 `async def handler(**kwargs)` 又加上 `@sa.check_login` 的路由，应用都启动不了。应当把合成的 `request` 参数插到可变关键字参数前面；如果已经有 `request` 参数，就不要再插入。

```
return signature.replace(parameters=[*signature.parameters.values(), request_param])
```

建议改成：

```
params = list(signature.parameters.values())
    var_kw = [p for p in params if p.kind is inspect.Parameter.VAR_KEYWORD]
    if var_kw:
        params.insert(params.index(var_kw[0]), request_param)
    else:
        params.append(request_param)
    return signature.replace(parameters=params)
```

- **性能**

`wrapper` 永远是 `async def`，FastAPI 会把它当成协程路由并直接 await。被装饰的如果是同步 `def`，`view(...)` 会在事件循环里当场执行，而不是像未装饰的同步接口那样丢进 Starlette 的线程池。处理函数里的阻塞操作（数据库驱动、`requests`、文件读写）会卡住整个事件循环。同步处理函数应该用 `starlette.concurrency.run_in_threadpool` 卸到线程池。

```
outcome = view(*call_args, **call_kwargs)
                if inspect.isawaitable(outcome):
                    return await outcome
                return outcome
```

建议改成：

```
if inspect.iscoroutinefunction(view):
                    return await view(*call_args, **call_kwargs)
                return await run_in_threadpool(view, *call_args, **call_kwargs)
```

### `src/sa_token/integration/fastapi_oauth2.py`

- **安全**

`/introspect` 和 `/revoke` 完全没有客户端认证或授权，只读取原始的 `token` 字段。`server.introspect()` 会返回 `{active, client_id, sub, scope}`，所以这个接口等于一个无需登录的令牌探测口，还能泄露资源所有者（`sub`）和已授予的 scope。RFC 7662 第 2.1 节明确要求自省接口必须有某种授权，以防止令牌扫描。RFC 7009 第 2.1 节同样要求机密客户端在吊销时做客户端认证，否则任何知道令牌的第三方都能把它作废，对合法客户端造成拒绝服务。

另外，`create_oauth2_router` 没有提供接入保护的办法：没有把 `dependencies=` 传给 `APIRouter`，`server._verify_client_secret` 又是私有的，接入方不重写这两个路由就没法加保护。建议增加例如 `dependencies: Sequence[Depends] | None = None`（挂到路由或只挂到 introspect/revoke），并在调用 `introspect` / `revoke_token` 之前先认证客户端（HTTP Basic，或从请求体读取 `client_id` / `client_secret`）。

```
@router.post("/introspect")
    async def introspect_endpoint(request: Request) -> JSONResponse:
        parameters = await _read_parameters(request)
        return JSONResponse(await server.introspect(str(parameters.get("token", ""))))
```

### `src/sa_token/integration/flask.py`

- **缺陷**

这里没有把 `login_type` 传下去。`run_auth_flow` 默认 `login_type="login"`（见 `adapter/pipeline.py` 第 48 行），所以 `SaTokenFlask(app, login_type="admin")` 会拿默认的 `StpLogic` 去校验令牌（令牌名、配置、会话命名空间都不对），而不是 `admin` 那一套。本文件其它入口都传了 `login_type=self.login_type`（`_before_request`、`_guard`、`login_id_or_none`），这里不一致，是真实缺陷：可能凭空返回 401，更糟的是从错误的账号体系解析出身份。`check_disable` 因为调用了 `self.login_id()`，会继承这个错误。

```
result = run_sync(run_auth_flow(self._context(), get_manager(), build_rule()))
```

建议改成：

```
result = run_sync(
            run_auth_flow(
                self._context(),
                get_manager(),
                build_rule(),
                login_type=self.login_type,
            )
        )
```

- **安全**

请求级缓存只用固定属性名做键，没有按 `login_type` 分开。一个应用注册多个 `SaTokenFlask`（文档里的多账号写法，例如 `login_type="user"` 和 `login_type="admin"`）时，两边都会在同一个 app 上注册 `before_request`，后注册的会覆盖 `g.sa_login_id` / `g.sa_token`。`login_id()` 看到缓存就直接返回（`cached = getattr(g, "sa_login_id", None)`），可能返回另一个登录体系的身份，造成身份混淆和越权。应按登录类型分别存放（例如 `g.setdefault("sa_token", {})[self.login_type] = ...`），读取时用同一个键。

```
g.sa_token = ctx.state.get("stp_token")
        g.sa_login_id = ctx.state.get("stp_login_id")
```

建议改成：

```
state = g.setdefault("sa_token_state", {})
        state[self.login_type] = {
            "token": ctx.state.get("stp_token"),
            "login_id": ctx.state.get("stp_login_id"),
        }
```

### `src/sa_token/manager.py`

- **缺陷**

代码和自己的注释相反：没有配置存储时，`build()` 会静默退回 `MemoryStorage`。多进程、多 worker 部署下，这正好就是注释警告的故障（“登录成功，下一个请求却说未登录”），而且会把配置错误藏到生产环境，表现为随机的认证失败。要么直接抛出明确错误（强制调用方显式选择内存存储），要么至少在使用这个回退时打出非常醒目的警告。

```
storage = MemoryStorage()
```

建议改成：

```
raise ValueError(
                "未配置 Storage：请显式调用 .storage(...)（如需单机内存存储，请显式传入 MemoryStorage()）"
            )
```

### `src/sa_token/oauth2/model.py`

- **缺陷**

`from_json` 只用 `except ValueError` 包住了 `json.loads`，但构造对象本身在缺少必填字段时会抛 `TypeError`（这里只检查了 `code`；`client_id`、`login_id`、`redirect_uri` 都是必填）。这破坏了声明的 `AuthorizationCode | None` 约定：`OAuth2Server._consume_code` 这类调用方会写 `if parsed is None: raise OAuth2Error("invalid_grant", ...)`。损坏或旧版本的存储数据（或版本之间字段改名）会变成未处理的 `TypeError`，最终是 HTTP 500，而不是预期的 `invalid_grant`。在 `_consume_code` 里更严重：解析之前已经用 `compare_and_delete` 删掉了授权码，于是授权码被悄悄烧掉。`OAuth2Client.from_json` 和 `AccessTokenInfo.from_json` 有同样的问题。

```
if not isinstance(payload, dict) or "code" not in payload:
            return None
        allowed = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in payload.items() if k in allowed})
```

建议改成：

```
if not isinstance(payload, dict) or "code" not in payload:
            return None
        allowed = set(cls.__dataclass_fields__)
        try:
            return cls(**{k: v for k, v in payload.items() if k in allowed})
        except TypeError:
            return None
```

### `src/sa_token/oauth2/server.py`

- **安全**

这里的 `redirect_uri` 应该是必填，而不是可选。`create_authorization_code()` 签发每个授权码时都会绑定 `redirect_uri`。RFC 6749 第 4.1.3 节规定：授权请求里带了 `redirect_uri`，换令牌时就必须带上，并且要逐字比较。按现在的写法，攻击者只要泄露或截获授权码（Referer 泄露、同一设备上的恶意应用、日志暴露），不用知道回调地址就能兑换。这去掉了把授权码绑定到合法客户端的两个因素之一，削弱了授权码注入和混淆攻击的防护。既然存下来的授权码一定有 `redirect_uri`，参数缺失就应当当成错误。

```
if redirect_uri is not None and authorization_code.redirect_uri != redirect_uri:
            raise OAuth2Error("invalid_grant", "redirect_uri 与申请时不一致")
```

建议改成：

```
if redirect_uri is None or authorization_code.redirect_uri != redirect_uri:
            raise OAuth2Error("invalid_grant", "redirect_uri 与申请时不一致")
```

- **安全**

`revoke_token()` 只删除和传入令牌完全匹配的那一个键，配对的另一张凭证还在。吊销 access_token 后，对应的 refresh_token 仍然有效，客户端可以立刻再换一张全新的 access_token。这和模块文档说的“存储里删掉即刻失效”直接矛盾。吊销 refresh_token 时，当前 access_token 也会一直用到过期。应当把配对关系存下来（例如像 `_issue_tokens()` 那样，在刷新记录里记下 access_token，并在访问令牌记录里放反向引用或 token family id），让一次吊销同时废掉两张令牌。

```
for suffix in ("access", "refresh"):
            key = self._key(suffix, token)
```

### `src/sa_token/online/__init__.py`

- **缺陷**

`send_to_device` 在 `await self._sender(...)` 的同时遍历还活着的、按用户分组的连接字典。并发的 `register()`（`self._connections.setdefault(login_id, {})[resolved_id] = connection`）或 `unregister()`（`bucket.pop(...)`）会在 await 期间改同一个字典，抛出 `RuntimeError: dictionary changed size during iteration`，剩下的推送全部中断。它也没有像其它访问点那样持有 `self._lock`。应当先把条目拍成快照。

```
local = self._connections.get(login_id, {})
        for connection_id, connection in local.items():
```

建议改成：

```
async with self._lock:
            local = list(self._connections.get(login_id, {}).items())
        for connection_id, connection in local:
```

### `src/sa_token/security/refresh.py`

- **安全**

`refresh()` 只相信刷新令牌自己的记录，从不读取 `_family_key(record.family_id)` 来确认这个 family 是否还活着、有没有被作废。作废完全依赖 `revoke_family()` 去删 family 记录里列出的每张令牌，而那条路径本身会丢数据（见 `revoke_family` 里非原子的 `set`，以及 `issue()` 在记录已经写入之后失败）。任何没出现在 family 列表里的刷新令牌，作废之后仍然能继续换新的访问令牌。下面不轮换的分支甚至完全不碰 family 记录，所以永远发现不了作废。这里应当读 family 记录，不存在或已 `revoked` 就拒绝。

```
if record.state != "active":
            if self._manager.config.refresh_token_reuse_detection:
                await self.revoke_family(record.family_id)
```

- **缺陷**

破坏性步骤发生在新凭证生成之前，而且没有回滚。此时旧刷新令牌已经被 CAS 标成 `used`，旧访问令牌也在这里被销毁。如果 `login()` 抛错（`check_disable`、分配令牌、保存会话），或者随后的 `issue()` 抛出 `REFRESH_CONFLICT` / `REFRESH_FAMILY_REVOKED`，客户端会既没有有效访问令牌，刷新令牌也已被消费；而 `login()` 刚创建的访问令牌还留在存储里，既不返回也不清理。更糟的是，客户端用同一张刷新令牌重试时会走进 `state != "active"` 分支，把整个 family 作废，一次短暂的存储冲突就会把用户永久锁在外面。应当先签发新令牌，或者失败时把记录恢复为 `active`，并注销那张新的访问令牌。

```
logic = self._manager.stp(record.login_type)
        await logic.logout_by_token(record.access_token, revoke_refresh=False)
```

- **缺陷**

无条件 `set` 会把记录重新激活，即使它在中间已经被删掉。上面的 CAS 之后，并发的 `revoke()`、`revoke_for_access()`（由 `logout_by_token` / `kickout_by_token` 调用）或 `revoke_family()` 可能已经删了这个键；这次写入会把已经作废的刷新令牌复活成 `active`，并把它的 `refresh_token_timeout` 重新设满（默认 30 天）。应当改用 `compare_and_set(key, used_record.to_json(), active_record.to_json(), ...)`，返回 `False` 时中止（或重新检查 family）。

```
await self._storage.set(
                key,
                active_record.to_json(),
                self._manager.config.refresh_token_timeout,
            )
```

- **缺陷**

刷新记录在 family / 用户索引更新之前就被写成 `active`，而下面两次调用都可能抛错（`REFRESH_FAMILY_REVOKED`、`REFRESH_CONFLICT`）。走到这些路径时，存下来的刷新令牌以及调用方（`login_with_refresh`）签发的访问令牌在存储里仍然有效，但没有登记进任何 family，于是 `revoke_family()` 和 `revoke_all_for_login()` 都找不到它们：这是一个无法吊销的活会话。应当用 `try/except` 包住这两次调用，重新抛出之前先删掉 `self._refresh_key(refresh_token)`（并注销 `access_token`）。

```
await self._update_family(resolved_family, record)
        await self._add_user_family(login_type, login_id, resolved_family)
```

- **缺陷**

对 family 记录的读-改-写不是原子的：这个普通 `set` 会覆盖掉上面 `get` 之后、这次写入之前，`_update_family` 用 CAS 追加进去的内容。过期的 `refresh_tokens` / `access_tokens` 列表被写回去，于是并发签发的刷新令牌既不会在这里被删除，也不会被注销，但 family 已经被标成作废。而 `refresh()` 又不会再检查 family，这张令牌会继续可用。作废应当放进 `compare_and_set` 重试循环（重新读取、重新标 `revoked`、重新收集令牌列表），避免丢掉并发新增的令牌。`revoke_all_for_login` 有同样的窗口：它 `get` 之后才创建的 family，会在用户索引被删除后变成孤儿。

```
family.revoked = True
        await self._storage.set(key, family.to_json(), self._manager.config.refresh_token_timeout)
```

### `src/sa_token/session.py`

- **缺陷**

`save()` 用内存里的 `_data` 快照无条件覆盖整个会话，没有重新加载、没有锁、也没有版本检查。`get_session()` 每次调用都会做一个新快照，两个并发任务或进程（例如一次 `login()` 正在追加终端，另一个请求在调用 `session.set(...)`，或者注销正在删键）会各自写回自己的完整副本，后写的人会悄悄丢掉对方的修改，包括把刚删掉的终端写回来，以及覆盖已经删除的键。这和模块文档说的“每次写操作都会落存储……不会出现各自持有过期副本”相反，因为所有读取（`get`、`get_typed`、`has`、`keys`、`terminal_list`）也不会再从存储刷新。存储契约已经提供了 `compare_and_set`（“用于并发下的安全更新”），`security/refresh.py` 和 `sso/__init__.py` 也在用。`save()` 应该同样用带重试的 CAS（或按键加锁），而不是无条件 `set`；读取也应当能从存储刷新。

```
await self._storage.set(self._key, self._data.to_json(), self._timeout)
```

### `src/sa_token/stp_logic.py`

- **安全**

账号会话不存在时，`logout()` 会提前返回，于是也跳过了下面的 `revoke_all_for_login()`。会话经常在刷新令牌还活着的时候就被删掉：`_save_or_drop_session()` 会在 `terminal_list` 变空时丢掉它（默认如此，因为 `is_logout_keep_session=False`），而按设备注销（`device is not None`）又不会作废刷新 family。于是 “logout(device='pc') → logout(device='app') → logout(login_id)” 这条顺序走完后，每张刷新令牌都还有效，客户端可以再刷新出一张全新的访问令牌。刷新 family 的吊销不应当以会话还在为前提。

```
session = await self.get_session(normalized_id, create=False)
        if session is None:
            return
        removed = await self._remove_terminals(session, device, destroy=True)
```

- **缺陷**

和 `logout()` 同样的提前返回：账号会话不在时（TTL 过期，或上一次按设备踢人后被 `_save_or_drop_session` 丢掉），`kickout()` / `replaced()` 会变成什么都不做，`revoke_all_for_login(..., logout_access=False)` 也不会被调用。还活着的刷新令牌可以换成一张新的、并非离线状态的访问令牌，踢人就失效了。刷新令牌的吊销应当移到 `session is None` 判断之前，或放到判断外面。

```
session = await self.get_session(normalized_id, create=False)
        if session is None:
            return
        offline_count = await self._offline_terminals(session, normalized_id, device, state)
```

- **缺陷**

`session.raw.terminal_list` 的更新是非原子的读-改-写：`get_session()` 加载一份快照，这段代码在内存里修改，然后 `session.save()` 盲目 `SET` 回去（`SaSession.save` 没有 CAS，存储层的 `compare_and_set` 这里也没用）。同一账号的两次并发 `login()`（多设备登录、表单重复提交、两个应用副本）会各自保存自己的副本，输掉的那次写入会从索引里消失，但它的令牌记录仍然有效。这张孤儿令牌此后无法被 `logout(login_id)`、`kickout()`、`replaced()` 或 `get_terminal_list()` 找到，也就是用户无法被完全注销。`logout_by_token`、`kickout_by_token` 和 `_offline_terminals` 是同一种写法。应当用 `compare_and_set` 加重试来保护会话更新，或者把终端索引放到按令牌分开的键上，而不是放在共享的会话大对象里。

```
session.raw.history_terminal_count += 1
        session.raw.terminal_list.append(
```

## 中

### `examples/fastapi/main.py`

- **缺陷**

清理只在 `WebSocketDisconnect` 时做。`online.register(...)` 之后如果抛出其它异常（例如套接字已经关闭时 `send_text("pong")` 让 Starlette 抛 `RuntimeError`，或 `online.heartbeat(...)` 里的存储错误），异常会逃出处理函数，连接会一直留在注册表里。`OnlineManager._connections` 是进程内字典，没有 TTL（只有存储里的记录会过期），泄漏的 `WebSocket` 对象也一直可达，`send_to_user()` 会继续往一条死连接推送。应当把 `unregister` 放进 `finally`，让每条退出路径都会清理。

```
except WebSocketDisconnect:
        await online.unregister(login_id, connection.connection_id)
```

建议改成：

```
except WebSocketDisconnect:
        pass
    finally:
        await online.unregister(login_id, connection.connection_id)
```

- **安全**

`/pay` 用 `check_safe("pay")` 保护，但 `/open-safe` 只要已经登录就发放这次二次验证，没有重新输入密码、OTP 或其它升级验证。作为参考示例，这种写法会被原样复制，悄悄毁掉安全模式的意义（偷到有效令牌的人立刻就能做“敏感操作”）。请在这里把第二因素写明确，例如先校验密码或 OTP 再调用 `open_safe`，并在文档字符串里说明跳过这一步就等于没有保护。

```
async def open_safe(login_id: LoginId) -> dict:
```

### `examples/flask/main.py`

- **缺陷**

`request.get_json(silent=True) or {}` 只防住了 `None` 和假值的请求体。一个为真、但不是对象的 JSON（例如 `["admin"]`、`"x"`、`1`）会原样返回，接着 `payload.get(...)` 会抛 `AttributeError: 'list' object has no attribute 'get'`，变成 500 而不是预期的 400。应当确认解析结果是 `dict`。

```
payload = request.get_json(silent=True) or {}
```

建议改成：

```
payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return {"code": 400, "message": "请求体必须是 JSON 对象"}, 400
```

- **缺陷**

用户名完全没有校验。`StpUtilSync.login("")`（用户名缺失、为空或只有空白）会让 `StpLogic.normalize_login_id` 抛出基类 `SaTokenException`，它的 `http_status` 是 500。错误请求会表现为服务器内部错误，而不是密码错误时用的 400。用户名里包含 `:` 也会这样。这个文件是 Flask 接入的标准复制模板，登录前应当显式检查用户名。

```
token = StpUtilSync.login(username, device="web")
```

建议改成：

```
if not username:
        return {"code": 400, "message": "账号或密码错误"}, 400

    token = StpUtilSync.login(username, device="web")
```

### `src/sa_token/adapter/path.py`

- **性能**

`**` 回溯没有记忆化，匹配代价是路径段数 `n` 和 `**` 个数 `k` 的 O(n^k)。每个请求都会跑（`run_path_auth` → `resolve` → `matches`），路径又由请求方控制：像 `/api/**/a/**/b/**/c` 这样的模式，配上一条很长且匹配失败的 URL，递归调用会组合爆炸（而且递归很深）。同一个 `(pattern_index, path_index)` 会被反复探索，把访问过的状态记下来就能变成 O(模式长度 × 路径长度)。

```
for skip in range(path_index, len(path_parts) + 1):
                if _match_parts(pattern_parts, pattern_index + 1, path_parts, skip):
                    return True
```

建议改成：

```
for skip in range(path_index, len(path_parts) + 1):
                if (pattern_index + 1, skip) in seen:
                    continue
                seen.add((pattern_index + 1, skip))
                if _match_parts(pattern_parts, pattern_index + 1, path_parts, skip, seen):
                    return True
```

- **安全**

匹配用的是原始路径段：重复斜杠会被折叠，但 `.` 和 `..` 不会。请求路径 `/public/../admin/user` 会命中忽略规则 `/public/**`，从而不做任何认证就放行；而前面的代理或 WSGI 层如果先把路径规范化再分发，同一个请求实际会进到 `/admin/user`。`ignore` 的优先级是绝对的，所以这是一条默认放行的路径。匹配前应当拒绝或规范化 `.` / `..` 段（或者路径里含有它们时直接不匹配）。

```
pattern_parts = [part for part in pattern.strip("/").split("/") if part != ""]
    path_parts = [part for part in path.strip("/").split("/") if part != ""]
```

建议改成：

```
pattern_parts = [part for part in pattern.strip("/").split("/") if part != ""]
    path_parts = _normalize_segments(path)
    if path_parts is None:  # 含无法解析的 ".."，直接拒绝匹配
        return False
```

- **安全**

没有命中的路径是默认放行：返回的规则没有 `ignore`、没有 `require_login`、也没有权限或角色，于是 `run_auth_flow` 直接短路成 `AuthResult(anonymous=True)`，请求不认证就处理了。表里漏掉的路由（新加的接口、模式写错、尾部斜杠不一致）默认都是公开的。请把这一点写明确：要么在类的文档字符串里突出默认允许，要么提供默认拒绝选项（例如 `default_rule` / `deny_by_default`），让配置错误时失败关闭而不是失败开放。

```
matched = [rule for rule in self._rules if rule.matches(path, method)]
        if not matched:
            return PathRule(path)
```

### `src/sa_token/adapter/pipeline.py`

- **安全**

`set_current()` 返回两个 `contextvars` 重置令牌，就是为了让调用方恢复之前的状态，但 `resolve_token` 和 `run_auth_flow`（第 68 行）都把它们丢掉了，认证路径上也没有任何地方清除绑定。在 ASGI 的每个请求任务里这没有问题，但同步适配器是在工作线程上直接调用这个函数的（例如 Flask 的 `_before_request` → `resolve_token(ctx, manager)`，以及 `SaTokenFlask.token()`），也没有任何适配器在请求结束时调用 `clear_current()`。响应发出之后，令牌和 login_id 仍留在被复用的工作线程上下文里。之后同一个线程上、没有再走过 sa-token 钩子的请求（或钩子运行前就读取 `get_current_token()` / `StpUtil.get_login_id_from_context()` 的代码）能看到上一个请求的身份，造成跨请求身份泄漏。另外，如果 `check_login` / `check_permission` / `check_role` 抛错，部分绑定也会因为同样的原因留下来。建议把重置引用返回出去（例如放在 `AuthResult` 的字段上），或者提供一个类似 `sa_token_context` 的入口，要求适配器用它包住整个请求，以便请求结束时清掉身份。

```
ctx.state["stp_token"] = token
    set_current(token, None)
    return token
```

### `src/sa_token/config.py`

- **缺陷**

`__post_init__` 是这个配置对象唯一的校验点。模块文档说它会从 YAML、环境变量或配置中心构建，但它既不校验 `Literal` 类型的字段，也不校验数字字段。非法值不会立刻失败，还会悄悄改变和安全有关的行为。例如在 `stp_logic._enforce_max_login_count` 里，`mode = self.config.overflow_logout_mode` 会去字典里查，任何无法识别的值都会得到 `state is None`，于是走 `_destroy_token()` 而不是 `_mark_token_offline()`。写成 `"logut"` 或 `"kick_out"` 这样的笔误会静默关掉离线原因记录，而且不报错。`replaced_range` 写错则会把顶号范围静默降成 `curr_device`。`timeout`、`active_timeout`、`offline_record_timeout`、`perm_cache_timeout` 的负数或 0（除了文档说明的 `-1` 哨兵）也会被接受。建议在这里用 `typing.get_args(...)` 校验 Literal 字段，并检查数字范围，让配置错误在启动时暴露，而不是到请求时才把行为降级。

```
def __post_init__(self) -> None:
        if not self.token_name:
            raise ValueError("token_name 不能为空")
        if self.storage_key_prefix and not self.storage_key_prefix.endswith(":"):
            self.storage_key_prefix += ":"
```

建议改成：

```
def __post_init__(self) -> None:
        if not self.token_name or not self.token_name.strip():
            raise ValueError("token_name 不能为空")
        if self.storage_key_prefix and not self.storage_key_prefix.endswith(":"):
            self.storage_key_prefix += ":"
        if self.overflow_logout_mode not in get_args(OverflowLogoutMode):
            raise ValueError(f"overflow_logout_mode 非法：{self.overflow_logout_mode!r}")
        if self.replaced_range not in get_args(ReplacedRange):
            raise ValueError(f"replaced_range 非法：{self.replaced_range!r}")
        for name in ("timeout", "active_timeout", "offline_record_timeout", "perm_cache_timeout"):
            value = getattr(self, name)
            if not isinstance(value, int) or value < NEVER_EXPIRE:
                raise ValueError(f"{name} 非法：{value!r}")
```

### `src/sa_token/context.py`

- **文档**

文档字符串声称可以用 `async with`，但 `contextlib.contextmanager` 只生成同步上下文管理器（`_GeneratorContextManager` 没有 `__aenter__` / `__aexit__`）。在异步代码里写 `async with sa_token_context(...)` 会抛 `TypeError: 'async with' requires an object with __aenter__ and __aexit__ methods`。这个模块明确面向异步场景（见模块文档），要么把文档改成异步调用方仍必须用普通 `with`，要么再提供一个 `@asynccontextmanager` 版本。

```
同步与异步代码都能用（``with`` 与 ``async with`` 场景下 contextvars 的
    传播规则一致），因此不必再提供一个异步版本。
```

建议改成：

```
同步与异步代码都用普通的 ``with``（本函数返回的是同步上下文管理器，
    ``async with`` 会抛 TypeError）；contextvars 在两种场景下的传播规则一致，
    因此不必再提供一个异步版本。
```

### `src/sa_token/exception.py`

- **缺陷**

`DisableException` 总是由 `StpLogic.check_disable()` 用 `remaining = get_disable_time(...)` 构造。这个函数的约定会返回哨兵值（`-1` 表示永久封禁，`-2` 表示未封禁）。永久封禁时文案会变成“……剩余 -1 秒”。框架适配器（flask / django / starlette）会把 `exc.message` 直接放进响应，这段让人困惑的文字会对用户可见。负数或哨兵值应当显示成“永久”（或干脆不写剩余时间），不要把原始数字插进去。

```
f"账号 {login_id} 的服务 {service} 已被封禁（等级 {level}，剩余 {remaining} 秒）",
```

建议改成：

```
super().__init__(
            f"账号 {login_id} 的服务 {service} 已被封禁"
            f"（等级 {level}，剩余 {'永久' if remaining < 0 else f'{remaining} 秒'}）",
            login_type=login_type,
        )
```

### `src/sa_token/integration/django.py`

- **缺陷**

同上：`run_auth_flow` 里的 `set_current(...)` 发生在后台事件循环线程，装饰器执行完后当前请求线程的 contextvars 仍是空的，视图内 `StpUtil.get_login_id_from_context()` / `StpUtil.get_token_value()` 返回 `None`（只能靠 `request.sa_login_id`）。建议在 `run_sync` 返回后用 `set_current(result.token, result.login_id)` 在本线程补一次绑定。

```
result = run_sync(run_auth_flow(ctx, get_manager(), rule_factory()))
```

- **缺陷**

装饰器不支持 `async def` 视图：wrapper 是普通同步函数，`functools.wraps` 不会让 Django 的 `iscoroutinefunction` 判定为协程视图，于是 Django 会把它当同步视图调用；`view(request, ...)` 返回的协程既不会被 await（触发 RuntimeWarning），也会被当成响应对象继续往下传，最终报 500。建议用 `asyncio.iscoroutinefunction(view)` 分支，另提供一个 async wrapper 直接 `await run_auth_flow(...)`（Django 4.1+），这样也顺带解决上一条上下文绑定问题。

```
def wrapper(request: Any, *args: Any, **kwargs: Any) -> Any:
```

### `src/sa_token/integration/fastapi.py`

- **缺陷**

`had_request` 只根据参数名判断。如果接口声明了一个名叫 `request`、但不是 Starlette/FastAPI `Request` 的请求体或查询参数（例如 `async def create(request: CreateSchema)`），`_endpoint_signature` 不会再添加真正的 `request: Request` 参数，FastAPI 也不会注入 Request，`_extract_request` 会对每次调用抛出 `RuntimeError("未找到 Request")`，变成 500。应当按注解或类型识别 Request，而不是按名字。

```
had_request = "request" in inspect.signature(view).parameters
```

建议改成：

```
params = inspect.signature(view).parameters
            had_request = any(
                param.annotation is Request for param in params.values()
            )
```

- **缺陷**

`__signature__` 上的签名会原样保留用户模块的注解（接口模块使用 `from __future__ import annotations` 时，注解是字符串）。FastAPI 的 `get_typed_signature` 用 `call.__globals__` 去求值这些注解，而 `wrapper` 的全局命名空间是本模块的，于是任何用户自定义类型（Pydantic 模型、枚举、前向引用）都会在注册路由时抛 `NameError`。应当在公布签名之前，先在视图自己的命名空间里把注解解析出来。

```
wrapper.__signature__ = _endpoint_signature(view)
```

建议改成：

```
sig = _endpoint_signature(view)
            hints = typing.get_type_hints(view)
            wrapper.__signature__ = sig.replace(
                parameters=[
                    p.replace(annotation=hints.get(p.name, p.annotation))
                    for p in sig.parameters.values()
                ]
            )
```

### `src/sa_token/integration/fastapi_oauth2.py`

- **缺陷**

请求体解析没有保护，而且会逃出 `token_endpoint` 里对 `OAuth2Error` 的处理（这次调用在 `try:` 之前），畸形的客户端请求会变成 HTTP 500，而不是 RFC 6749 第 5.2 节要求的 `400 invalid_request`：

- `await request.json()` 在 JSON 不合法时抛 `json.JSONDecodeError`。
- `(await request.body()).decode("utf-8")` 在非 UTF-8 请求体时抛 `UnicodeDecodeError`。

这两种都可以用一次恶意请求触发。应当包住解码并改抛协议错误，例如：

```python
try:
    payload = await request.json()
except ValueError as exc:
    raise OAuth2Error("invalid_request", "请求体不是合法 JSON") from exc
...
try:
    body = (await request.body()).decode("utf-8")
except UnicodeDecodeError as exc:
    raise OAuth2Error("invalid_request", "请求体编码非法") from exc
```

（`introspect_endpoint` / `revoke_endpoint` 也需要同样的保护，它们连 `try` 都没有。）

```
if "application/json" in content_type:
        payload = await request.json()
        return payload if isinstance(payload, dict) else {}
    body = (await request.body()).decode("utf-8")
```

- **安全**

令牌响应里有 `access_token` / `refresh_token`，但没有带 `Cache-Control: no-store`（以及 `Pragma: no-cache`）。RFC 6749 第 5.1 节要求任何包含令牌或凭证的响应都必须这样，否则共享代理缓存和浏览器历史可能留下仍然有效的凭证。这个接口的每个响应都要加这些头，包括 `_oauth_error` 里的错误响应。

```
return JSONResponse(response.to_dict())
```

建议改成：

```
return JSONResponse(
                response.to_dict(),
                headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            )
```

### `src/sa_token/integration/flask.py`

- **缺陷**

`token()` 看起来像纯读取，其实有副作用：`resolve_token()` 最后会 `set_current(token, None)`（见 `adapter/pipeline.py` 第 39 行），把请求级的 `_current_login_id` 上下文变量重置成 `None`。后果是：一个视图同时用了 `@sa.check_login` 和 `@sa.check_safe`（后者的包装函数在守卫已经绑定身份之后又调用 `self.token()`），或者视图里调用了 `sa.token()` / `sa.login_id_or_none()`，都会把已绑定的身份清掉，随后 `StpUtil.get_login_id()` / `get_current_login_id()` 返回 `None`。应当复用 `_before_request` 里已经解析好的令牌（`g.sa_token`），或用没有副作用的 `read_token(ctx, manager.config)` 去读。

```
def token(self) -> str | None:
        return resolve_token(self._context(), get_manager())
```

建议改成：

```
def token(self) -> str | None:
        from flask import g

        cached = getattr(g, "sa_token", None)
        if cached is not None:
            return cached
        return read_token(self._context(), get_manager().config)
```

### `src/sa_token/integration/starlette.py`

- **缺陷**

`resolve_token()` 内部会执行 `set_current(token, None)`，也就是把请求级上下文里的 login_id 强制清成 None。FastAPI 的依赖与端点运行在同一个 contextvars 上下文中，因此这里已经由 `SaTokenMiddleware` / 前置依赖绑定的登录身份会被抹掉：即便本函数拿到了有效 login_id 并返回给端点，端点里再调用 `get_current_login_id()`（如 `SaTokenFastAPI.login_id()`）仍会得到 None 并抛 `NotLoginException`。建议在取到 login_id 后用 `set_current(token, login_id)` 重新绑定（`current_token` 依赖也存在同样的清空副作用）。

```
ctx = StarletteHttpContext(request)
    token = resolve_token(ctx, get_manager())
    return await get_manager().stp().get_login_id_or_none(token)
```

建议改成：

```
ctx = StarletteHttpContext(request)
    token = resolve_token(ctx, get_manager())
    login_id = await get_manager().stp().get_login_id_or_none(token)
    set_current(token, login_id)
    request.state.sa_token = token
    request.state.sa_login_id = login_id
    return login_id
```

### `src/sa_token/listener.py`

- **缺陷**

`Listener` 的类型是 `Callable[[EventData], Any | Awaitable[Any]]`，但这里只 await 协程结果。如果监听器返回的是其它可等待对象（例如 `Future` / `Task`，或实现了 `__await__` 的对象，如异步包装的可调用对象、第三方 awaitable），它会被悄悄丢掉：工作可能根本不会被调度，异常也不会冒出来（这里什么都不抛，所以也没有日志）。应当用 `inspect.isawaitable(result)` 覆盖所有可等待类型。

```
result = registration.listener(data)
                if registration.is_async or asyncio.iscoroutine(result):
                    await result
```

建议改成：

```
result = registration.listener(data)
                if registration.is_async or inspect.isawaitable(result):
                    await result
```

- **缺陷**

如果发出的 `EventData` 的 `event == Event.ALL`（这是合法的枚举成员），`Event.ALL` 那一桶会和自己拼在一起，每个通配监听器对这个事件会被调用两次。通配查找应当只在发出的事件本身不是 `ALL` 时才追加。

```
matched = [*self._listeners.get(data.event, []), *self._listeners.get(Event.ALL, [])]
```

建议改成：

```
matched = list(self._listeners.get(data.event, []))
        if data.event is not Event.ALL:
            matched.extend(self._listeners.get(Event.ALL, []))
```

### `src/sa_token/manager.py`

- **缺陷**

`build()` 把构建器自己那份可变的 `SaTokenConfig` 和 `EventBus` 按引用交给管理器。后果有两个：（1）调用两次 `build()` 会得到两个共享同一份配置、同一个事件总线的管理器，给其中一个注册的监听器也会在另一个上触发，`on()` / `set_option()` 会串到别的管理器；（2）`build()` 之后再改构建器（或改 `manager.config`）会悄悄改变已经建好的管理器。应当给配置做快照（例如 `dataclasses.replace(self._config)`），并且每次构建新建一个 `EventBus`，把已注册的监听器复制过去。

```
manager = SaTokenManager(
            self._config,
            storage,
            strategy=self._strategy,
            stp_interface=self._stp_interface,
            events=self._events,
        )
```

建议改成：

```
config = dataclasses.replace(self._config)
        config.__post_init__()
        manager = SaTokenManager(
            config,
            storage,
            strategy=self._strategy,
            stp_interface=self._stp_interface,
            events=self._events.copy(),
        )
```

### `src/sa_token/model.py`

- **缺陷**

`state` 从 JSON 里原样取出，没有做类型校验。如果损坏、旧版本或跨语言的记录把 `state` 存成了列表或字典（不可哈希），这里的 `self.state in _OFFLINE_STATES` 会抛 `TypeError`，而不是返回布尔值。`is_offline` 在请求热路径上（`stp_logic._read_token_info` → `renew_timeout` / `get_token_session` / `get_offline_reason`），一张本来可以恢复的坏记录会变成未处理的 500。应当在 `from_json` 里规范化或校验 `state`（例如只有它是 `str` 时才保留，否则设为 `None`），或者让这次成员判断本身能防住异常。

```
return self.state in _OFFLINE_STATES
```

建议改成：

```
return isinstance(self.state, str) and self.state in _OFFLINE_STATES
```

- **缺陷**

`from_json` 的约定是“不可用的数据返回 `None`”（`stp_logic.get_session` 的调用方把 `None` 当成“新建一个会话”），但只有 `json.loads` 被保护了。这里有两个漏洞：（1）显式写 `"terminal_list": null` 时，`payload.get("terminal_list", [])` 会返回 `None`（默认值只在键不存在时生效），推导式会抛 `TypeError: 'NoneType' object is not iterable`；（2）`TerminalInfo.from_dict` 要求有 `token`，任何没有这个键的字典项都会抛 `TypeError`。两者都会从 `from_json` 冒出去，而不是降级成 `None`。应当校验容器类型，畸形终端则跳过或返回 `None`。

```
terminals = [
            TerminalInfo.from_dict(item)
            for item in payload.get("terminal_list", [])
            if isinstance(item, dict)
        ]
```

建议改成：

```
raw_terminals = payload.get("terminal_list")
        if raw_terminals is None:
            raw_terminals = []
        if not isinstance(raw_terminals, list):
            return None
        terminals = []
        for item in raw_terminals:
            if not isinstance(item, dict) or "token" not in item:
                continue
            terminals.append(TerminalInfo.from_dict(item))
```

- **缺陷**

`payload.get("data", {})` 只在键缺失时才用默认值；显式的 `"data": null`（或其它写入方产生的非字典值，如列表、字符串）会被原样接受并存下来。之后 `SaSession` 会把 `SessionData.data` 当字典来改、来读，错误会在很远的地方表现为 `TypeError: 'NoneType' object does not support item assignment`。`create_time` / `history_terminal_count` 也一样，非整数会在后面的运算里出错。应当校验类型并退回安全默认值（或返回 `None`）。

```
data=payload.get("data", {}),
```

建议改成：

```
data=payload["data"] if isinstance(payload.get("data"), dict) else {},
```

### `src/sa_token/oauth2/model.py`

- **安全**

`from_json` 过滤了键，但从不校验值的类型，于是 `allows_redirect` 文档里说的“精确匹配”安全不变量完全取决于存下来的 JSON 形状。如果 `redirect_uris` 被反序列化成字符串（例如 `"https://app.example.com/cb"`），`redirect_uri in self.redirect_uris` 会退化成子串匹配，从而接受 `https://app.example.com/cb.evil.test` 这种值，而这正是注释说要避免的开放重定向。`grant_types` 也一样（`"authorization_code" not in client.grant_types` 变成子串判断），`scopes` 也一样（`create_authorization_code` 里的 `scope not in client.scopes` 会把任何碰巧是已注册 scope 字符串子串的 scope 都授出去）。应当确认这些字段是 `str` 的列表，否则拒绝这条记录。

```
allowed = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in payload.items() if k in allowed})


@dataclass
class AuthorizationCode:
```

建议改成：

```
allowed = set(cls.__dataclass_fields__)
        data = {k: v for k, v in payload.items() if k in allowed}
        if not isinstance(data.get("client_id"), str):
            return None
        for name in ("redirect_uris", "grant_types", "scopes"):
            value = data.get(name)
            if value is not None and not (
                isinstance(value, list) and all(isinstance(i, str) for i in value)
            ):
                return None
        try:
            return cls(**data)
        except TypeError:
            return None


@dataclass
class AuthorizationCode:
```

### `src/sa_token/oauth2/server.py`

- **安全**

PKCE 方法处理太宽松：（1）`plain` 被无条件接受，而 `plain` 时 challenge 就是 verifier 本身，任何能看到授权请求的人（它走在重定向 URL 里）都能完全绕过 PKCE。RFC 7636 第 4.4.1 节只允许在确实不支持 S256 时使用 `plain`，很多服务器直接拒绝它。（2）任何无法识别的方法（`S512`、`PLAIN`、拼写错误）会静默掉进 S256 分支，之后才表现为让人困惑的“code_verifier 校验失败”，而不是在授权时就返回 `invalid_request`。应当在 `create_authorization_code()` 里用明确的允许列表校验 `code_challenge_method`（并把 `plain` 做成需要服务器开关才启用），让坏输入尽早被拒绝，安全策略也写清楚。

```
expected = (
            code_verifier if code.code_challenge_method == "plain" else _s256(code_verifier)
        )
```

建议改成：

```
if code.code_challenge_method == "plain":
            if not _ALLOW_PLAIN_PKCE:
                raise OAuth2Error("invalid_request", "不支持 plain 方式的 PKCE")
            expected = code_verifier
        elif code.code_challenge_method == "S256":
            expected = _s256(code_verifier)
        else:
            raise OAuth2Error("invalid_request", "未知的 code_challenge_method")
```

- **缺陷**

所有 OAuth2 错误都硬编码成 400，不符合规范。框架适配器又把 `http_status` 直接映射成 HTTP 响应，错误的状态码会漏给客户端：`invalid_client` 必须是 401（RFC 6749 第 5.2 节），`invalid_token` 必须是 401（RFC 6750 第 3.1 节），否则资源服务器不会触发标准的“401 然后刷新”流程；`insufficient_scope` 必须是 403。应当按 `error` 推导状态码，而不是用一个常量。

```
http_status = 400
```

- **缺陷**

旧凭证在新凭证存在之前就被销毁。`_issue_tokens()` 里任何存储失败（连接断开、超时、内存不足）都会让用户同时失去已删除的 refresh_token 和 access_token，除了完整重新授权没有恢复办法。应当先签发替换令牌，成功后再删旧的一对（清理失败就记日志），或者给删除包一条补偿路径，签发失败时恢复之前的刷新记录。

```
raise OAuth2Error("invalid_grant", "refresh_token 已被使用")
        await self._storage.delete(self._key("access", info.access_token))
```

### `src/sa_token/online/__init__.py`

- **缺陷**

`heartbeat()` 对共享存储做的是非原子的读-改-写。如果 `unregister()` / `disconnect_user()` / `disconnect_device()`（或另一个进程里的踢人事件）在 `get()` 和 `set()` 之间删掉了这个键，这次调用会用全新的 `heartbeat_timeout` TTL 把记录复活。用户被踢之后，在最多 `heartbeat_timeout` 秒内，`is_online()` / `get_online_users()` 仍会认为他在线，跨进程的踢人标记也就失效了。`Storage` 已经提供了 `compare_and_set(key, expected, new_value, ttl)`，应当用它（或 Lua / 只续期的原子路径），让刷新不能把已删除的键重新创建出来。

```
user.last_heartbeat = now_ms()
        await self._storage.set(key, user.to_json(), self.heartbeat_timeout)
```

- **缺陷**

连接快照是在获取 `self._lock` 之前拍的，而 `connection_ids` 是在锁里面取的。如果中间有连接注册进来（register 先写存储，再拿锁），它的 id 会出现在 `connection_ids` 里，于是它的存储记录被删除，也会从 `_connections` 里弹出，但对象不在 `connections` 里，`self._closer` 永远不会对它调用。结果是一条还活着、但不再被跟踪、也永远不会关闭的 WebSocket。两个快照应当在同一段加锁区域内取得。

```
connections = self.local_connections(login_id)
        async with self._lock:
            connection_ids = list(self._connections.get(login_id, {}).keys())
```

建议改成：

```
async with self._lock:
            bucket = self._connections.pop(login_id, {})
            connection_ids = list(bucket.keys())
            connections = list(bucket.values())
```

- **性能**

这里有两个问题：（1）`self._lock` 在对每个本地连接 `await self._storage.exists(...)` 期间一直被持有，于是每次扫描都会按连接数串行等待完整的 Redis 往返，`register` / `unregister` / `disconnect_*` 全部被堵住。连接多或存储慢、存储在远端时会很明显。（2）如果 `exists()` 在循环中途抛错，已经从 `_connections` 里 `pop` 出来的条目会和本地的 `stale` 列表一起丢失，这些套接字永远不会交给 `self._closer`，它们泄漏并保持打开，同时不再被跟踪。应当在锁内只收集候选的（键, 连接）对，到锁外做存储检查，然后再拿锁删除确认过期的条目并关闭它们。

```
async with self._lock:
            for login_id, bucket in list(self._connections.items()):
                for connection_id, connection in list(bucket.items()):
                    if not await self._storage.exists(self._key(login_id, connection_id)):
```

### `src/sa_token/security/nonce.py`

- **缺陷**

`issue()` 在写入前会规范化主体（`str(subject).strip()`），但 `consume()` 拿原始的 `str(subject)` 去比。调用方如果传入带首尾空白的主体（或签发时被规范化过的非字符串主体），即使 nonce 有效也会被 `NONCE_MISMATCH` 拒绝，两条路径对“什么算同一个主体”会悄悄不一致。应当把规范化抽成共用函数，两边都用（`purpose` 也要一致校验）。

```
if record.subject != str(subject) or record.purpose != purpose:
```

建议改成：

```
if record.subject != self._normalize_subject(subject) or record.purpose != purpose:
```

- **可维护性**

`state` 会随每条记录存下来，但没有任何地方读取。`consume()` 只检查 `subject` / `purpose`，所以状态不是 `issued` 的记录（例如其它组件写入的未来的 `revoked` / `consumed`）仍会被接受。要么在 `consume()` 时校验 `record.state == "issued"`，要么在真正用到之前删掉这个字段，避免存下来的状态和安全决策脱节。

```
state: str = "issued"
```

### `src/sa_token/security/refresh.py`

- **性能**

`revoke_for_access` 会扫整片键空间：Redis 的 `SCAN` 遍历每个键并在服务端过滤，这里还对每个候选键发一次 `GET`。它在每次 `logout_by_token` 和 `kickout_by_token` 时都会调用（`stp_logic.py` 第 314、340 行），也就是一次普通注销的代价是 O(库里的总键数)，而且即使匹配的记录已经删掉，循环仍会继续扫描。应当维护反向索引 `access_token -> refresh key`（或把刷新令牌放进 `TokenInfo`），让这次查找变成一次读取，而不是全库扫描。

```
cursor, keys = await self._storage.scan(f"{prefix}refresh:*", cursor, 200)
```

- **性能**

这些列表只会增长，而 family 的 TTL 在每次轮换时都会被刷新。默认 `refresh_token_timeout` 是 30 天，客户端每几分钟刷新一次，一个 JSON 值里会堆积成千上万张访问令牌和刷新令牌。每次轮换的 `not in` 成员检查是 O(n)，`revoke_family` 还要对每一项做 `get_token_info` + `logout_by_token` 和一次 `delete`（成千上万次串行往返）。应当删掉刷新记录已经不存在的条目，限制列表长度，或者把 family 成员存成单独的键，而不是一个不断变大的大对象。

```
if record.access_token not in family.access_tokens:
                family.access_tokens.append(record.access_token)
            if record.refresh_token not in family.refresh_tokens:
                family.refresh_tokens.append(record.refresh_token)
```

### `src/sa_token/security/temp_token.py`

- **安全**

`namespace`（以及 `token`）只在 `create()` 里通过 `_validate()` 校验。`parse()`、`consume()`、`delete()` 和 `find_token()` 用未校验的输入拼存储键，于是读取路径可以绕过“命名空间里不能有冒号”的限制，键空间会撞车：命名空间 `"a:b"` 加令牌 `"c"`，和命名空间 `"a"` 加令牌 `"b:c"` 会生成完全相同的键（调用方传入的令牌可以含冒号，虽然生成出来的不会）。这样就能跨命名空间读取或删除一次性令牌。应当抽出只检查命名空间的函数，并在每个拼键的公开方法里调用。

```
def _key(self, namespace: str, token: str) -> str:
        return f"{self._key_prefix}security:temp:{namespace}:{token}"
```

- **安全**

对一个已经有索引项的值再次签发令牌时，会覆盖索引，但之前签发的令牌会在存储里活到 TTL 结束。对一次性操作（重置密码、验证邮箱）来说，这意味着同一个业务值可以同时有多张有效令牌：用户申请了新链接之后，持有旧重置链接的攻击者仍然可以 `consume()` 它，而 `find_token()` 只报告最新的那张。覆盖索引之前，应当读出旧的索引值并删掉那张令牌（或使用 `compare_and_set` 再显式作废）。

```
if record_index and isinstance(value, str):
                    await self._storage.set(self._index_key(namespace, value), token, ttl)
```

### `src/sa_token/session.py`

- **缺陷**

修改先写进 `_data`，然后才 await 存储写入。`save()` 失败时（Redis 超时、连接错误、序列化错误）这个句柄已经脏了：异常会传出去，调用方以为写入没发生，但改动还在内存里，会被同一个句柄上一次成功的 `save()` 写出去（例如后来的 `set()`，或 `StpLogic._save_or_drop_session()`）。`clear()` 是最坏的情况：本地会话数据已经全部清掉，调用方看到了错误，之后仍会被刷进存储。`save()` 抛错时应当给 `_data` 做快照并回滚（或者先持久化，成功后再提交本地修改）。

```
async def clear(self) -> None:
        self._data.data.clear()
        await self.save()
```

### `src/sa_token/storage/base.py`

- **文档**

TTL 契约只定义了 `None` 与 `-1`，对 `0` 和其它负数没有任何约定，而两个现有实现已经出现行为分歧：`MemoryStorage._to_expire_at` 把 `ttl <= 0` 视为“立即过期”（键写入后马上不可读），`RedisStorage._normalize_ttl` 则用 `max(1, ttl)` 钳成 1 秒存活。同一段业务代码（如 `set(k, v, ttl=0)`）在内存后端与 Redis 后端下结果不同，属于难以排查的一致性缺陷。建议在契约中明确 `ttl` 只能是 `None`/`-1` 或正整数，并规定 `0`/其它负数的统一语义（推荐“立即过期或删除”），要求各实现遵守。

```
``ttl`` 单位为秒；``None`` 与 ``-1`` 等价，均表示永不过期。
```

### `src/sa_token/stp_logic.py`

- **缺陷**

`config.dynamic_active_timeout` 永远不会生效。代码库里没有任何地方给 `TokenInfo.active_timeout` 赋值：`login()` 没有这个参数，`_allocate_token()` 也只构造 `TokenInfo(login_id, device, login_type, timeout, tag)`，所以这个字段永远是默认的 `None`，条件总是落到 `self.config.active_timeout`。更糟的是，`_touch_active` 里配套的判断（`if self.config.active_timeout < 0 and not self.config.dynamic_active_timeout: return`）意味着：`dynamic_active_timeout=True` 且 `active_timeout=-1` 时，每个请求都会写 `last-active` 键，但从来不会读它，纯属开销。要么把按令牌的 `active_timeout` 从 `login()` / `_allocate_token()` 传进去，要么删掉这个配置开关和这段死分支。

```
active_timeout = (
            info.active_timeout
            if self.config.dynamic_active_timeout and info.active_timeout is not None
            else self.config.active_timeout
        )
```

- **性能**

`_renew` 在每次成功的 `check_login` 上都会跑，也就是每个已认证请求一次，并做 4 次存储往返（`_touch_active` 里 1 次 `set`，加上 3 次 `expire`），还要发一个事件。三次 `expire` 是贵的部分：它们无条件重写上一个请求刚刚延长过的 TTL，`Event.RENEW` 还会让任何审计日志或指标监听器每个请求记一条，把它们淹没。应当只在剩余 TTL 真正掉得比较多时才续期（例如 `storage.ttl()` 低于 `timeout` 的大约一半时才重新 `expire`），并把 RENEW 降级成抽样或需要显式打开的事件。

```
await self.storage.expire(self._token_key(token), timeout)
        await self.storage.expire(self._session_key(info.login_id), timeout)
        await self.storage.expire(self._token_session_key(token), timeout)
        await self._emit(Event.RENEW, login_id=info.login_id, token=token, timeout=timeout)
```

## 低

### `examples/fastapi/main.py`

- **可维护性**

`python -O` 会去掉断言。如果这里的令牌上下文缺失，调用会退化成 `open_safe(None, "pay", 300)`，接口仍然返回 `{"ok": True}`，用户会以为二次验证已经打开，其实没有。应当用会抛错的显式判断（例如 `NotLoginException`），或者复用注入进来的依赖，而不是去读上下文里的令牌。

```
assert token is not None
```

### `examples/flask/main.py`

- **安全**

每次登录成功都会被授予 `admin` 角色，于是任何已认证的调用方都能访问 `/admin/panel`。哪怕只是演示，这种写法也容易被原样复制进真实服务。应当把角色限定到特定演示账号（例如只有 `username == "admin"` 时才给 admin），让示例里的角色检查真的有可能失败。

```
StpUtilSync.set_roles(username, ["admin"])
```

建议改成：

```
StpUtilSync.set_roles(username, ["admin"] if username == "admin" else ["user"])
```

- **安全**

`debug=True` 会打开 Werkzeug 的交互式调试器。应用一旦能从浏览器访问到（例如绑在 `0.0.0.0`、跑在容器里、或通过隧道暴露），就可以在浏览器里执行任意代码。调试默认应当关闭，需要时再用环境变量显式打开，并在文档字符串里说明这个示例必须只在本机使用。

```
app.run(debug=True)
```

建议改成：

```
app.run(debug=os.getenv("FLASK_DEBUG") == "1")
```

### `examples/native/quick_start.py`

- **可维护性**

这里用 `assert` 作为踢人演示唯一的行为检查。`python -O` 会去掉断言，如果这个示例被当成冒烟测试（CI 或文档构建）复用，行为回退时它仍会以 0 退出。另外，如果 `check_login` 根本不抛异常，`except` 分支会被跳过，脚本什么都不打印，却仍然成功退出。应当做显式检查，例如在处理函数里写 `if exc.type is not NotLoginType.KICK_OUT: raise AssertionError(...)`，并在 `try` 上加 `else: raise AssertionError("expected NotLoginException")`。

```
assert exc.type is NotLoginType.KICK_OUT
```

- **可维护性**

这个 `assert` 同时还在给下面的 `session.set(...)` 做 `None` 收窄。`python -O` 下，会话为 `None` 时后面会变成让人困惑的 `AttributeError`，而不是一次明确的失败。如果只是为了给类型检查器收窄类型，这样可以；但作为可运行的示例，显式写 `if session is None: raise RuntimeError(...)` 失败方式才确定。

```
assert session is not None
```

### `src/sa_token/adapter/path.py`

- **性能**

大写方法集合在每次调用时都重新构建，而 `matches` 对每条规则、每个请求都会调用一次。应当在 `__post_init__` 里规范化一次（例如 `self._methods = {m.upper() for m in methods}`），之后和缓存好的集合比较。

```
if self.methods and method.upper() not in {m.upper() for m in self.methods}:
```

建议改成：

```
if self._methods and method.upper() not in self._methods:
```

### `src/sa_token/adapter/pipeline.py`

- **可维护性**

`build_rule` 是公开 API 的一部分（在 `adapter/__init__.py` 的 `__all__` 里重新导出，flask / django / fastapi / starlette 接入也在用），但它不在本模块的 `__all__` 里，所以 `from sa_token.adapter.pipeline import *` 会悄悄把它漏掉。为了一致，应当把它加进去。

```
__all__ = ["AuthResult", "resolve_token", "run_auth_flow", "run_path_auth"]
```

建议改成：

```
__all__ = ["AuthResult", "build_rule", "resolve_token", "run_auth_flow", "run_path_auth"]
```

### `src/sa_token/config.py`

- **可维护性**

`from_dict` 会丢掉未知的键，而且没有任何提示。这和 `SaTokenBuilder.set_option` 不一致（同样的情况它会抛“未知配置项”）。外部配置里拼错的键（例如 `cookie_securre`、`jwt_secrety_key`、`token_prefx`）会被静默忽略，可能不安全的默认值继续生效，调用方还以为设置已经生效。另外，来自环境变量或 YAML 的值没有做类型转换，`timeout="60"`（字符串）会一直传到登录路径上的运算，在离加载配置很远的地方才失败。至少应当把被忽略的键记下来，或者加一个 `strict: bool = False` 参数，遇到未知键就抛错，并对已知字段做类型转换和校验。

```
known = {f.name for f in fields(cls)}
        return cls(**{key: value for key, value in values.items() if key in known})
```

### `src/sa_token/context.py`

- **可维护性**

`tokens is None` 这个分支把两个变量都硬设成 `None`，而不是恢复之前绑定的值，这和文档字符串说的“还原到绑定前的状态”相反。嵌套使用时（例如已经有一个 `sa_token_context(...)` 块在生效，外层框架又在请求结束时调用 `clear_current()`），内层身份会被悄悄清掉，而不是被恢复。`adapter/pipeline.py` 这类调用方使用 `set_current(...)` 时会丢掉返回的重置令牌，这条回退路径很容易走到。应当把它的文档改成“无条件清除”（也可以改名），或者把重置令牌参数改成必填，这样总能正确恢复。

```
if tokens is None:
        _current_token.set(None)
        _current_login_id.set(None)
        return
```

### `src/sa_token/exception.py`

- **缺陷**

直接用字典下标意味着，任何不在 `_NOT_LOGIN_MESSAGES` 里的 `NotLoginType` 值（例如以后新增的枚举成员，或另一个模块从存储解码出来的值）会抛 `KeyError`，而不是认证错误。`KeyError` 不是 `SaTokenException`，适配器不会把它映射成 401，请求会退化成未处理的 500。应当用 `.get()` 配一条通用兜底文案，让异常约定始终成立。

```
super().__init__(_NOT_LOGIN_MESSAGES[not_login_type], login_type=login_type)
```

建议改成：

```
super().__init__(
            _NOT_LOGIN_MESSAGES.get(not_login_type, "登录状态无效"),
            login_type=login_type,
        )
```

### `src/sa_token/integration/__init__.py`

- **可维护性**

`__all__` 只声明了 fastapi/starlette/flask/django 四个子模块，但包内还存在 `fastapi_oauth2.py`（提供 `create_oauth2_router` / `authorization_redirect`）。由于 `from sa_token.integration import *` 会按 `__all__` 导入子模块，`fastapi_oauth2` 不会被暴露，容易被使用者忽略；建议将其补入 `__all__`，或在此处注释说明它是通过 `sa_token.integration.fastapi_oauth2` 显式导入的可选扩展模块。

```
__all__ = ["fastapi", "starlette", "flask", "django"]
```

建议改成：

```
__all__ = ["fastapi", "starlette", "flask", "django", "fastapi_oauth2"]
```

### `src/sa_token/integration/fastapi_oauth2.py`

- **缺陷**

401 质询发的是光秃秃的 `WWW-Authenticate: Basic`，缺少必需的 `realm` 参数（RFC 6749 第 5.2 节 / RFC 7617）。更重要的是，这些接口实际上从不接受 HTTP Basic 凭证：`token_endpoint` 只从请求体读取 `client_id` / `client_secret`。符合规范的客户端收到这个质询后，会带着 `Authorization: Basic ...` 头重试，而这段代码会忽略它，于是重试再次以 `invalid_client` 失败。要么支持 Basic 客户端认证（解码 `request.headers.get("authorization")` 并合并进 `parameters`），要么换掉或去掉这个头，例如 `WWW-Authenticate: Bearer realm="oauth2"`。

```
headers = {"WWW-Authenticate": "Basic"} if status == 401 else None
```

- **缺陷**

对 JSON 请求体，键存在且值为 JSON `null` 时，`parameters.get("client_secret", "")` 返回的是 `None`，`str(...)` 会变成字面量 `"None"`，然后被当成真密钥交给 `_verify_client_secret`。这和紧上面 `authorization_code` / `refresh_token` 分支把原始值传下去的做法不一致。应当用一个小的规范化函数（`value if isinstance(value, str) else ""`），让缺失、null、非字符串字段变成空字符串，而不是它们的 `repr`。

```
client_secret=str(parameters.get("client_secret", "")),
```

### `src/sa_token/integration/flask.py`

- **缺陷**

这里用 `assert` 来保证声明的 `str` 返回类型，但 `python -O` 会去掉断言。那时这个方法会静默返回 `None`（并缓存进 `g.sa_login_id`），对每个调用方都违反约定。应当改成显式检查并抛出 `SaTokenException`，这样优化构建下的行为也一样。

```
assert result.login_id is not None
```

建议改成：

```
if result.login_id is None:  # pragma: no cover - require_login 保证非空
            raise SaTokenException("登录校验未返回 login_id")
```

### `src/sa_token/integration/starlette.py`

- **性能**

每个 Depends 扩展都会重新跑一遍完整鉴权流程（读 header/cookie/query 取 token + `check_login` 访问存储）。当请求已经过 `SaTokenMiddleware`（尤其是配置了 `path_auth` 时）或同一路由挂了多个本模块依赖时，同一请求会重复做多次存储往返；并且 `check_login()` / `check_permission()` 每次调用都返回新的闭包对象，FastAPI 的依赖缓存无法去重。建议把已完成的鉴权结果缓存在 `request.state`（中间件已写入 `sa_token` / `sa_login_id`）上，`_authorize` 命中时直接复用。

```
ctx = StarletteHttpContext(request)
    rule = build_rule(permissions=permissions, roles=roles, mode=mode)
    result = await run_auth_flow(ctx, get_manager(), rule)
```

- **可维护性**

`_authorize` 调用 `run_auth_flow` 时未传 `login_type`，`check_disable` / `check_safe` 也用 `get_manager().stp()` 的默认账号体系，而 `SaTokenMiddleware` 是支持自定义 `login_type` 的。当应用配置了非默认的 login_type（如 "user"）时，这些 Depends 扩展会去校验另一套账号体系（token 名称、存储 key 都不同），导致已登录用户被判定 401。建议让这些工厂接受 `login_type` 参数（或从 request.state / 中间件配置读取）并向下透传。

```
await get_manager().stp().check_disable(login_id, service=service, level=level)
```

- **缺陷**

用 `assert` 保证鉴权不变量在 `python -O` 下会被整条删除。目前 `build_rule` 默认 `require_login=True`，不变量成立；但一旦有调用方传入 `require_login=False`（或规则命中 ignore 分支），依赖就会在声明为 `str` 的位置静默返回 None，把鉴权失败变成下游的 AttributeError/None 传播。建议改为显式抛出 `NotLoginException`，既保留类型收窄又不受 -O 影响。

```
assert result.login_id is not None
```

建议改成：

```
if result.login_id is None:
        raise NotLoginException(NotLoginType.NOT_TOKEN)
```

### `src/sa_token/listener.py`

- **性能**

`emit()` 在认证热路径上被内联 await（例如 `StpLogic.login` / `logout` 经由 `_emit`），但同步监听器是直接在事件循环上调用的。做阻塞审计 I/O（数据库、HTTP、写文件）的监听器会在每次登录或注销时卡住事件循环。应当在文档里说明同步监听器必须是非阻塞的，或者用 `asyncio.to_thread` / `run_in_executor` 把它们分发出去。

```
async def emit(self, data: EventData) -> None:
```

### `src/sa_token/manager.py`

- **缺陷**

`hasattr` 对数据类的方法也会返回 True（`key_prefix`、`make_key`、`from_dict`），所以 `set_option(key_prefix="satoken")` 这种从外部配置文件来的、看起来合理的键会通过校验，然后用字符串盖掉绑定方法，之后 `config.key_prefix(...)` / `make_key(...)` 会以让人困惑的 `TypeError` 失败。应当对照真正的数据类字段名来校验。

```
if not hasattr(self._config, key):
                raise ValueError(f"未知配置项：{key}")
```

建议改成：

```
if key not in {f.name for f in dataclasses.fields(self._config)}:
                raise ValueError(f"未知配置项：{key}")
```

### `src/sa_token/online/__init__.py`

- **可维护性**

发送和关闭失败在五个地方（`send_to_user`、`send_to_device`、`disconnect_user`、`disconnect_device`、`cleanup_stale_connections`）被光秃秃的 `except Exception: continue` 吞掉，没有任何日志。`Exception` 也会盖住编程错误（用户提供的 `sender` / `closer` 里的 `TypeError`、`AttributeError`，以及和 `CancelledError` 相邻的问题），配错的回调会静默报告“发送了 0 条消息”，连接其实也没关掉，非常难查。至少应当按 debug 或 warning 记日志，并考虑把捕获范围收窄到发送方或关闭方实际抛出的传输异常。

```
except Exception:
                # 推送失败通常意味着连接已断，交给连接自身的清理流程处理。
                continue
```

- **缺陷**

用 `id(connection)` 派生默认 `connection_id` 作为跨进程键的一部分是不安全的：内存地址只在一个进程里、对当前还活着的对象唯一，两个不同进程可能给同一个 `login_id` 生成相同的十六进制 id。它们就会共用一个存储键（`online:user:<login_id>:<id>`），一个进程的 `register` 会覆盖另一个进程的记录，它的 `unregister` / `disconnect_*` 也会把对方删掉。另一条连接会从 `is_online()` / `get_online_users()` 里悄悄消失，并被 `cleanup_stale_connections()` 拆掉。应当用全局唯一的 id（例如 `uuid4().hex`，可选再加进程前缀）。

```
resolved_id = connection_id or f"{id(connection):x}"
```

### `src/sa_token/security/nonce.py`

- **可维护性**

如果键在 `get()` 和 `compare_and_delete()` 之间过期，`compare_and_delete` 返回 False，调用方会收到 `NONCE_REPLAYED`（“nonce 已被其它请求使用”）。这把普通过期误报成重放攻击，会误导审计和告警。删除失败后应当再检查一次是否还存在，键已经没了就抛 `INVALID_NONCE`。

```
if not await self._storage.compare_and_delete(key, raw):
            raise SecurityException("NONCE_REPLAYED", "nonce 已被其它请求使用")
```

### `src/sa_token/security/temp_token.py`

- **缺陷**

`consume()` 返回 `Any | None`，其中 `None` 表示“令牌无效或已被使用”，但 `value: Any` 也允许合法存下一个 `None`。那种情况下，令牌已经被 `compare_and_delete` 原子销毁，调用方却收到 `None`，分不清是成功消费还是重放或过期（对用真值判断的调用方，`0`、`""`、`False` 这些假值也有同样的歧义）。返回一个哨兵或 `tuple[bool, Any]`，或者像 `NonceManager.consume` 那样失败时抛 `SecurityException`，才能把两种结果区分开。

```
return record.value
```

### `src/sa_token/session.py`

- **可维护性**

这个属性把活的、可变的 `SessionData.terminal_list`（以及里面可变的 `TerminalInfo`）直接交出去。调用方可以 `append` / `remove` / 修改，却不会触发任何 `save()`，改动会被悄悄丢掉（或者更糟，被一次无关的 `save()` 很久以后才刷出去），破坏这个类文档说的“每次写入都会落到存储”。和明确标成内核内部的 `raw` 不同，这看起来像公开访问器。应当返回副本（例如 `list(self._data.terminal_list)`），或者把它标成只读或内部接口，并提供会调用 `save()` 的显式修改方法。

```
return self._data.terminal_list
```

### `src/sa_token/storage/__init__.py`

- **可维护性**

`RedisStorage` 出现在 `__all__` 里，README 也写成 `from sa_token.storage import RedisStorage`，但这个名字在运行时只通过 PEP 562 的 `__getattr__` 存在。静态类型检查器（例如 mypy）不会为 `from ... import ...` 解析模块级 `__getattr__`，用户对自己的代码做类型检查时会得到“Module 'sa_token.storage' has no attribute 'RedisStorage'”。建议加一段 `TYPE_CHECKING` 保护的再导出，让这个名字在静态分析里可见，运行时导入仍然保持惰性；也可以把类缓存进 `globals()`，避免每次访问属性都重新执行导入。

```
def __getattr__(name: str) -> Any:
    if name == "RedisStorage":
        from .redis import RedisStorage

        return RedisStorage
```

建议改成：

```
if TYPE_CHECKING:  # 仅供静态类型检查，运行时仍惰性导入
    from .redis import RedisStorage


def __getattr__(name: str) -> Any:
    if name == "RedisStorage":
        from .redis import RedisStorage

        globals()["RedisStorage"] = RedisStorage
        return RedisStorage
```

### `src/sa_token/storage/base.py`

- **文档**

`expire` 的返回值语义在实现间并不等价于“键不存在”：`RedisStorage` 在 `ttl is None` 时走 `PERSIST`，而 Redis 对“键存在但本来就没有 TTL”同样返回 0/False。也就是说调用方无法用 `False` 判断键是否存在（`if not await storage.expire(k, ttl): # 当作键已失效` 会误判）。建议把契约写清楚：返回值仅表示 TTL 状态是否被成功修改，键存在性请用 `exists()`/`ttl() == -2` 判断；或要求实现在键不存在时才返回 False（Redis 侧需额外 EXISTS 判断）。

```
"""更新 TTL，键不存在时返回 False。"""
```

- **文档**

游标语义存在歧义：入参 `cursor=None` 表示“从头开始扫描”，出参 `None` 表示“扫描结束”，同一个值承担两种含义，调用方很容易把首轮返回值当起始游标再次传入而造成重复扫描。此外游标是不透明值（Redis 原生用 `"0"` 同时表示开始与结束，`MemoryStorage` 用的是排序后的偏移量），契约应显式要求：实现必须把“结束”统一映射为 `None`，调用方不得自行构造或解析游标，且游标不可跨实现/跨进程复用。

```
"""按 glob 模式游标扫描键，返回 ``(下一个游标, 键列表)``；游标为 None 表示结束。"""
```

- **可维护性**

两点风险：1) `@runtime_checkable` 的 `isinstance` 只校验同名属性是否存在，既不校验签名也不校验方法是否为协程函数，一个含同步 `get`/`set` 的对象同样能通过检查；当前代码库中没有任何 `isinstance(x, SaStorage)` 调用，该装饰器实际未起到校验作用，反而容易让人误以为运行时可以验证契约。2) 所有方法都是 `...` 默认体（非 `@abstractmethod`），一旦被显式继承而漏写某个方法（例如 `ttl()`），调用会静默返回 `None` 而非报错，直接破坏 `-> int` / `-> bool` 契约并在上层引发难以定位的 `TypeError`。若确实允许被继承，建议默认体改为 `raise NotImplementedError`；若仅用于结构化类型检查，可考虑去掉 `runtime_checkable`。

```
@runtime_checkable
class SaStorage(Protocol):
```

### `src/sa_token/stp_logic.py`

- **缺陷**

`keyword` 被直接插进 Redis 的 glob 模式，没有转义。关键字里的 glob 元字符（`*`、`?`、`[`、`]`、`\`）会改变匹配含义。没有闭合 `]` 的 `[` 会让 Redis 拒绝这个模式并表现为 500；不受信任的管理台查询如果传入 `*`，会静默退化成导出整片键空间。拼模式之前应当转义关键字（例如把每个元字符包进 `[]`，或拒绝非字母数字输入），`search_session` 也要做同样的修复。

```
pattern = f"{prefix}*{keyword}*" if keyword else f"{prefix}*"
```

### `src/sa_token/stp_util.py`

- **缺陷**

`get_manager()` 把可变的模块全局变量 `_manager` 读了两次（一次判断 `is None`，一次返回）。如果另一个线程在两次读取之间调用了 `clear_manager()` / `set_manager()`（例如应用重建或测试拆卸时请求还在飞），函数可能返回 `None`，尽管注解承诺的是 `SaTokenManager`。每个门面调用都会得到让人困惑的 `AttributeError`，而不是预期的 `SaTokenNotInitializedException`。应当把全局变量读进一个局部变量，再校验那个局部变量。

```
def get_manager() -> SaTokenManager:
    if _manager is None:
        raise SaTokenNotInitializedException()
    return _manager
```

建议改成：

```
def get_manager() -> SaTokenManager:
    manager = _manager
    if manager is None:
        raise SaTokenNotInitializedException()
    return manager
```

- **缺陷**

这一对门面方法对 nonce 主体的规范化不一致：`NonceManager.issue` 存的是 `str(subject).strip()`，而 `NonceManager.consume` 比较的是没有 strip 的 `str(subject)`。任何带首尾空白的主体（例如从表单或请求头读到的登录 id），`issue_nonce` 会成功，对应的 `consume_nonce` 却总是以 `NONCE_MISMATCH` 失败，nonce 变成无法消费。另外 `str(None)` 会得到非空字符串 `"None"`，悄悄绕过 `issue` 里对空主体的校验。两条路径应当用同样的方式规范化主体（最好把 `NonceManager.consume` 里的不对称也一起改掉）。

```
await get_manager().nonces.consume(nonce, str(subject), purpose=purpose)
```

建议改成：

```
await get_manager().nonces.consume(nonce, str(subject).strip(), purpose=purpose)
```

### `tests/conftest.py`

- **可维护性**

`created` 列表会被写入（`created.append(manager)`），但没有任何地方读取：夹具函数体里没有，拆卸里也没有。它是死状态，唯一作用是在拆卸之前强引用测试期间建出来的每个管理器。要么删掉它（以及只为它的注解而导入的 `SaTokenManager`），要么真正用它，例如在拆卸时释放每个管理器的存储。

```
created: list[SaTokenManager] = []
```

- **测试**

`clear_manager()` 只对请求了 `build_manager` 的测试运行（直接请求，或经由 `manager` / `stp`）。自己用 `SaToken.builder()...build()` 建管理器的测试（默认会调用 `set_manager()`）如果没有请求这个夹具，会把全局 `_manager` 留在那里，泄漏到后面的测试（例如破坏那些期望 `SaTokenNotInitializedException` 的测试，或让 `StpUtil` 静默使用一个过期的管理器）。建议用一个 autouse 清理夹具，让每个测试结束都会重置，不管它用了哪些夹具：

```python
@pytest.fixture(autouse=True)
def _reset_global_manager():
    yield
    clear_manager()
```

```
clear_manager()
```

## 补扫

下面 21 条来自 `scripts/ocr-rescan/`。`src/sa_token/strategy/base.py` 和 `src/sa_token/token_io.py` 已重新扫描，没有意见。

### 严重

### `src/sa_token/strategy/jwt.py`

- **安全**

`payload.update(extra)` 发生在保留声明（`loginId`、`iat`、`jti`、`iss`、`aud`）已经写好之后。`extra` 里只要有同名键，就会悄悄覆盖保留字段。覆盖 `loginId` 可以冒充别人；覆盖 `jti` 破坏“每次登录令牌唯一”；覆盖 `iss` / `aud` 绕过配置的签发方和受众；覆盖 `iat` 伪造签发时间。要么先合并 `extra` 再写保留字段，要么合并前丢掉这些保留键。

```
        if extra:
            payload.update(extra)
        return self._jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
```

建议改成：

```
        if extra:
            _reserved = {"loginId", "iat", "jti", "iss", "aud"}
            for key, value in extra.items():
                if key not in _reserved:
                    payload[key] = value
        return self._jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
```

### 高

### `src/sa_token/security/temp_token.py`

- **缺陷**

`compare_and_delete(key, raw)` 在 `TempTokenRecord.from_json(raw)` 之前就把存储值删掉了。如果 `raw` 损坏、反序列化失败，这张令牌就永久丢失，没法再查看。`delete()` 是先解析再删除，这个顺序才对。`consume()` 也应先解析、确认有效，然后再做破坏性的比较删除。

```
async def consume(self, token: str, *, namespace: str = "default") -> Any | None:
    key = self._key(namespace, token)
    raw = await self._storage.get(key)
    if raw is None or not await self._storage.compare_and_delete(key, raw):
        return None
    record = TempTokenRecord.from_json(raw)
```

建议改成：

```
async def consume(self, token: str, *, namespace: str = "default") -> Any | None:
    key = self._key(namespace, token)
    raw = await self._storage.get(key)
    if raw is None:
        return None
    record = TempTokenRecord.from_json(raw)
    if record is None:
        return None
    if not await self._storage.compare_and_delete(key, raw):
        return None
    return record.value
```

- **缺陷**

`value: Any` 允许传入 `None`，而 `parse()` 和 `consume()` 在“令牌不存在”和“存的值就是 None”时都返回 `None`。调用方分不清这两种情况。应当在 `create()` 里拒绝 `None`，或者令牌不存在时抛出专门异常，避免返回值有歧义。

```
async def create(
    self,
    value: Any,
    timeout: int,
    *,
    namespace: str = "default",
    record_index: bool = False,
) -> str:
```

建议改成：

```
    if value is None:
        raise SecurityException("TEMP_TOKEN_VALUE_NONE", "value must not be None")
```

### `src/sa_token/strategy/builtin.py`

- **安全**

`TikStrategy.__init__` 没有检查 `length` 必须是正整数。`length` 为 0 或负数时，`range(self.length)` 是空的，`generate()` 返回空字符串 `""`。空令牌没有熵，这个类的安全目的就没了。至少应要求长度大于等于 1。

```
    def __init__(self, length: int = 8) -> None:
        self.length = length
```

建议改成：

```
    def __init__(self, length: int = 8) -> None:
        if length < 1:
            raise ValueError("TikStrategy token length must be at least 1")
        self.length = length
```

### `src/sa_token/strategy/jwt.py`

- **缺陷**

解码时捕获了所有 `Exception`，不只是 PyJWT 的解码错误。密钥损坏、算法非法、参数类型不对，都会被吞掉并返回 `None`。配置错误看起来就像登录失败，而且没有堆栈。应当只捕获 `PyJWTError`，其它异常继续抛出。

```
        except Exception:
            return None
```

建议改成：

```
        except self._jwt.exceptions.PyJWTError:
            return None
```

### `src/sa_token/sync.py`

- **缺陷**

`_get_background_loop()` 在 `_loop_lock` 里确认循环还活着，然后先释放锁，`run_sync` 才去使用返回的循环。这段空窗里另一个线程可以调用 `shutdown_sync_loop()`，关掉循环并把 `_loop` 设为 `None`。第一个线程随后向已关闭的循环提交任务，抛出 `RuntimeError: Event loop is closed`。应当在提交期间一直持有锁，或者在 `run_sync` 里发现循环已关闭时重试。

```
def _get_background_loop() -> asyncio.AbstractEventLoop:
    with _loop_lock:
        if _loop is not None and not _loop.is_closed():
            return _loop
```

- **缺陷**

如果循环在任务还在跑时被停掉，`asyncio.run_coroutine_threadsafe(...).result()` 会抛出 `asyncio.CancelledError`。它继承自 `BaseException`，不是 `Exception`，普通的 `except Exception` 接不住，WSGI 线程会带着未处理的堆栈崩溃。应当在 `run_sync` 里接住它，再抛出一个文档里写明的 `RuntimeError`。

```
        return asyncio.run_coroutine_threadsafe(coro, _get_background_loop()).result()
```

### 中

### `src/sa_token/security/refresh.py`

- **性能**

每次 `refresh()` 都把新的访问令牌和刷新令牌追加进 family 列表，这些列表从不裁剪。单独 `revoke()` 会从存储删掉一张刷新令牌，但不会把它从 `family.refresh_tokens` 里去掉。记录会无限变大，`revoke_family()` 也会越来越慢。应当清掉过期项，或只保留当前这一代，并在删除令牌时同步更新 family 记录。

```
    family.access_tokens.append(record.access_token)
    family.refresh_tokens.append(record.refresh_token)
```

- **可维护性**

`revoke_family()` 会把 family 标成已吊销并删掉其中的刷新令牌，但不会把这个 `family_id` 从 `_add_user_family` 维护的用户索引里移除。`revoke_all_for_login()` 仍会遍历这些过期 id，再去做一次存储查询。时间一长，用户索引会留下曾经创建过的每一个 family id。`revoke_family()` 应当同时从用户索引里删掉这个 id。

```
async def revoke_family(self, family_id: str, *, logout_access: bool = True) -> None:
```

- **可维护性**

`_RefreshRecord.from_json()` 和 `_FamilyRecord.from_json()` 使用 `cls(**payload)`。以后版本多出来的字段，或结构变更后缺少的字段，都会抛 `TypeError`。`except` 再返回 `None`，于是库里已有的记录全部读不出来，正常刷新也可能被当成 `REFRESH_FAMILY_REVOKED`。应当只取已知字段，其余用默认值补上。

```
            return cls(**payload) if isinstance(payload, dict) else None
```

### `src/sa_token/sso/__init__.py`

- **性能**

重试循环没有退避。同一个 `login_id` 的多个 service 同时登记时，12 次重试会在事件循环里连续飞跑，很快把次数用完然后抛 `SsoError`。每次比较并设置失败后，应当睡一小段带抖动或指数退避的时间。

```
    for _ in range(12):
        raw = await self._storage.get(key)
```

建议改成：

```
        await asyncio.sleep(random.uniform(0.01, 0.05) * (2 ** attempt))
```

### `src/sa_token/storage/memory.py`

- **缺陷**

传给 `scan` 的游标如果不是数字，`int(cursor)` 会抛出未处理的 `ValueError`，方法直接崩溃。应当捕获 `ValueError` 和 `TypeError`，或先用 `str.isdigit()` 检查。

```
start = int(cursor) if cursor else 0
```

建议改成：

```
try:
    start = int(cursor) if cursor else 0
except (ValueError, TypeError):
    start = 0
```

- **性能**

`_maybe_cleanup()` 只在 `set()` 里触发。读多写少时（令牌反复用 `get` / `exists` 校验、很少重新签发），过期项会一直留在 `self._data` 里，直到下一次 `set()`。`_get_unlocked` 的惰性删除只清掉再次被读到的键。应当在持锁的 `get` 和 `scan` 里也调用 `_maybe_cleanup`。

```
            self._data[key] = _Entry(value, _to_expire_at(ttl))
            self._maybe_cleanup()
```

### `src/sa_token/storage/redis.py`

- **缺陷**

`_normalize_ttl` 把 `ttl=0` 悄悄变成 1 秒，文档没写。文档只说 `None` 和 `-1` 表示永不过期，基类契约也没定义 `0`。有的调用方把 `0` 当成无限期，有的当成立即过期。现在的 `max(1, ttl)` 两种都不是。要么把 `0` 也当成永不过期，要么对 `ttl=0` 抛 `ValueError`，并且把选择写进文档。

```
    return max(1, ttl)
```

### `src/sa_token/sync.py`

- **性能**

`run_coroutine_threadsafe(...).result()` 会无限等待。协程死锁、网络卡住，或 `MemoryStorage` 的锁出问题，调用它的 WSGI 线程就永远不返回，线程池会被耗尽。应当加超时参数，例如 `.result(timeout=30)`，并写明这次调用可能阻塞。

```
return asyncio.run_coroutine_threadsafe(coro, _get_background_loop()).result()
```

- **性能**

`shutdown_sync_loop()` 立刻停掉循环，既不取消未完成任务，也不等待还在飞的协程。线程又是守护线程，退出时正在写的会话和令牌可能被丢掉。应当在 `stop()` 之前取消 `asyncio.all_tasks(loop)`，或者写明这只适合测试和进程退出。

```
        _loop.call_soon_threadsafe(_loop.stop)
```

### `src/sa_token/strategy/__init__.py`

- **缺陷**

`random` 后面如果不是数字，会静默退回 32 位。`token_style="randomxyz"` 或 `token_style="random"` 仍会签发 32 字符的令牌，拼写错误被藏住了。后缀不是数字就应当报错。

```
        return RandomStrategy(int(suffix) if suffix.isdigit() else 32)
```

建议改成：

```
        if not suffix.isdigit():
            raise ValueError(
                f"random 风格后必须跟数字（如 random32、random64），收到: {suffix!r}"
            )
        return RandomStrategy(int(suffix))
```

- **可维护性**

`JwtStrategy` 写在 `__all__` 里，但只通过模块的 `__getattr__` 暴露。mypy、pyright、PyCharm 分析时不会执行 `__getattr__`，`from sa_token.strategy import JwtStrategy` 的静态检查会失败。应当在模块顶层用保护导入，或者从 `__all__` 里去掉它，让使用者改从 `sa_token.strategy.jwt` 导入。

```
    "JwtStrategy",
```

### 低

### `src/sa_token/security/refresh.py`

- **性能**

`_update_family()` 和 `_add_user_family()` 在比较并设置失败时，紧凑地重试 12 次，中间没有等待。争用高时 12 次会立刻全部失败，合法客户端收到 `REFRESH_CONFLICT`。重试之间应当加一小段随机退避。

```
        for _ in range(12):
            raw = await self._storage.get(key)
```

- **性能**

`revoke_for_access()` 会扫描全部 `refresh:*` 键，再逐个读取，才能找到某一张访问令牌。键很多时这是 O(n)。应当维护 `access_token -> refresh_token` 的索引，或者写明这条路径不适合放在热注销上。

```
        cursor, keys = await self._storage.scan(f"{prefix}refresh:*", cursor, 200)
```

### `src/sa_token/strategy/__init__.py`

- **可维护性**

`config.jwt_secret_key or ""` 把默认的 `None` 先变成空字符串，再交给 `JwtStrategy`。策略确实会拒绝空密钥，但 `or ""` 看起来像空字符串是合法回退。应当在工厂里检查这个配置项，并抛出点名 `jwt_secret_key` 的错误。

```
            config.jwt_secret_key or "",
```

建议改成：

```
        if not config.jwt_secret_key:
            raise ValueError(
                "使用 JWT 风格时必须在 SaTokenConfig 中配置 jwt_secret_key"
            )
```
