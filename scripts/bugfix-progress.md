# 审查问题修改进度

只改表格里的状态。严重程度：critical / high / medium / low。状态：待修改 / 已修改。

| 序号 | 文件 | 严重程度 | 类型 | 问题 | 状态 |
| --- | --- | --- | --- | --- | --- |
| 1 | `examples/fastapi/main.py` | medium | bug | Cleanup is only performed for `WebSocketDisconnect`. Any other exception raised after `on… | 已修改 |
| 2 | `examples/fastapi/main.py` | medium | security | `/pay` is protected by `check_safe("pay")`, but `/open-safe` grants that second-factor cl… | 已修改 |
| 3 | `examples/fastapi/main.py` | low | maintainability | Assertions are stripped under `python -O`. If the token context is ever missing here, the… | 已修改 |
| 4 | `examples/flask/main.py` | medium | bug | The username is never validated. `StpUtilSync.login("")` (missing/empty/whitespace-only `… | 已修改 |
| 5 | `examples/flask/main.py` | medium | bug | `request.get_json(silent=True) or {}` only guards against `None`/falsy bodies. A truthy n… | 已修改 |
| 6 | `examples/flask/main.py` | low | security | Every successful login is granted the `admin` role, which makes `/admin/panel` reachable … | 已修改 |
| 7 | `examples/flask/main.py` | low | security | `debug=True` enables the Werkzeug interactive debugger, which allows arbitrary code execu… | 已修改 |
| 8 | `examples/native/quick_start.py` | low | maintainability | This `assert` doubles as the `None` narrowing for `session.set(...)` below, so under `pyt… | 已修改 |
| 9 | `examples/native/quick_start.py` | low | maintainability | `assert` is used here as the only behavioral check of the kickout demo. Under `python -O`… | 已修改 |
| 10 | `src/sa_token/adapter/path.py` | high | bug | All matched rules are collapsed into a single `mode`, and the AND escalation is sticky. B… | 已修改 |
| 11 | `src/sa_token/adapter/path.py` | medium | security | Matching is done on raw segments: duplicate slashes are collapsed, but dot segments are n… | 已修改 |
| 12 | `src/sa_token/adapter/path.py` | medium | security | Unmatched paths are fail-open: the returned rule has no `ignore`, no `require_login`, no … | 已修改 |
| 13 | `src/sa_token/adapter/path.py` | medium | performance | `**` backtracking has no memoization, so matching cost is O(n^k) in the number of path se… | 已修改 |
| 14 | `src/sa_token/adapter/path.py` | low | performance | The uppercase method set is rebuilt on every call, and `matches` is invoked once per rule… | 已修改 |
| 15 | `src/sa_token/adapter/pipeline.py` | medium | security | `set_current()` returns the two `contextvars` reset tokens precisely so the caller can re… | 已修改 |
| 16 | `src/sa_token/adapter/pipeline.py` | low | maintainability | `build_rule` is part of the public API (re-exported in `adapter/__init__.py`'s `__all__` … | 已修改 |
| 17 | `src/sa_token/config.py` | medium | bug | `__post_init__` is the only validation point for a config object that the module docstrin… | 已修改 |
| 18 | `src/sa_token/config.py` | low | maintainability | `from_dict` drops unknown keys without any signal, which is inconsistent with `SaTokenBui… | 已修改 |
| 19 | `src/sa_token/context.py` | medium | documentation | The docstring claims this works with `async with`, but `contextlib.contextmanager` only p… | 已修改 |
| 20 | `src/sa_token/context.py` | low | maintainability | The `tokens is None` branch hard-sets both vars to `None` instead of restoring any previo… | 已修改 |
| 21 | `src/sa_token/exception.py` | medium | bug | `DisableException` is always constructed from `StpLogic.check_disable()` with `remaining … | 已修改 |
| 22 | `src/sa_token/exception.py` | low | bug | Direct dict indexing means any `NotLoginType` value not present in `_NOT_LOGIN_MESSAGES` … | 已修改 |
| 23 | `src/sa_token/integration/__init__.py` | low | maintainability | `__all__` 只声明了 fastapi/starlette/flask/django 四个子模块，但包内还存在 `fastapi_oauth2.py`（提供 `create… | 已修改 |
| 24 | `src/sa_token/integration/django.py` | high | bug | 身份上下文绑定在 PATH_AUTH 分支会丢失。`run_path_auth`/`run_auth_flow` 内部通过 `set_current(token, login_i… | 已修改 |
| 25 | `src/sa_token/integration/django.py` | medium | bug | 同上：`run_auth_flow` 里的 `set_current(...)` 发生在后台事件循环线程，装饰器执行完后当前请求线程的 contextvars 仍是空的，视图内 … | 已修改 |
| 26 | `src/sa_token/integration/django.py` | medium | bug | 装饰器不支持 `async def` 视图：wrapper 是普通同步函数，`functools.wraps` 不会让 Django 的 `iscoroutinefunction… | 已修改 |
| 27 | `src/sa_token/integration/fastapi.py` | high | bug | Appending a `KEYWORD_ONLY` parameter unconditionally produces an invalid signature when t… | 已修改 |
| 28 | `src/sa_token/integration/fastapi.py` | high | performance | `wrapper` is always an `async def`, so FastAPI treats the route as a coroutine and awaits… | 已修改 |
| 29 | `src/sa_token/integration/fastapi.py` | medium | bug | The signature carried by `__signature__` keeps the user module's annotations as-is (strin… | 已修改 |
| 30 | `src/sa_token/integration/fastapi.py` | medium | bug | `had_request` is decided purely by parameter *name*. If an endpoint declares a body/query… | 已修改 |
| 31 | `src/sa_token/integration/fastapi_oauth2.py` | high | security | `/introspect` and `/revoke` are exposed with no client authentication or authorization at… | 已修改 |
| 32 | `src/sa_token/integration/fastapi_oauth2.py` | medium | bug | Body parsing is unguarded and can escape the `OAuth2Error` handling in `token_endpoint` (… | 已修改 |
| 33 | `src/sa_token/integration/fastapi_oauth2.py` | medium | security | The token response carries `access_token`/`refresh_token` but is returned without `Cache-… | 已修改 |
| 34 | `src/sa_token/integration/fastapi_oauth2.py` | low | bug | For a JSON body, `parameters.get("client_secret", "")` returns `None` when the key is pre… | 已修改 |
| 35 | `src/sa_token/integration/fastapi_oauth2.py` | low | bug | The 401 challenge is emitted as a bare `WWW-Authenticate: Basic`, which is missing the re… | 已修改 |
| 36 | `src/sa_token/integration/flask.py` | high | security | The request-scoped cache is keyed only by fixed attribute names and is not namespaced by … | 已修改 |
| 37 | `src/sa_token/integration/flask.py` | high | bug | `login_type` is not propagated here. `run_auth_flow` defaults to `login_type="login"` (se… | 已修改 |
| 38 | `src/sa_token/integration/flask.py` | medium | bug | `token()` looks like a pure getter but has a side effect: `resolve_token()` ends with `se… | 已修改 |
| 39 | `src/sa_token/integration/flask.py` | low | bug | `assert` is used to guarantee the declared `str` return type, but assertions are stripped… | 已修改 |
| 40 | `src/sa_token/integration/starlette.py` | medium | bug | `resolve_token()` 内部会执行 `set_current(token, None)`，也就是把请求级上下文里的 login_id 强制清成 None。FastAP… | 已修改 |
| 41 | `src/sa_token/integration/starlette.py` | low | maintainability | `_authorize` 调用 `run_auth_flow` 时未传 `login_type`，`check_disable` / `check_safe` 也用 `get_m… | 已修改 |
| 42 | `src/sa_token/integration/starlette.py` | low | performance | 每个 Depends 扩展都会重新跑一遍完整鉴权流程（读 header/cookie/query 取 token + `check_login` 访问存储）。当请求已经过 `Sa… | 已修改 |
| 43 | `src/sa_token/integration/starlette.py` | low | bug | 用 `assert` 保证鉴权不变量在 `python -O` 下会被整条删除。目前 `build_rule` 默认 `require_login=True`，不变量成立；但一旦… | 已修改 |
| 44 | `src/sa_token/listener.py` | medium | bug | If an `EventData` is emitted with `event == Event.ALL` (a legitimate enum member), the `E… | 已修改 |
| 45 | `src/sa_token/listener.py` | medium | bug | `Listener` is typed as `Callable[[EventData], Any / Awaitable[Any]]`, but only coroutine … | 已修改 |
| 46 | `src/sa_token/listener.py` | low | performance | `emit()` is awaited inline on hot auth paths (e.g. `StpLogic.login`/`logout` via `_emit`)… | 已修改 |
| 47 | `src/sa_token/manager.py` | high | bug | The code contradicts its own comment: when no storage is configured, `build()` silently f… | 已修改 |
| 48 | `src/sa_token/manager.py` | medium | bug | `build()` hands the builder's own mutable `SaTokenConfig` and `EventBus` to the manager b… | 已修改 |
| 49 | `src/sa_token/manager.py` | low | bug | `hasattr` also returns True for the dataclass's methods (`key_prefix`, `make_key`, `from_… | 已修改 |
| 50 | `src/sa_token/model.py` | medium | bug | `from_json` is documented/used as "return `None` for unusable payloads" (callers in `stp_… | 已修改 |
| 51 | `src/sa_token/model.py` | medium | bug | `payload.get("data", {})` only falls back when the key is missing; an explicit `"data": n… | 已修改 |
| 52 | `src/sa_token/model.py` | medium | bug | `state` is taken verbatim from the JSON payload with no type validation. If a corrupted /… | 已修改 |
| 53 | `src/sa_token/oauth2/model.py` | high | bug | `from_json` only guards `json.loads` with `except ValueError`, but the constructor call i… | 已修改 |
| 54 | `src/sa_token/oauth2/model.py` | medium | security | `from_json` filters keys but never validates value types, so the exact-match security inv… | 已修改 |
| 55 | `src/sa_token/oauth2/server.py` | high | security | `redirect_uri` should be mandatory here, not optional. `create_authorization_code()` requ… | 已修改 |
| 56 | `src/sa_token/oauth2/server.py` | high | security | `revoke_token()` only removes the exact key that matches the supplied token, so the paire… | 已修改 |
| 57 | `src/sa_token/oauth2/server.py` | medium | bug | A single hard-coded 400 for every OAuth2 error is not spec-compliant, and because the fra… | 已修改 |
| 58 | `src/sa_token/oauth2/server.py` | medium | bug | Old credentials are destroyed before the new ones exist, so any storage failure inside `_… | 已修改 |
| 59 | `src/sa_token/oauth2/server.py` | medium | security | PKCE method handling is too permissive: (1) `plain` is accepted unconditionally, and with… | 已修改 |
| 60 | `src/sa_token/online/__init__.py` | high | bug | `send_to_device` iterates the *live* per-user connection dict while awaiting `self._sende… | 已修改 |
| 61 | `src/sa_token/online/__init__.py` | medium | bug | The connection snapshot is taken *before* acquiring `self._lock`, while `connection_ids` … | 已修改 |
| 62 | `src/sa_token/online/__init__.py` | medium | performance | Two problems here: (1) `self._lock` is held across `await self._storage.exists(...)` for … | 已修改 |
| 63 | `src/sa_token/online/__init__.py` | medium | bug | `heartbeat()` is a non-atomic read-modify-write on shared storage. If `unregister()`/`dis… | 已修改 |
| 64 | `src/sa_token/online/__init__.py` | low | bug | Deriving the default `connection_id` from `id(connection)` is unsafe as a cross-process k… | 已修改 |
| 65 | `src/sa_token/online/__init__.py` | low | maintainability | Send/close failures are swallowed by a bare `except Exception: continue` in five places (… | 已修改 |
| 66 | `src/sa_token/security/nonce.py` | medium | bug | `issue()` normalizes the subject (`str(subject).strip()`) before persisting it, but `cons… | 已修改 |
| 67 | `src/sa_token/security/nonce.py` | medium | maintainability | `state` is persisted with every record but is never read anywhere — `consume()` only chec… | 已修改 |
| 68 | `src/sa_token/security/nonce.py` | low | maintainability | If the key expires between `get()` and `compare_and_delete()`, `compare_and_delete` retur… | 已修改 |
| 69 | `src/sa_token/security/refresh.py` | high | bug | Destructive steps happen before the new credentials exist, with no rollback. At this poin… | 已修改 |
| 70 | `src/sa_token/security/refresh.py` | high | bug | Non-atomic read-modify-write on the family record: this plain `set` overwrites whatever `… | 已修改 |
| 71 | `src/sa_token/security/refresh.py` | high | bug | The refresh record is persisted as `active` before the family/user indexes are updated, a… | 已修改 |
| 72 | `src/sa_token/security/refresh.py` | high | bug | Unconditional `set` re-activates the record even if it was deleted in between. A concurre… | 已修改 |
| 73 | `src/sa_token/security/refresh.py` | high | security | `refresh()` only trusts the refresh-token record and never loads `_family_key(record.fami… | 已修改 |
| 74 | `src/sa_token/security/refresh.py` | medium | performance | Every `refresh()` appends a new access token and refresh token to the family lists, and t… | 已修改 |
| 75 | `src/sa_token/security/refresh.py` | medium | performance | These lists only ever grow while the family TTL is refreshed on every rotation. With the … | 已修改 |
| 76 | `src/sa_token/security/refresh.py` | medium | maintainability | `_RefreshRecord.from_json()` and `_FamilyRecord.from_json()` use `cls(**payload)`. Extra … | 已修改 |
| 77 | `src/sa_token/security/refresh.py` | medium | maintainability | `revoke_family()` marks the family revoked and deletes its refresh tokens, but never remo… | 已修改 |
| 78 | `src/sa_token/security/refresh.py` | medium | performance | `revoke_for_access` walks the whole keyspace: Redis `SCAN` iterates every key and filters… | 已修改 |
| 79 | `src/sa_token/security/refresh.py` | low | performance | `_update_family()` and `_add_user_family()` retry 12 times with no delay when compare-and… | 已修改 |
| 80 | `src/sa_token/security/refresh.py` | low | performance | `revoke_for_access()` scans every `refresh:*` key and reads each value to find one access… | 已修改 |
| 81 | `src/sa_token/security/temp_token.py` | high | bug | `compare_and_delete(key, raw)` deletes the stored value before `TempTokenRecord.from_json… | 已修改 |
| 82 | `src/sa_token/security/temp_token.py` | high | bug | `value: Any` accepts `None`, and both `parse()` and `consume()` return `None` when the to… | 已修改 |
| 83 | `src/sa_token/security/temp_token.py` | medium | security | Re-issuing a token for a value that already has an index entry overwrites the index but l… | 已修改 |
| 84 | `src/sa_token/security/temp_token.py` | medium | security | `namespace` (and `token`) are only validated in `create()` via `_validate()`. `parse()`, … | 已修改 |
| 85 | `src/sa_token/security/temp_token.py` | low | bug | `consume()` returns `Any / None` where `None` means "token invalid/already used", but `va… | 不修改 |
| 86 | `src/sa_token/session.py` | high | bug | `save()` blindly overwrites the whole session payload from the in-memory `_data` snapshot… | 已修改 |
| 87 | `src/sa_token/session.py` | medium | bug | Mutations are applied to `_data` before the storage write is awaited, so a failing `save(… | 已修改 |
| 88 | `src/sa_token/session.py` | low | maintainability | This property hands out the live, mutable `SessionData.terminal_list` (and its mutable `T… | 已修改 |
| 89 | `src/sa_token/sso/__init__.py` | medium | performance | The retry loop has no backoff. When several services register the same `login_id` at once… | 已修改 |
| 90 | `src/sa_token/storage/__init__.py` | low | maintainability | `RedisStorage` is advertised in `__all__` and documented in the README as `from sa_token.… | 已修改 |
| 91 | `src/sa_token/storage/base.py` | medium | documentation | TTL 契约只定义了 `None` 与 `-1`，对 `0` 和其它负数没有任何约定，而两个现有实现已经出现行为分歧：`MemoryStorage._to_expire_at` … | 已修改 |
| 92 | `src/sa_token/storage/base.py` | low | documentation | `expire` 的返回值语义在实现间并不等价于“键不存在”：`RedisStorage` 在 `ttl is None` 时走 `PERSIST`，而 Redis 对“键存在但… | 已修改 |
| 93 | `src/sa_token/storage/base.py` | low | maintainability | 两点风险：1) `@runtime_checkable` 的 `isinstance` 只校验同名属性是否存在，既不校验签名也不校验方法是否为协程函数，一个含同步 `get`/`… | 已修改 |
| 94 | `src/sa_token/storage/base.py` | low | documentation | 游标语义存在歧义：入参 `cursor=None` 表示“从头开始扫描”，出参 `None` 表示“扫描结束”，同一个值承担两种含义，调用方很容易把首轮返回值当起始游标再次传入而… | 已修改 |
| 95 | `src/sa_token/storage/memory.py` | medium | performance | `_maybe_cleanup()` runs only inside `set()`. A read-heavy workload that rarely writes lea… | 已修改 |
| 96 | `src/sa_token/storage/memory.py` | medium | bug | `int(cursor)` raises an unhandled `ValueError` when `scan` receives a non-numeric cursor.… | 已修改 |
| 97 | `src/sa_token/storage/redis.py` | medium | bug | `_normalize_ttl` turns `ttl=0` into 1 second without saying so. The docstring only docume… | 已修改 |
| 98 | `src/sa_token/stp_logic.py` | high | bug | Same early-return hazard as `logout()`: when the Account-Session is absent (expired TTL, … | 已修改 |
| 99 | `src/sa_token/stp_logic.py` | high | security | `logout()` returns early when the Account-Session is missing, which also skips `revoke_al… | 已修改 |
| 100 | `src/sa_token/stp_logic.py` | high | bug | `session.raw.terminal_list` is updated with a non-atomic read-modify-write: `get_session(… | 已修改 |
| 101 | `src/sa_token/stp_logic.py` | medium | performance | `_renew` runs on every successful `check_login`, i.e. on every authenticated request, and… | 已修改 |
| 102 | `src/sa_token/stp_logic.py` | medium | bug | `config.dynamic_active_timeout` can never take effect. Nothing in the codebase populates … | 已修改 |
| 103 | `src/sa_token/stp_logic.py` | low | bug | `keyword` is interpolated straight into a Redis glob pattern without escaping. Glob metac… | 已修改 |
| 104 | `src/sa_token/stp_util.py` | low | bug | The nonce subject is normalized inconsistently across this pair of facade methods: `Nonce… | 已修改 |
| 105 | `src/sa_token/stp_util.py` | low | bug | `get_manager()` reads the mutable module global `_manager` twice (once for the `is None` … | 已修改 |
| 106 | `src/sa_token/strategy/__init__.py` | medium | bug | A non-numeric suffix after `random` silently falls back to 32 characters. `token_style="r… | 已修改 |
| 107 | `src/sa_token/strategy/__init__.py` | medium | maintainability | `JwtStrategy` is in `__all__` but is only exposed through module `__getattr__`. mypy, pyr… | 已修改 |
| 108 | `src/sa_token/strategy/__init__.py` | low | maintainability | `config.jwt_secret_key or ""` turns the default `None` into an empty string before `JwtSt… | 已修改 |
| 109 | `src/sa_token/strategy/builtin.py` | high | security | `TikStrategy.__init__` does not require `length` to be a positive integer. `length` of 0 … | 已修改 |
| 110 | `src/sa_token/strategy/jwt.py` | critical | security | `payload.update(extra)` runs after the reserved claims (`loginId`, `iat`, `jti`, `iss`, `… | 已修改 |
| 111 | `src/sa_token/strategy/jwt.py` | high | bug | The decode path catches every `Exception`, not only PyJWT decode errors. A bad secret, an… | 已修改 |
| 112 | `src/sa_token/sync.py` | high | bug | `_get_background_loop()` checks that the loop is alive under `_loop_lock`, then releases … | 已修改 |
| 113 | `src/sa_token/sync.py` | high | bug | `asyncio.run_coroutine_threadsafe(...).result()` can raise `asyncio.CancelledError` if th… | 已修改 |
| 114 | `src/sa_token/sync.py` | medium | performance | `run_coroutine_threadsafe(...).result()` waits forever. A hung coroutine, a deadlock, or … | 已修改 |
| 115 | `src/sa_token/sync.py` | medium | performance | `shutdown_sync_loop()` stops the loop without cancelling pending tasks or waiting for in-… | 已修改 |
| 116 | `tests/conftest.py` | low | maintainability | The `created` list is written to (`created.append(manager)`) but never read anywhere — no… | 已修改 |
| 117 | `tests/conftest.py` | low | test | `clear_manager()` only runs for tests that request `build_manager` (directly or via `mana… | 已修改 |
| 118 | `src/sa_token/adapter/path.py` | high | security | `..` 退到根以外时 `ant_match` 返回不匹配，`resolve` 对未命中路径匿名放行，`.login("/**")` 盖不住 `/..`、`/foo/../..`。详见 `scripts/delegate-review.zh-CN.md`。 | 已修改 |
| 119 | `src/sa_token/storage/redis.py` | medium | bug | `set_if_absent` 在 TTL 为 0 时不写入却返回成功，并发下不能占位。详见 `scripts/delegate-review.zh-CN.md`。 | 已修改 |
| 120 | `src/sa_token/session.py` | medium | bug | 冲突合并会把本地未删除的终端写回，并发登出后的终端可能复活成幽灵在线。详见 `scripts/delegate-review.zh-CN.md`。 | 已修改 |
| 121 | `src/sa_token/integration/flask.py` | medium | bug | 装饰器经 `run_sync` 鉴权后没有在请求线程 `set_current`，视图里 `get_current_login_id()` 仍为空。详见 `scripts/delegate-review.zh-CN.md`。 | 已修改 |
