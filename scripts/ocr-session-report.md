# sa-token-python 中断扫描的审查意见

来源：`C:\Users\starcwm\.opencodereview\sessions\D_.A-Project-sa-token-python\dfec471d-ad3d-4711-82fe-6fb18a26cc9c.jsonl`

已提交意见 117 条。其中 96 条来自中断前的会话，21 条来自后来对未完成文件的补扫（`scripts/ocr-rescan/`）。

- **critical**: 1
- **high**: 27
- **medium**: 53
- **low**: 36
- **补扫后无意见**: `src/sa_token/strategy/base.py`、`src/sa_token/token_io.py`

## high

### `src/sa_token/adapter/path.py`

- **bug**

All matched rules are collapsed into a single `mode`, and the AND escalation is sticky. Because `run_auth_flow` applies `rule.mode` to both `check_permission` and `check_role`, one AND rule silently rewrites the semantics of every other matched OR rule: e.g. `.permission("/x", "a", "b", mode="OR")` plus `.role("/x", "r1", "r2", mode="AND")` yields permissions `["a", "b"]` evaluated with AND, so a user holding only `a` is now denied. The mode should be tracked per rule/per list (e.g. keep a list of `(permissions, mode)` and `(roles, mode)` groups and evaluate each group separately) rather than merged into one flag.

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

- **bug**

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

- **bug**

Appending a `KEYWORD_ONLY` parameter unconditionally produces an invalid signature when the endpoint already declares `**kwargs`. `inspect.Signature` enforces parameter ordering (a `VAR_KEYWORD` may not be followed by a `KEYWORD_ONLY`), so `Signature.replace(...)` raises `ValueError: wrong parameter order` at decoration time — i.e. the app fails to start for any route like `async def handler(**kwargs)` decorated with `@sa.check_login`. Insert the synthetic `request` parameter *before* the `VAR_KEYWORD` parameter (and skip it entirely when a `request` parameter already exists).

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

- **performance**

`wrapper` is always an `async def`, so FastAPI treats the route as a coroutine and awaits it directly. When the decorated endpoint is a *sync* `def`, `view(...)` is executed inline on the event loop instead of in Starlette's threadpool (which is what FastAPI does for undecorated sync endpoints). Any blocking work in such a handler (DB drivers, `requests`, file I/O) will stall the whole loop. Offload sync handlers with `starlette.concurrency.run_in_threadpool`.

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

- **security**

`/introspect` and `/revoke` are exposed with no client authentication or authorization at all — only the raw `token` field is read. `server.introspect()` returns `{active, client_id, sub, scope}`, so this endpoint is an unauthenticated token-scanning oracle that also discloses the resource owner (`sub`) and granted scopes for any presented token; RFC 7662 §2.1 explicitly requires the introspection endpoint to be protected ("To prevent token scanning attacks, the endpoint MUST also require some form of authorization"). Likewise RFC 7009 §2.1 requires client authentication on revocation for confidential clients, so any third party that learns a token can revoke it (denial of service against the legitimate client).

Note also that `create_oauth2_router` offers no way to plug protection in — no `dependencies=` parameter is forwarded to `APIRouter`, and `server._verify_client_secret` is private, so an integrator cannot secure these routes without reimplementing them. Suggest adding e.g. `dependencies: Sequence[Depends] | None = None` (applied to the router or just to introspect/revoke) and authenticating the client (HTTP Basic or `client_id`/`client_secret` from the body) before calling `introspect`/`revoke_token`.

```
@router.post("/introspect")
    async def introspect_endpoint(request: Request) -> JSONResponse:
        parameters = await _read_parameters(request)
        return JSONResponse(await server.introspect(str(parameters.get("token", ""))))
```

### `src/sa_token/integration/flask.py`

- **bug**

`login_type` is not propagated here. `run_auth_flow` defaults to `login_type="login"` (see `adapter/pipeline.py:48`), so an instance created as `SaTokenFlask(app, login_type="admin")` will validate the token against the *default* `StpLogic` (wrong token name / config / session namespace) instead of the `admin` one. Every other entry point in this file passes `login_type=self.login_type` (`_before_request`, `_guard`, `login_id_or_none`), which makes this an inconsistency and a real defect: it can produce spurious 401s or, worse, resolve an identity from the wrong account system. `check_disable` inherits the bug since it calls `self.login_id()`.

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

- **security**

The request-scoped cache is keyed only by fixed attribute names and is not namespaced by `login_type`. When an app registers more than one `SaTokenFlask` (the documented multi-account pattern, e.g. `login_type="user"` and `login_type="admin"`), both instances register a `before_request` hook on the same app, so the last hook wins and overwrites `g.sa_login_id` / `g.sa_token`. `login_id()` then short-circuits on that cached value (`cached = getattr(g, "sa_login_id", None)`) and can return an identity belonging to a different login type — an identity-confusion / privilege issue. Store the state per login type (e.g. `g.setdefault("sa_token", {})[self.login_type] = ...`) and read it back with the same key.

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

- **bug**

The code contradicts its own comment: when no storage is configured, `build()` silently falls back to `MemoryStorage`. In a multi-process/multi-worker deployment this produces exactly the failure the comment warns about ("logged in, but the next request says not logged in"), and it hides misconfiguration until it surfaces as random auth failures in production. Either raise an explicit error (forcing the caller to opt in to in-memory storage) or at minimum emit a loud warning when the fallback is used.

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

- **bug**

`from_json` only guards `json.loads` with `except ValueError`, but the constructor call itself can raise `TypeError` when the stored payload is missing a required field (`code` is the only key validated here; `client_id`, `login_id` and `redirect_uri` are mandatory). This breaks the declared `AuthorizationCode | None` contract: callers such as `OAuth2Server._consume_code` explicitly check `if parsed is None: raise OAuth2Error("invalid_grant", ...)`, so corrupt/legacy storage data (or a field added/renamed between versions) will escape as an unhandled `TypeError` → HTTP 500 instead of the intended `invalid_grant`. It is worse in `_consume_code`, where the code has already been deleted via `compare_and_delete` before parsing, so the authorization code is silently burned. The same problem exists in `OAuth2Client.from_json` and `AccessTokenInfo.from_json`.

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

- **security**

`redirect_uri` should be mandatory here, not optional. `create_authorization_code()` requires and binds a `redirect_uri` to every code it issues, and RFC 6749 §4.1.3 states the token request MUST include `redirect_uri` whenever it was present in the authorization request, with the value compared exactly. As written, an attacker who leaks/intercepts a code (Referer leak, malicious app on the same device, log exposure) can redeem it without ever knowing the redirect target, which removes one of the two factors binding the code to the legitimate client and weakens the code-injection / mix-up defenses. Since the stored code always has a `redirect_uri`, treat a missing parameter as an error.

```
if redirect_uri is not None and authorization_code.redirect_uri != redirect_uri:
            raise OAuth2Error("invalid_grant", "redirect_uri 与申请时不一致")
```

建议改成：

```
if redirect_uri is None or authorization_code.redirect_uri != redirect_uri:
            raise OAuth2Error("invalid_grant", "redirect_uri 与申请时不一致")
```

- **security**

`revoke_token()` only removes the exact key that matches the supplied token, so the paired credential survives. Revoking an access_token leaves its refresh_token valid, letting the client immediately mint a brand-new access_token — this directly contradicts the module docstring's promise that credentials can be invalidated instantly ("存储里删掉即刻失效"). Revoking a refresh_token likewise leaves the current access_token usable until it expires. Consider persisting the pairing (e.g. store the access_token value in the refresh record, as `_issue_tokens()` already does, and a back-reference or token family id in the access record) so a revocation cascades to both tokens.

```
for suffix in ("access", "refresh"):
            key = self._key(suffix, token)
```

### `src/sa_token/online/__init__.py`

- **bug**

`send_to_device` iterates the *live* per-user connection dict while awaiting `self._sender(...)`. A concurrent `register()` (which does `self._connections.setdefault(login_id, {})[resolved_id] = connection`) or `unregister()` (`bucket.pop(...)`) mutates that same dict object during the await, raising `RuntimeError: dictionary changed size during iteration` and aborting the remaining pushes. It also reads shared state without `self._lock`, unlike every other accessor. Snapshot the items first.

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

- **security**

`refresh()` only trusts the refresh-token record and never loads `_family_key(record.family_id)` to verify the family is still alive/unrevoked. Revocation relies entirely on `revoke_family()` deleting every token listed in the family record, and that path is lossy (see the non-atomic `set` in `revoke_family`, and `issue()` failing after the record is already persisted). Any refresh token that is missing from the family list therefore survives revocation and can keep minting new access tokens — and in the non-rotation branch below it never touches the family record at all, so the revocation is never detected. Read the family record here and reject when it is absent or `revoked`.

```
if record.state != "active":
            if self._manager.config.refresh_token_reuse_detection:
                await self.revoke_family(record.family_id)
```

- **bug**

Destructive steps happen before the new credentials exist, with no rollback. At this point the old refresh token has already been CAS'd to `used` and the old access token is destroyed here; if `login()` raises (`check_disable`, token allocation, session save) or the subsequent `issue()` raises `REFRESH_CONFLICT`/`REFRESH_FAMILY_REVOKED`, the client is left with no valid access token and a consumed refresh token, while the freshly created access token from `login()` stays live in storage and is never returned or cleaned up. Worse, a client retry with the same refresh token hits the `state != "active"` branch and revokes the whole family, so a transient storage conflict permanently locks the user out. Issue the new tokens first, or restore the record to `active` and log out the new access token on failure.

```
logic = self._manager.stp(record.login_type)
        await logic.logout_by_token(record.access_token, revoke_refresh=False)
```

- **bug**

Unconditional `set` re-activates the record even if it was deleted in between. A concurrent `revoke()`, `revoke_for_access()` (called from `logout_by_token`/`kickout_by_token`) or `revoke_family()` removes this key after the CAS above; this write then resurrects an already-revoked refresh token as `active` and resets its full `refresh_token_timeout` (30 days by default). Use `compare_and_set(key, used_record.to_json(), active_record.to_json(), ...)` and abort (or re-check the family) when it returns `False`.

```
await self._storage.set(
                key,
                active_record.to_json(),
                self._manager.config.refresh_token_timeout,
            )
```

- **bug**

The refresh record is persisted as `active` before the family/user indexes are updated, and both calls below can raise (`REFRESH_FAMILY_REVOKED`, `REFRESH_CONFLICT`). On those paths the stored refresh token — and the access token issued by the caller (`login_with_refresh`) — remain valid in storage but are registered in no family, so neither `revoke_family()` nor `revoke_all_for_login()` can ever reach them: an unrevocable live session. Wrap these two calls in `try/except` and delete `self._refresh_key(refresh_token)` (plus log out `access_token`) before re-raising.

```
await self._update_family(resolved_family, record)
        await self._add_user_family(login_type, login_id, resolved_family)
```

- **bug**

Non-atomic read-modify-write on the family record: this plain `set` overwrites whatever `_update_family` CAS-appended between the `get` above and this write. The stale `refresh_tokens`/`access_tokens` lists are restored, so a refresh token issued concurrently is neither deleted here nor logged out, yet the family is marked revoked — and since `refresh()` never re-checks the family, that token keeps working. Perform the revoke in a `compare_and_set` retry loop (re-read, re-apply `revoked`, re-collect the token lists) so no concurrently added token is lost. Note `revoke_all_for_login` has the same window: families created after its `get` are orphaned once the user index is deleted.

```
family.revoked = True
        await self._storage.set(key, family.to_json(), self._manager.config.refresh_token_timeout)
```

### `src/sa_token/session.py`

- **bug**

`save()` blindly overwrites the whole session payload from the in-memory `_data` snapshot, with no reload, lock or version check. Since `get_session()` builds a fresh snapshot per call, two concurrent tasks/processes (e.g. a `login()` appending a terminal while another request calls `session.set(...)`, or a logout deleting the key) will each write their own full copy, and the last writer silently drops the other's changes — including resurrecting terminals that were just removed and extending/overwriting keys that were deleted. This contradicts the module docstring ("每次写操作都会落存储…不会出现各自持有过期副本"), because all readers (`get`, `get_typed`, `has`, `keys`, `terminal_list`) never re-read from storage either. The storage contract already exposes `compare_and_set` ("用于并发下的安全更新") and it is used in `security/refresh.py` and `sso/__init__.py`; `save()` should use the same CAS-with-retry (or a per-key lock) instead of an unconditional `set`, and reads should be able to refresh from storage.

```
await self._storage.set(self._key, self._data.to_json(), self._timeout)
```

### `src/sa_token/stp_logic.py`

- **security**

`logout()` returns early when the Account-Session is missing, which also skips `revoke_all_for_login()` below. The session is routinely deleted while refresh tokens are still alive: `_save_or_drop_session()` drops it as soon as `terminal_list` becomes empty (the default, since `is_logout_keep_session=False`), and device-scoped logouts (`device is not None`) never revoke refresh families. So the sequence "logout(device='pc') -> logout(device='app') -> logout(login_id)" leaves every refresh token valid, and the client can call refresh to mint a brand-new access token after a full logout. Revocation of the refresh families should not be conditional on the session existing.

```
session = await self.get_session(normalized_id, create=False)
        if session is None:
            return
        removed = await self._remove_terminals(session, device, destroy=True)
```

- **bug**

Same early-return hazard as `logout()`: when the Account-Session is absent (expired TTL, or already dropped by `_save_or_drop_session` after a previous device-scoped kickout), `kickout()` / `replaced()` become a silent no-op and `revoke_all_for_login(..., logout_access=False)` is never called. Any surviving refresh token can then be exchanged for a fresh, non-offline access token, defeating the kickout. Move the refresh revocation before/outside the `session is None` guard.

```
session = await self.get_session(normalized_id, create=False)
        if session is None:
            return
        offline_count = await self._offline_terminals(session, normalized_id, device, state)
```

- **bug**

`session.raw.terminal_list` is updated with a non-atomic read-modify-write: `get_session()` loads a snapshot, this block mutates it in memory, and `session.save()` blindly `SET`s it back (`SaSession.save` has no CAS, and the storage layer's `compare_and_set` is unused here). Two concurrent `login()` calls for the same account — multi-device login, a double-submitted form, or two app replicas — will each save their own copy, so the loser's terminal entry disappears from the index while its token record stays valid. The orphaned token can then never be reached by `logout(login_id)`, `kickout()`, `replaced()`, or `get_terminal_list()`, i.e. the user cannot be fully logged out. The same pattern applies to `logout_by_token`, `kickout_by_token` and `_offline_terminals`. Consider guarding the session update with `compare_and_set` + retry, or keeping the terminal index in a per-token key rather than in the shared session blob.

```
session.raw.history_terminal_count += 1
        session.raw.terminal_list.append(
```

## medium

### `examples/fastapi/main.py`

- **bug**

Cleanup is only performed for `WebSocketDisconnect`. Any other exception raised after `online.register(...)` — e.g. `RuntimeError` from Starlette when `send_text("pong")` runs on an already-closed socket, or a storage error inside `online.heartbeat(...)` — escapes the handler and leaves the connection registered forever. `OnlineManager._connections` is an in-process dict with no TTL (only the storage record expires), so the leaked `WebSocket` object also stays reachable and `send_to_user()` will keep pushing to a dead connection. Move `unregister` into a `finally` block so cleanup happens on every exit path.

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

- **security**

`/pay` is protected by `check_safe("pay")`, but `/open-safe` grants that second-factor clearance to anyone who is merely logged in — no password re-entry, OTP, or other step-up verification is performed. As the reference example this pattern will be copied verbatim and silently defeats the purpose of safe mode (an attacker who steals a valid token immediately gains access to the "sensitive operation"). Please make the second factor explicit here, e.g. require and verify a password/OTP payload before calling `open_safe`, and note in the docstring that skipping it removes the protection.

```
async def open_safe(login_id: LoginId) -> dict:
```

### `examples/flask/main.py`

- **bug**

`request.get_json(silent=True) or {}` only guards against `None`/falsy bodies. A truthy non-object JSON body (e.g. `["admin"]`, `"x"`, `1`) is returned as-is, and the subsequent `payload.get(...)` raises `AttributeError: 'list' object has no attribute 'get'`, producing a 500 instead of the intended 400. Validate that the parsed body is a `dict` (or use `request.get_json(silent=True, ...)` plus an `isinstance` check).

```
payload = request.get_json(silent=True) or {}
```

建议改成：

```
payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return {"code": 400, "message": "请求体必须是 JSON 对象"}, 400
```

- **bug**

The username is never validated. `StpUtilSync.login("")` (missing/empty/whitespace-only `username`) makes `StpLogic.normalize_login_id` raise a base `SaTokenException`, whose `http_status` is 500 — so a bad request surfaces as an internal server error rather than the 400 used for a wrong password. The same happens for a username containing `:`. Since this file is the canonical copy-paste template for the Flask integration, check the username explicitly before signing in.

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

- **performance**

`**` backtracking has no memoization, so matching cost is O(n^k) in the number of path segments `n` and the number of `**` wildcards `k`. This runs on every request (`run_path_auth` → `resolve` → `matches`), and the path is attacker-controlled: a pattern such as `/api/**/a/**/b/**/c` plus a long non-matching URL causes a combinatorial explosion of recursive calls (and deep recursion). Since the same `(pattern_index, path_index)` pair is re-explored many times, memoizing visited states turns this into O(len(pattern) * len(path)).

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

- **security**

Matching is done on raw segments: duplicate slashes are collapsed, but dot segments are not. A request path like `/public/../admin/user` matches an ignore rule `/public/**` and is therefore released without any auth check, while a fronting proxy/WSGI layer that normalizes the path before dispatch will route the same request to `/admin/user`. Since `ignore` has absolute precedence, this is a fail-open path. Reject or normalize `.`/`..` segments before matching (or refuse to match paths containing them).

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

- **security**

Unmatched paths are fail-open: the returned rule has no `ignore`, no `require_login`, no permissions/roles, so `run_auth_flow` short-circuits to `AuthResult(anonymous=True)` and the request is served without authentication. Any route omitted from the table (a newly added endpoint, a typo in a pattern, or a trailing-slash variant) is public by default. Please make this explicit — either document default-allow prominently in the class docstring, or offer a default-deny option (e.g. a `default_rule`/`deny_by_default` flag) so a configuration mistake fails closed.

```
matched = [rule for rule in self._rules if rule.matches(path, method)]
        if not matched:
            return PathRule(path)
```

### `src/sa_token/adapter/pipeline.py`

- **security**

`set_current()` returns the two `contextvars` reset tokens precisely so the caller can restore the previous state, but both `resolve_token` and `run_auth_flow` (line 68) discard them, and nothing in the auth path ever clears the binding. In an ASGI per-request task this is harmless, but the sync adapters call this function directly on the worker thread (e.g. Flask's `_before_request` → `resolve_token(ctx, manager)`, and `SaTokenFlask.token()`), and no adapter registers a teardown that calls `clear_current()`. The token/login_id therefore stay bound in the reused worker thread's context after the response is sent, so a later request served by the same thread that does not go through the sa-token hook (or any code reading `get_current_token()` / `StpUtil.get_login_id_from_context()` before the hook runs) can observe the *previous* request's identity — cross-request identity leakage. Also, if `check_login` / `check_permission` / `check_role` raises, the partially bound state is left behind for the same reason. Suggest returning the reset refs (e.g. as a field on `AuthResult`) or exposing a `sa_token_context`-style entry point that adapters are required to wrap the request in, so identity is cleared at request end.

```
ctx.state["stp_token"] = token
    set_current(token, None)
    return token
```

### `src/sa_token/config.py`

- **bug**

`__post_init__` is the only validation point for a config object that the module docstring says will be built from YAML / env vars / a config center, but it validates neither the `Literal`-typed fields nor the numeric ones. Invalid values do not fail fast and can silently change security-relevant behavior: e.g. in `stp_logic._enforce_max_login_count`, `mode = self.config.overflow_logout_mode` is looked up in a dict and any unrecognized value yields `state is None`, which takes the `_destroy_token()` branch instead of `_mark_token_offline()` — a typo like `"logut"`/`"kick_out"` silently disables offline-reason records with no error. Likewise a `replaced_range` typo silently downgrades the top-off scope to `curr_device`, and negative/zero values for `timeout`, `active_timeout`, `offline_record_timeout` or `perm_cache_timeout` (other than the documented `-1` sentinel) are accepted. Consider validating the Literal fields via `typing.get_args(...)` and range-checking the numeric fields here, so misconfiguration is reported at startup rather than degrading behavior at request time.

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

- **documentation**

The docstring claims this works with `async with`, but `contextlib.contextmanager` only produces a synchronous context manager (`_GeneratorContextManager` has no `__aenter__`/`__aexit__`). Writing `async with sa_token_context(...)` in async code raises `TypeError: 'async with' requires an object with __aenter__ and __aexit__ methods`. Since this module is explicitly targeted at async scenarios (see the module docstring), either correct the docstring to state that async callers must still use plain `with`, or additionally expose an `@asynccontextmanager` variant.

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

- **bug**

`DisableException` is always constructed from `StpLogic.check_disable()` with `remaining = get_disable_time(...)`, whose contract returns sentinel values (`-1` = permanent ban, `-2` = not disabled). For a permanent ban the message therefore reads “…剩余 -1 秒”, and since the framework adapters (flask/django/starlette) put `exc.message` straight into the response payload, this confusing text is user-visible. Consider rendering negative/sentinel values as “永久” (or omitting the remaining-time clause) instead of interpolating the raw number.

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

- **bug**

同上：`run_auth_flow` 里的 `set_current(...)` 发生在后台事件循环线程，装饰器执行完后当前请求线程的 contextvars 仍是空的，视图内 `StpUtil.get_login_id_from_context()` / `StpUtil.get_token_value()` 返回 `None`（只能靠 `request.sa_login_id`）。建议在 `run_sync` 返回后用 `set_current(result.token, result.login_id)` 在本线程补一次绑定。

```
result = run_sync(run_auth_flow(ctx, get_manager(), rule_factory()))
```

- **bug**

装饰器不支持 `async def` 视图：wrapper 是普通同步函数，`functools.wraps` 不会让 Django 的 `iscoroutinefunction` 判定为协程视图，于是 Django 会把它当同步视图调用；`view(request, ...)` 返回的协程既不会被 await（触发 RuntimeWarning），也会被当成响应对象继续往下传，最终报 500。建议用 `asyncio.iscoroutine_function(view)` 分支，另提供一个 async wrapper 直接 `await run_auth_flow(...)`（Django 4.1+），这样也顺带解决上一条上下文绑定问题。

```
def wrapper(request: Any, *args: Any, **kwargs: Any) -> Any:
```

### `src/sa_token/integration/fastapi.py`

- **bug**

`had_request` is decided purely by parameter *name*. If an endpoint declares a body/query parameter named `request` that is not a Starlette/FastAPI `Request` (e.g. `async def create(request: CreateSchema)`), `_endpoint_signature` will not add a real `request: Request` parameter, FastAPI will never inject the Request, and `_extract_request` will raise `RuntimeError("未找到 Request")` → 500 for every call. Detect the request by annotation/type rather than by name.

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

- **bug**

The signature carried by `__signature__` keeps the user module's annotations as-is (strings when the endpoint module uses `from __future__ import annotations`). FastAPI's `get_typed_signature` evaluates those annotations with `call.__globals__`, which for `wrapper` is *this* module's globals — so any user-defined type (Pydantic model, enum, forward ref) raises `NameError` during route registration. Resolve the hints eagerly in the view's own namespace before publishing the signature.

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

- **bug**

Body parsing is unguarded and can escape the `OAuth2Error` handling in `token_endpoint` (the call sits *before* the `try:`), turning a malformed client request into an HTTP 500 instead of the RFC 6749 §5.2 `400 invalid_request`:
- `await request.json()` raises `json.JSONDecodeError` for an invalid JSON body.
- `(await request.body()).decode("utf-8")` raises `UnicodeDecodeError` for a non-UTF-8 body.

Both are attacker-triggerable with a single bad request. Wrap the decoding and raise a protocol error instead, e.g.:

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
(The same guard is needed for `introspect_endpoint`/`revoke_endpoint`, which have no `try` at all.)

```
if "application/json" in content_type:
        payload = await request.json()
        return payload if isinstance(payload, dict) else {}
    body = (await request.body()).decode("utf-8")
```

- **security**

The token response carries `access_token`/`refresh_token` but is returned without `Cache-Control: no-store` (and `Pragma: no-cache`), which RFC 6749 §5.1 mandates for any response containing tokens or credentials; otherwise shared/proxy caches and browser history may retain live credentials. Apply the headers to every response from this endpoint, including the error path in `_oauth_error`.

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

- **bug**

`token()` looks like a pure getter but has a side effect: `resolve_token()` ends with `set_current(token, None)` (see `adapter/pipeline.py:39`), which resets the request-scoped `_current_login_id` contextvar to `None`. Consequences: a view decorated with both `@sa.check_login` and `@sa.check_safe` (whose wrapper calls `self.token()` after the guard already bound the identity), or any call to `sa.token()` / `sa.login_id_or_none()` inside a view, wipes the bound identity so that subsequent `StpUtil.get_login_id()` / `get_current_login_id()` calls return `None`. Reuse the token already resolved in `_before_request` (`g.sa_token`) or read it side-effect free via `read_token(ctx, manager.config)`.

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

- **bug**

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

- **bug**

`Listener` is typed as `Callable[[EventData], Any | Awaitable[Any]]`, but only coroutine results are awaited. A listener that returns another awaitable (e.g. a `Future`/`Task`, or an object implementing `__await__` such as an `async`-wrapped callable or a third-party awaitable) is silently discarded: the work may never be scheduled and its exception is never surfaced (no log line either, since nothing raises here). Use `inspect.isawaitable(result)` to cover every awaitable type.

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

- **bug**

If an `EventData` is emitted with `event == Event.ALL` (a legitimate enum member), the `Event.ALL` bucket is concatenated with itself, so every wildcard listener is invoked twice for that event. Guard the wildcard lookup so it is only added when the emitted event is not already `ALL`.

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

- **bug**

`build()` hands the builder's own mutable `SaTokenConfig` and `EventBus` to the manager by reference. Consequences: (1) calling `build()` twice yields two managers that share one config object and one event bus, so a listener registered for one fires for the other and `on()`/`set_option()` calls leak across managers; (2) mutating the builder after `build()` (or mutating `manager.config`) silently changes the already-built manager. Snapshot the config (e.g. `dataclasses.replace(self._config)`) and create a fresh `EventBus` per build, copying over the registered listeners.

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

- **bug**

`state` is taken verbatim from the JSON payload with no type validation. If a corrupted / legacy / cross-language record stores `state` as a list or dict (unhashable), `self.state in _OFFLINE_STATES` raises `TypeError` here instead of returning a boolean. Since `is_offline` is on the request hot path (`stp_logic._read_token_info` -> `renew_timeout`/`get_token_session`/`get_offline_reason`), this turns a recoverable bad-record case into an unhandled 500. Normalize/validate `state` in `from_json` (e.g. only keep it when it is a `str`, otherwise set it to `None`), or make this membership test defensive.

```
return self.state in _OFFLINE_STATES
```

建议改成：

```
return isinstance(self.state, str) and self.state in _OFFLINE_STATES
```

- **bug**

`from_json` is documented/used as "return `None` for unusable payloads" (callers in `stp_logic.get_session` treat `None` as "create a fresh session"), but only `json.loads` is guarded. Two escapes here: (1) an explicit `"terminal_list": null` makes `payload.get("terminal_list", [])` return `None`, so the comprehension raises `TypeError: 'NoneType' object is not iterable` (the default only applies when the key is absent); (2) `TerminalInfo.from_dict` requires `token`, so any dict item without that key raises `TypeError`. Both propagate out of `from_json` instead of degrading to `None`. Validate the container type and skip/`None`-return on malformed terminals.

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

- **bug**

`payload.get("data", {})` only falls back when the key is missing; an explicit `"data": null` (or a non-dict value such as a list/string produced by another writer) is accepted and stored as-is. `SessionData.data` is then mutated/read as a dict by `SaSession`, so the failure surfaces far away as `TypeError: 'NoneType' object does not support item assignment`. The same applies to `create_time` / `history_terminal_count`, where a non-int value breaks later arithmetic. Validate the types and fall back to safe defaults (or return `None`).

```
data=payload.get("data", {}),
```

建议改成：

```
data=payload["data"] if isinstance(payload.get("data"), dict) else {},
```

### `src/sa_token/oauth2/model.py`

- **security**

`from_json` filters keys but never validates value types, so the exact-match security invariant documented in `allows_redirect` depends entirely on the stored JSON shape. If `redirect_uris` is deserialized as a string (e.g. `"https://app.example.com/cb"`), `redirect_uri in self.redirect_uris` degrades to *substring* matching and would accept `https://app.example.com/cb.evil.test` style values — the open-redirect the comment says is being avoided. The same applies to `grant_types` (`"authorization_code" not in client.grant_types` becomes a substring test) and `scopes` (`scope not in client.scopes` in `create_authorization_code` would grant any scope that happens to be a substring of the registered scope string). Validate that these fields are lists of `str` and reject the record otherwise.

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

- **security**

PKCE method handling is too permissive: (1) `plain` is accepted unconditionally, and with `plain` the challenge *is* the verifier, so any attacker who observes the authorization request (it travels in the redirect URL) gets full PKCE protection bypassed — RFC 7636 §4.4.1 only permits `plain` when S256 is genuinely unsupported, and many servers reject it outright; (2) any unrecognized method value (`S512`, `PLAIN`, typos) silently falls through to the S256 branch and surfaces later as a confusing "code_verifier 校验失败" instead of an `invalid_request` at authorization time. Validate `code_challenge_method` against an explicit allow-list in `create_authorization_code()` (and make `plain` opt-in via a server flag) so bad input is rejected early and the security policy is explicit.

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

- **bug**

A single hard-coded 400 for every OAuth2 error is not spec-compliant, and because the framework adapters map `http_status` straight onto the HTTP response, the wrong status leaks to clients: `invalid_client` must be 401 (RFC 6749 §5.2), `invalid_token` must be 401 (RFC 6750 §3.1) — otherwise resource servers won't trigger the standard "401 → refresh" flow — and `insufficient_scope` must be 403. Derive the status from `error` instead of using one constant.

```
http_status = 400
```

- **bug**

Old credentials are destroyed before the new ones exist, so any storage failure inside `_issue_tokens()` (connection drop, timeout, OOM) leaves the user with a deleted refresh_token *and* a deleted access_token and no way to recover short of a full re-authorization. Prefer issuing the replacement tokens first and only then removing the old pair (logging if that cleanup fails), or wrap the delete in a compensating path so a failed issuance restores the previous refresh record.

```
raise OAuth2Error("invalid_grant", "refresh_token 已被使用")
        await self._storage.delete(self._key("access", info.access_token))
```

### `src/sa_token/online/__init__.py`

- **bug**

`heartbeat()` is a non-atomic read-modify-write on shared storage. If `unregister()`/`disconnect_user()`/`disconnect_device()` (or a kickout event in another process) deletes the key between the `get()` and the `set()`, this call resurrects the record with a fresh `heartbeat_timeout` TTL. The user then stays "online" in `is_online()`/`get_online_users()` for up to `heartbeat_timeout` seconds after being kicked, and cross-process kickout marking is defeated. `Storage` already exposes `compare_and_set(key, expected, new_value, ttl)` — use it (or a Lua/atomic expire-only path) so the refresh cannot recreate a deleted key.

```
user.last_heartbeat = now_ms()
        await self._storage.set(key, user.to_json(), self.heartbeat_timeout)
```

- **bug**

The connection snapshot is taken *before* acquiring `self._lock`, while `connection_ids` is taken inside it. If a connection registers in between (register writes to storage first, then takes the lock), its id ends up in `connection_ids` — so its storage record is deleted and it is popped from `_connections` — but the object is missing from `connections`, so `self._closer` is never called for it. Result: a live WebSocket that is no longer tracked and never closed. Take both snapshots inside the same locked section.

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

- **performance**

Two problems here: (1) `self._lock` is held across `await self._storage.exists(...)` for *every* local connection, so a full Redis round-trip per connection serializes all `register`/`unregister`/`disconnect_*` calls for the whole scan — noticeable with many connections or a slow/remote storage. (2) If `exists()` raises mid-loop, entries already `pop`ped out of `_connections` are lost with the local `stale` list, so those sockets are never passed to `self._closer` — they leak and stay open while being untracked. Collect the candidate (key, connection) pairs under the lock, run the storage checks outside it, then re-acquire the lock to remove confirmed-stale entries and close them.

```
async with self._lock:
            for login_id, bucket in list(self._connections.items()):
                for connection_id, connection in list(bucket.items()):
                    if not await self._storage.exists(self._key(login_id, connection_id)):
```

### `src/sa_token/security/nonce.py`

- **bug**

`issue()` normalizes the subject (`str(subject).strip()`) before persisting it, but `consume()` compares against the raw `str(subject)`. A caller that passes a subject with surrounding whitespace (or a non-str subject that was normalized on issue) will be rejected with `NONCE_MISMATCH` even though the nonce is valid, and the two code paths can silently disagree about what identifies the same subject. Extract the normalization into a shared helper and use it on both sides (and validate `purpose` consistently too).

```
if record.subject != str(subject) or record.purpose != purpose:
```

建议改成：

```
if record.subject != self._normalize_subject(subject) or record.purpose != purpose:
```

- **maintainability**

`state` is persisted with every record but is never read anywhere — `consume()` only checks `subject`/`purpose`, so a record whose state is anything other than `issued` (e.g. a future `revoked`/`consumed` value written by another component) is still accepted. Either validate `record.state == "issued"` during `consume()` or drop the field until it is actually needed, so the persisted state cannot diverge from the security decision.

```
state: str = "issued"
```

### `src/sa_token/security/refresh.py`

- **performance**

`revoke_for_access` walks the whole keyspace: Redis `SCAN` iterates every key and filters server-side, and this issues a `GET` per candidate key. It is invoked on every `logout_by_token` and `kickout_by_token` (stp_logic.py:314, 340), i.e. a normal user logout costs O(total keys in the DB), and the loop keeps scanning even after the matching record is deleted. Maintain a reverse index `access_token -> refresh key` (or store the refresh token inside `TokenInfo`) so this becomes a single lookup instead of a full scan.

```
cursor, keys = await self._storage.scan(f"{prefix}refresh:*", cursor, 200)
```

- **performance**

These lists only ever grow while the family TTL is refreshed on every rotation. With the default `refresh_token_timeout` of 30 days, a client refreshing every few minutes accumulates thousands of access/refresh tokens in one JSON value; the `not in` membership checks are O(n) per rotation, and `revoke_family` then performs a `get_token_info` + `logout_by_token` and a `delete` for each entry (thousands of sequential round trips). Prune entries whose refresh record no longer exists, cap the list length, or store family members as individual keys instead of one ever-growing blob.

```
if record.access_token not in family.access_tokens:
                family.access_tokens.append(record.access_token)
            if record.refresh_token not in family.refresh_tokens:
                family.refresh_tokens.append(record.refresh_token)
```

### `src/sa_token/security/temp_token.py`

- **security**

`namespace` (and `token`) are only validated in `create()` via `_validate()`. `parse()`, `consume()`, `delete()` and `find_token()` build storage keys from unvalidated input, so the ":"-in-namespace guard can be bypassed on the read paths and key spaces can collide: namespace `"a:b"` + token `"c"` produces exactly the same key as namespace `"a"` + token `"b:c"` (a caller-supplied token can contain colons even though generated ones cannot). That allows cross-namespace reads/deletes of one-time tokens. Extract a namespace-only check and call it in every public method that composes a key.

```
def _key(self, namespace: str, token: str) -> str:
        return f"{self._key_prefix}security:temp:{namespace}:{token}"
```

- **security**

Re-issuing a token for a value that already has an index entry overwrites the index but leaves the previously issued token alive in storage until its TTL expires. For one-time actions (password reset, email verification) this means several simultaneously valid tokens per business value: an attacker holding an older reset link can still `consume()` it after the user requested a new one, while `find_token()` only reports the newest. Consider reading the previous index value and deleting that token key (or using `compare_and_set` plus explicit revocation) before overwriting the index.

```
if record_index and isinstance(value, str):
                    await self._storage.set(self._index_key(namespace, value), token, ttl)
```

### `src/sa_token/session.py`

- **bug**

Mutations are applied to `_data` before the storage write is awaited, so a failing `save()` (Redis timeout, connection error, serialization error) leaves the handle dirty: the exception propagates, the caller assumes the write never happened, but the change is still in memory and will be persisted by the *next* successful `save()` on the same handle (e.g. a later `set()`, or `StpLogic._save_or_drop_session()`). `clear()` is the worst case — all session data is wiped locally and then flushed later even though the caller saw an error. Snapshot and roll back `_data` when `save()` raises (or persist first and only then commit the local change).

```
async def clear(self) -> None:
        self._data.data.clear()
        await self.save()
```

### `src/sa_token/storage/base.py`

- **documentation**

TTL 契约只定义了 `None` 与 `-1`，对 `0` 和其它负数没有任何约定，而两个现有实现已经出现行为分歧：`MemoryStorage._to_expire_at` 把 `ttl <= 0` 视为“立即过期”（键写入后马上不可读），`RedisStorage._normalize_ttl` 则用 `max(1, ttl)` 钳成 1 秒存活。同一段业务代码（如 `set(k, v, ttl=0)`）在内存后端与 Redis 后端下结果不同，属于难以排查的一致性缺陷。建议在契约中明确 `ttl` 只能是 `None`/`-1` 或正整数，并规定 `0`/其它负数的统一语义（推荐“立即过期或删除”），要求各实现遵守。

```
``ttl`` 单位为秒；``None`` 与 ``-1`` 等价，均表示永不过期。
```

### `src/sa_token/stp_logic.py`

- **bug**

`config.dynamic_active_timeout` can never take effect. Nothing in the codebase populates `TokenInfo.active_timeout`: `login()` exposes no such parameter and `_allocate_token()` builds `TokenInfo(login_id, device, login_type, timeout, tag)` only, so the field is always its `None` default and this condition always falls through to `self.config.active_timeout`. Worse, the companion guard in `_touch_active` (`if self.config.active_timeout < 0 and not self.config.dynamic_active_timeout: return`) means that with `dynamic_active_timeout=True` and `active_timeout=-1` the `last-active` key is written on every single request but never read — pure overhead. Either thread a per-token `active_timeout` through `login()`/`_allocate_token()`, or drop the config flag and the dead branch.

```
active_timeout = (
            info.active_timeout
            if self.config.dynamic_active_timeout and info.active_timeout is not None
            else self.config.active_timeout
        )
```

- **performance**

`_renew` runs on every successful `check_login`, i.e. on every authenticated request, and performs 4 storage round-trips (1 `set` in `_touch_active` + 3 `expire`) plus an event emission. The three `expire` calls are the expensive part: they unconditionally rewrite TTLs that were just extended by the previous request, and the `Event.RENEW` emission will flood any audit-log/metrics listener with one record per request. Consider only renewing when the remaining TTL has actually dropped meaningfully (e.g. re-`expire` when `storage.ttl()` is below ~half of `timeout`), and demoting RENEW to a sampled or explicitly opted-in event.

```
await self.storage.expire(self._token_key(token), timeout)
        await self.storage.expire(self._session_key(info.login_id), timeout)
        await self.storage.expire(self._token_session_key(token), timeout)
        await self._emit(Event.RENEW, login_id=info.login_id, token=token, timeout=timeout)
```

## low

### `examples/fastapi/main.py`

- **maintainability**

Assertions are stripped under `python -O`. If the token context is ever missing here, the call degrades to `open_safe(None, "pay", 300)` and the endpoint still returns `{"ok": True}`, so a user would believe second-factor auth was opened when it was not. Prefer an explicit guard that raises (e.g. `NotLoginException`) or reuse the injected dependency instead of reading the context token.

```
assert token is not None
```

### `examples/flask/main.py`

- **security**

Every successful login is granted the `admin` role, which makes `/admin/panel` reachable by any authenticated caller. Even for a demo, this pattern tends to be copied verbatim into real services; scope the role to a specific demo account (e.g. only when `username == "admin"`) so the example shows a role check that can actually fail.

```
StpUtilSync.set_roles(username, ["admin"])
```

建议改成：

```
StpUtilSync.set_roles(username, ["admin"] if username == "admin" else ["user"])
```

- **security**

`debug=True` enables the Werkzeug interactive debugger, which allows arbitrary code execution from the browser when the app is reachable (e.g. bound to `0.0.0.0`, run in a container, or exposed through a tunnel). Prefer keeping debug off by default and enabling it explicitly via an environment variable, and mention in the docstring that the example must stay on localhost.

```
app.run(debug=True)
```

建议改成：

```
app.run(debug=os.getenv("FLASK_DEBUG") == "1")
```

### `examples/native/quick_start.py`

- **maintainability**

`assert` is used here as the only behavioral check of the kickout demo. Under `python -O` assertions are stripped, so if this example is reused as a smoke test (CI/docs build) it will exit 0 even when the behavior regresses. Also, if `check_login` does *not* raise at all, the `except` branch is skipped and the script prints nothing yet still succeeds silently. Prefer an explicit check, e.g. `if exc.type is not NotLoginType.KICK_OUT: raise AssertionError(...)` inside the handler plus an `else: raise AssertionError("expected NotLoginException")` on the `try`.

```
assert exc.type is NotLoginType.KICK_OUT
```

- **maintainability**

This `assert` doubles as the `None` narrowing for `session.set(...)` below, so under `python -O` a `None` session would surface later as a confusing `AttributeError` instead of a clear failure. If the intent is only type narrowing for the checker it is fine, but for a runnable example an explicit `if session is None: raise RuntimeError(...)` gives a deterministic failure mode.

```
assert session is not None
```

### `src/sa_token/adapter/path.py`

- **performance**

The uppercase method set is rebuilt on every call, and `matches` is invoked once per rule per request. Normalize `methods` once in `__post_init__` (e.g. `self._methods = {m.upper() for m in methods}`) and compare against the cached set.

```
if self.methods and method.upper() not in {m.upper() for m in self.methods}:
```

建议改成：

```
if self._methods and method.upper() not in self._methods:
```

### `src/sa_token/adapter/pipeline.py`

- **maintainability**

`build_rule` is part of the public API (re-exported in `adapter/__init__.py`'s `__all__` and used by the flask/django/fastapi/starlette integrations), but it is missing from this module's `__all__`, so `from sa_token.adapter.pipeline import *` silently omits it. Add it for consistency.

```
__all__ = ["AuthResult", "resolve_token", "run_auth_flow", "run_path_auth"]
```

建议改成：

```
__all__ = ["AuthResult", "build_rule", "resolve_token", "run_auth_flow", "run_path_auth"]
```

### `src/sa_token/config.py`

- **maintainability**

`from_dict` drops unknown keys without any signal, which is inconsistent with `SaTokenBuilder.set_option` (it raises `未知配置项` for the same situation). A misspelled key in external config (e.g. `cookie_securre`, `jwt_secrety_key`, `token_prefx`) is therefore ignored silently and the potentially unsafe default stays in effect — the caller believes the setting was applied. Also, values coming from env vars/YAML are passed through untyped, so `timeout="60"` (str) reaches the arithmetic in the login path and fails far from the config load. Suggest at least logging the ignored keys, or adding a `strict: bool = False` parameter that raises on unknown keys, plus type coercion/validation for the known fields.

```
known = {f.name for f in fields(cls)}
        return cls(**{key: value for key, value in values.items() if key in known})
```

### `src/sa_token/context.py`

- **maintainability**

The `tokens is None` branch hard-sets both vars to `None` instead of restoring any previously bound value, which contradicts the docstring ("还原到绑定前的状态"). In nested usage (e.g. a `sa_token_context(...)` block already active, then an outer framework calls `clear_current()` on request teardown) the inner identity is silently wiped rather than restored. Since callers such as `adapter/pipeline.py` use `set_current(...)` and discard the returned reset tokens, this fallback path is easy to hit. Consider documenting it as "unconditionally clear" (and/or renaming it), or making the reset-token argument mandatory so a proper restore is always available.

```
if tokens is None:
        _current_token.set(None)
        _current_login_id.set(None)
        return
```

### `src/sa_token/exception.py`

- **bug**

Direct dict indexing means any `NotLoginType` value not present in `_NOT_LOGIN_MESSAGES` (e.g. a new enum member added later, or a value decoded from storage in another module) raises `KeyError` instead of an authentication error. Because `KeyError` is not a `SaTokenException`, adapters won't map it to 401 and the request degrades into an unhandled 500. Use `.get()` with a generic fallback message so the exception contract always holds.

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

- **maintainability**

`__all__` 只声明了 fastapi/starlette/flask/django 四个子模块，但包内还存在 `fastapi_oauth2.py`（提供 `create_oauth2_router` / `authorization_redirect`）。由于 `from sa_token.integration import *` 会按 `__all__` 导入子模块，`fastapi_oauth2` 不会被暴露，容易被使用者忽略；建议将其补入 `__all__`，或在此处注释说明它是通过 `sa_token.integration.fastapi_oauth2` 显式导入的可选扩展模块。

```
__all__ = ["fastapi", "starlette", "flask", "django"]
```

建议改成：

```
__all__ = ["fastapi", "starlette", "flask", "django", "fastapi_oauth2"]
```

### `src/sa_token/integration/fastapi_oauth2.py`

- **bug**

The 401 challenge is emitted as a bare `WWW-Authenticate: Basic`, which is missing the required `realm` parameter (RFC 6749 §5.2 / RFC 7617), and — more importantly — the endpoints never actually accept HTTP Basic credentials: `token_endpoint` only reads `client_id`/`client_secret` from the body. A spec-conformant client that receives this challenge will retry with an `Authorization: Basic ...` header, which this code ignores, so the retry fails again with `invalid_client`. Either support Basic client authentication (decode `request.headers.get("authorization")` and merge it into `parameters`) or drop/replace the header, e.g. `WWW-Authenticate: Bearer realm="oauth2"`.

```
headers = {"WWW-Authenticate": "Basic"} if status == 401 else None
```

- **bug**

For a JSON body, `parameters.get("client_secret", "")` returns `None` when the key is present with a JSON `null`, so `str(...)` produces the literal string `"None"` and hands it to `_verify_client_secret` as if it were a real secret. It is inconsistent with the `authorization_code`/`refresh_token` branches just above, which pass the raw value through. Use a small normalizer (`value if isinstance(value, str) else ""`) so missing/null/non-string fields become empty rather than their `repr`.

```
client_secret=str(parameters.get("client_secret", "")),
```

### `src/sa_token/integration/flask.py`

- **bug**

`assert` is used to guarantee the declared `str` return type, but assertions are stripped under `python -O`; the method would then silently return (and cache into `g.sa_login_id`) `None`, violating the contract for every caller. Prefer an explicit check that raises a `SaTokenException` so the behaviour is identical in optimized builds.

```
assert result.login_id is not None
```

建议改成：

```
if result.login_id is None:  # pragma: no cover - require_login 保证非空
            raise SaTokenException("登录校验未返回 login_id")
```

### `src/sa_token/integration/starlette.py`

- **performance**

每个 Depends 扩展都会重新跑一遍完整鉴权流程（读 header/cookie/query 取 token + `check_login` 访问存储）。当请求已经过 `SaTokenMiddleware`（尤其是配置了 `path_auth` 时）或同一路由挂了多个本模块依赖时，同一请求会重复做多次存储往返；并且 `check_login()` / `check_permission()` 每次调用都返回新的闭包对象，FastAPI 的依赖缓存无法去重。建议把已完成的鉴权结果缓存在 `request.state`（中间件已写入 `sa_token` / `sa_login_id`）上，`_authorize` 命中时直接复用。

```
ctx = StarletteHttpContext(request)
    rule = build_rule(permissions=permissions, roles=roles, mode=mode)
    result = await run_auth_flow(ctx, get_manager(), rule)
```

- **maintainability**

`_authorize` 调用 `run_auth_flow` 时未传 `login_type`，`check_disable` / `check_safe` 也用 `get_manager().stp()` 的默认账号体系，而 `SaTokenMiddleware` 是支持自定义 `login_type` 的。当应用配置了非默认的 login_type（如 "user"）时，这些 Depends 扩展会去校验另一套账号体系（token 名称、存储 key 都不同），导致已登录用户被判定 401。建议让这些工厂接受 `login_type` 参数（或从 request.state / 中间件配置读取）并向下透传。

```
await get_manager().stp().check_disable(login_id, service=service, level=level)
```

- **bug**

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

- **performance**

`emit()` is awaited inline on hot auth paths (e.g. `StpLogic.login`/`logout` via `_emit`), yet synchronous listeners are called directly on the event loop. A listener that performs blocking audit I/O (DB/HTTP/file writes) will stall the loop for every login/logout. Consider documenting that sync listeners must be non-blocking, or dispatch them with `asyncio.to_thread`/`run_in_executor`.

```
async def emit(self, data: EventData) -> None:
```

### `src/sa_token/manager.py`

- **bug**

`hasattr` also returns True for the dataclass's methods (`key_prefix`, `make_key`, `from_dict`), so `set_option(key_prefix="satoken")` — a plausible key coming from an external config file — passes validation and then shadows the bound method with a string, breaking `config.key_prefix(...)`/`make_key(...)` later with a confusing `TypeError`. Validate against the actual dataclass field names instead.

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

- **maintainability**

Send/close failures are swallowed by a bare `except Exception: continue` in five places (`send_to_user`, `send_to_device`, `disconnect_user`, `disconnect_device`, `cleanup_stale_connections`) with no logging. Because `Exception` also covers programming errors (`TypeError`, `AttributeError`, `CancelledError`-adjacent bugs in a user-supplied `sender`/`closer`), a misconfigured callback silently reports "0 messages sent" and connections that were never actually closed — very hard to diagnose. At minimum log at debug/warning level, and consider narrowing to the transport-specific exception the sender/closer raises.

```
except Exception:
                # 推送失败通常意味着连接已断，交给连接自身的清理流程处理。
                continue
```

- **bug**

Deriving the default `connection_id` from `id(connection)` is unsafe as a cross-process key component: memory addresses are only unique among *live* objects in one process, so two different processes can produce the same hex id for the same `login_id`. They would then share one storage key (`online:user:<login_id>:<id>`), meaning one process's `register` overwrites the other's record and its `unregister`/`disconnect_*` deletes it — the other connection silently drops out of `is_online()`/`get_online_users()` and gets torn down by `cleanup_stale_connections()`. Prefer a globally unique id (e.g. `uuid4().hex`, optionally with a per-process prefix).

```
resolved_id = connection_id or f"{id(connection):x}"
```

### `src/sa_token/security/nonce.py`

- **maintainability**

If the key expires between `get()` and `compare_and_delete()`, `compare_and_delete` returns False and the caller receives `NONCE_REPLAYED` ("nonce 已被其它请求使用"), which misreports a plain expiry as a replay attack and can mislead auditing/alerting. Consider re-checking existence after a failed delete and raising `INVALID_NONCE` when the key is gone.

```
if not await self._storage.compare_and_delete(key, raw):
            raise SecurityException("NONCE_REPLAYED", "nonce 已被其它请求使用")
```

### `src/sa_token/security/temp_token.py`

- **bug**

`consume()` returns `Any | None` where `None` means "token invalid/already used", but `value: Any` also permits a legitimately stored `None`. In that case the token has already been atomically destroyed by `compare_and_delete`, yet the caller receives `None` and cannot tell a successful consumption from a replay/expiry (the same ambiguity affects falsy values such as `0`, `""`, `False` for callers that test truthiness). Returning a sentinel/`tuple[bool, Any]`, or raising a `SecurityException` on failure as `NonceManager.consume` does, would keep the two outcomes distinguishable.

```
return record.value
```

### `src/sa_token/session.py`

- **maintainability**

This property hands out the live, mutable `SessionData.terminal_list` (and its mutable `TerminalInfo` elements). Callers can `append`/`remove`/edit through it without any `save()` being triggered, so the change is silently lost (or, worse, flushed much later by an unrelated `save()`), breaking the "every write lands in storage" invariant this class documents. Unlike `raw`, which is explicitly marked as core-internal, this looks like a public accessor. Return a copy (e.g. `list(self._data.terminal_list)`) or document it as read-only/internal and provide explicit mutators that call `save()`.

```
return self._data.terminal_list
```

### `src/sa_token/storage/__init__.py`

- **maintainability**

`RedisStorage` is advertised in `__all__` and documented in the README as `from sa_token.storage import RedisStorage`, but the name only exists at runtime via PEP 562 `__getattr__`. Static type checkers (e.g. mypy) do not resolve module-level `__getattr__` for `from ... import ...`, so users type-checking their own code get "Module 'sa_token.storage' has no attribute 'RedisStorage'". Consider adding a `TYPE_CHECKING`-guarded re-export so the name is statically visible while the runtime import stays lazy, and optionally cache the class into `globals()` to avoid re-executing the import on every attribute access.

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

- **documentation**

`expire` 的返回值语义在实现间并不等价于“键不存在”：`RedisStorage` 在 `ttl is None` 时走 `PERSIST`，而 Redis 对“键存在但本来就没有 TTL”同样返回 0/False。也就是说调用方无法用 `False` 判断键是否存在（`if not await storage.expire(k, ttl): # 当作键已失效` 会误判）。建议把契约写清楚：返回值仅表示 TTL 状态是否被成功修改，键存在性请用 `exists()`/`ttl() == -2` 判断；或要求实现在键不存在时才返回 False（Redis 侧需额外 EXISTS 判断）。

```
"""更新 TTL，键不存在时返回 False。"""
```

- **documentation**

游标语义存在歧义：入参 `cursor=None` 表示“从头开始扫描”，出参 `None` 表示“扫描结束”，同一个值承担两种含义，调用方很容易把首轮返回值当起始游标再次传入而造成重复扫描。此外游标是不透明值（Redis 原生用 `"0"` 同时表示开始与结束，`MemoryStorage` 用的是排序后的偏移量），契约应显式要求：实现必须把“结束”统一映射为 `None`，调用方不得自行构造或解析游标，且游标不可跨实现/跨进程复用。

```
"""按 glob 模式游标扫描键，返回 ``(下一个游标, 键列表)``；游标为 None 表示结束。"""
```

- **maintainability**

两点风险：1) `@runtime_checkable` 的 `isinstance` 只校验同名属性是否存在，既不校验签名也不校验方法是否为协程函数，一个含同步 `get`/`set` 的对象同样能通过检查；当前代码库中没有任何 `isinstance(x, SaStorage)` 调用，该装饰器实际未起到校验作用，反而容易让人误以为运行时可以验证契约。2) 所有方法都是 `...` 默认体（非 `@abstractmethod`），一旦被显式继承而漏写某个方法（例如 `ttl()`），调用会静默返回 `None` 而非报错，直接破坏 `-> int` / `-> bool` 契约并在上层引发难以定位的 `TypeError`。若确实允许被继承，建议默认体改为 `raise NotImplementedError`；若仅用于结构化类型检查，可考虑去掉 `runtime_checkable`。

```
@runtime_checkable
class SaStorage(Protocol):
```

### `src/sa_token/stp_logic.py`

- **bug**

`keyword` is interpolated straight into a Redis glob pattern without escaping. Glob metacharacters in the keyword (`*`, `?`, `[`, `]`, `\`) change the match semantics — `[` without a closing `]` makes Redis reject the pattern and surface as a 500 — and an untrusted admin-console query like `*` silently degrades into a full keyspace dump. Escape the keyword before building the pattern (e.g. wrap each metacharacter in `[]`, or reject non-alphanumeric input), and apply the same fix in `search_session`.

```
pattern = f"{prefix}*{keyword}*" if keyword else f"{prefix}*"
```

### `src/sa_token/stp_util.py`

- **bug**

`get_manager()` reads the mutable module global `_manager` twice (once for the `is None` check, once for the return). If another thread calls `clear_manager()`/`set_manager()` between those two reads (e.g. app rebuild or test teardown while requests are still in flight), the function can return `None` even though the annotation promises `SaTokenManager`, pushing a confusing `AttributeError` into every facade call instead of the intended `SaTokenNotInitializedException`. Read the global once into a local and validate that local.

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

- **bug**

The nonce subject is normalized inconsistently across this pair of facade methods: `NonceManager.issue` stores `str(subject).strip()`, while `NonceManager.consume` compares against the *unstripped* `str(subject)`. So for any subject with surrounding whitespace (e.g. a login id read from a form/header), `issue_nonce` succeeds but the matching `consume_nonce` always fails with `NONCE_MISMATCH`, and the nonce becomes unconsumable. Additionally `str(None)` yields the non-empty string `"None"`, which silently bypasses the empty-subject validation in `issue`. Normalize the subject identically on both paths (ideally fix the asymmetry in `NonceManager.consume` as well).

```
await get_manager().nonces.consume(nonce, str(subject), purpose=purpose)
```

建议改成：

```
await get_manager().nonces.consume(nonce, str(subject).strip(), purpose=purpose)
```

### `tests/conftest.py`

- **maintainability**

The `created` list is written to (`created.append(manager)`) but never read anywhere — not in the fixture body, not in the teardown. It is dead state that only keeps strong references to every manager built during the test alive until teardown. Either drop it (and the `SaTokenManager` import used only for its annotation) or actually use it, e.g. to release each manager's storage during teardown.

```
created: list[SaTokenManager] = []
```

- **test**

`clear_manager()` only runs for tests that request `build_manager` (directly or via `manager`/`stp`). Tests that build a manager themselves with `SaToken.builder()...build()` — which calls `set_manager()` by default — without requesting this fixture will leave the global `_manager` set and leak it into later tests (e.g. breaking tests that expect `SaTokenNotInitializedException`, or silently using a stale manager through `StpUtil`). Consider an autouse cleanup fixture so the reset happens for every test regardless of which fixtures are used:

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

### critical

### `src/sa_token/strategy/jwt.py`

- **security**

`payload.update(extra)` runs after the reserved claims (`loginId`, `iat`, `jti`, `iss`, `aud`) are already set, so any key in `extra` that collides with a reserved claim silently overwrites it. Overwriting `loginId` enables impersonation. Overwriting `jti` defeats the unique-token guarantee. Overwriting `iss` / `aud` bypasses the configured issuer and audience. Overwriting `iat` falsifies the issue time. Either merge `extra` before the reserved claims, or drop reserved keys from `extra`.

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

### high

### `src/sa_token/security/temp_token.py`

- **bug**

`compare_and_delete(key, raw)` deletes the stored value before `TempTokenRecord.from_json(raw)` runs. If `raw` is corrupt and cannot be deserialized, the token is gone and cannot be recovered. `delete()` parses first and only then deletes. `consume()` should do the same: parse and validate, then perform the destructive compare-and-delete.

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

- **bug**

`value: Any` accepts `None`, and both `parse()` and `consume()` return `None` when the token is missing and when the stored value is `None`. Callers cannot tell those cases apart. Reject `None` in `create()`, or raise when the token is missing so the return value is never ambiguous.

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

- **security**

`TikStrategy.__init__` does not require `length` to be a positive integer. `length` of 0 or less makes `range(self.length)` empty, so `generate()` returns `""`. An empty token has no entropy. Enforce a minimum length of at least 1.

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

- **bug**

The decode path catches every `Exception`, not only PyJWT decode errors. A bad secret, an invalid algorithm, or a programming mistake is swallowed and returned as `None`, so a configuration error looks like a failed login with no traceback. Catch `PyJWTError` and let unexpected errors propagate.

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

- **bug**

`_get_background_loop()` checks that the loop is alive under `_loop_lock`, then releases the lock before `run_sync` uses the returned loop. Another thread can call `shutdown_sync_loop()` in that window, close the loop, and set `_loop = None`. The first thread then submits work to a closed loop and raises `RuntimeError: Event loop is closed`. Hold the lock across submit, or retry inside `run_sync` when the loop is already closed.

```
def _get_background_loop() -> asyncio.AbstractEventLoop:
    with _loop_lock:
        if _loop is not None and not _loop.is_closed():
            return _loop
```

- **bug**

`asyncio.run_coroutine_threadsafe(...).result()` can raise `asyncio.CancelledError` if the loop stops while the task is still running. `CancelledError` is a `BaseException`, so ordinary `except Exception` handlers do not catch it and the WSGI thread crashes. Catch it in `run_sync` and re-raise a documented `RuntimeError`.

```
        return asyncio.run_coroutine_threadsafe(coro, _get_background_loop()).result()
```

### medium

### `src/sa_token/security/refresh.py`

- **performance**

Every `refresh()` appends a new access token and refresh token to the family lists, and those lists are never trimmed. `revoke()` deletes one refresh token from storage but does not remove it from `family.refresh_tokens`. The record grows without bound, and `revoke_family()` gets slower. Prune expired entries, or keep only the current generation, and remove a token from the family record when it is deleted.

```
    family.access_tokens.append(record.access_token)
    family.refresh_tokens.append(record.refresh_token)
```

- **maintainability**

`revoke_family()` marks the family revoked and deletes its refresh tokens, but never removes that `family_id` from the user index maintained by `_add_user_family`. `revoke_all_for_login()` still walks those stale ids and looks them up again. The index keeps every family id ever created. `revoke_family()` should also drop the id from the user index.

```
async def revoke_family(self, family_id: str, *, logout_access: bool = True) -> None:
```

- **maintainability**

`_RefreshRecord.from_json()` and `_FamilyRecord.from_json()` use `cls(**payload)`. Extra fields from a newer version, or missing fields after a schema change, raise `TypeError`. The `except` returns `None`, so every previously stored record becomes unreadable and a legitimate refresh can look like `REFRESH_FAMILY_REVOKED`. Deserialize only known fields and fill defaults for the rest.

```
            return cls(**payload) if isinstance(payload, dict) else None
```

### `src/sa_token/sso/__init__.py`

- **performance**

The retry loop has no backoff. When several services register the same `login_id` at once, 12 attempts run back to back on the event loop and burn the retry budget, then raise `SsoError`. Sleep briefly, with jitter or exponential backoff, after each failed compare-and-set.

```
    for _ in range(12):
        raw = await self._storage.get(key)
```

建议改成：

```
        await asyncio.sleep(random.uniform(0.01, 0.05) * (2 ** attempt))
```

### `src/sa_token/storage/memory.py`

- **bug**

`int(cursor)` raises an unhandled `ValueError` when `scan` receives a non-numeric cursor. A bad caller or a corrupted cursor crashes the method. Catch `ValueError` and `TypeError`, or check `str.isdigit()` first.

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

- **performance**

`_maybe_cleanup()` runs only inside `set()`. A read-heavy workload that rarely writes leaves expired entries in `self._data` until the next `set()`. Lazy removal in `_get_unlocked` only drops keys that are read again. Also call `_maybe_cleanup` from `get` and `scan` while the lock is held.

```
            self._data[key] = _Entry(value, _to_expire_at(ttl))
            self._maybe_cleanup()
```

### `src/sa_token/storage/redis.py`

- **bug**

`_normalize_ttl` turns `ttl=0` into 1 second without saying so. The docstring only documents `None` and `-1` as “never expire”, and the base protocol leaves `0` unspecified. Some callers treat `0` as unlimited, others as expire immediately. The current `max(1, ttl)` is neither. Treat `0` as never-expire, or raise `ValueError`, and document the choice.

```
    return max(1, ttl)
```

### `src/sa_token/sync.py`

- **performance**

`run_coroutine_threadsafe(...).result()` waits forever. A hung coroutine, a deadlock, or a stuck `MemoryStorage` lock blocks the calling WSGI thread until the pool is exhausted. Add a timeout argument, for example `.result(timeout=30)`, and document that the call can block.

```
return asyncio.run_coroutine_threadsafe(coro, _get_background_loop()).result()
```

- **performance**

`shutdown_sync_loop()` stops the loop without cancelling pending tasks or waiting for in-flight coroutines. With a daemon thread, session writes and token updates can be abandoned on shutdown. Cancel `asyncio.all_tasks(loop)` before `stop()`, or document that this is only for tests and process exit.

```
        _loop.call_soon_threadsafe(_loop.stop)
```

### `src/sa_token/strategy/__init__.py`

- **bug**

A non-numeric suffix after `random` silently falls back to 32 characters. `token_style="randomxyz"` or `token_style="random"` still issues 32-character tokens, which hides typos. Reject a suffix that is not digits.

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

- **maintainability**

`JwtStrategy` is in `__all__` but is only exposed through module `__getattr__`. mypy, pyright, and PyCharm do not execute `__getattr__`, so `from sa_token.strategy import JwtStrategy` fails static checking. Import it at module level behind a guard, or remove it from `__all__` and tell users to import `sa_token.strategy.jwt`.

```
    "JwtStrategy",
```

### low

### `src/sa_token/security/refresh.py`

- **performance**

`_update_family()` and `_add_user_family()` retry 12 times with no delay when compare-and-set fails. Under contention every attempt fails immediately and the client gets `REFRESH_CONFLICT`. Add a short randomized backoff between retries.

```
        for _ in range(12):
            raw = await self._storage.get(key)
```

- **performance**

`revoke_for_access()` scans every `refresh:*` key and reads each value to find one access token. With a large keyspace this is O(n). Keep an `access_token -> refresh_token` index, or document that this path is not for the hot logout path.

```
        cursor, keys = await self._storage.scan(f"{prefix}refresh:*", cursor, 200)
```

### `src/sa_token/strategy/__init__.py`

- **maintainability**

`config.jwt_secret_key or ""` turns the default `None` into an empty string before `JwtStrategy` sees it. The strategy does reject an empty key, but the `or ""` looks like an empty string is a valid fallback. Check the config field in the factory and raise an error that names `jwt_secret_key`.

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
