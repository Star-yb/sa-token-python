# Delegation 审查记录

日期：2026-09-30。模式：工作区（`ocr delegate preview` + `ocr delegate rule`）。审查由当前 Cursor 会话完成，没有调用 OCR 自己的模型。

审了 50 个文件。下面 4 条已按本记录改完，进度见 `scripts/bugfix-progress.md` 的 118–121。

- **高**: 1
- **中**: 3

## 高

### 118 `src/sa_token/adapter/path.py`

- **安全**

路径里的 `..` 退到根以外时，`ant_match` 直接返回不匹配。`PathAuthConfig.resolve` 对一条规则都没中的路径是匿名放行。文档建议用 `.login("/**")` 兜住全部请求，但 `/..`、`/foo/../..` 现在匹配不到 `/**`。这段规范化加上之前，`/**` 能匹配这些路径。

```python
if path_parts is None:
    return False
```

```python
if not matched:
    return PathRule(path)
```

退到根以外时按拒绝处理，或者让 `/**` 仍然命中，不要放进默认放行。

## 中

### 119 `src/sa_token/storage/redis.py`

- **缺陷**

`set_if_absent` 在 TTL 为 0 时只查询键是否存在，不写入，却在键不存在时返回成功。内存实现会在锁里占位。Redis 上两个并发调用可以同时成功，而且令牌实际没有存下来。`timeout=0` 是配置允许的「立即过期」。

```python
async def set_if_absent(self, key: str, value: str, ttl: int | None = None) -> bool:
    seconds = _normalize_ttl(ttl)
    if seconds == 0:
        return not bool(await self._redis.exists(key))
```

TTL 为 0 时返回 `False`，或者用和内存实现一样的原子占位，不要报告已写入。

### 120 `src/sa_token/session.py`

- **缺陷**

合并冲突时，会把本地仍保留的终端写回远端。另一次登出已经从会话里摘掉的终端，会被这次无关的 `session.set()` 加回去。令牌键本身已经删除，登录校验仍会失败，但会话列表里会出现幽灵终端，`max_login_count` 会把它算进在线数。

```python
for item in self._data.terminal_list:
    by_token[item.token] = item
```

只合入相对 base 真正新增或修改的终端，不要把未改动的本地终端覆盖到远端已删除的项上。

### 121 `src/sa_token/integration/flask.py`

- **缺陷**

`@sa.check_login` 通过 `run_sync` 跑鉴权，`set_current` 发生在后台事件循环线程里。装饰器回到 Flask 请求线程后只写了 `g`，没有再调用 `set_current`。Django 装饰器有这一步。因此只加了装饰器、没有路径规则的 Flask 视图里，`get_current_login_id()` 仍是空的。带 `path_auth` 的 `before_request` 会在请求线程上补一次，那条路径是好的。

```python
result = run_sync(
    run_auth_flow(
        self._context(),
        get_manager(),
        rule_factory(),
        login_type=self.login_type,
    )
)
self._remember(result.token, result.login_id)
return view(*args, **kwargs)
```

`run_sync` 返回后，在请求线程上执行 `set_current(result.token, result.login_id)`。
