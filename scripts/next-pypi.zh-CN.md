# 下次大更新再上传 PyPI

当前 PyPI 版本是 **0.1.6**：https://pypi.org/project/sa-token-python/0.1.6/

0.1.6 之后仓库里还有下面这些改动。留到下次大更新，再发新版本上传。不为这些小修单独发版。

## 尚未进入 0.1.6

### Python 3.10 同步调用超时

文件：`src/sa_token/sync.py`

`run_sync` 超时后应取消后台协程，并抛出 `RuntimeError`（文案：`同步调用超时`）。Python 3.10 上 `future.result(timeout=...)` 抛出的是 `concurrent.futures.TimeoutError`，它和内置 `TimeoutError` 不是同一个类，原来的 `except TimeoutError` 接不住。3.11 及以上这两个名字已经合并，0.1.6 在那些版本上的超时行为是对的。

只影响同时满足这三条的调用：

- 运行在 Python 3.10
- 走同步接口 `StpUtilSync` / `run_sync`（Flask、Django 同步视图，或没有事件循环的脚本）
- 这一次调用超过 `timeout`（默认 30 秒）一直不返回

超时时间内正常返回的登录和鉴权不受影响。FastAPI 里直接 `await` 的用法不经过 `run_sync`，也不受影响。

### 风格

`cbd43f2` 修了 CI 的 ruff：示例导入换行、`raise ... from exc`、在线推送那句日志换行。运行结果与 0.1.6 相同，随下次发版一起走。

## 明确不改

临时令牌 `consume()`：缺失、损坏、重放返回 `None`；调用方存进去的 `0`、`""`、`False` 会原样返回。`create()` 已经拒绝 `None`。调用方不要用真值判断消费结果。此项保持不改。
