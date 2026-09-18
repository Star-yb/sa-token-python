"""SaTokenManager 与 Builder。

Manager 负责组装：配置 + 存储 + Token 策略 + 事件总线 + 权限数据源，
并按 ``login_type`` 缓存 :class:`StpLogic` 实例。
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Any

from .config import SaTokenConfig
from .listener import Event, EventBus, Listener
from .model import DEFAULT_LOGIN_TYPE
from .stp_logic import StpLogic
from .strategy import TokenStrategy, create_strategy

if TYPE_CHECKING:  # pragma: no cover - 仅供类型检查
    from .security import NonceManager, RefreshTokenManager, TempTokenManager
    from .storage.base import SaStorage
    from .stp_interface import StpInterface

__all__ = ["SaTokenManager", "SaTokenBuilder", "SaToken", "__version__"]

__version__ = "0.1.2"

_BANNER = r"""
   _____         ______      __
  / ___/____ _  /_  __/___  / /_____  ____
  \__ \/ __ `/   / / / __ \/ //_/ _ \/ __ \
 ___/ / /_/ /   / / / /_/ / ,< /  __/ / / /
/____/\__,_/   /_/  \____/_/|_|\___/_/ /_/
"""


class SaTokenManager:
    """框架无关的运行时核心。"""

    def __init__(
        self,
        config: SaTokenConfig,
        storage: SaStorage,
        *,
        strategy: TokenStrategy | None = None,
        stp_interface: StpInterface | None = None,
        events: EventBus | None = None,
    ) -> None:
        self.config = config
        self.storage = storage
        self.strategy = strategy or create_strategy(config)
        self.stp_interface = stp_interface
        self.events = events or EventBus()
        self._logics: dict[str, StpLogic] = {}
        self._nonce_manager: NonceManager | None = None
        self._refresh_token_manager: RefreshTokenManager | None = None
        self._temp_token_manager: TempTokenManager | None = None

    def stp(self, login_type: str = DEFAULT_LOGIN_TYPE) -> StpLogic:
        """取得指定账号体系的逻辑实例，不同 ``login_type`` 之间存储完全隔离。"""
        logic = self._logics.get(login_type)
        if logic is None:
            logic = StpLogic(self, login_type)
            self._logics[login_type] = logic
        return logic

    def on(self, event: Event, listener: Listener, *, priority: int = 0) -> None:
        self.events.on(event, listener, priority=priority)

    @property
    def nonces(self) -> NonceManager:
        """服务端 Nonce 管理器，按需创建且复用当前 Storage。"""
        if self._nonce_manager is None:
            from .security import NonceManager

            self._nonce_manager = NonceManager(
                self.storage,
                key_prefix=self.config.storage_key_prefix,
                timeout=self.config.nonce_timeout,
            )
        return self._nonce_manager

    @property
    def refresh_tokens(self) -> RefreshTokenManager:
        """登录态 Refresh Token 管理器（不是 OAuth2 Refresh Token）。"""
        if self._refresh_token_manager is None:
            from .security import RefreshTokenManager

            self._refresh_token_manager = RefreshTokenManager(self)
        return self._refresh_token_manager

    @property
    def temp_tokens(self) -> TempTokenManager:
        """邀请、重置密码等短时业务 Token 管理器。"""
        if self._temp_token_manager is None:
            from .security import TempTokenManager

            self._temp_token_manager = TempTokenManager(
                self.storage, key_prefix=self.config.storage_key_prefix
            )
        return self._temp_token_manager

    def print_banner(self) -> None:
        lines = [
            _BANNER,
            f":: sa-token-python ::   (v{__version__})",
            f":: Python ::            {sys.version.split()[0]}",
            f":: Token Style ::       {self.config.token_style}",
            f":: Token Timeout ::     {self.config.timeout} 秒",
            f":: Storage ::           {type(self.storage).__name__}",
            "",
        ]
        print("\n".join(lines))


class SaTokenBuilder:
    """链式配置构建器。

    每个方法只改配置，``build()` 之前不会产生任何副作用，便于测试。
    """

    def __init__(self) -> None:
        self._config = SaTokenConfig()
        self._storage: SaStorage | None = None
        self._strategy: TokenStrategy | None = None
        self._stp_interface: StpInterface | None = None
        self._events = EventBus()
        self._set_global = True

    # 配置项 ---------------------------------------------------------------

    def config(self, config: SaTokenConfig) -> SaTokenBuilder:
        """整体替换配置，之后仍可用其它方法微调。"""
        self._config = config
        return self

    def storage(self, storage: SaStorage) -> SaTokenBuilder:
        self._storage = storage
        return self

    def strategy(self, strategy: TokenStrategy) -> SaTokenBuilder:
        self._strategy = strategy
        return self

    def stp_interface(self, stp_interface: StpInterface) -> SaTokenBuilder:
        self._stp_interface = stp_interface
        return self

    def token_name(self, name: str) -> SaTokenBuilder:
        self._config.token_name = name
        return self

    def timeout(self, seconds: int) -> SaTokenBuilder:
        self._config.timeout = seconds
        return self

    def active_timeout(self, seconds: int) -> SaTokenBuilder:
        self._config.active_timeout = seconds
        return self

    def token_style(self, style: str) -> SaTokenBuilder:
        self._config.token_style = style
        return self

    def token_prefix(self, prefix: str) -> SaTokenBuilder:
        self._config.token_prefix = prefix
        return self

    def is_concurrent(self, value: bool) -> SaTokenBuilder:
        self._config.is_concurrent = value
        return self

    def is_share(self, value: bool) -> SaTokenBuilder:
        self._config.is_share = value
        return self

    def max_login_count(self, count: int) -> SaTokenBuilder:
        self._config.max_login_count = count
        return self

    def auto_renew(self, value: bool) -> SaTokenBuilder:
        self._config.auto_renew = value
        return self

    def storage_key_prefix(self, prefix: str) -> SaTokenBuilder:
        self._config.storage_key_prefix = prefix
        return self

    def jwt_secret_key(self, secret: str) -> SaTokenBuilder:
        self._config.jwt_secret_key = secret
        return self

    def print_banner(self, value: bool) -> SaTokenBuilder:
        self._config.is_print_banner = value
        return self

    def set_option(self, **options: Any) -> SaTokenBuilder:
        """批量设置任意配置项，便于从配置文件加载。"""
        for key, value in options.items():
            if not hasattr(self._config, key):
                raise ValueError(f"未知配置项：{key}")
            setattr(self._config, key, value)
        return self

    def on(self, event: Event, listener: Listener, *, priority: int = 0) -> SaTokenBuilder:
        self._events.on(event, listener, priority=priority)
        return self

    def as_global(self, value: bool) -> SaTokenBuilder:
        """是否把构建结果设为 ``StpUtil`` 使用的全局实例，默认是。"""
        self._set_global = value
        return self

    # 构建 -----------------------------------------------------------------

    def build(self) -> SaTokenManager:
        storage = self._storage
        if storage is None:
            # 不静默降级到内存：多进程部署下会出现「登录了但下个请求说没登录」。
            from .storage.memory import MemoryStorage

            storage = MemoryStorage()
        self._config.__post_init__()
        manager = SaTokenManager(
            self._config,
            storage,
            strategy=self._strategy,
            stp_interface=self._stp_interface,
            events=self._events,
        )
        if self._config.is_print_banner:
            manager.print_banner()
        if self._set_global:
            from .stp_util import set_manager

            set_manager(manager)
        return manager


class SaToken:
    """入口门面：``SaToken.builder()...build()``。"""

    @staticmethod
    def builder() -> SaTokenBuilder:
        return SaTokenBuilder()
