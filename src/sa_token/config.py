"""sa-token 配置。

配置对象是纯数据，不含任何行为，方便从 YAML / 环境变量 / 配置中心加载后直接构造。
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from typing import Any, Literal

__all__ = [
    "NEVER_EXPIRE",
    "OverflowLogoutMode",
    "ReplacedRange",
    "SaTokenConfig",
]

#: timeout 取该值时表示永不过期。
NEVER_EXPIRE = -1

OverflowLogoutMode = Literal["logout", "kickout", "replaced"]
ReplacedRange = Literal["curr_device", "all_device"]


@dataclass
class SaTokenConfig:
    """全局配置项，字段命名与 Java / Go / Rust 版保持一致。"""

    token_name: str = "Authorization"
    """从 Header / Cookie / Query 中读取 token 时使用的键名。"""

    timeout: int = 2592000
    """token 绝对有效期（秒），-1 表示永不过期。"""

    active_timeout: int = NEVER_EXPIRE
    """活跃超时（秒）：超过该时长未访问则冻结，-1 表示不启用。"""

    dynamic_active_timeout: bool = False
    """是否允许单个 token 覆盖全局 active_timeout。"""

    auto_renew: bool = True
    """校验通过后是否自动续期。"""

    token_style: str = "uuid"
    """token 生成风格，见 sa_token.strategy。"""

    token_prefix: str = "Bearer "
    """读取 Header 时需要剥离的前缀，空字符串表示不剥离。"""

    is_read_header: bool = True
    is_read_cookie: bool = True
    is_read_query: bool = True
    is_write_cookie: bool = False
    """登录成功后是否把 token 写进 Cookie（需要框架适配层支持）。"""

    cookie_path: str = "/"
    cookie_domain: str | None = None
    cookie_secure: bool = False
    cookie_http_only: bool = True
    cookie_same_site: str | None = "Lax"

    is_concurrent: bool = True
    """是否允许同一账号多端同时在线。False 表示新登录顶掉旧登录。"""

    is_share: bool = True
    """多端在线时是否共享同一个 token。仅在 is_concurrent=True 时生效。"""

    max_login_count: int = 12
    """同一账号最大同时在线数，-1 表示不限制。"""

    overflow_logout_mode: OverflowLogoutMode = "logout"
    """超出 max_login_count 时，对最旧登录采取的处理方式。"""

    replaced_range: ReplacedRange = "curr_device"
    """顶号影响范围：仅同设备类型，还是全部设备。"""

    storage_key_prefix: str = "satoken:"
    """所有存储键的统一前缀，便于多租户或共享 Redis。"""

    is_logout_keep_session: bool = False
    """登出后是否保留 Account-Session 数据。"""

    offline_record_enabled: bool = True
    """是否记录被踢 / 被顶的下线原因，便于前端提示。"""

    offline_record_timeout: int = 3600
    """下线记录保留秒数。"""

    perm_cache_timeout: int = 0
    """StpInterface 查询结果的缓存秒数，0 表示不缓存。"""

    refresh_token_timeout: int = 2592000
    """登录态 Refresh Token 有效期（秒），与 OAuth2 Refresh Token 相互独立。"""

    refresh_token_rotate: bool = True
    """刷新 access token 时是否同时轮转 refresh token。"""

    refresh_token_reuse_detection: bool = True
    """检测旧 refresh token 重放并吊销整个 token family。"""

    nonce_timeout: int = 60
    """服务端签发 Nonce 的默认有效期（秒）。"""

    jwt_secret_key: str | None = None
    jwt_algorithm: str = "HS256"

    is_print_banner: bool = True
    """初始化时是否打印启动横幅。"""

    extra: dict[str, Any] = field(default_factory=dict)
    """给扩展模块（OAuth2 / SSO / 在线用户）放自定义配置。"""

    def __post_init__(self) -> None:
        if not self.token_name:
            raise ValueError("token_name 不能为空")
        if self.storage_key_prefix and not self.storage_key_prefix.endswith(":"):
            self.storage_key_prefix += ":"

    @classmethod
    def from_dict(cls, values: dict[str, Any]) -> SaTokenConfig:
        """从字典构造配置，忽略未知字段，便于对接外部配置中心。"""
        known = {f.name for f in fields(cls)}
        return cls(**{key: value for key, value in values.items() if key in known})

    def key_prefix(self, login_type: str) -> str:
        return f"{self.storage_key_prefix}{login_type}:"

    def make_key(self, login_type: str, suffix: str, identifier: str) -> str:
        """拼接存储键：``satoken:login:token:abc``。"""
        return f"{self.key_prefix(login_type)}{suffix}:{identifier}"
