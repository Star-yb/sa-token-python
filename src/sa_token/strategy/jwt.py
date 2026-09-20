"""有状态 JWT 策略。

token 自带 claims，但校验时**仍然查存储**，因此踢人、顶号、封禁全部继续有效。
这是刻意的取舍：纯无状态 JWT 无法在服务端即时作废，与本项目的核心语义冲突。

需要额外安装：``pip install "sa-token-python-core[jwt]"``。
"""

from __future__ import annotations

import secrets
from typing import Any

from ..model import now_ms

__all__ = ["JwtStrategy"]


class JwtStrategy:
    name = "jwt"

    def __init__(
        self,
        secret_key: str,
        *,
        algorithm: str = "HS256",
        issuer: str | None = None,
        audience: str | None = None,
    ) -> None:
        if not secret_key:
            raise ValueError("使用 JWT 风格时必须配置 jwt_secret_key")
        try:
            import jwt as pyjwt
        except ImportError as exc:  # pragma: no cover - 依赖缺失路径
            raise ImportError(
                'JwtStrategy 需要 PyJWT 依赖，请执行：pip install "sa-token-python-core[jwt]"'
            ) from exc
        self._jwt = pyjwt
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.issuer = issuer
        self.audience = audience

    def generate(self, login_id: str, extra: dict[str, Any] | None = None) -> str:
        issued_at = now_ms() // 1000
        payload: dict[str, Any] = {
            "loginId": login_id,
            "iat": issued_at,
            # jti 让相同 login_id 的多次登录得到不同 token，多端语义才成立。
            "jti": secrets.token_hex(12),
        }
        if self.issuer:
            payload["iss"] = self.issuer
        if self.audience:
            payload["aud"] = self.audience
        if extra:
            payload.update(extra)
        return self._jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def parse(self, token: str) -> dict[str, Any] | None:
        try:
            return self._jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                audience=self.audience,
                issuer=self.issuer,
                # 过期与否由存储层的 TTL 决定，避免两套过期时间互相打架。
                options={"verify_exp": False},
            )
        except Exception:
            return None
