from __future__ import annotations

import pytest

from sa_token import SaToken, SaTokenManager
from sa_token.storage import MemoryStorage
from sa_token.stp_util import clear_manager


@pytest.fixture
def build_manager():
    """返回一个构建 Manager 的工厂，测试之间互不干扰。"""
    created: list[SaTokenManager] = []

    def _build(**options) -> SaTokenManager:
        builder = SaToken.builder().storage(MemoryStorage()).print_banner(False)
        if options:
            builder = builder.set_option(**options)
        manager = builder.build()
        created.append(manager)
        return manager

    yield _build
    clear_manager()


@pytest.fixture
def manager(build_manager) -> SaTokenManager:
    return build_manager()


@pytest.fixture
def stp(manager: SaTokenManager):
    return manager.stp()
