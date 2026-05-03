# Copyright 2025 Alibaba Group Holding Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

from types import SimpleNamespace
from unittest.mock import MagicMock

from src.api.lifecycle_helpers import merge_list_scope_from_request
from src.api.schema import ListSandboxesRequest, PaginationRequest, SandboxFilter
from src.config import AppConfig, AuthzConfig, IngressConfig, RuntimeConfig, ServerConfig
from src.middleware.principal import build_user_principal


def _min_config() -> AppConfig:
    return AppConfig(
        server=ServerConfig(),
        authz=AuthzConfig(
            owner_metadata_key="access.owner",
            team_metadata_key="access.team",
        ),
        runtime=RuntimeConfig(type="docker", execd_image="x"),
        ingress=IngressConfig(mode="direct"),
    )


def test_merge_list_scope_injects_owner_for_user():
    z = _min_config()
    p = build_user_principal("alice", "t1", "read_only", z.authz)
    list_req = ListSandboxesRequest(
        filter=SandboxFilter(state=None, metadata={"k": "v"}),
        pagination=PaginationRequest(page=1, pageSize=20),
    )
    http_request = MagicMock()
    http_request.state = SimpleNamespace(principal=p)
    out = merge_list_scope_from_request(http_request, list_req, z)
    assert out.filter.metadata
    assert out.filter.metadata.get("k") == "v"
    assert out.filter.metadata.get("access.owner") == p.canonical_owner
    assert out.filter.metadata.get("access.team") == p.canonical_team
