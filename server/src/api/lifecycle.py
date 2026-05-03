# Copyright 2025 Alibaba Group Holding Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
API routes for OpenSandbox Lifecycle API.

This module defines FastAPI routes that map to the OpenAPI specification endpoints.
All business logic is delegated to the service layer that backs each operation.
"""

from typing import List, Optional

import httpx
from fastapi import APIRouter, Header, Query, Request, status
from fastapi.exceptions import HTTPException
from fastapi.responses import Response, StreamingResponse

from src.api.schema import (
    CreateSandboxRequest,
    CreateSandboxResponse,
    Endpoint,
    ErrorResponse,
    ListSandboxesRequest,
    ListSandboxesResponse,
    PaginationRequest,
    RenewSandboxExpirationRequest,
    RenewSandboxExpirationResponse,
    Sandbox,
    SandboxFilter,
)
from src.api.lifecycle_helpers import (
    apply_reserved_metadata_for_create,
    get_principal,
    log_mutation_audit,
    merge_list_scope_from_request,
)
from src.config import get_config
from src.middleware.authorization import LifecycleAction, authorize_action
from src.services.factory import create_sandbox_service

# RFC 2616 Section 13.5.1
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}

# Headers that shouldn't be forwarded to untrusted/internal backends
SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
}

# Initialize router
router = APIRouter(tags=["Sandboxes"])

# Initialize service based on configuration from config.toml (defaults to docker)
sandbox_service = create_sandbox_service()


# ============================================================================
# Sandbox CRUD Operations
# ============================================================================

@router.post(
    "/sandboxes",
    response_model=CreateSandboxResponse,
    response_model_exclude_none=True,
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        202: {"description": "Sandbox creation accepted for asynchronous provisioning"},
        400: {"model": ErrorResponse, "description": "The request was invalid or malformed"},
        401: {"model": ErrorResponse, "description": "Authentication credentials are missing or invalid"},
        403: {"model": ErrorResponse, "description": "The authenticated user lacks permission for this operation"},
        409: {"model": ErrorResponse, "description": "The operation conflicts with the current state"},
        500: {"model": ErrorResponse, "description": "An unexpected server error occurred"},
    },
)
async def create_sandbox(
    http_request: Request,
    body: CreateSandboxRequest,
    x_request_id: Optional[str] = Header(None, alias="X-Request-ID", description="Unique request identifier for tracing"),
) -> CreateSandboxResponse:
    """
    Create a sandbox from a container image.

    Creates a new sandbox from a container image with optional resource limits,
    environment variables, and metadata. Sandboxes are provisioned directly from
    the specified image without requiring a pre-created template.

    Args:
        body: Sandbox creation request
        x_request_id: Unique request identifier for tracing (optional; server generates if omitted).

    Returns:
        CreateSandboxResponse: Accepted sandbox creation request

    Raises:
        HTTPException: If sandbox creation scheduling fails
    """
    cfg = get_config()
    principal = get_principal(http_request)
    authorize_action(
        principal,
        LifecycleAction.CREATE,
        owner_key=cfg.authz.owner_metadata_key,
        team_key=cfg.authz.team_metadata_key,
    )
    body = apply_reserved_metadata_for_create(body, principal, cfg)
    try:
        res = sandbox_service.create_sandbox(body)
        log_mutation_audit(
            http_request, action=LifecycleAction.CREATE, sandbox_id=res.id, outcome="success"
        )
        return res
    except HTTPException as exc:
        err = exc.detail
        if isinstance(err, dict):
            code = err.get("code")
        else:
            code = None
        log_mutation_audit(
            http_request,
            action=LifecycleAction.CREATE,
            sandbox_id=None,
            outcome="error",
            error_code=code,
        )
        raise
    except Exception:
        log_mutation_audit(
            http_request,
            action=LifecycleAction.CREATE,
            sandbox_id=None,
            outcome="error",
            error_code="UNEXPECTED",
        )
        raise


# Search endpoint
@router.get(
    "/sandboxes",
    response_model=ListSandboxesResponse,
    response_model_exclude_none=True,
    responses={
        200: {"description": "Paginated collection of sandboxes"},
        400: {"model": ErrorResponse, "description": "The request was invalid or malformed"},
        401: {"model": ErrorResponse, "description": "Authentication credentials are missing or invalid"},
        500: {"model": ErrorResponse, "description": "An unexpected server error occurred"},
    },
)
async def list_sandboxes(
    http_request: Request,
    state: Optional[List[str]] = Query(None, description="Filter by lifecycle state. Pass multiple times for OR logic."),
    metadata: Optional[str] = Query(None, description="Arbitrary metadata key-value pairs for filtering (URL encoded)."),
    page: int = Query(1, ge=1, description="Page number for pagination"),
    page_size: int = Query(20, ge=1, le=200, alias="pageSize", description="Number of items per page"),
    x_request_id: Optional[str] = Header(None, alias="X-Request-ID", description="Unique request identifier for tracing"),
) -> ListSandboxesResponse:
    """
    List sandboxes with optional filtering and pagination.

    List all sandboxes with optional filtering and pagination using query parameters.
    All filter conditions use AND logic. Multiple `state` parameters use OR logic within states.

    Args:
        state: Filter by lifecycle state.
        metadata: Arbitrary metadata key-value pairs for filtering.
        page: Page number for pagination.
        page_size: Number of items per page.
        x_request_id: Unique request identifier for tracing (optional; server generates if omitted).

    Returns:
        ListSandboxesResponse: Paginated list of sandboxes
    """
    # Parse metadata query string into dictionary
    metadata_dict = {}
    if metadata:
        from urllib.parse import parse_qsl
        try:
            # Parse query string format: key=value&key2=value2
            # strict_parsing=True rejects malformed segments like "a=1&broken"
            parsed = parse_qsl(metadata, keep_blank_values=True, strict_parsing=True)
            metadata_dict = dict(parsed)
        except Exception as e:
            from fastapi import HTTPException
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"code": "INVALID_METADATA_FORMAT", "message": f"Invalid metadata format: {str(e)}"}
            )

    # Construct request object
    list_req = ListSandboxesRequest(
        filter=SandboxFilter(state=state, metadata=metadata_dict if metadata_dict else None),
        pagination=PaginationRequest(page=page, pageSize=page_size),
    )

    import logging

    logger = logging.getLogger(__name__)
    logger.info("ListSandboxes: %s", list_req.filter)

    cfg = get_config()
    principal = get_principal(http_request)
    authorize_action(
        principal,
        LifecycleAction.LIST_SANDBOXES,
        owner_key=cfg.authz.owner_metadata_key,
        team_key=cfg.authz.team_metadata_key,
    )
    list_req = merge_list_scope_from_request(http_request, list_req, cfg)

    # Delegate to the service layer for filtering and pagination
    return sandbox_service.list_sandboxes(list_req)


@router.get(
    "/sandboxes/{sandbox_id}",
    response_model=Sandbox,
    response_model_exclude_none=True,
    responses={
        200: {"description": "Sandbox current state and metadata"},
        401: {"model": ErrorResponse, "description": "Authentication credentials are missing or invalid"},
        403: {"model": ErrorResponse, "description": "The authenticated user lacks permission for this operation"},
        404: {"model": ErrorResponse, "description": "The requested resource does not exist"},
        500: {"model": ErrorResponse, "description": "An unexpected server error occurred"},
    },
)
async def get_sandbox(
    http_request: Request,
    sandbox_id: str,
    x_request_id: Optional[str] = Header(None, alias="X-Request-ID", description="Unique request identifier for tracing"),
) -> Sandbox:
    """
    Fetch a sandbox by id.

    Returns the complete sandbox information including image specification,
    status, metadata, and timestamps.

    Args:
        sandbox_id: Unique sandbox identifier
        x_request_id: Unique request identifier for tracing (optional; server generates if omitted).

    Returns:
        Sandbox: Complete sandbox information

    Raises:
        HTTPException: If sandbox not found or access denied
    """
    cfg = get_config()
    principal = get_principal(http_request)
    authorize_action(
        principal,
        LifecycleAction.GET_SANDBOX,
        owner_key=cfg.authz.owner_metadata_key,
        team_key=cfg.authz.team_metadata_key,
    )
    box = sandbox_service.get_sandbox(sandbox_id)
    authorize_action(
        principal,
        LifecycleAction.GET_SANDBOX,
        owner_key=cfg.authz.owner_metadata_key,
        team_key=cfg.authz.team_metadata_key,
        sandbox=box,
    )
    return box


@router.delete(
    "/sandboxes/{sandbox_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={
        204: {"description": "Sandbox successfully deleted"},
        401: {"model": ErrorResponse, "description": "Authentication credentials are missing or invalid"},
        403: {"model": ErrorResponse, "description": "The authenticated user lacks permission for this operation"},
        404: {"model": ErrorResponse, "description": "The requested resource does not exist"},
        409: {"model": ErrorResponse, "description": "The operation conflicts with the current state"},
        500: {"model": ErrorResponse, "description": "An unexpected server error occurred"},
    },
)
async def delete_sandbox(
    http_request: Request,
    sandbox_id: str,
    x_request_id: Optional[str] = Header(None, alias="X-Request-ID", description="Unique request identifier for tracing"),
) -> Response:
    """
    Delete a sandbox.

    Terminates sandbox execution. The sandbox will transition through Stopping state to Terminated.

    Args:
        sandbox_id: Unique sandbox identifier
        x_request_id: Unique request identifier for tracing (optional; server generates if omitted).

    Returns:
        Response: 204 No Content

    Raises:
        HTTPException: If sandbox not found or deletion fails
    """
    cfg = get_config()
    principal = get_principal(http_request)
    authorize_action(
        principal,
        LifecycleAction.DELETE,
        owner_key=cfg.authz.owner_metadata_key,
        team_key=cfg.authz.team_metadata_key,
    )
    try:
        box = sandbox_service.get_sandbox(sandbox_id)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_404_NOT_FOUND:
            log_mutation_audit(
                http_request,
                action=LifecycleAction.DELETE,
                sandbox_id=sandbox_id,
                outcome="not_found",
            )
        raise
    authorize_action(
        principal,
        LifecycleAction.DELETE,
        owner_key=cfg.authz.owner_metadata_key,
        team_key=cfg.authz.team_metadata_key,
        sandbox=box,
    )
    try:
        sandbox_service.delete_sandbox(sandbox_id)
        log_mutation_audit(
            http_request, action=LifecycleAction.DELETE, sandbox_id=sandbox_id, outcome="success"
        )
    except HTTPException as exc:
        err = exc.detail
        if isinstance(err, dict):
            code = err.get("code")
        else:
            code = None
        log_mutation_audit(
            http_request,
            action=LifecycleAction.DELETE,
            sandbox_id=sandbox_id,
            outcome="error",
            error_code=code,
        )
        raise
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ============================================================================
# Sandbox Lifecycle Operations
# ============================================================================

@router.post(
    "/sandboxes/{sandbox_id}/pause",
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        202: {"description": "Pause operation accepted"},
        401: {"model": ErrorResponse, "description": "Authentication credentials are missing or invalid"},
        403: {"model": ErrorResponse, "description": "The authenticated user lacks permission for this operation"},
        404: {"model": ErrorResponse, "description": "The requested resource does not exist"},
        409: {"model": ErrorResponse, "description": "The operation conflicts with the current state"},
        500: {"model": ErrorResponse, "description": "An unexpected server error occurred"},
    },
)
async def pause_sandbox(
    http_request: Request,
    sandbox_id: str,
    x_request_id: Optional[str] = Header(None, alias="X-Request-ID", description="Unique request identifier for tracing"),
) -> Response:
    """
    Pause execution while retaining state.

    Pauses a running sandbox while preserving its state.
    Poll GET /sandboxes/{sandboxId} to track state transition to Paused.

    Args:
        sandbox_id: Unique sandbox identifier
        x_request_id: Unique request identifier for tracing (optional; server generates if omitted).

    Returns:
        Response: 202 Accepted

    Raises:
        HTTPException: If sandbox not found or cannot be paused
    """
    cfg = get_config()
    principal = get_principal(http_request)
    authorize_action(
        principal,
        LifecycleAction.PAUSE,
        owner_key=cfg.authz.owner_metadata_key,
        team_key=cfg.authz.team_metadata_key,
    )
    box = sandbox_service.get_sandbox(sandbox_id)
    authorize_action(
        principal,
        LifecycleAction.PAUSE,
        owner_key=cfg.authz.owner_metadata_key,
        team_key=cfg.authz.team_metadata_key,
        sandbox=box,
    )
    try:
        sandbox_service.pause_sandbox(sandbox_id)
        log_mutation_audit(
            http_request, action=LifecycleAction.PAUSE, sandbox_id=sandbox_id, outcome="success"
        )
    except HTTPException as exc:
        err = exc.detail
        if isinstance(err, dict):
            code = err.get("code")
        else:
            code = None
        log_mutation_audit(
            http_request,
            action=LifecycleAction.PAUSE,
            sandbox_id=sandbox_id,
            outcome="error",
            error_code=code,
        )
        raise
    return Response(status_code=status.HTTP_202_ACCEPTED)


@router.post(
    "/sandboxes/{sandbox_id}/resume",
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        202: {"description": "Resume operation accepted"},
        401: {"model": ErrorResponse, "description": "Authentication credentials are missing or invalid"},
        403: {"model": ErrorResponse, "description": "The authenticated user lacks permission for this operation"},
        404: {"model": ErrorResponse, "description": "The requested resource does not exist"},
        409: {"model": ErrorResponse, "description": "The operation conflicts with the current state"},
        500: {"model": ErrorResponse, "description": "An unexpected server error occurred"},
    },
)
async def resume_sandbox(
    http_request: Request,
    sandbox_id: str,
    x_request_id: Optional[str] = Header(None, alias="X-Request-ID", description="Unique request identifier for tracing"),
) -> Response:
    """
    Resume a paused sandbox.

    Resumes execution of a paused sandbox.
    Poll GET /sandboxes/{sandboxId} to track state transition to Running.

    Args:
        sandbox_id: Unique sandbox identifier
        x_request_id: Unique request identifier for tracing (optional; server generates if omitted).

    Returns:
        Response: 202 Accepted

    Raises:
        HTTPException: If sandbox not found or cannot be resumed
    """
    cfg = get_config()
    principal = get_principal(http_request)
    authorize_action(
        principal,
        LifecycleAction.RESUME,
        owner_key=cfg.authz.owner_metadata_key,
        team_key=cfg.authz.team_metadata_key,
    )
    box = sandbox_service.get_sandbox(sandbox_id)
    authorize_action(
        principal,
        LifecycleAction.RESUME,
        owner_key=cfg.authz.owner_metadata_key,
        team_key=cfg.authz.team_metadata_key,
        sandbox=box,
    )
    try:
        sandbox_service.resume_sandbox(sandbox_id)
        log_mutation_audit(
            http_request, action=LifecycleAction.RESUME, sandbox_id=sandbox_id, outcome="success"
        )
    except HTTPException as exc:
        err = exc.detail
        if isinstance(err, dict):
            code = err.get("code")
        else:
            code = None
        log_mutation_audit(
            http_request,
            action=LifecycleAction.RESUME,
            sandbox_id=sandbox_id,
            outcome="error",
            error_code=code,
        )
        raise
    return Response(status_code=status.HTTP_202_ACCEPTED)


@router.post(
    "/sandboxes/{sandbox_id}/renew-expiration",
    response_model=RenewSandboxExpirationResponse,
    response_model_exclude_none=True,
    responses={
        200: {"description": "Sandbox expiration updated successfully"},
        400: {"model": ErrorResponse, "description": "The request was invalid or malformed"},
        401: {"model": ErrorResponse, "description": "Authentication credentials are missing or invalid"},
        403: {"model": ErrorResponse, "description": "The authenticated user lacks permission for this operation"},
        404: {"model": ErrorResponse, "description": "The requested resource does not exist"},
        409: {"model": ErrorResponse, "description": "The operation conflicts with the current state"},
        500: {"model": ErrorResponse, "description": "An unexpected server error occurred"},
    },
)
async def renew_sandbox_expiration(
    http_request: Request,
    sandbox_id: str,
    renew_body: RenewSandboxExpirationRequest,
    x_request_id: Optional[str] = Header(None, alias="X-Request-ID", description="Unique request identifier for tracing"),
) -> RenewSandboxExpirationResponse:
    """
    Renew sandbox expiration.

    Renews the absolute expiration time of a sandbox.
    The new expiration time must be in the future and after the current expiresAt time.

    Args:
        sandbox_id: Unique sandbox identifier
        renew_body: Renewal request with new expiration time
        x_request_id: Unique request identifier for tracing (optional; server generates if omitted).

    Returns:
        RenewSandboxExpirationResponse: Updated expiration time

    Raises:
        HTTPException: If sandbox not found or renewal fails
    """
    cfg = get_config()
    principal = get_principal(http_request)
    authorize_action(
        principal,
        LifecycleAction.RENEW,
        owner_key=cfg.authz.owner_metadata_key,
        team_key=cfg.authz.team_metadata_key,
    )
    box = sandbox_service.get_sandbox(sandbox_id)
    authorize_action(
        principal,
        LifecycleAction.RENEW,
        owner_key=cfg.authz.owner_metadata_key,
        team_key=cfg.authz.team_metadata_key,
        sandbox=box,
    )
    try:
        res = sandbox_service.renew_expiration(sandbox_id, renew_body)
        log_mutation_audit(
            http_request, action=LifecycleAction.RENEW, sandbox_id=sandbox_id, outcome="success"
        )
        return res
    except HTTPException as exc:
        err = exc.detail
        if isinstance(err, dict):
            code = err.get("code")
        else:
            code = None
        log_mutation_audit(
            http_request,
            action=LifecycleAction.RENEW,
            sandbox_id=sandbox_id,
            outcome="error",
            error_code=code,
        )
        raise


# ============================================================================
# Sandbox Endpoints
# ============================================================================

@router.get(
    "/sandboxes/{sandbox_id}/endpoints/{port}",
    response_model=Endpoint,
    response_model_exclude_none=True,
    responses={
        200: {"description": "Endpoint retrieved successfully"},
        401: {"model": ErrorResponse, "description": "Authentication credentials are missing or invalid"},
        403: {"model": ErrorResponse, "description": "The authenticated user lacks permission for this operation"},
        404: {"model": ErrorResponse, "description": "The requested resource does not exist"},
        500: {"model": ErrorResponse, "description": "An unexpected server error occurred"},
    },
)
async def get_sandbox_endpoint(
    http_request: Request,
    sandbox_id: str,
    port: int,
    use_server_proxy: bool = Query(False, description="Whether to return a server-proxied URL"),
    x_request_id: Optional[str] = Header(None, alias="X-Request-ID", description="Unique request identifier for tracing"),
) -> Endpoint:
    """
    Get sandbox access endpoint.

    Returns the public access endpoint URL for accessing a service running on a specific port
    within the sandbox. The service must be listening on the specified port inside the sandbox
    for the endpoint to be available.

    Args:
        http_request: FastAPI request object
        sandbox_id: Unique sandbox identifier
        port: Port number where the service is listening inside the sandbox (1-65535)
        use_server_proxy: Whether to return a server-proxied URL
        x_request_id: Unique request identifier for tracing (optional; server generates if omitted).

    Returns:
        Endpoint: Public endpoint URL

    Raises:
        HTTPException: If sandbox not found or endpoint not available
    """
    cfg = get_config()
    principal = get_principal(http_request)
    authorize_action(
        principal,
        LifecycleAction.GET_ENDPOINT,
        owner_key=cfg.authz.owner_metadata_key,
        team_key=cfg.authz.team_metadata_key,
    )
    box = sandbox_service.get_sandbox(sandbox_id)
    authorize_action(
        principal,
        LifecycleAction.GET_ENDPOINT,
        owner_key=cfg.authz.owner_metadata_key,
        team_key=cfg.authz.team_metadata_key,
        sandbox=box,
    )
    # Delegate to the service layer for endpoint resolution
    endpoint = sandbox_service.get_endpoint(sandbox_id, port)

    if use_server_proxy:
        # Construct proxy URL
        base_url = str(http_request.base_url).rstrip("/")
        base_url = base_url.replace("https://", "").replace("http://", "")
        endpoint.endpoint = f"{base_url}/sandboxes/{sandbox_id}/proxy/{port}"

    return endpoint


@router.api_route(
    "/sandboxes/{sandbox_id}/proxy/{port}/{full_path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
)
async def proxy_sandbox_endpoint_request(request: Request, sandbox_id: str, port: int, full_path: str):
    """
    Receives all incoming requests, determines the target sandbox from path parameter,
    and asynchronously proxies the request to it.
    """

    endpoint = sandbox_service.get_endpoint(sandbox_id, port)

    target_host = endpoint.endpoint
    query_string = request.url.query
    target_url = (
        f"http://{target_host}/{full_path}?{query_string}"
        if query_string
        else f"http://{target_host}/{full_path}"
    )

    client: httpx.AsyncClient = request.app.state.http_client

    try:
        # Filter headers
        headers = {}
        for key, value in request.headers.items():
            key_lower = key.lower()
            if (
                key_lower != "host"
                and key_lower not in HOP_BY_HOP_HEADERS
                and key_lower not in SENSITIVE_HEADERS
            ):
                headers[key] = value

        req = client.build_request(
            method=request.method,
            url=target_url,
            headers=headers,
            content=request.stream(),
        )

        # TODO: support websocket protocol?
        # since execd component does not have websocket handler currently, we just raise an error here
        if request.method == "GET" and request.headers.get("Upgrade") == "websocket":
            raise HTTPException(
                status_code=400, detail="Websocket upgrade is not supported yet"
            )

        resp = await client.send(req, stream=True)

        return StreamingResponse(
            content=resp.aiter_bytes(),
            status_code=resp.status_code,
            headers=resp.headers,
        )
    except httpx.ConnectError as e:
        raise HTTPException(
            status_code=502,
            detail=f"Could not connect to the backend sandbox {endpoint}: {e}",
        )
    except HTTPException:
        # Preserve explicit HTTP exceptions raised above (e.g. websocket upgrade not supported).
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"An internal error occurred in the proxy: {e}"
        )
