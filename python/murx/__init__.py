"""MURX: an authenticated routing gateway protocol.

Reference implementation of the wire format and reference client/server
described in docs/SPEC.md.
"""

from .packets import (
    PROTOCOL_VERSION,
    AddressFamily,
    Opcode,
    ReasonCode,
    AuthConnect,
    RouteRedirect,
    AuthReject,
    NodeAnnounce,
    NodeHeartbeat,
    HeartbeatAck,
    MurxProtocolError,
)
from .errors import MurxError, AuthenticationError, NoRouteError
from .client import MurxClient, RouteInfo
from .server import (
    MurxServer,
    AuthBackend,
    Router,
    StaticAuthBackend,
    NodeRegistryRouter,
    TokenStore,
)
from .node_registry import NodeRegistry, BackendAnnouncer
from .backend import TokenGatedServer
from .discovery import resolve_murx_server, split_client_id

__all__ = [
    "PROTOCOL_VERSION",
    "AddressFamily",
    "Opcode",
    "ReasonCode",
    "AuthConnect",
    "RouteRedirect",
    "AuthReject",
    "NodeAnnounce",
    "NodeHeartbeat",
    "HeartbeatAck",
    "MurxProtocolError",
    "MurxError",
    "AuthenticationError",
    "NoRouteError",
    "MurxClient",
    "RouteInfo",
    "MurxServer",
    "AuthBackend",
    "Router",
    "StaticAuthBackend",
    "NodeRegistryRouter",
    "TokenStore",
    "NodeRegistry",
    "BackendAnnouncer",
    "TokenGatedServer",
    "resolve_murx_server",
    "split_client_id",
]
