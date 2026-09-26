"""MURX: Multi-User Resource eXchange, an authenticated routing gateway protocol.

Reference implementation of the wire format and reference client/server
described in spec/SPEC.md.
"""

from .packets import (
    PROTOCOL_VERSION,
    SUPPORTED_VERSIONS,
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
    RouteTarget,
    StaticAuthBackend,
    NodeRegistryRouter,
    TokenStore,
)
from .tokens import SignedTokenIssuer, SignedTokenVerifier
from .node_registry import NodeRegistry, BackendAnnouncer
from .backend import TokenGatedServer
from .discovery import resolve_murx_server, split_client_id

__version__ = "0.2.0"

__all__ = [
    "PROTOCOL_VERSION",
    "SUPPORTED_VERSIONS",
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
    "RouteTarget",
    "StaticAuthBackend",
    "NodeRegistryRouter",
    "TokenStore",
    "SignedTokenIssuer",
    "SignedTokenVerifier",
    "NodeRegistry",
    "BackendAnnouncer",
    "TokenGatedServer",
    "resolve_murx_server",
    "split_client_id",
]
