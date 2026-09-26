"""Client-side server discovery for the ``user@domain`` convention.

See docs/SPEC.md section 9 (informative). This is ordinary DNS, not part
of the MURX wire protocol, but implemented here so sample clients don't
each reinvent it. ``dnspython`` is an optional dependency: without it,
this falls back straight to the ``murx.<domain>`` convention.
"""

from __future__ import annotations

import asyncio
from typing import Awaitable, Callable, Optional

DEFAULT_MURX_PORT = 2743

Resolver = Callable[[str], Awaitable[tuple[str, int]]]


def split_client_id(client_id: str) -> tuple[str, str]:
    """Split a ``user@domain`` Client ID into (user, domain).

    Raises ValueError if client_id doesn't have exactly one '@'.
    """
    parts = client_id.split("@")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError(f"client_id {client_id!r} is not in user@domain form")
    return parts[0], parts[1]


def _fallback_target(domain: str) -> tuple[str, int]:
    return f"murx.{domain}", DEFAULT_MURX_PORT


def _blocking_srv_lookup(domain: str) -> Optional[tuple[str, int]]:
    try:
        import dns.resolver  # type: ignore[import-not-found]
    except ImportError:
        return None
    try:
        answers = dns.resolver.resolve(f"_murx._tcp.{domain}", "SRV")
    except Exception:
        return None
    best = min(answers, key=lambda r: (r.priority, -r.weight))
    return str(best.target).rstrip("."), int(best.port)


async def resolve_murx_server(
    domain: str, resolver: Optional[Resolver] = None, try_srv: bool = True
) -> tuple[str, int]:
    """Resolve which MURX server handles ``domain``.

    The default, always-available answer is ``murx.<domain>`` on the
    registered port 2743/tcp -- no DNS lookup beyond an ordinary address
    record is required, since a fixed registered port exists precisely so
    clients don't need one.

    An SRV record ``_murx._tcp.<domain>`` is an optional, supported
    override for deployments that want a different host/port. Set
    ``try_srv=False`` to skip that probe entirely and go straight to the
    default (or pass an explicit ``resolver`` for full control, e.g. in
    tests).
    """
    if resolver is not None:
        return await resolver(domain)

    if try_srv:
        loop = asyncio.get_running_loop()
        srv_result = await loop.run_in_executor(None, _blocking_srv_lookup, domain)
        if srv_result is not None:
            return srv_result
    return _fallback_target(domain)
