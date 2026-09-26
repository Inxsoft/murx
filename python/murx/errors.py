class MurxError(Exception):
    """Base class for all murx library errors."""


class AuthenticationError(MurxError):
    """Raised by a client when the server sends AUTH_REJECT."""

    def __init__(self, reason_code, reason_text=""):
        self.reason_code = reason_code
        self.reason_text = reason_text
        super().__init__(f"MURX auth rejected ({reason_code!r}): {reason_text}")


class NoRouteError(MurxError):
    """Raised server-side when no backend node is available for a client."""
