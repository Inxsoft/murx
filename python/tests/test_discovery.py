import pytest

from murx.discovery import resolve_murx_server, split_client_id


def test_split_client_id():
    assert split_client_id("alice@example.com") == ("alice", "example.com")


@pytest.mark.parametrize("bad", ["alice", "alice@", "@example.com", "alice@a@b"])
def test_split_client_id_rejects_malformed(bad):
    with pytest.raises(ValueError):
        split_client_id(bad)


@pytest.mark.asyncio
async def test_resolve_murx_server_default_convention_skips_srv():
    host, port = await resolve_murx_server("example.com", try_srv=False)
    assert host == "murx.example.com"
    assert port == 2743


@pytest.mark.asyncio
async def test_resolve_murx_server_with_explicit_resolver_override():
    async def fake_resolver(domain):
        assert domain == "example.com"
        return "murx-east.example.com", 27430

    host, port = await resolve_murx_server("example.com", resolver=fake_resolver)
    assert (host, port) == ("murx-east.example.com", 27430)
