"""Server-side authority for OpenAI-compatible AI provider records.

The module owns three boundaries that must never be reimplemented elsewhere:

* endpoint validation, where personal records are public HTTPS only while
  operator-managed global records may use a private HTTP engine;
* credential sealing with the externally supplied Fernet key ring
  (``ITSM_AI_CREDENTIAL_KEYS``, legacy ``ITSM_AI_CREDENTIAL_KEY``), never generated
  or stored in the database;
* the HTTP stack used to execute a personal provider, which resolves and
  filters the destination again for every connection it opens.

The connection-time filter lives in an ``httpcore`` network backend, so the
socket is only opened to an address this process resolved and approved. TLS
still uses the record hostname as SNI because httpcore performs the TLS
handshake with the origin host, not with the approved address. Redirects and
environment proxies are disabled, so an approved connection cannot be
forwarded elsewhere.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import httpcore
import httpx
from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from itsm.config import Settings

_MAX_ENDPOINT = 500
_LOCAL_HOSTNAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost"})

KEY_STATE_PRIMARY = "primary"
KEY_STATE_OLDER = "older"
KEY_STATE_UNREADABLE = "unreadable"
KEY_STATE_UNAVAILABLE = "unavailable"

# Fingerprints are a domain-separated digest prefix, never a key fragment.
_FINGERPRINT_DOMAIN = b"itsm.ai-credential-key.v1\x00"
_FINGERPRINT_HEX = 12


class ProviderEndpointError(ValueError):
    """The endpoint is outside the allowed shape or destination."""


class CredentialUnavailable(Exception):
    """Credential storage is not configured in this process."""


class CredentialInvalid(Exception):
    """A sealed credential cannot be read with the configured key."""


@dataclass(frozen=True)
class ProviderModelSelection:
    """Server-resolved selection passed to the Pydantic AI runtime.

    ``api_key`` is the decrypted record credential. It is never returned by an
    API, logged or persisted outside the provider row ciphertext.
    """

    base_url: str
    model: str
    api_key: str
    allow_private: bool = False


def _hostname(value: str) -> str:
    return value.rstrip(".").lower()


def is_public_address(value: str) -> bool:
    """True only for an address that can be a public internet destination."""
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address):
        mapped = address.ipv4_mapped
        if mapped is not None:
            address = mapped
    return address.is_global and not address.is_multicast


def _literal_address(host: str) -> str | None:
    candidate = host.split("%", 1)[0]
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return None
    return host


def validate_provider_endpoint(value: object, *, scope: str) -> str:
    """Validate and normalize a provider base URL for its authority scope."""
    if not isinstance(value, str):
        raise ProviderEndpointError("baseUrl must be a string")
    text = value.strip()
    if not text or len(text) > _MAX_ENDPOINT:
        raise ProviderEndpointError("baseUrl must be a bounded absolute URL")
    if any(character.isspace() or ord(character) < 32 for character in text):
        raise ProviderEndpointError("baseUrl must not contain whitespace or control characters")
    parts = urlsplit(text)
    if parts.scheme not in {"http", "https"}:
        raise ProviderEndpointError("baseUrl must use http or https")
    if parts.username is not None or parts.password is not None:
        raise ProviderEndpointError("baseUrl must not contain credentials")
    if parts.query or parts.fragment:
        raise ProviderEndpointError("baseUrl must not contain a query or fragment")
    if not parts.hostname:
        raise ProviderEndpointError("baseUrl must include a host")
    try:
        _ = parts.port
    except ValueError as exc:
        raise ProviderEndpointError("baseUrl has an invalid port") from exc
    host = _hostname(parts.hostname)
    if scope == "personal":
        if parts.scheme != "https":
            raise ProviderEndpointError("personal provider endpoints require HTTPS")
        if host in _LOCAL_HOSTNAMES or host.endswith(".localhost"):
            raise ProviderEndpointError("personal provider endpoints must be publicly reachable")
        literal = _literal_address(host)
        if literal is not None and not is_public_address(literal):
            raise ProviderEndpointError("personal provider endpoints must be publicly routable")
    path = parts.path.rstrip("/")
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def resolve_addresses(host: str, port: int | None) -> tuple[str, ...]:
    """Resolve one host to unique address strings; literals resolve to themselves."""
    literal = _literal_address(host)
    if literal is not None:
        return (literal,)
    results = socket.getaddrinfo(host, port or 443, type=socket.SOCK_STREAM)
    addresses: list[str] = []
    for entry in results:
        address = str(entry[4][0])
        if address not in addresses:
            addresses.append(address)
    return tuple(addresses)


def ensure_public_endpoint(url: str) -> None:
    """Pre-flight the destination of a personal endpoint; fail closed.

    This check improves the error message before a request is attempted. The
    authoritative boundary is :class:`_PublicOnlyNetworkBackend`, which repeats
    resolution and filtering for the actual connection, so a DNS answer that
    changes between the two calls cannot reach a private address.
    """
    parts = urlsplit(url)
    host = parts.hostname
    if host is None:
        raise ProviderEndpointError("provider endpoint must include a host")
    try:
        addresses = resolve_addresses(host, parts.port or 443)
    except OSError as exc:
        raise ProviderEndpointError("provider endpoint could not be resolved") from exc
    if not addresses:
        raise ProviderEndpointError("provider endpoint did not resolve to an address")
    if any(not is_public_address(address) for address in addresses):
        raise ProviderEndpointError("provider endpoint resolves to a non-public address")


def credential_key_values(settings: Settings) -> list[str]:
    """Ordered key ring: configured keys first, then the legacy decrypt key.

    The first value encrypts; every later value only decrypts. The legacy
    ``ITSM_AI_CREDENTIAL_KEY`` is appended when it is not already in the ring so
    an installation can migrate to the ring without losing old ciphertext.
    """
    values: list[str] = []
    ring = settings.ai_credential_keys
    if ring is not None:
        for entry in ring.get_secret_value().split(","):
            value = entry.strip()
            if value and value not in values:
                values.append(value)
    legacy = settings.ai_credential_key
    if legacy is not None:
        value = legacy.get_secret_value().strip()
        if value and value not in values:
            values.append(value)
    return values


def credential_fingerprint(value: str) -> str:
    """Short, non-reversible identifier for one key; never the key itself."""
    digest = hashlib.sha256(_FINGERPRINT_DOMAIN + value.encode("utf-8")).hexdigest()
    return digest[:_FINGERPRINT_HEX]


def credential_key_fingerprints(settings: Settings) -> list[str]:
    """Ring fingerprints in encrypting order; the first is the active key."""
    return [credential_fingerprint(value) for value in credential_key_values(settings)]


def primary_fingerprint(settings: Settings) -> str | None:
    fingerprints = credential_key_fingerprints(settings)
    return fingerprints[0] if fingerprints else None


def _fernets(settings: Settings) -> list[Fernet]:
    values = credential_key_values(settings)
    if not values:
        raise CredentialUnavailable("credential storage is not configured")
    try:
        return [Fernet(value.encode("ascii")) for value in values]
    except (ValueError, TypeError, UnicodeEncodeError) as exc:
        raise CredentialUnavailable("credential storage is not configured") from exc


def _cipher(settings: Settings) -> MultiFernet:
    return MultiFernet(_fernets(settings))


def primary_cipher(settings: Settings) -> Fernet:
    """The encrypting key; older ring entries decrypt but never encrypt."""
    return _fernets(settings)[0]


def credential_storage_available(settings: Settings) -> bool:
    try:
        _fernets(settings)
    except CredentialUnavailable:
        return False
    return True


def credential_key_state(settings: Settings, token: str) -> str:
    """Classify one stored ciphertext against the current ring.

    ``primary`` means the encrypting key reads it, ``older`` means only a
    decryption-only ring entry does, ``unreadable`` means no configured key
    does and ``unavailable`` means the process has no ring at all.
    """
    try:
        primary = primary_cipher(settings)
    except CredentialUnavailable:
        return KEY_STATE_UNAVAILABLE
    try:
        encoded = token.encode("ascii")
    except AttributeError, UnicodeEncodeError:
        return KEY_STATE_UNREADABLE
    try:
        primary.decrypt(encoded)
        return KEY_STATE_PRIMARY
    except InvalidToken:
        pass
    try:
        _cipher(settings).decrypt(encoded)
    except InvalidToken:
        return KEY_STATE_UNREADABLE
    return KEY_STATE_OLDER


def seal_credential(settings: Settings, value: str) -> str:
    """Encrypt one provider credential for storage; keys never leave process env."""
    try:
        return _cipher(settings).encrypt(value.encode("utf-8")).decode("ascii")
    except CredentialUnavailable, UnicodeEncodeError:
        raise CredentialUnavailable("credential storage is not configured") from None


def unseal_credential(settings: Settings, token: str) -> str:
    try:
        return _cipher(settings).decrypt(token.encode("ascii")).decode("utf-8")
    except CredentialUnavailable, UnicodeEncodeError:
        raise CredentialUnavailable("credential storage is not configured") from None
    except InvalidToken as exc:
        raise CredentialInvalid("the stored provider credential cannot be read") from exc


def rotate_credential(settings: Settings, token: str) -> str:
    """Re-encrypt one ciphertext under the primary key, keeping its timestamp."""
    try:
        return _cipher(settings).rotate(token.encode("ascii")).decode("ascii")
    except CredentialUnavailable, UnicodeEncodeError:
        raise CredentialUnavailable("credential storage is not configured") from None
    except (InvalidToken, AttributeError, TypeError) as exc:
        raise CredentialInvalid("the stored provider credential cannot be read") from exc


class _PublicOnlyNetworkBackend(httpcore.AsyncNetworkBackend):
    """Connect only to public addresses resolved for this exact connection."""

    def __init__(self) -> None:
        self._delegate = httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: object = None,
    ) -> httpcore.AsyncNetworkStream:
        try:
            addresses = await asyncio.to_thread(resolve_addresses, host, port)
        except OSError as exc:
            raise httpcore.ConnectError(
                f"refusing provider endpoint {host}: it did not resolve"
            ) from exc
        if not addresses or any(not is_public_address(address) for address in addresses):
            raise httpcore.ConnectError(
                f"refusing provider endpoint {host}: it resolves outside the public internet"
            )
        last: Exception | None = None
        for address in addresses:
            try:
                return await self._delegate.connect_tcp(
                    address,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,  # type: ignore[arg-type]
                )
            except (OSError, httpcore.ConnectError) as exc:
                last = exc
        raise httpcore.ConnectError(
            f"refusing provider endpoint {host}: no public address accepted the connection"
        ) from last

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: object = None,
    ) -> httpcore.AsyncNetworkStream:
        raise httpcore.ConnectError("unix sockets are not allowed for provider endpoints")

    async def sleep(self, seconds: float) -> None:
        await self._delegate.sleep(seconds)


def provider_http_client(*, allow_private: bool, timeout: float = 30.0) -> httpx.AsyncClient:
    """Build the client used for one execution boundary.

    Personal providers get the public-only backend. Global operator providers
    may target a private LAN engine, matching the installation's existing
    server-configured endpoint allowance. Both disable redirects and ignore
    proxy environment variables, so an approved destination is not forwarded.
    """
    transport = httpx.AsyncHTTPTransport(
        verify=True,
        trust_env=False,
        retries=0,
        http2=False,
    )
    if not allow_private:
        # httpx 0.28 does not expose the httpcore network backend, so replace
        # the freshly built pool (which has no connections) with the guarded one.
        transport._pool = httpcore.AsyncConnectionPool(
            ssl_context=httpx.create_ssl_context(),
            max_connections=10,
            max_keepalive_connections=5,
            keepalive_expiry=5.0,
            http1=True,
            http2=False,
            retries=0,
            network_backend=_PublicOnlyNetworkBackend(),
        )
    return httpx.AsyncClient(
        transport=transport,
        follow_redirects=False,
        trust_env=False,
        timeout=timeout,
    )


def build_provider_model(
    selection: ProviderModelSelection, *, http_client: httpx.AsyncClient
) -> object:
    """Build the Pydantic AI model for a server-resolved provider record.

    The caller owns ``http_client`` and must close it when the turn ends; the
    runtime creates one guarded client per execution boundary.
    """
    from pydantic_ai.models.openai import OpenAIChatModel
    from pydantic_ai.providers.openai import OpenAIProvider

    provider = OpenAIProvider(
        base_url=selection.base_url,
        api_key=selection.api_key,
        http_client=http_client,
    )
    return OpenAIChatModel(selection.model, provider=provider)


__all__ = [
    "KEY_STATE_OLDER",
    "KEY_STATE_PRIMARY",
    "KEY_STATE_UNAVAILABLE",
    "KEY_STATE_UNREADABLE",
    "CredentialInvalid",
    "CredentialUnavailable",
    "ProviderEndpointError",
    "ProviderModelSelection",
    "build_provider_model",
    "credential_fingerprint",
    "credential_key_fingerprints",
    "credential_key_state",
    "credential_key_values",
    "credential_storage_available",
    "ensure_public_endpoint",
    "is_public_address",
    "primary_cipher",
    "primary_fingerprint",
    "provider_http_client",
    "resolve_addresses",
    "rotate_credential",
    "seal_credential",
    "unseal_credential",
    "validate_provider_endpoint",
]
