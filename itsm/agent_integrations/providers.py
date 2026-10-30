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
import json
import socket
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import httpcore
import httpx
from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from itsm.config import PersonalPrivateEndpoint, Settings, parse_personal_private_endpoints

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


class ProviderAddressBlocked(httpcore.ConnectError):
    """The resolved destination is outside this deployment's policy."""


# Cloud metadata services are never reachable through a hostname allowlist;
# only an explicit CIDR entry (for example ``169.254.169.254/32``) can include
# them, and doing so is a deliberate, documented deployment decision.
_METADATA_ADDRESSES = frozenset({"169.254.169.254", "fd00:ec2::254", "100.100.100.200"})

_CHECK_TIMEOUT = 10.0
_CHECK_MAX_BYTES = 64 * 1024

# Discovery keeps every id a provider reports, up to this documented bound, so an
# automatic listing stays bounded even for a very large catalogue. The record's
# offered ``models`` list is capped separately by the service.
_MAX_DISCOVERED_MODELS = 500
_MAX_MODEL_LABEL = 200
_MODALITY_KEYS = ("input_modalities", "modalities")


def _address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return None


def _address_class(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Classify a resolved address: public, private or never-allowed.

    Loopback, link-local and metadata addresses are only reachable through an
    explicit CIDR, even when the hostname itself is allowlisted. Multicast,
    unspecified and reserved addresses are treated the same way.
    """

    if isinstance(address, ipaddress.IPv6Address):
        mapped = address.ipv4_mapped
        if mapped is not None:
            address = mapped
    if str(address) in _METADATA_ADDRESSES:
        return "blocked"
    if address.is_global and not address.is_multicast:
        return "public"
    if address.is_loopback or address.is_link_local:
        return "blocked"
    if address.is_multicast or address.is_unspecified or address.is_reserved:
        return "blocked"
    return "private"


@dataclass(frozen=True)
class ProviderNetworkPolicy:
    """Deployment-authorized destinations for one provider boundary.

    The empty policy keeps the historical personal behavior: every resolved
    address must be public. An allowlist may add CIDRs, single addresses and
    exact ``hostname[:port]`` values. The decision is always taken against the
    address resolved at connection time, so a name that later points somewhere
    else is refused instead of being trusted for having been approved once.
    """

    allowlist: tuple[PersonalPrivateEndpoint, ...] = ()

    def host_allowed(self, host: str, port: int | None) -> bool:
        name = host.rstrip(".").lower()
        return any(entry.matches_host(name, port) for entry in self.allowlist)

    def contains(self, address: str) -> bool:
        return any(entry.contains(address) for entry in self.allowlist)

    def permits(self, host: str, addresses: Iterable[str], *, port: int | None) -> bool:
        """True only when every resolved address is allowed for this host."""
        checked = list(addresses)
        if not checked:
            return False
        host_allowed = self.host_allowed(host, port)
        for value in checked:
            address = _address(value)
            if address is None:
                return False
            kind = _address_class(address)
            if kind == "public":
                continue
            if self.contains(value):
                continue
            if kind == "private" and host_allowed:
                continue
            return False
        return True


def personal_endpoint_policy(settings: Settings) -> ProviderNetworkPolicy:
    """Policy for personal providers, resolved from deployment configuration."""
    return ProviderNetworkPolicy(
        allowlist=parse_personal_private_endpoints(settings.ai_personal_private_endpoints)
    )


def personal_endpoint_policy_from_entries(
    entries: Iterable[str],
) -> ProviderNetworkPolicy:
    """Policy rebuilt from allowlist entries relayed inside a worker request.

    The entries are validated with the same parser as the deployment setting, so
    a broker or caller cannot smuggle a rule the configuration could not express.
    """
    return ProviderNetworkPolicy(
        allowlist=parse_personal_private_endpoints(",".join(str(entry) for entry in entries))
    )


@dataclass(frozen=True)
class ProviderModelSelection:
    """Server-resolved selection passed to the Pydantic AI runtime.

    ``api_key`` is the decrypted record credential. It is never returned by an
    API, logged or persisted outside the provider row ciphertext.

    ``allow_private`` is ``True`` for an owner-trusted global record, a
    :class:`ProviderNetworkPolicy` for a personal record (deployment allowlist),
    or ``False`` for the strict public-only default. Keeping the policy in this
    field lets every existing execution boundary pass it through unchanged.
    """

    base_url: str
    model: str
    api_key: str
    allow_private: bool | ProviderNetworkPolicy = False

    @property
    def network_policy(self) -> ProviderNetworkPolicy | None:
        """Guarded policy for this selection, or ``None`` for owner-trusted access."""
        if self.allow_private is True:
            return None
        if isinstance(self.allow_private, ProviderNetworkPolicy):
            return self.allow_private
        return ProviderNetworkPolicy()


def _hostname(value: str) -> str:
    return value.rstrip(".").lower()


@dataclass(frozen=True)
class DiscoveredModel:
    """One model id reported by an OpenAI-compatible models listing.

    ``input_modalities`` keeps whatever the provider reported (for example
    OpenRouter's ``architecture.input_modalities``) or ``None`` when the provider
    said nothing, so a caller can distinguish "unknown" from "text only".
    """

    id: str
    input_modalities: tuple[str, ...] | None = None

    def as_payload(self) -> dict[str, object]:
        """Public discovery entry; never contains upstream bytes beyond the id."""
        return {
            "id": self.id,
            "inputModalities": list(self.input_modalities)
            if self.input_modalities is not None
            else None,
        }


@dataclass(frozen=True)
class ProviderProbe:
    """Closed-code result of one bounded models listing plus its parsed entries."""

    code: str
    models: tuple[DiscoveredModel, ...] = ()

    @property
    def count(self) -> int:
        return len(self.models)


def _modalities(value: object) -> tuple[str, ...] | None:
    """Normalize a provider-reported modality list, or ``None`` when unknown."""
    if not isinstance(value, list):
        return None
    labels: list[str] = []
    for item in value:
        if not isinstance(item, str):
            continue
        label = item.strip().lower()
        if label and label not in labels:
            labels.append(label)
    return tuple(labels)


def _entry_modalities(entry: dict[str, object]) -> tuple[str, ...] | None:
    architecture = entry.get("architecture")
    if isinstance(architecture, dict):
        reported = _modalities(architecture.get("input_modalities"))
        if reported is not None:
            return reported
    for key in _MODALITY_KEYS:
        reported = _modalities(entry.get(key))
        if reported is not None:
            return reported
    return None


def _discovered_models(data: list[object]) -> tuple[DiscoveredModel, ...]:
    """Parse, deduplicate and bound the entries of a models listing."""
    found: list[DiscoveredModel] = []
    seen: set[str] = set()
    for entry in data:
        if len(found) >= _MAX_DISCOVERED_MODELS:
            break
        if isinstance(entry, str):
            label, modalities = entry, None
        elif isinstance(entry, dict):
            raw = entry.get("id")
            if not isinstance(raw, str):
                continue
            label, modalities = raw, _entry_modalities(entry)
        else:
            continue
        label = label.strip()
        if not label or len(label) > _MAX_MODEL_LABEL:
            continue
        key = label.casefold()
        if key in seen:
            continue
        seen.add(key)
        found.append(DiscoveredModel(label, modalities))
    return tuple(found)


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


def validate_provider_endpoint(
    value: object,
    *,
    scope: str,
    policy: ProviderNetworkPolicy | None = None,
) -> str:
    """Validate and normalize a provider base URL for its authority scope.

    A personal record is public HTTPS by default. The deployment policy may
    allowlist an exact hostname or an address range, in which case HTTP is also
    accepted for that destination. Global records stay owner-trusted.
    """
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
        active = policy or ProviderNetworkPolicy()
        literal = _literal_address(host)
        port = parts.port or (443 if parts.scheme == "https" else 80)
        allowlisted = active.host_allowed(host, port) or (
            literal is not None and active.contains(literal)
        )
        if parts.scheme != "https" and not allowlisted:
            raise ProviderEndpointError(
                "personal provider endpoints require HTTPS unless the deployment "
                "allowlists the destination"
            )
        if (host in _LOCAL_HOSTNAMES or host.endswith(".localhost")) and not allowlisted:
            raise ProviderEndpointError("personal provider endpoints must be publicly reachable")
        if literal is not None and not active.permits(host, (literal,), port=port):
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


def ensure_endpoint_allowed(url: str, policy: ProviderNetworkPolicy | None = None) -> None:
    """Pre-flight the destination of a provider endpoint; fail closed.

    This check improves the error message before a request is attempted. The
    authoritative boundary is :class:`_PolicyNetworkBackend`, which repeats
    resolution and filtering for the actual connection, so a DNS answer that
    changes between the two calls cannot reach a destination outside the policy.
    """
    parts = urlsplit(url)
    host = parts.hostname
    if host is None:
        raise ProviderEndpointError("provider endpoint must include a host")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    try:
        addresses = resolve_addresses(host, port)
    except OSError as exc:
        raise ProviderEndpointError("provider endpoint could not be resolved") from exc
    if not addresses:
        raise ProviderEndpointError("provider endpoint did not resolve to an address")
    active = policy or ProviderNetworkPolicy()
    if not active.permits(host, addresses, port=port):
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


class _PolicyNetworkBackend(httpcore.AsyncNetworkBackend):
    """Connect only to destinations this deployment allows for this boundary."""

    def __init__(self, policy: ProviderNetworkPolicy) -> None:
        self._policy = policy
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
            raise ProviderAddressBlocked(
                f"refusing provider endpoint {host}: it did not resolve"
            ) from exc
        if not self._policy.permits(host, addresses, port=port):
            raise ProviderAddressBlocked(
                f"refusing provider endpoint {host}: its resolved destination is not allowed"
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
            f"refusing provider endpoint {host}: no allowed address accepted the connection"
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


def provider_http_client(
    *,
    allow_private: bool | ProviderNetworkPolicy = False,
    policy: ProviderNetworkPolicy | None = None,
    timeout: float = 30.0,
) -> httpx.AsyncClient:
    """Build the client used for one execution boundary.

    ``allow_private=True`` keeps the owner-trusted global behavior. A
    :class:`ProviderNetworkPolicy` (or the explicit ``policy`` argument) applies
    the deployment allowlist to a personal record; ``False`` is the strict
    public-only default. Every client disables redirects and ignores proxy
    environment variables, so an approved destination is never forwarded.
    """
    if policy is None:
        if isinstance(allow_private, ProviderNetworkPolicy):
            policy = allow_private
        elif allow_private is not True:
            policy = ProviderNetworkPolicy()
    transport = httpx.AsyncHTTPTransport(
        verify=True,
        trust_env=False,
        retries=0,
        http2=False,
    )
    if policy is not None:
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
            network_backend=_PolicyNetworkBackend(policy),
        )
    return httpx.AsyncClient(
        transport=transport,
        follow_redirects=False,
        trust_env=False,
        timeout=timeout,
    )


def _blocked_address(exc: BaseException) -> bool:
    """True when a transport failure came from this module's address policy."""
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        if isinstance(current, ProviderAddressBlocked):
            return True
        seen.add(id(current))
        current = current.__cause__ or current.__context__
    return False


async def _list_provider_models(
    base_url: str,
    api_key: str,
    *,
    allow_private: bool | ProviderNetworkPolicy = False,
    timeout: float = _CHECK_TIMEOUT,
    max_bytes: int = _CHECK_MAX_BYTES,
) -> tuple[str, list[object] | None]:
    """One bounded ``GET {baseUrl}/models`` through the guarded transport.

    Returns a closed status code plus the raw ``data`` entries when the answer
    was a well-formed listing. It never returns or logs the credential, an
    upstream response body or a resolved address.
    """
    url = base_url.rstrip("/") + "/models"
    body = bytearray()
    client = provider_http_client(allow_private=allow_private, timeout=timeout)
    try:
        async with client.stream(
            "GET",
            url,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json",
            },
        ) as response:
            status = response.status_code
            if status in {401, 403}:
                return "unauthorized", None
            if 300 <= status < 400:
                return "redirect", None
            if status != 200:
                return "invalid_response", None
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > max_bytes:
                    return "invalid_response", None
    except httpx.TimeoutException:
        return "timeout", None
    except httpx.HTTPError as exc:
        return ("blocked_address" if _blocked_address(exc) else "unreachable"), None
    finally:
        await client.aclose()
    try:
        payload = json.loads(bytes(body))
    except ValueError:
        return "invalid_response", None
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, list):
        return "invalid_response", None
    return "ok", data


async def probe_provider_models(
    base_url: str,
    api_key: str,
    *,
    allow_private: bool | ProviderNetworkPolicy = False,
    timeout: float = _CHECK_TIMEOUT,
    max_bytes: int = _CHECK_MAX_BYTES,
) -> tuple[str, int | None]:
    """Bounded models listing returning a closed status code and model count."""
    code, data = await _list_provider_models(
        base_url,
        api_key,
        allow_private=allow_private,
        timeout=timeout,
        max_bytes=max_bytes,
    )
    return code, None if data is None else len(data)


async def discover_provider_models(
    base_url: str,
    api_key: str,
    *,
    allow_private: bool | ProviderNetworkPolicy = False,
    timeout: float = _CHECK_TIMEOUT,
    max_bytes: int = _CHECK_MAX_BYTES,
) -> ProviderProbe:
    """Discover a provider's models for storage and for an owner-visible check.

    Nothing but the closed status code, the bounded model ids and their reported
    input modalities leaves this function; a failure returns no entries at all.
    """
    code, data = await _list_provider_models(
        base_url,
        api_key,
        allow_private=allow_private,
        timeout=timeout,
        max_bytes=max_bytes,
    )
    if code != "ok" or data is None:
        return ProviderProbe(code)
    return ProviderProbe(code, _discovered_models(data))


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
    "DiscoveredModel",
    "ProviderAddressBlocked",
    "ProviderEndpointError",
    "ProviderModelSelection",
    "ProviderNetworkPolicy",
    "ProviderProbe",
    "build_provider_model",
    "credential_fingerprint",
    "credential_key_fingerprints",
    "credential_key_state",
    "credential_key_values",
    "credential_storage_available",
    "discover_provider_models",
    "ensure_endpoint_allowed",
    "is_public_address",
    "personal_endpoint_policy",
    "personal_endpoint_policy_from_entries",
    "primary_cipher",
    "primary_fingerprint",
    "probe_provider_models",
    "provider_http_client",
    "resolve_addresses",
    "rotate_credential",
    "seal_credential",
    "unseal_credential",
    "validate_provider_endpoint",
]
