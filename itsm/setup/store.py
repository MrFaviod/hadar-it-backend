"""Private bootstrap store for the setup service.

The store lives outside the application database and outside the API process:
a private directory (``0700``) holding ``0600`` JSON files, an exclusive
``flock`` for every mutation and an append-only sanitized journal. The public
sanitized state is a separate file from the private secrets file, so serving
``status`` never needs to read a credential hash.

Credentials are only ever persisted as Argon2id hashes. Session cookies are
persisted as SHA-256 digests. The clear credential is returned exactly once to
the process that generated or consumed it.
"""

from __future__ import annotations

import fcntl
import json
import os
import secrets
import stat
import tempfile
import uuid
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from pydantic import SecretStr

from itsm.identity.hashing import hash_password, hash_token, verify_password

SESSION_TTL_MINUTES = 60
MAX_CLAIM_ATTEMPTS = 5
DEFAULT_STATE_DIR = Path("/var/lib/itsm-setup")
SETUP_DIRECTORY_MODE = 0o700
SETUP_FILE_MODE = 0o600
ReleaseMode = Literal["dev", "prod"]
_STATE_FILE = "state.json"
_SECRETS_FILE = "secrets.json"
_JOURNAL_FILE = "journal.jsonl"
_ANCHOR_FILE = "anchor.json"
_ENABLED_FILE = "enabled.json"
_LOCK_FILE = "lock"
_CLAIM_STATES = (
    "unclaimed",
    "claimed",
    "ai_configured",
    "ai_deferred",
    "storage_ready",
    "owner_ready",
    "configuring",
    "verifying",
    "complete",
)


class SetupError(Exception):
    """Base class for refusals that the API or CLI renders as sanitized JSON."""

    code = "setup_error"


class SetupConfigurationError(SetupError):
    """The mode or the settings cannot run the setup service."""

    code = "setup_configuration"


class SetupDisabled(SetupError):
    """The operator has not enabled setup in this state directory."""

    code = "setup_disabled"


class AlreadyClaimed(SetupError):
    """The installation already has a setup owner; unclaimed is never restored."""

    code = "already_claimed"


class NotClaimed(SetupError):
    """An operator command needs a claimed installation."""

    code = "not_claimed"


class ClaimLocked(SetupError):
    """Too many failed attempts; only an operator rotation unlocks the claim."""

    code = "claim_locked"


class InvalidCredential(SetupError):
    """The presented one-time credential does not match."""

    code = "claim_invalid"


class ClaimUnavailable(SetupError):
    """Setup is enabled but no claim credential exists (interrupted provisioning)."""

    code = "claim_unavailable"


class StoreUnsafe(SetupError):
    """A path or file mode is not safe for secret material."""

    code = "store_unsafe"


class RevisionConflict(SetupError):
    """An optimistic revision check lost against another writer."""

    code = "revision_conflict"


class StateRefused(SetupError):
    """The current setup state does not allow this operation."""

    code = "state_refused"


def utcnow() -> datetime:
    """Current UTC time as an aware datetime."""

    return datetime.now(UTC)


def _parse_bool(value: str) -> bool:
    lowered = value.strip().lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    raise SetupConfigurationError("ITSM_AUTH_COOKIE_SECURE must be a boolean")


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _iso(value: datetime) -> str:
    return _as_utc(value).isoformat()


def _parse_iso(value: str) -> datetime:
    return _as_utc(datetime.fromisoformat(value))


@dataclass(frozen=True)
class SetupSettings:
    """Small, database-free settings for the setup process."""

    state_dir: Path
    release_mode: ReleaseMode
    allowed_origins: tuple[str, ...] = ()
    cookie_secure: bool = True
    # Operator-supplied ring for provider credentials. Absent means the
    # credential form is blocked with a diagnosis; this process never generates
    # a key. The allowlist is the deployment's private-destination policy.
    ai_credential_keys: SecretStr | None = None
    ai_credential_key: SecretStr | None = None
    ai_personal_private_endpoints: str = ""

    @classmethod
    def from_environ(cls, environ: Mapping[str, str] | None = None) -> SetupSettings:
        source = os.environ if environ is None else environ
        raw_mode = source.get("RELEASE_MODE")
        if raw_mode == "demo":
            raise SetupConfigurationError(
                "RELEASE_MODE=demo does not offer the setup service; only dev and prod do"
            )
        if raw_mode not in {"dev", "prod"}:
            raise SetupConfigurationError(
                "RELEASE_MODE must be dev or prod for the setup service; no default mode exists"
            )
        mode: ReleaseMode = "dev" if raw_mode == "dev" else "prod"
        state_dir = source.get("ITSM_SETUP_STATE_DIR") or str(DEFAULT_STATE_DIR)
        origins = tuple(
            part.strip()
            for part in source.get("ITSM_SETUP_ALLOWED_ORIGINS", "").split(",")
            if part.strip()
        )
        cookie_secure = _parse_bool(source.get("ITSM_AUTH_COOKIE_SECURE", "true"))
        ring = source.get("ITSM_AI_CREDENTIAL_KEYS")
        legacy = source.get("ITSM_AI_CREDENTIAL_KEY")
        return cls(
            state_dir=Path(state_dir),
            release_mode=mode,
            allowed_origins=origins,
            cookie_secure=cookie_secure,
            ai_credential_keys=SecretStr(ring) if ring and ring.strip() else None,
            ai_credential_key=SecretStr(legacy) if legacy and legacy.strip() else None,
            ai_personal_private_endpoints=source.get("ITSM_AI_PERSONAL_PRIVATE_ENDPOINTS", ""),
        )

    def with_state_dir(self, state_dir: str | Path) -> SetupSettings:
        return replace(self, state_dir=Path(state_dir))


@dataclass(frozen=True)
class SessionGrant:
    """A freshly created setup session; the raw values are returned only once."""

    token: str
    csrf_token: str
    state: str
    recovered: bool = False


class SetupStore:
    """Private, database-free bootstrap state with exclusive mutations."""

    def __init__(
        self,
        state_dir: str | Path,
        *,
        clock: Callable[[], datetime] | None = None,
        release_mode: ReleaseMode = "dev",
    ) -> None:
        self.state_dir = Path(state_dir)
        self.release_mode = release_mode
        self._clock = clock or utcnow
        self.state_path = self.state_dir / _STATE_FILE
        self.secrets_path = self.state_dir / _SECRETS_FILE
        self.journal_path = self.state_dir / _JOURNAL_FILE
        self.anchor_path = self.state_dir / _ANCHOR_FILE
        self.enabled_path = self.state_dir / _ENABLED_FILE
        self.lock_path = self.state_dir / _LOCK_FILE

    # ------------------------------------------------------------------ paths
    def validate(self) -> None:
        """Refuse an unsafe existing state directory without creating it."""

        try:
            info = self.state_dir.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISLNK(info.st_mode):
            raise StoreUnsafe("the setup state directory must not be a symbolic link")
        if not stat.S_ISDIR(info.st_mode):
            raise StoreUnsafe("the setup state path is not a directory")
        if stat.S_IMODE(info.st_mode) != SETUP_DIRECTORY_MODE:
            os.chmod(self.state_dir, SETUP_DIRECTORY_MODE)

    def ensure_ready(self) -> None:
        """Create the private directory or refuse an unsafe existing one."""

        self.state_dir.mkdir(mode=SETUP_DIRECTORY_MODE, parents=True, exist_ok=True)
        self.validate()

    def _assert_secure_file(self, path: Path) -> None:
        try:
            info = path.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISLNK(info.st_mode):
            raise StoreUnsafe(f"{path.name} must not be a symbolic link")
        if not stat.S_ISREG(info.st_mode):
            raise StoreUnsafe(f"{path.name} is not a regular file")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise StoreUnsafe(f"{path.name} is accessible outside its owner")

    def _read_json(self, path: Path, default: Any) -> Any:
        self._assert_secure_file(path)
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return default
        except OSError as exc:
            raise StoreUnsafe(f"{path.name} cannot be opened safely") from exc
        with os.fdopen(descriptor, "rb") as handle:
            raw = handle.read()
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StoreUnsafe(f"{path.name} is not valid JSON") from exc
        if not isinstance(value, dict):
            raise StoreUnsafe(f"{path.name} must contain a JSON object")
        return value

    def _atomic_write(self, path: Path, payload: bytes) -> None:
        self._assert_secure_file(path)
        descriptor, temporary = tempfile.mkstemp(prefix=".tmp-", dir=self.state_dir)
        try:
            os.fchmod(descriptor, SETUP_FILE_MODE)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            directory = os.open(self.state_dir, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except BaseException:
            with suppress(FileNotFoundError):
                os.unlink(temporary)
            raise

    def _write_json(self, path: Path, value: dict[str, Any]) -> None:
        encoded = json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        self._atomic_write(path, encoded + b"\n")

    def _append_journal(
        self,
        action: str,
        revision: int,
        receipt: dict[str, Any],
        idempotency_key: str,
    ) -> None:
        entry = {
            "id": uuid.uuid4().hex,
            "at": _iso(self._clock()),
            "action": action,
            "revision": revision,
            "idempotency_key": idempotency_key,
            "receipt": receipt,
        }
        encoded = (json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        self._assert_secure_file(self.journal_path)
        try:
            descriptor = os.open(
                self.journal_path,
                os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW,
                SETUP_FILE_MODE,
            )
        except OSError as exc:
            raise StoreUnsafe("the setup journal cannot be opened safely") from exc
        try:
            os.fchmod(descriptor, SETUP_FILE_MODE)
            os.write(descriptor, encoded)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _read_journal(self) -> list[dict[str, Any]]:
        """Read the append-only journal; a trailing partial append is ignored."""

        self._assert_secure_file(self.journal_path)
        try:
            descriptor = os.open(self.journal_path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return []
        except OSError as exc:
            raise StoreUnsafe("the setup journal cannot be opened safely") from exc
        with os.fdopen(descriptor, "rb") as handle:
            raw = handle.read()
        complete = raw if raw.endswith(b"\n") else raw.rsplit(b"\n", 1)[0]
        entries: list[dict[str, Any]] = []
        for line in complete.splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise StoreUnsafe("the setup journal is not valid JSON") from exc
            if not isinstance(entry, dict):
                raise StoreUnsafe("the setup journal entry is invalid")
            entries.append(entry)
        return entries

    def _claim_high_water(self) -> int:
        """Highest claim revision on record, from the anchor and the journal.

        Neither source is part of the restorable ``state.json``/``secrets.json``
        pair, so a restored snapshot cannot rewind the mark. The anchor is
        written once with ``O_EXCL``; the journal is append-only.
        """

        high = 0
        anchor = self._read_json(self.anchor_path, None)
        if anchor is not None:
            try:
                high = int(anchor["revision"])
            except (KeyError, TypeError, ValueError) as exc:
                raise StoreUnsafe("the setup claim anchor is invalid") from exc
            if high < 1:
                raise StoreUnsafe("the setup claim anchor revision is invalid")
        for entry in self._read_journal():
            if entry.get("action") != "claim":
                continue
            try:
                revision = int(entry["revision"])
            except (KeyError, TypeError, ValueError) as exc:
                raise StoreUnsafe("the setup journal revision is invalid") from exc
            high = max(high, revision)
        return high

    def _diverged(self, private: dict[str, Any]) -> bool:
        """A durable claim exists but the restorable state no longer agrees."""

        high = self._claim_high_water()
        if high <= 0:
            return False
        return private["state"] == "unclaimed" or private["revision"] < high

    def _write_claim_anchor(self, revision: int, instance_id: str | None) -> None:
        """Write the claim anchor once; it is never rewritten or restored."""

        payload = {
            "revision": revision,
            "instance_id": instance_id,
            "claimed_at": _iso(self._clock()),
        }
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n"
        self._assert_secure_file(self.anchor_path)
        try:
            descriptor = os.open(
                self.anchor_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                SETUP_FILE_MODE,
            )
        except FileExistsError as exc:
            raise AlreadyClaimed("this installation already has a setup owner") from exc
        except OSError as exc:
            raise StoreUnsafe("the setup claim anchor cannot be opened safely") from exc
        try:
            os.fchmod(descriptor, SETUP_FILE_MODE)
            os.write(descriptor, encoded)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        directory = os.open(self.state_dir, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self.ensure_ready()
        self._assert_secure_file(self.lock_path)
        try:
            descriptor = os.open(
                self.lock_path,
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                SETUP_FILE_MODE,
            )
        except OSError as exc:
            raise StoreUnsafe("the setup lock cannot be opened safely") from exc
        try:
            os.fchmod(descriptor, SETUP_FILE_MODE)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    # ------------------------------------------------------------------ state
    def _default_private(self) -> dict[str, Any]:
        now = _iso(self._clock())
        return {
            "version": 1,
            "revision": 0,
            "state": "unclaimed",
            "instance_id": None,
            "claim": None,
            "recovery": None,
            "attempts": 0,
            "locked": False,
            "sessions": {},
            "ai": None,
            "created_at": now,
            "updated_at": now,
            "claimed_at": None,
        }

    def _read_private(self) -> dict[str, Any]:
        raw = self._read_json(self.secrets_path, None)
        if raw is None:
            return self._default_private()
        try:
            sessions = raw.get("sessions") or {}
            if not isinstance(sessions, dict):
                raise StoreUnsafe("the setup session table is invalid")
            state = str(raw.get("state", "unclaimed"))
            if state not in _CLAIM_STATES:
                raise StoreUnsafe("the setup state is invalid")
            return {
                "version": int(raw.get("version", 1)),
                "revision": int(raw.get("revision", 0)),
                "state": state,
                "instance_id": raw.get("instance_id"),
                "claim": raw.get("claim"),
                "recovery": raw.get("recovery"),
                "attempts": int(raw.get("attempts", 0)),
                "locked": bool(raw.get("locked", False)),
                "sessions": dict(sessions),
                "ai": raw.get("ai"),
                "created_at": raw.get("created_at"),
                "updated_at": raw.get("updated_at"),
                "claimed_at": raw.get("claimed_at"),
            }
        except (TypeError, ValueError) as exc:
            raise StoreUnsafe("the private setup state is invalid") from exc

    def _render_public(self, private: dict[str, Any]) -> dict[str, Any]:
        record = private.get("ai")
        receipt = record.get("receipt") if isinstance(record, dict) else None
        return {
            "version": 1,
            "revision": private["revision"],
            "state": private["state"],
            "mode": self.release_mode,
            "release_mode": self.release_mode,
            "instance_id": private["instance_id"],
            "ai": receipt,
            "updated_at": private["updated_at"],
            "claimed_at": private["claimed_at"],
        }

    def public_state(self) -> dict[str, Any]:
        """Read the public projection; never exposes a credential or a session."""

        private = self._read_private()
        public = self._read_json(self.state_path, None)
        if isinstance(public, dict) and public.get("revision") == private["revision"]:
            return public
        return self._render_public(private)

    def operator_enabled(self) -> bool:
        marker = self._read_json(self.enabled_path, None)
        if marker is None:
            return False
        return bool(marker.get("enabled")) and marker.get("mode") == self.release_mode

    def status_snapshot(self) -> dict[str, Any]:
        """Compute the anonymous status fields from the private state."""

        enabled = self.operator_enabled()
        private = self._read_private()
        diverged = self._diverged(private)
        state = private["state"] if enabled else "disabled"
        setup_enabled = enabled and state != "complete"
        claim_available = (
            setup_enabled
            and state == "unclaimed"
            and bool(private["claim"])
            and not private["locked"]
            and not diverged
        )
        return {
            "state": state,
            "instance_id": private["instance_id"],
            "setup_enabled": setup_enabled,
            "claim_available": claim_available,
            "locked": private["locked"],
            "checks": {"state_diverged": "failed"} if diverged else {},
        }

    def _persist(
        self,
        private: dict[str, Any],
        *,
        expected_revision: int,
        action: str,
        receipt: dict[str, Any],
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        current = self._read_private()
        if current["revision"] != expected_revision:
            raise RevisionConflict("the private setup state changed under this writer")
        updated = dict(private)
        updated["revision"] = expected_revision + 1
        updated["updated_at"] = _iso(self._clock())
        self._write_json(self.secrets_path, updated)
        self._write_json(self.state_path, self._render_public(updated))
        self._append_journal(
            action,
            updated["revision"],
            receipt,
            idempotency_key or uuid.uuid4().hex,
        )
        return updated

    def _write_enabled_marker(self) -> None:
        self._write_json(
            self.enabled_path,
            {
                "enabled": True,
                "mode": self.release_mode,
                "created_at": _iso(self._clock()),
            },
        )

    # ----------------------------------------------------------------- claims
    def enable_claim(self) -> str:
        """Enable setup and return a fresh one-time claim credential."""

        if self.release_mode not in {"dev", "prod"}:
            raise SetupConfigurationError("setup is only available in dev and prod")
        with self._locked():
            private = self._read_private()
            if private["state"] != "unclaimed":
                raise AlreadyClaimed("this installation already has a setup owner")
            if self._diverged(private):
                raise AlreadyClaimed("this installation already has a setup owner")
            credential = secrets.token_urlsafe(32)
            private["claim"] = {
                "hash": hash_password(credential),
                "created_at": _iso(self._clock()),
            }
            private["attempts"] = 0
            private["locked"] = False
            if not private["instance_id"]:
                private["instance_id"] = uuid.uuid4().hex
            self._write_enabled_marker()
            self._persist(
                private,
                expected_revision=private["revision"],
                action="enable-claim",
                receipt={"state": "unclaimed", "enabled": True},
            )
            return credential

    def rotate_claim(self) -> str:
        """Invalidate the previous claim credential and return a new one."""

        if not self.operator_enabled():
            raise SetupDisabled("setup is not enabled in this state directory")
        with self._locked():
            private = self._read_private()
            if private["state"] != "unclaimed":
                raise AlreadyClaimed("this installation already has a setup owner")
            if self._diverged(private):
                raise AlreadyClaimed("this installation already has a setup owner")
            credential = secrets.token_urlsafe(32)
            private["claim"] = {
                "hash": hash_password(credential),
                "created_at": _iso(self._clock()),
            }
            private["attempts"] = 0
            private["locked"] = False
            if not private["instance_id"]:
                private["instance_id"] = uuid.uuid4().hex
            self._persist(
                private,
                expected_revision=private["revision"],
                action="rotate-claim",
                receipt={"state": "unclaimed", "rotated": True},
            )
            return credential

    def issue_recovery(self) -> str:
        """Issue a one-time recovery credential for an already claimed setup."""

        if not self.operator_enabled():
            raise SetupDisabled("setup is not enabled in this state directory")
        with self._locked():
            private = self._read_private()
            if private["state"] != "claimed":
                raise NotClaimed("recovery requires an installation already claimed")
            credential = secrets.token_urlsafe(32)
            private["recovery"] = {
                "hash": hash_password(credential),
                "created_at": _iso(self._clock()),
            }
            private["attempts"] = 0
            private["locked"] = False
            self._persist(
                private,
                expected_revision=private["revision"],
                action="recover-issue",
                receipt={"state": "claimed", "owner_preserved": True},
            )
            return credential

    def claim(self, credential: str) -> SessionGrant:
        """Consume the claim credential, or a recovery credential, exactly once."""

        if not credential:
            raise InvalidCredential("the claim credential is not valid")
        if not self.operator_enabled():
            raise SetupDisabled("setup is not enabled in this state directory")
        with self._locked():
            private = self._read_private()
            if self._diverged(private):
                raise AlreadyClaimed("this installation already has a setup owner")
            state = private["state"]
            if state == "claimed":
                recovery = private.get("recovery")
                if isinstance(recovery, dict):
                    if private["locked"]:
                        raise ClaimLocked(
                            "too many failed attempts; issue a new recovery credential"
                        )
                    if verify_password(recovery["hash"], credential):
                        private["recovery"] = None
                        private["attempts"] = 0
                        private["locked"] = False
                        grant = self._new_session(private, recovered=True)
                        self._persist(
                            private,
                            expected_revision=private["revision"],
                            action="recover",
                            receipt={"state": "claimed", "recovered": True},
                        )
                        return grant
                    self._record_failure(private, action="recover-denied")
                    raise InvalidCredential("the claim credential is not valid")
                raise AlreadyClaimed("this installation already has a setup owner")
            if state != "unclaimed":
                raise AlreadyClaimed("this installation already has a setup owner")
            if private["locked"]:
                raise ClaimLocked("too many failed attempts; rotate the claim credential")
            record = private.get("claim")
            if not isinstance(record, dict):
                raise ClaimUnavailable("no claim credential is available")
            if not verify_password(record["hash"], credential):
                self._record_failure(private, action="claim-denied")
                raise InvalidCredential("the claim credential is not valid")
            private["claim"] = None
            private["recovery"] = None
            private["state"] = "claimed"
            private["claimed_at"] = _iso(self._clock())
            private["attempts"] = 0
            private["locked"] = False
            grant = self._new_session(private, recovered=False)
            self._write_claim_anchor(private["revision"] + 1, private["instance_id"])
            self._persist(
                private,
                expected_revision=private["revision"],
                action="claim",
                receipt={"state": "claimed", "recovered": False},
            )
            return grant

    def _record_failure(self, private: dict[str, Any], *, action: str) -> None:
        private["attempts"] = int(private["attempts"]) + 1
        if private["attempts"] >= MAX_CLAIM_ATTEMPTS:
            private["locked"] = True
        self._persist(
            private,
            expected_revision=private["revision"],
            action=action,
            receipt={"attempts": private["attempts"], "locked": private["locked"]},
        )

    # --------------------------------------------------------------- sessions
    def _new_session(self, private: dict[str, Any], *, recovered: bool) -> SessionGrant:
        now = self._clock()
        sessions: dict[str, Any] = {}
        if not recovered:
            sessions = {
                digest: record
                for digest, record in private["sessions"].items()
                if isinstance(record, dict) and _parse_iso(record["expires_at"]) > _as_utc(now)
            }
        token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        sessions[hash_token(token)] = {
            "csrf_token": csrf_token,
            "created_at": _iso(now),
            "expires_at": _iso(now + timedelta(minutes=SESSION_TTL_MINUTES)),
        }
        private["sessions"] = sessions
        return SessionGrant(
            token=token,
            csrf_token=csrf_token,
            state="claimed",
            recovered=recovered,
        )

    def resolve_session(self, token: str | None) -> dict[str, Any] | None:
        """Return the server-side session for a raw cookie token, if still valid."""

        if not token:
            return None
        private = self._read_private()
        record = private["sessions"].get(hash_token(token))
        if isinstance(record, dict):
            try:
                expires_at = _parse_iso(record["expires_at"])
            except KeyError, TypeError, ValueError:
                expires_at = None
            if expires_at is not None and expires_at > _as_utc(self._clock()):
                return record
        if private["sessions"]:
            self._prune_sessions()
        return None

    def _prune_sessions(self) -> None:
        """Delete expired or malformed session rows instead of keeping them."""

        with self._locked():
            private = self._read_private()
            now = _as_utc(self._clock())
            sessions: dict[str, Any] = {}
            for digest, record in private["sessions"].items():
                if not isinstance(record, dict):
                    continue
                try:
                    expires_at = _parse_iso(record["expires_at"])
                except KeyError, TypeError, ValueError:
                    continue
                if expires_at > now:
                    sessions[digest] = record
            removed = len(private["sessions"]) - len(sessions)
            if removed <= 0:
                return
            private["sessions"] = sessions
            self._persist(
                private,
                expected_revision=private["revision"],
                action="prune-sessions",
                receipt={"state": private["state"], "removed": removed},
            )

    def end_session(self, token: str | None) -> bool:
        """Delete the hashed row for a raw cookie token; True when it existed."""

        if not token:
            return False
        with self._locked():
            private = self._read_private()
            digest = hash_token(token)
            if not isinstance(private["sessions"].get(digest), dict):
                return False
            del private["sessions"][digest]
            self._persist(
                private,
                expected_revision=private["revision"],
                action="logout",
                receipt={"state": private["state"], "signed_out": True},
            )
            return True

    # ---------------------------------------------------------------------- ai
    def ai_private_record(self) -> dict[str, Any] | None:
        """Read the sealed provider record; only the setup process may call this."""

        record = self._read_private().get("ai")
        return dict(record) if isinstance(record, dict) else None

    def record_ai_configured(
        self,
        *,
        ciphertext: str,
        base_url: str,
        model: str,
        scope: str,
        key_fingerprint: str | None,
        receipt: dict[str, Any],
        discovered_models: int | None = None,
    ) -> dict[str, Any]:
        """Store the ciphertext privately and publish only the sanitized receipt."""

        with self._locked():
            private = self._read_private()
            if private["state"] not in {"claimed", "ai_deferred"}:
                raise StateRefused("AI configuration requires a claimed installation")
            now = _iso(self._clock())
            public = dict(receipt)
            public["status"] = "configured"
            public["pending"] = False
            public["checked_at"] = now
            private["state"] = "ai_configured"
            private["ai"] = {
                "ciphertext": ciphertext,
                "base_url": base_url,
                "model": model,
                "scope": scope,
                "key_fingerprint": key_fingerprint,
                "discovery": {"code": "ok", "models": discovered_models},
                "configured_at": now,
                "receipt": public,
            }
            updated = self._persist(
                private,
                expected_revision=private["revision"],
                action="configure-ai",
                receipt=public,
            )
            stored = updated["ai"]["receipt"]
            return dict(stored)

    def record_ai_deferred(
        self,
        *,
        reason: str | None = None,
    ) -> dict[str, Any]:
        """Keep the pending item visible instead of simulating a configured provider."""

        with self._locked():
            private = self._read_private()
            if private["state"] != "claimed":
                raise StateRefused("deferring AI requires a claimed installation")
            now = _iso(self._clock())
            public = {
                "status": "pending",
                "pending": True,
                "reason": reason,
                "deferred_at": now,
            }
            private["state"] = "ai_deferred"
            private["ai"] = {"receipt": public}
            updated = self._persist(
                private,
                expected_revision=private["revision"],
                action="defer-ai",
                receipt=public,
            )
            stored = updated["ai"]["receipt"]
            return dict(stored)
