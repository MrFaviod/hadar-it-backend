"""Stable refusals shared by the host, the sandbox driver and the HTTP layer.

These live outside ``host.py`` so the sandbox launcher and the capability broker
can raise the same types without importing the whole host module.  The
hierarchy and names are the ones the v1 host exposed; ``host`` re-exports them.
"""

from __future__ import annotations

from collections.abc import Iterable


class ExtensionHostError(Exception):
    """Base class for host refusals; the API maps these to JSON errors."""


class ExtensionUnavailable(ExtensionHostError):
    """Native extensions are not configured in this process."""


class ExtensionValidationFailed(ExtensionHostError):
    """A package, its manifest or a reviewer input failed validation."""

    def __init__(self, message: str, errors: Iterable[str] = ()) -> None:
        self.errors = tuple(dict.fromkeys(str(error) for error in errors))[:40]
        super().__init__(message)


class ExtensionTooLarge(ExtensionHostError):
    """The archive, response or report exceeds a hard limit."""


class ExtensionNotFound(ExtensionHostError):
    """The requested module, candidate, operation or version does not exist."""


class ExtensionConflict(ExtensionHostError):
    """The requested transition is not legal in the current state."""


class ExtensionStale(ExtensionConflict):
    """The caller's expected revision no longer matches stored state."""


class ExtensionDisabled(ExtensionConflict):
    """The module is installed but disabled."""


class ExtensionDigestMismatch(ExtensionConflict):
    """Submitted bytes, a digest or a review do not match."""


class ExtensionRollbackIncompatible(ExtensionConflict):
    """The target version cannot read the stored data schema."""


class ExtensionRequiresUpgrade(ExtensionConflict):
    """An installed SDK v1 module is never executed by the v2 runtime."""


class ExtensionIdempotencyConflict(ExtensionConflict):
    """A capability key was reused with a different request body."""


class ExtensionImportFailed(ExtensionValidationFailed):
    """The module backend could not be imported, bound or registered."""


class ExtensionHandlerFailed(ExtensionHostError):
    """A module handler failed; private detail stays in the host log."""


class ExtensionStoreConflict(ExtensionConflict):
    """An optimistic version check failed."""


class ExtensionStoreValidation(ExtensionValidationFailed):
    """A store or declarative collection request is invalid."""


class ExtensionMigrationFailed(ExtensionHostError):
    """A module migration failed; the previous version and data stay active."""


class ExtensionSandboxUnavailable(ExtensionUnavailable):
    """The kernel cannot provide the required isolation on this host."""


__all__ = [
    "ExtensionConflict",
    "ExtensionDigestMismatch",
    "ExtensionDisabled",
    "ExtensionHandlerFailed",
    "ExtensionHostError",
    "ExtensionIdempotencyConflict",
    "ExtensionImportFailed",
    "ExtensionMigrationFailed",
    "ExtensionNotFound",
    "ExtensionRequiresUpgrade",
    "ExtensionRollbackIncompatible",
    "ExtensionSandboxUnavailable",
    "ExtensionStale",
    "ExtensionStoreConflict",
    "ExtensionStoreValidation",
    "ExtensionTooLarge",
    "ExtensionUnavailable",
    "ExtensionValidationFailed",
]
