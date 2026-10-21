"""Identity, authentication and authorization for the ITSM backend.

The package owns portable SQL policy storage, Casbin evaluation, Argon2id
password hashing, opaque server-side sessions, actor principals and the audit
trail. Business modules must call :class:`itsm.identity.service.IdentityService`
instead of trusting endpoint checks or caller-supplied identity headers.
"""

from __future__ import annotations

__all__ = ["permissions"]
