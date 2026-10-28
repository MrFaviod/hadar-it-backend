"""Native application extensions: manifests, lifecycle, storage and HTTP API."""

from itsm.extensions.host import (
    ExtensionHostService,
    ScheduleView,
    submit_workspace_candidate,
)

__all__ = [
    "ExtensionHostService",
    "ScheduleView",
    "submit_workspace_candidate",
]
