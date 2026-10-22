"""Directory module: inventory people, departments and hierarchical locations."""

from __future__ import annotations

from itsm.directory.service import (
    DepartmentView,
    DirectoryService,
    LocationTree,
    LocationView,
    PersonView,
)

__all__ = [
    "DepartmentView",
    "DirectoryService",
    "LocationTree",
    "LocationView",
    "PersonView",
]
