"""Installation-global appearance: durable presets, safe graphics and ZIP portability."""

from itsm.appearance.api import create_appearance_router
from itsm.appearance.service import AppearanceService, build_appearance_service

__all__ = ["AppearanceService", "build_appearance_service", "create_appearance_router"]
