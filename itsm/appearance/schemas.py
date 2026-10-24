"""Validated public appearance contract, preserving the original preset shape."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_NAME = 120
MAX_DESCRIPTION = 500
MAX_GRAPHIC_STRING = 3_000_000
GRAPHIC_KEYS = ("logo", "logoDark", "logoCompact", "favicon")
COLOR_KEYS = ("primary", "secondary", "accent")
_HEX = re.compile(r"^#[0-9a-fA-F]{6}$")


def _single_line(value: str, maximum: int) -> str:
    text = value.strip()
    if not text:
        raise ValueError("must not be empty")
    if len(text) > maximum:
        raise ValueError(f"must be at most {maximum} characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in text):
        raise ValueError("must not contain control characters")
    return text


def _plain_text(value: str, maximum: int) -> str:
    text = value.strip()
    if len(text) > maximum:
        raise ValueError(f"must be at most {maximum} characters")
    if any(
        (ord(character) < 32 and character not in "\n\r\t") or ord(character) == 127
        for character in text
    ):
        raise ValueError("must not contain control characters")
    return text


def _graphic(value: str | None) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError("must be a string")
    text = value.strip()
    if len(text) > MAX_GRAPHIC_STRING:
        raise ValueError("graphic reference is too large")
    if any(ord(character) < 32 or ord(character) == 127 for character in text):
        raise ValueError("graphic reference must not contain control characters")
    return text


class PresetBranding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    appName: str = Field(max_length=MAX_NAME)
    organizationName: str = Field(max_length=MAX_NAME)
    logo: str = ""
    logoDark: str = ""
    logoCompact: str = ""
    favicon: str = ""

    @field_validator("appName", "organizationName")
    @classmethod
    def _names(cls, value: str) -> str:
        return _single_line(value, MAX_NAME)

    @field_validator(*GRAPHIC_KEYS)
    @classmethod
    def _graphics(cls, value: str | None) -> str:
        return _graphic(value)


class PresetPalette(BaseModel):
    model_config = ConfigDict(extra="forbid")

    primary: str
    secondary: str
    accent: str

    @field_validator(*COLOR_KEYS)
    @classmethod
    def _colors(cls, value: str) -> str:
        if not _HEX.fullmatch(value):
            raise ValueError("must be a #rrggbb color")
        return value.lower()


class PresetColorModes(BaseModel):
    model_config = ConfigDict(extra="forbid")

    light: PresetPalette
    dark: PresetPalette


class PresetPreferences(BaseModel):
    model_config = ConfigDict(extra="forbid")

    defaultMode: Literal["light", "dark", "system"] = "system"
    compact: bool = False


class PresetPayload(BaseModel):
    """One preset as edited or imported; the server owns the id and version."""

    model_config = ConfigDict(extra="forbid")

    id: str | None = Field(default=None, max_length=80)
    name: str = Field(max_length=MAX_NAME)
    version: Literal[1] = 1
    description: str = ""
    branding: PresetBranding
    colors: PresetColorModes
    preferences: PresetPreferences = Field(default_factory=PresetPreferences)

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        return _single_line(value, MAX_NAME)

    @field_validator("description")
    @classmethod
    def _description(cls, value: str) -> str:
        return _plain_text(value, MAX_DESCRIPTION)

    @field_validator("id")
    @classmethod
    def _id(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        text = value.strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", text):
            raise ValueError("id is invalid")
        return text


class ImportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    preset: PresetPayload
    policy: Literal["both", "replace"] = "both"
