"""Isolated, bounded WeasyPrint rendering with deny-all resource fetching.

A PDF is rendered in a freshly spawned process so a crash, a runaway document
or a memory-hungry font stack cannot take down the API/worker process.  The
child only sees the HTML string and the exact image bytes registered by
composition; every other URL (HTTP, HTTPS, file, data, or an unknown resource
key) is rejected before WeasyPrint can open it.
"""

from __future__ import annotations

import multiprocessing
import os
import re
from collections.abc import Mapping
from tempfile import TemporaryDirectory

from weasyprint import URLFetcher
from weasyprint.urls import URLFetcherResponse

MAX_HTML_BYTES = 8 * 1024 * 1024
MAX_RESOURCE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_RESOURCE_BYTES = 64 * 1024 * 1024
MAX_RESOURCES = 128
MAX_OUTPUT_BYTES = 512 * 1024 * 1024
MAX_TIMEOUT_SECONDS = 600.0
MIN_MEMORY_MB = 64
MAX_MEMORY_MB = 4096
MIN_TIMEOUT_SECONDS = 0.01

_RESOURCE_KEY = re.compile(r"^(?:logo|photo-[0-9]{1,4})\.png$")
_RESOURCE_PREFIX = "resource://"


class RenderError(RuntimeError):
    """Base class for bounded rendering failures."""


class RenderTimeout(RenderError):
    """The document exceeded its rendering time budget."""


class RenderFailed(RenderError):
    """The isolated renderer failed or produced an invalid/bounded PDF."""


class _RestrictedFetcher(URLFetcher):
    """Serve only exact registered ``resource://`` keys, reject everything else."""

    def __init__(self, resources: Mapping[str, bytes]) -> None:
        super().__init__(timeout=10)
        self._resources = dict(resources)

    def fetch(self, url, headers=None) -> URLFetcherResponse:
        if not isinstance(url, str) or not url.startswith(_RESOURCE_PREFIX):
            raise ValueError("report rendering only accepts registered resources")
        key = url[len(_RESOURCE_PREFIX) :]
        data = self._resources.get(key)
        if not isinstance(data, bytes):
            raise ValueError("report resource is not registered")
        return URLFetcherResponse(
            url=url,
            body=data,
            headers={"Content-Type": "image/png"},
            status=200,
        )


def _validate_arguments(
    composition,
    *,
    timeout_seconds: float,
    memory_mb: int,
    max_bytes: int,
) -> tuple[str, dict[str, bytes]]:
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
        raise ValueError("timeout_seconds must be a number")
    timeout = float(timeout_seconds)
    if not (MIN_TIMEOUT_SECONDS <= timeout <= MAX_TIMEOUT_SECONDS):
        raise ValueError(
            f"timeout_seconds must be between {MIN_TIMEOUT_SECONDS:g} and {MAX_TIMEOUT_SECONDS:g}"
        )

    if isinstance(memory_mb, bool) or not isinstance(memory_mb, int):
        raise ValueError("memory_mb must be an integer")
    if not (MIN_MEMORY_MB <= memory_mb <= MAX_MEMORY_MB):
        raise ValueError(f"memory_mb must be between {MIN_MEMORY_MB} and {MAX_MEMORY_MB}")

    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int):
        raise ValueError("max_bytes must be an integer")
    if not (1 <= max_bytes <= MAX_OUTPUT_BYTES):
        raise ValueError(f"max_bytes must be between 1 and {MAX_OUTPUT_BYTES}")

    html = getattr(composition, "html", None)
    resources = getattr(composition, "resources", None)
    if not isinstance(html, str):
        raise ValueError("composition.html must be a string")
    if len(html.encode("utf-8")) > MAX_HTML_BYTES:
        raise ValueError("composition HTML exceeds the rendering limit")
    if not isinstance(resources, Mapping):
        raise ValueError("composition.resources must be a mapping")
    if len(resources) > MAX_RESOURCES:
        raise ValueError(f"composition.resources exceeds {MAX_RESOURCES} entries")

    normalized: dict[str, bytes] = {}
    total = 0
    for key, value in resources.items():
        if not isinstance(key, str) or not _RESOURCE_KEY.fullmatch(key):
            raise ValueError("composition resource keys must be registered image names")
        if not isinstance(value, (bytes, bytearray, memoryview)):
            raise ValueError("composition resource values must be bytes")
        data = bytes(value)
        if not data or len(data) > MAX_RESOURCE_BYTES:
            raise ValueError("composition resource exceeds the per-image limit")
        total += len(data)
        if total > MAX_TOTAL_RESOURCE_BYTES:
            raise ValueError("composition resources exceed the total rendering limit")
        normalized[key] = data
    return html, normalized


def _apply_limits(memory_mb: int) -> None:
    try:
        import resource
    except ImportError:  # pragma: no cover - Linux target has resource
        return
    limit = memory_mb * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    if hasattr(resource, "RLIMIT_CORE"):
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def _render_worker(
    html: str,
    resources: dict[str, bytes],
    output_path: str,
    memory_mb: int,
    connection,
) -> None:
    try:
        _apply_limits(memory_mb)
        import logging

        logging.getLogger("weasyprint").setLevel(logging.ERROR)
        from weasyprint import HTML

        fetcher = _RestrictedFetcher(resources)
        pdf = HTML(string=html, url_fetcher=fetcher).write_pdf()
        if not isinstance(pdf, (bytes, bytearray)) or not bytes(pdf).startswith(b"%PDF-"):
            raise ValueError("renderer did not produce a PDF")
        with open(output_path, "xb") as output:
            output.write(pdf)
        connection.send(("ok", len(pdf)))
    except BaseException as exc:  # noqa: BLE001 - status crosses the process boundary
        try:
            connection.send(("failed", type(exc).__name__))
        except Exception:
            pass
    finally:
        try:
            connection.close()
        except Exception:
            pass


def render_pdf(
    composition,
    *,
    timeout_seconds: float = 120,
    memory_mb: int = 512,
    max_bytes: int = 50 * 1024 * 1024,
) -> bytes:
    """Render a composition to a real PDF in an isolated, bounded process."""
    html, resources = _validate_arguments(
        composition,
        timeout_seconds=timeout_seconds,
        memory_mb=memory_mb,
        max_bytes=max_bytes,
    )
    timeout = float(timeout_seconds)

    with TemporaryDirectory(prefix="itsm-report-") as directory:
        output_path = os.path.join(directory, "document.pdf")
        context = multiprocessing.get_context("spawn")
        receive, send = context.Pipe(duplex=False)
        process = context.Process(
            target=_render_worker,
            args=(html, resources, output_path, memory_mb, send),
        )
        process.daemon = False
        try:
            process.start()
        except Exception as exc:
            receive.close()
            send.close()
            raise RenderFailed("unable to start the isolated PDF renderer") from exc
        send.close()

        try:
            process.join(timeout)
            if process.is_alive():
                process.terminate()
                process.join(5)
                if process.is_alive():
                    process.kill()
                    process.join(5)
                raise RenderTimeout(f"PDF rendering timed out after {timeout:g}s")

            status = None
            try:
                if receive.poll(5):
                    status = receive.recv()
            except (EOFError, OSError):
                status = None
        finally:
            receive.close()

        if process.exitcode != 0:
            raise RenderFailed(
                f"PDF rendering failed with exit code {process.exitcode}"
            )
        if not status or not isinstance(status, tuple) or status[0] != "ok":
            detail = status[1] if isinstance(status, tuple) and len(status) > 1 else "unknown"
            raise RenderFailed(f"PDF rendering failed ({detail})")

        try:
            size = os.stat(output_path).st_size
        except OSError as exc:
            raise RenderFailed("PDF rendering did not produce an output file") from exc
        if size > max_bytes:
            raise RenderFailed("PDF exceeds the configured size limit")
        try:
            with open(output_path, "rb") as output:
                pdf = output.read(max_bytes + 1)
        except OSError as exc:
            raise RenderFailed("PDF output could not be read") from exc
        if len(pdf) > max_bytes:
            raise RenderFailed("PDF exceeds the configured size limit")
        if not pdf.startswith(b"%PDF-"):
            raise RenderFailed("PDF output is invalid")
        return pdf
