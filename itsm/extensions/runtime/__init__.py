"""Stdlib-only execution runtime for sandboxed extension modules.

Importing this package has no side effects: ``runner.py`` is started as a
standalone script and imports its siblings by name, while the host imports
``sqlite_store`` and ``sandbox`` for storage and availability checks.
"""
