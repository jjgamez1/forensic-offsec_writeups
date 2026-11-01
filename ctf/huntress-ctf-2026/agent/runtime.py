"""Shared Python-environment selection and dependency preflight helpers."""

from __future__ import annotations

import importlib
import importlib.metadata
import os
import pathlib
import re
import shutil
import sys
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parent.parent
AGENT_DIR = ROOT / "agent"
VENV_DIR = AGENT_DIR / ".venv"
VENV_PYTHON = VENV_DIR / "bin" / "python"
REQUIREMENTS_PATH = AGENT_DIR / "requirements.txt"
FALLBACK_IMPORTS = {
    "pycryptodomex": ("Cryptodome",),
}
SYSTEM_TOOLS = ("readelf", "objdump", "objcopy")


class RuntimeEnvironmentError(RuntimeError):
    """The configured CTF Python environment is missing or incomplete."""


def configured_python() -> pathlib.Path:
    if not VENV_PYTHON.is_file():
        raise RuntimeEnvironmentError(
            f"Configured environment is missing its interpreter: {VENV_PYTHON}"
        )
    return VENV_PYTHON


def running_in_configured_environment() -> bool:
    return pathlib.Path(sys.prefix).resolve() == VENV_DIR.resolve()


def reexec_in_configured_environment() -> None:
    """Replace a system-Python process with the repository's configured venv."""
    if running_in_configured_environment():
        return
    python = configured_python()
    original = getattr(sys, "orig_argv", None)
    arguments = list(original[1:]) if original else [sys.argv[0], *sys.argv[1:]]
    os.execv(str(python), [str(python), *arguments])


def _parse_requirement(line: str, line_number: int) -> tuple[str, str | None]:
    match = re.fullmatch(
        r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:==\s*([A-Za-z0-9][A-Za-z0-9.!+_-]*))?\s*",
        line,
    )
    if not match:
        raise RuntimeEnvironmentError(
            f"Unsupported requirements.txt entry on line {line_number}"
        )
    return match.group(1), match.group(2)


def dependency_preflight() -> dict[str, Any]:
    """Verify every Python requirement is installed at its pin and imports."""
    report: dict[str, Any] = {
        "python": sys.executable,
        "prefix": sys.prefix,
        "requirements_file": str(REQUIREMENTS_PATH.relative_to(ROOT)),
        "requirements": [],
        "system_tools": {},
        "errors": [],
    }
    try:
        lines = REQUIREMENTS_PATH.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        report["errors"].append(f"Cannot read {REQUIREMENTS_PATH.name}")
        report["passed"] = False
        return report

    for line_number, line in enumerate(lines, 1):
        content = line.split("#", 1)[0].strip()
        if not content:
            continue
        try:
            name, required_version = _parse_requirement(content, line_number)
        except RuntimeEnvironmentError as exc:
            report["errors"].append(str(exc))
            continue

        item: dict[str, Any] = {
            "distribution": name,
            "required_version": required_version,
            "installed_version": None,
            "imports": [],
            "ok": False,
        }
        try:
            distribution = importlib.metadata.distribution(name)
            installed_version = distribution.version
            item["installed_version"] = installed_version
            module_text = distribution.read_text("top_level.txt")
            modules = (
                tuple(
                    module.strip()
                    for module in module_text.splitlines()
                    if module.strip()
                )
                if module_text
                else FALLBACK_IMPORTS.get(
                    name.casefold().replace("_", "-"),
                    (re.sub(r"[-.]+", "_", name),),
                )
            )
            for module in modules:
                importlib.import_module(module)
                item["imports"].append(module)
            version_ok = (
                required_version is None or installed_version == required_version
            )
            item["ok"] = version_ok and bool(item["imports"])
            if not version_ok:
                report["errors"].append(
                    f"{name} version {installed_version} is installed; "
                    f"requirements.txt pins {required_version}"
                )
        except (importlib.metadata.PackageNotFoundError, ImportError, OSError) as exc:
            report["errors"].append(
                f"{name} is missing or cannot import ({type(exc).__name__})"
            )
        report["requirements"].append(item)

    for tool in SYSTEM_TOOLS:
        location = shutil.which(tool)
        report["system_tools"][tool] = location
        if location is None:
            report["errors"].append(f"Required system tool {tool} is unavailable")

    report["passed"] = not report["errors"]
    return report


def format_preflight_errors(report: dict[str, Any]) -> str:
    errors = report.get("errors", [])
    return "; ".join(str(error) for error in errors) or "unknown preflight failure"
