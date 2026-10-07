#!/usr/bin/env python3
"""Analyze the inert PowerShell triage fixtures without executing PowerShell."""

import argparse
import base64
import json
import pathlib
import re
import zipfile


SCENARIO_TECHNIQUE = {
    "resource_hijacking": "T1496",
    "synthetic_collection": "T1555.003",
    "synthetic_impact": "T1486",
}


def read_samples(path, password):
    if path.is_dir():
        return {
            item.name: item.read_text(encoding="utf-8", errors="replace")
            for item in sorted(path.glob("*.ps1"))
        }

    try:
        import pyzipper
    except ImportError:
        try:
            with zipfile.ZipFile(path) as archive:
                return {
                    pathlib.PurePosixPath(name).name: archive.read(name).decode(
                        "utf-8", errors="replace"
                    )
                    for name in archive.namelist()
                    if name.lower().endswith(".ps1")
                }
        except (RuntimeError, NotImplementedError) as exc:
            raise SystemExit(
                "This ZIP uses AES encryption. Install pyzipper "
                "(python3 -m pip install pyzipper) and rerun the script."
            ) from exc

    with pyzipper.AESZipFile(path) as archive:
        archive.pwd = password.encode("utf-8")
        return {
            pathlib.PurePosixPath(name).name: archive.read(name).decode(
                "utf-8", errors="replace"
            )
            for name in archive.namelist()
            if name.lower().endswith(".ps1")
        }


def decode_descriptor(source, filename):
    match = re.search(
        r"FromBase64String\s*\(\s*['\"]([A-Za-z0-9+/=]+)['\"]\s*\)",
        source,
        flags=re.IGNORECASE,
    )
    if not match:
        raise ValueError(f"{filename}: no embedded Base64 descriptor found")

    try:
        decoded = base64.b64decode(match.group(1), validate=True).decode("utf-8")
        descriptor = json.loads(decoded)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{filename}: embedded descriptor is not valid Base64 JSON") from exc

    native_types = {
        item.lower()
        for item in re.findall(r"\[([A-Za-z][A-Za-z0-9_.]+)\]", source)
    }
    return descriptor, native_types


def classify(descriptor, native_types):
    values = descriptor
    collection_items = values.get("c")

    if (
        isinstance(values.get("c"), str)
        and values["c"].lower().startswith("wallet_")
        and any("diagnostics.process" in item for item in native_types)
    ):
        scenario = "resource_hijacking"
        indicators = {
            "url": values.get("b"),
            "wallet": values.get("c"),
            "mutex": values.get("h"),
        }
    elif (
        isinstance(values.get("b"), str)
        and values["b"].startswith(".")
        and isinstance(values.get("c"), str)
        and values["c"].lower().startswith("recovery-")
        and any("security.cryptography.aes" in item for item in native_types)
    ):
        scenario = "synthetic_impact"
        indicators = {
            "extension": values.get("b"),
            "recovery_note": values.get("c"),
            "url": values.get("d"),
        }
    elif (
        isinstance(collection_items, list)
        and any(str(item).lower() in {"login data", "cookies"} for item in collection_items)
        and any("compression.zipfile" in item for item in native_types)
    ):
        scenario = "synthetic_collection"
        indicators = {
            "url": values.get("b"),
            "first_filename": next(
                (item for item in collection_items if isinstance(item, str)), None
            ),
            "user_agent": values.get("f"),
        }
    else:
        raise ValueError("Could not classify the PowerShell sample from its decoded fields")

    if not all(value is not None for value in indicators.values()):
        raise ValueError(f"Incomplete indicator set for scenario {scenario}")

    return {
        "scenario": scenario,
        "attack_technique": SCENARIO_TECHNIQUE[scenario],
        **indicators,
    }


def answer_fields(results):
    resource = results["resource-sample.ps1"]
    collection = results["collection-sample.ps1"]
    impact = results["impact-sample.ps1"]
    return {
        "resource-scenario": resource["scenario"],
        "resource-attack": resource["attack_technique"],
        "resource-url": resource["url"],
        "resource-wallet": resource["wallet"],
        "resource-mutex": resource["mutex"],
        "collection-scenario": collection["scenario"],
        "collection-attack": collection["attack_technique"],
        "collection-url": collection["url"],
        "collection-file": collection["first_filename"],
        "collection-user-agent": collection["user_agent"],
        "impact-scenario": impact["scenario"],
        "impact-attack": impact["attack_technique"],
        "impact-extension": impact["extension"],
        "impact-note": impact["recovery_note"],
        "impact-url": impact["url"],
    }


def main():
    parser = argparse.ArgumentParser(
        description="Extract scenario classifications and indicators from inert PowerShell samples."
    )
    parser.add_argument("input", type=pathlib.Path, help="ZIP archive or directory of .ps1 files")
    parser.add_argument(
        "--password",
        default="infected",
        help="password for an AES-encrypted ZIP (default: infected)",
    )
    args = parser.parse_args()

    samples = read_samples(args.input, args.password)
    expected = {"resource-sample.ps1", "collection-sample.ps1", "impact-sample.ps1"}
    missing = expected - samples.keys()
    if missing:
        raise SystemExit("Missing expected sample(s): " + ", ".join(sorted(missing)))

    analyses = {}
    for filename in sorted(expected):
        descriptor, native_types = decode_descriptor(samples[filename], filename)
        analyses[filename] = classify(descriptor, native_types)

    print(
        json.dumps(
            {"analyses": analyses, "answers": answer_fields(analyses)},
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
