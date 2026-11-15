#!/usr/bin/env python3
"""
Pre-bakes and verifies solc compiler binaries for Solidity 0.8.19 - 0.8.28.
Downloads official Linux amd64 binaries from binaries.soliditylang.org,
validates cryptographic SHA256 checksums, and configures them for both
Foundry (svm) and Slither (solc-select) with zero network roundtrips.
"""
import hashlib
import json
import os
import re
import sys
import urllib.request

TARGET_VERSIONS = [f"0.8.{i}" for i in range(19, 29)]
LIST_URL = "https://binaries.soliditylang.org/linux-amd64/list.json"
BASE_BINARY_URL = "https://binaries.soliditylang.org/linux-amd64/"


def index_target_builds(data):
    """Validate the official manifest before any compiler is installed."""
    if not isinstance(data, dict) or not isinstance(data.get("builds"), list):
        raise ValueError("Solidity release manifest has no valid builds list")

    builds_by_version = {}
    for build in data["builds"]:
        if not isinstance(build, dict):
            continue
        version = build.get("version")
        if version in TARGET_VERSIONS and version not in builds_by_version:
            rel_path = build.get("path")
            checksum = str(build.get("sha256") or "").lower().removeprefix("0x")
            if (
                not isinstance(rel_path, str)
                or not rel_path
                or rel_path.startswith("/")
                or ".." in rel_path.split("/")
            ):
                raise ValueError(f"Invalid official binary path for solc {version}")
            if not re.fullmatch(r"[0-9a-f]{64}", checksum):
                raise ValueError(f"Missing or invalid SHA256 checksum for solc {version}")
            validated = dict(build)
            validated["sha256"] = checksum
            builds_by_version[version] = validated

    missing = [version for version in TARGET_VERSIONS if version not in builds_by_version]
    if missing:
        raise ValueError(
            "Solidity release manifest is missing target versions: " + ", ".join(missing)
        )
    return builds_by_version


def download_and_verify_solc():
    print(f"[*] Fetching Solidity release list from {LIST_URL}...")
    req = urllib.request.Request(LIST_URL, headers={"User-Agent": "Mozilla/5.0 (Aegis-RLVR Prebake)"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(f"[!] Failed to fetch solc manifest: {e}")
        sys.exit(1)

    builds_by_version = index_target_builds(data)
    print(f"[*] Found {len(builds_by_version)} target solc versions to pre-bake.")

    for v in TARGET_VERSIONS:
        build_info = builds_by_version[v]
        rel_path = build_info["path"]
        expected_sha = build_info["sha256"]
        binary_url = BASE_BINARY_URL + rel_path

        # Target directory for Foundry svm: ~/.svm/{version}/solc-{version}
        home_dir = os.path.expanduser("~")
        svm_dir = os.path.join(home_dir, ".svm", v)
        os.makedirs(svm_dir, exist_ok=True)
        dest_binary = os.path.join(svm_dir, f"solc-{v}")

        # Target directory for solc-select: ~/.solc-select/artifacts/solc-{v}/solc-{v}
        solc_select_dir = os.path.join(home_dir, ".solc-select", "artifacts", f"solc-{v}")
        os.makedirs(solc_select_dir, exist_ok=True)
        solc_select_binary = os.path.join(solc_select_dir, f"solc-{v}")

        # Reuse a verified svm binary, but do not skip solc-select registration:
        # both stores must be populated even when the Foundry cache is warm.
        binary_bytes = None
        if os.path.isfile(dest_binary):
            with open(dest_binary, "rb") as f:
                existing_bytes = f.read()
            existing_sha = hashlib.sha256(existing_bytes).hexdigest()
            if existing_sha == expected_sha:
                binary_bytes = existing_bytes
                print(f"[✓] solc {v} already cached and verified (SHA256: {existing_sha[:12]}...)")

        if binary_bytes is None:
            print(f"[+] Downloading solc {v} from {binary_url}...")
            bin_req = urllib.request.Request(binary_url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(bin_req, timeout=60) as resp:
                binary_bytes = resp.read()

            # Cryptographic Checksum Verification (Point 6)
            computed_sha = hashlib.sha256(binary_bytes).hexdigest()
            if computed_sha != expected_sha:
                raise ValueError(
                    f"FATAL: Checksum mismatch for solc {v}!\n"
                    f"Expected: {expected_sha}\n"
                    f"Computed: {computed_sha}"
                )

            with open(dest_binary, "wb") as f:
                f.write(binary_bytes)
            os.chmod(dest_binary, 0o755)

        # Ensure the solc-select artifact exists and matches the verified binary.
        expected_artifact_sha = hashlib.sha256(binary_bytes).hexdigest()
        artifact_ok = False
        if os.path.isfile(solc_select_binary):
            with open(solc_select_binary, "rb") as f:
                artifact_ok = hashlib.sha256(f.read()).hexdigest() == expected_artifact_sha
        if not artifact_ok:
            try:
                if os.path.lexists(solc_select_binary):
                    os.unlink(solc_select_binary)
                os.symlink(dest_binary, solc_select_binary)
            except OSError:
                with open(solc_select_binary, "wb") as f:
                    f.write(binary_bytes)
                os.chmod(solc_select_binary, 0o755)

        print(f"[✓] solc {v} registered for Foundry and solc-select [SHA256: {expected_artifact_sha[:12]}...]")

    # solc-select's wrapper reads this file to resolve the global compiler.
    # Keep the default aligned with the project's Solidity 0.8.20 target.
    default_version = "0.8.20"
    if default_version not in TARGET_VERSIONS:
        raise ValueError(f"Default solc version {default_version} is not pre-baked")
    solc_select_config = os.path.join(os.path.expanduser("~"), ".solc-select")
    os.makedirs(solc_select_config, exist_ok=True)
    with open(os.path.join(solc_select_config, "global-version"), "w", encoding="utf-8") as f:
        f.write(default_version + "\n")

    print(f"[*] All target solc versions pre-baked; solc-select global version set to {default_version}.")


if __name__ == "__main__":
    download_and_verify_solc()
