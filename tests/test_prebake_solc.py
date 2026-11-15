"""Fail-closed tests for the Solidity compiler prebake manifest."""

import pytest

from sandbox.prebake_solc import TARGET_VERSIONS, index_target_builds


def _manifest():
    return {
        "builds": [
            {
                "version": version,
                "path": f"solc-linux-amd64-v{version}",
                "sha256": "a" * 64,
            }
            for version in TARGET_VERSIONS
        ]
    }


def test_manifest_indexes_every_pinned_compiler_and_normalizes_checksums():
    manifest = _manifest()
    manifest["builds"][0]["sha256"] = "0x" + "A" * 64

    indexed = index_target_builds(manifest)

    assert list(indexed) == TARGET_VERSIONS
    assert indexed[TARGET_VERSIONS[0]]["sha256"] == "a" * 64


def test_manifest_missing_a_target_compiler_fails_closed():
    manifest = _manifest()
    manifest["builds"] = manifest["builds"][:-1]

    with pytest.raises(ValueError, match="missing target versions"):
        index_target_builds(manifest)


@pytest.mark.parametrize("checksum", ["", "not-a-digest", "a" * 63, "g" * 64])
def test_manifest_missing_or_invalid_checksum_fails_closed(checksum):
    manifest = _manifest()
    manifest["builds"][0]["sha256"] = checksum

    with pytest.raises(ValueError, match="SHA256 checksum"):
        index_target_builds(manifest)


def test_manifest_rejects_unsafe_binary_paths():
    manifest = _manifest()
    manifest["builds"][0]["path"] = "../unexpected-binary"

    with pytest.raises(ValueError, match="binary path"):
        index_target_builds(manifest)


def test_manifest_requires_a_builds_list():
    with pytest.raises(ValueError, match="builds list"):
        index_target_builds({"builds": None})
