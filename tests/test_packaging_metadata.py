"""Independent core/optional dependency and reviewed CVE policies."""
import tomllib
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

REPO_ROOT = Path(__file__).resolve().parents[1]


def _manifest():
    return tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def _exclude_newer_package():
    """Canonical-name -> cutoff (False, or an ISO timestamp). The table is
    written by hand, so keys may use ``_`` or ``-``; PEP 503 canonicalisation
    is what uv itself compares against the index name."""
    return {
        canonicalize_name(name): cutoff
        for name, cutoff in _manifest()["tool"]["uv"]["exclude-newer-package"].items()
    }


def _exact_pins(manifest):
    """Every (canonical name, pinned version) behind an ``==`` specifier,
    across core, extras, dependency groups and build-system.requires."""
    pins: dict[str, set] = {}

    def harvest(specs):
        for raw in specs or []:
            if not isinstance(raw, str):
                continue  # dependency-group include entries
            requirement = Requirement(raw)
            versions = {
                spec.version
                for spec in requirement.specifier
                if spec.operator == "==" and "*" not in spec.version
            }
            if versions:
                pins.setdefault(canonicalize_name(requirement.name), set()).update(versions)

    project = manifest["project"]
    harvest(project.get("dependencies"))
    for specs in project.get("optional-dependencies", {}).values():
        harvest(specs)
    for group in (manifest.get("dependency-groups") or {}).values():
        harvest(group if isinstance(group, list) else None)
    harvest(manifest.get("build-system", {}).get("requires"))
    return pins


def test_exact_pinned_deps_exempt_from_exclude_newer():
    # An ``==X.Y.Z`` pin cannot float, so exclude-newer adds no float
    # protection for it while still bricking resolution on any index whose
    # simple API omits per-file upload-time (uv then assumes "newer than the
    # cutoff"). #132558: pilk==0.2.4 bricked `uv lock` on the Tsinghua mirror.
    table = _exclude_newer_package()
    missing = {
        name: sorted(versions)
        for name, versions in _exact_pins(_manifest()).items()
        if name not in table
    }
    assert not missing, (
        "exact-pinned dependencies missing from [tool.uv.exclude-newer-package]; "
        f"add each as `false`: {missing}"
    )


def test_build_system_requires_exempt_from_exclude_newer():
    # Isolated build environments resolve under the same cutoff, so an
    # exact-pinned build requirement can fail to build at all.
    table = _exclude_newer_package()
    build_requires = _manifest()["build-system"]["requires"]
    missing = [
        Requirement(raw).name
        for raw in build_requires
        if not isinstance(raw, str)
        or canonicalize_name(Requirement(raw).name) not in table
    ]
    assert not missing, (
        "build-system.requires missing from [tool.uv.exclude-newer-package]; "
        f"add each as `false`: {missing}"
    )


def test_test_dependencies_are_group_only_in_manifest_and_lock():
    manifest = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    lock = tomllib.loads((REPO_ROOT / "uv.lock").read_text(encoding="utf-8"))
    hermes = next(package for package in lock["package"] if package["name"] == manifest["project"]["name"])
    assert manifest["tool"]["uv"]["default-groups"] == []
    assert "dev" in manifest["dependency-groups"]
    assert "dev" not in manifest["project"]["optional-dependencies"]
    assert "dev" in hermes["dev-dependencies"]
    assert "dev" not in hermes.get("optional-dependencies", {})


def test_core_and_optional_speech_dependencies():
    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    core = {Requirement(dep).name for dep in project["dependencies"]}
    assert "packaging" in core  # Runtime code imports it directly, not transitively.
    assert "faster-whisper" not in core
    assert "faster-whisper" in {
        Requirement(dep).name for dep in project["optional-dependencies"]["stt-whisper"]
    }


def test_starlette_server_pins_and_lock_exclude_cve_2026_48710():
    # BadHost's reviewed fixed boundary is independent of today's exact pin.
    floor = Version("1.0.1")
    metadata = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    lock = tomllib.loads((REPO_ROOT / "uv.lock").read_text(encoding="utf-8"))
    found = set()
    for extra, specs in metadata["project"]["optional-dependencies"].items():
        for requirement in map(Requirement, specs):
            if requirement.name != "starlette":
                continue
            pins = list(requirement.specifier)
            assert len(pins) == 1 and pins[0].operator == "==", (extra, requirement)
            assert Version(pins[0].version) >= floor, (extra, requirement)
            found.add(extra)
    assert {"web", "mcp", "computer-use"} <= found
    dev = [req for req in map(Requirement, metadata["dependency-groups"]["dev"])
           if req.name == "starlette"]
    assert len(dev) == 1
    pins = list(dev[0].specifier)
    assert len(pins) == 1 and pins[0].operator == "==" and Version(pins[0].version) >= floor
    versions = [Version(row["version"]) for row in lock["package"] if row["name"] == "starlette"]
    assert versions and all(version >= floor for version in versions)
