#!/usr/bin/env python3
"""Package this checkout's Linux build for a private Landscape Kit v1 repository."""
import hashlib
import json
import os
import re
import subprocess
import tomllib
import zipfile
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[1]
    version = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version):
        raise SystemExit("Landscape Kit v1 requires a version without suffixes")
    binary = root / "target/release/landscape-webserver"
    dist = root / "landscape-webui/dist"
    if not binary.is_file() or not (dist / "index.html").is_file():
        raise SystemExit("Build the backend and frontend first")
    output = root / "lkit-repository"
    release = output / "releases" / version
    release.mkdir(parents=True, exist_ok=False)
    archive = release / "landscape-webserver-x86_64.zst"
    subprocess.run(["zstd", "-T0", "-10", str(binary), "-o", str(archive)], check=True)
    with zipfile.ZipFile(release / "static.zip", "w", zipfile.ZIP_DEFLATED) as bundle:
        for path in sorted(dist.rglob("*")):
            if path.is_symlink():
                raise SystemExit(f"Frontend must not contain symlinks: {path}")
            if path.is_file():
                bundle.write(path, "static/" + path.relative_to(dist).as_posix())

    def digest(path):
        with path.open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()

    def asset(path):
        return {"url": path.name, "size": path.stat().st_size,
                "sha256": digest(path)}

    manifest = {"protocol_version": 1, "version": version, "assets": {
        "webserver": {"x86_64": asset(archive)}, "static": asset(release / "static.zip")}}
    info = {"version": version, "custom_build": True,
            "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
            "repository": os.environ.get("GITHUB_REPOSITORY", "mrlj147/landscape"),
            "branch": os.environ.get("GITHUB_REF_NAME") or subprocess.check_output(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=root, text=True).strip(),
            "binary_sha256": digest(binary)}
    for path, value in [(output / "repository.json", {"protocol_version": 1}),
                        (release / "manifest.json", manifest), (release / "build-info.json", info)]:
        path.write_text(json.dumps(value, indent=2) + "\n")
    # Deliberately no mutable stable/latest channel: install this exact build.
    print(json.dumps(info))


if __name__ == "__main__":
    main()
