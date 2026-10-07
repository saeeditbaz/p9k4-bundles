import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.parse import quote


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def app_notes(body, app, version_name, app_count):
    body = (body or "").replace("\r\n", "\n")
    # Mixed releases must explicitly scope notes to each APK.
    sections = re.split(r"(?m)^## +(vpn|reseller) *$", body or "")
    for index in range(1, len(sections), 2):
        if sections[index] == app:
            return re.split(r"(?m)^## +", sections[index + 1], maxsplit=1)[0].strip()[:5000]
    if app_count == 1 and len(sections) == 1:
        return (body or "").strip()[:5000]
    return f"Version {version_name}"


def main():
    repo = os.environ["GITHUB_REPOSITORY"]
    policy = json.loads(os.environ["APK_POLICY"])
    tag = os.environ.get("RELEASE_TAG", "")
    endpoint = f"repos/{repo}/releases/tags/{quote(tag, safe='')}" if tag else f"repos/{repo}/releases/latest"
    release = json.loads(run("gh", "api", endpoint))
    if release["draft"] or release["prerelease"]:
        raise SystemExit("Only stable releases are supported")
    sdk = Path(os.environ["ANDROID_HOME"])
    tools = sorted((sdk / "build-tools").glob("*"), key=lambda p: tuple(int(n) for n in re.findall(r"\d+", p.name)))[-1]
    manifest = {"schema_version": 1, "release_id": release["id"], "tag": release["tag_name"], "apps": {}}
    app_count = sum(any(a["name"] == values[0] and a["state"] == "uploaded" for a in release["assets"]) for values in policy.values())
    with tempfile.TemporaryDirectory() as directory:
        for app, (filename, package, signer) in policy.items():
            if not re.fullmatch(r"[a-z0-9-]+\.apk", filename):
                raise SystemExit("Invalid asset filename")
            assets = [a for a in release["assets"] if a["name"] == filename and a["state"] == "uploaded"]
            if not assets:
                continue
            if len(assets) != 1:
                raise SystemExit("Duplicate package assets")
            asset = assets[0]
            run("gh", "release", "download", release["tag_name"], "--repo", repo, "--pattern", filename, "--dir", directory)
            path = Path(directory) / filename
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if asset.get("digest") != "sha256:" + digest:
                raise SystemExit("Downloaded package hash mismatch")
            certificate = run(str(tools / "apksigner"), "verify", "--print-certs", str(path))
            if re.findall(r"certificate SHA-256 digest: ([a-f0-9]+)", certificate) != [signer]:
                raise SystemExit("Unexpected package signer")
            badging = run(str(tools / "aapt"), "dump", "badging", str(path))
            info = re.search(r"package: name='([^']+)' versionCode='(\d+)' versionName='([^']+)'", badging)
            if not info or info[1] != package or not 1 <= int(info[2]) <= 2100000000:
                raise SystemExit("Unexpected package or version")
            notes = app_notes(release.get("body"), app, info[3], app_count)
            manifest["apps"][app] = {"package_name": package, "version_code": int(info[2]), "version_name": info[3],
                "asset_id": asset["id"], "sha256": digest, "release_notes": notes}
        if not manifest["apps"]:
            raise SystemExit("No recognized package assets")
        target = Path(directory) / "catalog.json"
        target.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        run("gh", "release", "upload", release["tag_name"], str(target), "--repo", repo, "--clobber")
        print("Verified catalog published")


if __name__ == "__main__":
    main()
