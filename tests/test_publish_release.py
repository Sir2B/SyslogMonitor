"""Exercise release publication without modifying a GitHub release."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
PUBLISHER = ROOT / "packaging" / "publish_release.ps1"
PWSH = shutil.which("pwsh")
pytestmark = pytest.mark.skipif(PWSH is None, reason="PowerShell 7 is required")

GH_STUB = r"""
$global:releaseCreated = $false
$global:uploadCount = 0
function gh {
    $record = @{ args = @($args) }
    if ($args[1] -eq "edit") {
        $notesIndex = [array]::IndexOf($args, "--notes-file")
        $record["notes"] = Get-Content -LiteralPath $args[$notesIndex + 1] -Raw
    }
    ConvertTo-Json -InputObject $record -Compress -Depth 10 |
        Add-Content -LiteralPath $env:GH_LOG -Encoding utf8

    $global:LASTEXITCODE = 0
    switch ($args[1]) {
        "view" {
            if ($env:GH_LOOKUP_ERROR) {
                $global:LASTEXITCODE = 1
                Write-Output $env:GH_LOOKUP_ERROR
            } elseif ($env:GH_NEW_RELEASE -eq "1" -and -not $global:releaseCreated) {
                $global:LASTEXITCODE = 1
                Write-Output "release not found"
            } elseif ($env:GH_NEW_RELEASE -eq "1") {
                Write-Output '{"body":"Generated notes","assets":[]}'
            } else {
                Write-Output $env:GH_RELEASE_JSON
            }
        }
        "create" {
            if ($env:GH_FAIL_COMMAND -eq "create") {
                $global:LASTEXITCODE = 1
            } else {
                $global:releaseCreated = $true
            }
        }
        "upload" {
            $global:uploadCount++
            if ($env:GH_FAIL_COMMAND -eq "upload" -or
                ($env:GH_FAIL_COMMAND -eq "package-upload" -and $global:uploadCount -eq 2)) {
                $global:LASTEXITCODE = 1
            }
        }
        "edit" {
            if ($env:GH_FAIL_COMMAND -eq "edit") {
                $global:LASTEXITCODE = 1
            }
        }
        default { throw "Unexpected gh command: $($args -join ' ')" }
    }
}
& $env:PUBLISH_SCRIPT -Tag $env:RELEASE_TAG -Version $env:RELEASE_VERSION `
    -DistributionDir $env:DIST_PATH -Screenshot $env:SHOT_PATH -ScreenshotGalleryDir $env:GALLERY_PATH `
    -GalleryRemote $env:GALLERY_REMOTE
"""


@pytest.fixture
def release_files(tmp_path):
    dist = tmp_path / "dist"
    dist.mkdir()
    setup = dist / "SyslogMonitor-1.0.0-setup.exe"
    portable = dist / "SyslogMonitor-1.0.0-portable.zip"
    screenshot = tmp_path / "screenshot.png"
    for path in (setup, portable, screenshot):
        path.write_bytes(b"test asset")
    return dist, setup, portable, screenshot


def publish(tmp_path, release_files, *, release=None, tag="v1.0.0", lookup_error="", fail="",
            gallery=None, remote=None):
    dist, _setup, _portable, screenshot = release_files
    log_path = tmp_path / "gh.jsonl"
    env = os.environ.copy()
    env.update({
        "PUBLISH_SCRIPT": str(PUBLISHER),
        "RELEASE_TAG": tag,
        "RELEASE_VERSION": "1.0.0",
        "DIST_PATH": str(dist),
        "SHOT_PATH": str(screenshot),
        "GALLERY_PATH": str(gallery) if gallery is not None else "",
        "GALLERY_REMOTE": str(remote) if remote is not None else "",
        "GITHUB_REPOSITORY": "example/SyslogMonitor",
        "GH_LOG": str(log_path),
        "GH_NEW_RELEASE": "1" if release is None else "0",
        "GH_RELEASE_JSON": json.dumps(release),
        "GH_LOOKUP_ERROR": lookup_error,
        "GH_FAIL_COMMAND": fail,
    })
    result = subprocess.run(
        [PWSH, "-NoProfile", "-NonInteractive", "-Command", GH_STUB],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=30,
    )
    records = [json.loads(line) for line in log_path.read_text(encoding="utf-8-sig").splitlines()] \
        if log_path.exists() else []
    return result, records


def test_new_release_contains_all_assets_and_generated_notes(tmp_path, release_files):
    result, records = publish(tmp_path, release_files)
    assert result.returncode == 0, result.stderr
    assert [entry["args"][1] for entry in records] == ["view", "create", "view", "edit"]
    create = records[1]["args"]
    assert all(str(path) in create for path in release_files[1:])
    assert "--verify-tag" in create and "--generate-notes" in create
    assert "https://github.com/example/SyslogMonitor/releases/download/v1.0.0/screenshot.png" in records[3]["notes"]
    assert "Generated notes" in records[3]["notes"]


def test_existing_release_keeps_its_binaries(tmp_path, release_files):
    _dist, setup, portable, screenshot = release_files
    release = {"body": "Existing notes", "assets": [{"name": setup.name}, {"name": portable.name}]}
    result, records = publish(tmp_path, release_files, release=release)
    assert result.returncode == 0, result.stderr
    assert [entry["args"][1] for entry in records] == ["view", "upload", "edit"]
    assert str(screenshot) in records[1]["args"] and "--clobber" in records[1]["args"]
    assert "Existing notes" in records[2]["notes"]
    assert f"Keeping existing release asset: {setup.name}" in result.stdout
    assert f"Keeping existing release asset: {portable.name}" in result.stdout


@pytest.mark.parametrize("existing_release", [False, True])
def test_gallery_goes_to_branch_not_release(tmp_path, release_files, existing_release):
    gallery = tmp_path / "screenshots"
    gallery.mkdir()
    images = [gallery / f"screenshot-{name}.png" for name in ("light", "history", "analysis")]
    for image in images:
        image.write_bytes(b"test image")
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--quiet", "--bare", str(remote)], check=True)
    release = ({"body": "", "assets": [{"name": path.name} for path in release_files[1:3]]}
               if existing_release else None)
    result, records = publish(tmp_path, release_files, release=release, gallery=gallery, remote=remote)
    assert result.returncode == 0, result.stderr
    assert all(str(image) not in entry["args"] for entry in records for image in images)
    files = subprocess.run(["git", f"--git-dir={remote}", "ls-tree", "--name-only", "screenshots"],
                           capture_output=True, text=True, check=True).stdout.split()
    assert sorted(files) == sorted(image.name for image in images)
    notes = records[-1]["notes"]
    assert 'width="640"' in notes


def test_empty_gallery_fails_before_publishing(tmp_path, release_files):
    gallery = tmp_path / "screenshots"
    gallery.mkdir()
    result, records = publish(tmp_path, release_files, gallery=gallery)
    assert result.returncode != 0
    assert "No gallery screenshots found" in result.stderr
    assert records == []

@pytest.mark.parametrize("existing_indexes", [(), (1,), (2,)])
def test_existing_release_gets_only_missing_packages(tmp_path, release_files, existing_indexes):
    packages = release_files[1:3]
    existing = [release_files[index] for index in existing_indexes]
    missing = [package for package in packages if package not in existing]
    image = "https://github.com/example/SyslogMonitor/releases/download/v1.0.0/screenshot.png"
    release = {"body": f"![Screenshot]({image})", "assets": [{"name": path.name} for path in existing]}
    result, records = publish(tmp_path, release_files, release=release)
    assert result.returncode == 0, result.stderr
    assert [entry["args"][1] for entry in records] == ["view", "upload", "upload"]
    assert all(str(path) in records[2]["args"] for path in missing)
    assert all(str(path) not in records[2]["args"] for path in existing)
    assert "--clobber" not in records[2]["args"]


@pytest.mark.parametrize("asset_index,empty", [(1, False), (2, True), (3, False)])
def test_missing_or_empty_asset_fails_before_publishing(tmp_path, release_files, asset_index, empty):
    asset = release_files[asset_index]
    if empty:
        asset.write_bytes(b"")
    else:
        asset.unlink()
    result, records = publish(tmp_path, release_files)
    assert result.returncode != 0
    assert "release asset" in result.stderr.lower()
    assert records == []


def test_version_mismatch_fails_before_publishing(tmp_path, release_files):
    result, records = publish(tmp_path, release_files, tag="v1.0.1")
    assert result.returncode != 0
    assert "does not match" in result.stderr
    assert records == []


def test_lookup_failure_does_not_create_release(tmp_path, release_files):
    result, records = publish(tmp_path, release_files, lookup_error="GitHub API unavailable")
    assert result.returncode != 0
    assert "GitHub API unavailable" in result.stderr
    assert [entry["args"][1] for entry in records] == ["view"]


@pytest.mark.parametrize("command", ["create", "upload", "edit"])
def test_github_failures_are_reported(tmp_path, release_files, command):
    release = {"body": "", "assets": []} if command == "upload" else None
    result, records = publish(tmp_path, release_files, release=release, fail=command)
    assert result.returncode != 0
    assert records[-1]["args"][1] == command
    assert "Could not" in result.stderr


def test_package_upload_failure_is_reported(tmp_path, release_files):
    release = {"body": "Existing notes", "assets": []}
    result, records = publish(tmp_path, release_files, release=release, fail="package-upload")
    assert result.returncode != 0
    assert "Could not upload the Windows packages" in result.stderr
    assert [entry["args"][1] for entry in records] == ["view", "upload", "upload"]
