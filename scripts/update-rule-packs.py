#!/usr/bin/env python3
"""Update pinned Stable rule-pack release metadata for a review PR."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import urllib.error
import urllib.request


def request_json(url: str) -> dict[str, object]:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "BashLume-rule-sync"}
    if token := os.environ.get("GH_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as response:
        return json.load(response)


def sha256_url(url: str) -> str:
    headers = {"User-Agent": "BashLume-rule-sync"}
    if token := os.environ.get("GH_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    digest = hashlib.sha256()
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as response:
        while chunk := response.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=pathlib.Path, default=pathlib.Path("rules/packs.lock"))
    arguments = parser.parse_args()
    data = json.loads(arguments.lock.read_text(encoding="utf-8"))
    changed = False
    for name, pack in data["packs"].items():
        repository = pack["repository"]
        try:
            release = request_json(f"https://api.github.com/repos/{repository}/releases/latest")
        except urllib.error.HTTPError as error:
            if error.code == 404 and not pack.get("required", False):
                print(f"{name}: no Stable release yet")
                continue
            raise
        asset = next(
            (item for item in release["assets"] if item["name"] == pack["asset"]),
            None,
        )
        if asset is None:
            raise SystemExit(f"{repository} release {release['tag_name']} lacks {pack['asset']}")
        url = asset["browser_download_url"]
        digest = sha256_url(url)
        new = {
            "version": release["tag_name"],
            "url": url,
            "sha256": digest,
        }
        if any(pack.get(key) != value for key, value in new.items()):
            pack.update(new)
            changed = True
            print(f"{name}: {release['tag_name']} {digest}")
        else:
            print(f"{name}: already current")
    arguments.lock.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({"changed": changed}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
