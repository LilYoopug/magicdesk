#!/usr/bin/env python3
"""Validate release metadata against the selected repository channel."""

import argparse
from pathlib import Path
import re
import subprocess


VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}")


def git(repo, *arguments):
    return subprocess.check_output(
        ["git", "-C", str(repo), *arguments], text=True,
        stderr=subprocess.PIPE).strip()


def version_key(name):
    if not VERSION.fullmatch(name):
        raise ValueError(f"Invalid numbered version: {name}")
    parts = tuple(map(int, name.split(".")))
    return parts + (0,) * (4 - len(parts))


def properties(text):
    values = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if separator and key.strip() in ("magicDeskVersionName", "magicDeskVersionCode"):
            key = key.strip()
            if key in values:
                raise ValueError(f"Duplicate version property: {key}")
            values[key] = value.strip()
    try:
        name = values["magicDeskVersionName"]
        code = int(values["magicDeskVersionCode"])
    except (KeyError, ValueError) as error:
        raise ValueError("Missing or invalid version properties") from error
    version_key(name)
    if not 0 < code <= 2147483647:
        raise ValueError("versionCode must be a positive Java int")
    return name, code


def released_code(repo, tag):
    try:
        text = git(repo, "show", f"refs/tags/{tag}:gradle.properties")
    except subprocess.CalledProcessError:
        text = ""
    if "magicDeskVersionCode=" in text:
        name, code = properties(text)
        if tag != f"v{name}":
            raise ValueError(f"Release tag {tag} disagrees with its version properties")
        return code
    # Older release tags stored their version directly in app/build.gradle.
    text = git(repo, "show", f"refs/tags/{tag}:app/build.gradle")
    match = re.search(r"\bversionCode\s+(?:=\s*)?([0-9]+)", text)
    if not match:
        raise ValueError(f"No versionCode in {tag}")
    return int(match[1])


def verify(repo, channel, tag=None, main_ref="refs/remotes/origin/main"):
    if channel not in ("main", "develop", "release"):
        raise ValueError(f"Unknown channel: {channel}")
    if tag is not None and channel != "release":
        raise ValueError("A release tag requires the release channel")
    name, code = properties((repo / "gradle.properties").read_text(encoding="utf-8"))
    if channel == "release":
        head = git(repo, "rev-parse", "HEAD")
        main = git(repo, "rev-parse", "--verify", f"{main_ref}^{{commit}}")
        if subprocess.run(["git", "-C", str(repo), "merge-base", "--is-ancestor",
                           head, main], check=False).returncode != 0:
            raise ValueError("Release commit must belong to main")
        if tag is not None:
            if tag != f"v{name}":
                raise ValueError(f"Release tag must be v{name}, got {tag}")
            if git(repo, "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}") != head:
                raise ValueError("Release tag must point to the checked-out commit")

    tags = [item for item in git(repo, "tag", "--list", "v*").splitlines()
            if VERSION.fullmatch(item[1:]) and item != tag]
    if not tags:
        raise ValueError("No numbered release baseline; fetch the complete tag history")
    latest = max(tags, key=lambda item: version_key(item[1:]))
    previous_code = released_code(repo, latest)
    current, previous = version_key(name), version_key(latest[1:])
    newer_required = channel == "develop" or tag is not None
    if current < previous or (newer_required and current == previous):
        relation = "newer than" if newer_required else "at least"
        raise ValueError(f"{channel} version {name} must be {relation} {latest[1:]}")
    if current == previous:
        if code != previous_code:
            raise ValueError("An unchanged release version must retain its versionCode")
    elif code <= previous_code:
        raise ValueError(f"versionCode {code} must be greater than {previous_code}")
    return f"{channel}: {name} ({code}); release baseline {latest} ({previous_code})"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--channel", required=True, choices=("main", "develop", "release"))
    parser.add_argument("--tag")
    args = parser.parse_args()
    try:
        print(verify(Path(__file__).resolve().parents[1], args.channel, args.tag))
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Version verification failed: {error}\n")


if __name__ == "__main__":
    main()
