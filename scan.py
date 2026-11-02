"""shai-hulud-scan: a read-only check for the Shai-Hulud npm worm (the 2026 "ChainDrop" wave, plus the
file traces of the earlier waves).

It checks a folder on your machine (the default), or your GitHub account (--github):
  - every lockfile and installed package, against the published list of compromised versions
    (packages.txt);
  - the files the worm plants in repos it reaches: a VS Code task and a Claude Code hook that run its
    loader (setup.mjs), the payload itself, and a GitHub Actions workflow that dumps every secret;
  - a package.json that runs the loader on install;
  - with --github, also the public repos the worm creates under your account to upload what it stole.
It never changes, runs or installs anything. Python 3.10+, standard library only.

Usage:
  python3 scan.py ~/code                    # a folder and everything under it, node_modules included
  python3 scan.py "$(npm root -g)"          # your global npm packages
  read -rs "GITHUB_TOKEN?GitHub token: " && export GITHUB_TOKEN && python3 scan.py --github; unset GITHUB_TOKEN
  (that's zsh; in bash: read -rsp "GitHub token: " GITHUB_TOKEN && …)

Token: fine-grained, Repository access "All repositories", read-only Contents (Metadata is added
automatically), a short expiry. Without a token, --github --user NAME checks someone's public repos
(GitHub allows 60 requests an hour then: enough for a repo or two, with --repo).

Options:
  --github         check GitHub instead of a folder
  --user NAME      with --github and no token: whose public repos
  --repo OWNER/N   with --github: just this repo
  --out FILE       also write the findings as JSON
Exit status 1 if anything was found, so it can run in CI or on a schedule.
"""

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

API = "https://api.github.com"
TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()

COMPROMISED = {
    tuple(line.split())
    for line in Path(__file__).with_name("packages.txt").read_text().splitlines()
    if line.strip() and not line.startswith("#")
}
# SHA-256 of the worm's files, from Unit 42 and the CSA advisory.
HASHES = {
    "54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668": "the worm's loader",
    "fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb": "the worm's loader",
    "b27b82afa5f15512f3856e549fb83d873fd0049759a4b62ce64c8d7d4dc2c678": "the worm's loader",
    "9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc": "the worm's payload",
}
# The payload's names in this wave (math_init.js, Math_Symbol.js, router_runtime.js) and the last one.
PAYLOADS = {"math_init.js", "Math_Symbol.js", "router_runtime.js", "setup_bun.js", "bun_environment.js"}
LOADER = re.compile(r"\b(setup\.mjs|setup_bun\.js)\b")
# Strings from the payload, and the descriptions it gives the repos it uploads secrets to.
MARKERS = (b"thebeautifulmarchoftime", b"thebeautifulsnadsoftime", b"IfYouBlockThisAPIKeyItWillCrash")
EXFIL_DESCRIPTIONS = ("Shai-Hulud: Here We Go Again", "Sha1-Hulud: The Second Coming")
LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock"}
MAX_FILE = 50 * 1024 * 1024
calls = branches = 0


def spec_name(spec: str) -> str:
    """The package a yarn.lock entry is for: `foo@^1`, `"@s/p@npm:^1"`, or an alias `foo@npm:bar@^1`."""
    spec = spec.strip().strip('"')
    head, _, rest = spec.partition("@npm:")
    if rest and not rest[0].isdigit() and rest[0] not in "^~<>=*":
        head = rest
    return head[: head.index("@", 1)] if "@" in head[1:] else head


def locked(name: str, text: str) -> set[tuple[str, str]]:
    """Every (package, version) a lockfile pins."""
    if name.endswith(".json"):  # npm: v2/v3 list "packages", v1 nests "dependencies"
        data = json.loads(text)
        pairs = {
            (entry.get("name") or path.rsplit("node_modules/", 1)[-1], entry["version"])
            for path, entry in (data.get("packages") or {}).items()
            if path and isinstance(entry, dict) and "version" in entry
        }

        def walk(deps: dict) -> None:
            for package, entry in (deps or {}).items():
                pairs.add((package, entry.get("version", "")))
                walk(entry.get("dependencies"))

        walk(data.get("dependencies"))
        return pairs
    if name == "yarn.lock":  # `"foo@^1", foo@~1:` then an indented `version "1.2.3"` (v1) or `version: 1.2.3`
        pairs, names = set(), []
        for line in text.splitlines():
            if line and not line[0].isspace() and line.rstrip().endswith(":") and not line.startswith("#"):
                names = [spec_name(s) for s in line.rstrip()[:-1].split(",")]
            elif m := re.match(r'\s+version:?\s+"?([^"\s]+)', line):
                pairs |= {(n, m[1]) for n in names}
        return pairs
    if name == "pnpm-lock.yaml":  # `/foo/1.2.3:` (v5), `/foo@1.2.3:` (v6), `foo@1.2.3(peer@x):` (v9)
        return set(re.findall(r"^\s+'?/?((?:@[^/@\s']+/)?[^/@\s:'(]+)[@/](\d+\.\d+\.\d+[^\s:'(_]*)", text, re.M))
    # bun.lock: `"foo": ["foo@1.2.3", …]`
    return set(re.findall(r'"((?:@[^"/@]+/)?[^"/@\s]+)@(\d+\.\d+\.\d+[^"]*)"', text))


def wanted(path: str) -> bool:
    """Whether a file is one check() looks at, so everything else is never opened."""
    name = path.rsplit("/", 1)[-1]
    path = "/" + path
    return (
        name in LOCKFILES or name in PAYLOADS or name in ("package.json", "setup.mjs")
        or path.endswith(("/.vscode/tasks.json", "/.claude/settings.json", "/.claude/settings.local.json"))
        or ("/.github/workflows/" in path and name.endswith((".yml", ".yaml")))
    )


def check(path: str, size: int, read) -> list[str]:
    """What one file shows. read() returns its bytes."""
    name = path.rsplit("/", 1)[-1]
    if size > MAX_FILE:
        return []
    data = read()
    text = data.decode(errors="replace")
    if name in LOCKFILES:
        try:
            pairs = locked(name, text)
        except ValueError:
            return []
        return [f"{path} pins {p}@{v}, a compromised version" for p, v in sorted(pairs & COMPROMISED)]
    if name == "package.json":
        try:
            package = json.loads(text)
            scripts = package.get("scripts") or {}
        except (ValueError, AttributeError):
            return []
        found = []
        if any(LOADER.search(str(scripts.get(s, ""))) for s in ("preinstall", "install", "postinstall")):
            found.append(f"{path} runs the worm's loader on install")
        if "node_modules/" in path and (package.get("name"), package.get("version")) in COMPROMISED:
            found.append(f"{path}: {package['name']}@{package['version']} is installed, a compromised version")
        return found
    if name in PAYLOADS or name == "setup.mjs":
        if known := HASHES.get(hashlib.sha256(data).hexdigest()):
            return [f"{path} is {known} (a known hash)"]
        if any(m in data for m in MARKERS):
            return [f"{path} contains the worm's marker strings"]
        # Inside node_modules a name alone isn't enough: regenerate-unicode-properties ships a real
        # Math_Symbol.js (the Unicode category), and a compromised package is caught by its version.
        if re.search(r"(^|/)\.(claude|vscode)/", path) or (name in PAYLOADS and "node_modules/" not in path):
            return [f"{path}: the worm plants a file with this name here; look at it before anything runs it"]
        return []
    if name == "tasks.json" and LOADER.search(text):
        return [f"{path} runs the worm's loader when the folder opens in VS Code"]
    if name.startswith("settings") and LOADER.search(text):
        return [f"{path}: a Claude Code hook runs the worm's loader"]
    if "/.github/workflows/" in "/" + path and ("toJSON(secrets)" in text or name == "shai-hulud-workflow.yml"):
        return [f"{path} dumps every Actions secret (toJSON(secrets)): check it was you who added it"]
    return []


def scan_folder(root: str) -> tuple[list[str], dict]:
    found, counts = [], {"lockfiles": 0, "packages": 0}
    for folder, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d != ".git"]
        for file in files:
            path = os.path.join(folder, file)
            if not wanted(path):
                continue
            counts["lockfiles"] += file in LOCKFILES
            counts["packages"] += file == "package.json" and "node_modules" in folder
            try:
                found += check(path, os.path.getsize(path), Path(path).read_bytes)
            except OSError:
                pass
    return found, counts


def get(path: str, optional: bool = False):
    """One GET → (parsed JSON or None, Link header). None for 404/409 (missing, or an empty repo),
    and for 403 when optional (the token can't read that part)."""
    global calls
    calls += 1
    request = urllib.request.Request(path if path.startswith("http") else API + path)
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("X-GitHub-Api-Version", "2022-11-28")
    if TOKEN:
        request.add_header("Authorization", f"Bearer {TOKEN}")
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.load(response), response.headers.get("Link", "")
    except urllib.error.HTTPError as e:
        if e.code in (403, 429) and e.headers.get("X-RateLimit-Remaining") == "0":
            sys.exit("GitHub's rate limit is used up (without a token it's 60 requests an hour).")
        if e.code in (404, 409) or (optional and e.code == 403):
            return None, ""
        sys.exit(f"GitHub answered {e.code} for {path}: {e.read()[:300].decode(errors='replace')}")


def pages(path: str) -> list:
    items, url = [], path + ("&" if "?" in path else "?") + "per_page=100"
    while url:
        data, link = get(url)
        if data is None:
            return items
        items += data
        url = next((m[1] for m in re.finditer(r'<([^>]+)>;\s*rel="next"', link)), None)
    return items


blobs: dict[str, bytes] = {}


def blob(repo: str, sha: str) -> bytes:
    if sha not in blobs:  # the same lockfile is usually on every branch
        data, _ = get(f"/repos/{repo}/git/blobs/{sha}")
        blobs[sha] = base64.b64decode(data["content"]) if data else b""
    return blobs[sha]


def scan_repo(repo: dict) -> list[dict]:
    global branches
    name, rows = repo["full_name"], []
    if any(d in (repo.get("description") or "") for d in EXFIL_DESCRIPTIONS) or repo["name"].lower() == "shai-hulud":
        rows.append({"repo": name, "branch": None, "found": [
            f"made by the worm to upload stolen secrets ({'public' if not repo['private'] else 'private'}): "
            "your machine or token was compromised"
        ]})
    for branch in pages(f"/repos/{name}/branches"):
        branches += 1
        tree, _ = get(f"/repos/{name}/git/trees/{branch['commit']['sha']}?recursive=1")
        found = []
        for entry in (tree or {}).get("tree", []):
            if entry["type"] == "blob" and wanted(entry["path"]):
                found += check(entry["path"], entry.get("size", 0), lambda e=entry: blob(name, e["sha"]))
        if tree and tree.get("truncated"):
            print(f"  {name} {branch['name']}: too big to list fully; some files weren't checked", file=sys.stderr)
        if found:
            rows.append({"repo": name, "branch": branch["name"], "tip": branch["commit"]["sha"], "found": found})
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Read-only check for the Shai-Hulud npm worm.")
    parser.add_argument("paths", nargs="*", default=["."], help="folders to check (default: here)")
    parser.add_argument("--github", action="store_true", help="check GitHub instead of a folder")
    parser.add_argument("--user", help="with --github and no token: whose public repos")
    parser.add_argument("--repo", help="with --github: only this repo (owner/name)")
    parser.add_argument("--out", help="also write the findings as JSON to this file")
    args = parser.parse_args()

    if not args.github:
        found = []
        for root in args.paths:
            more, counts = scan_folder(root)
            found += more
            print(f"{root}: {counts['lockfiles']} lockfiles, {counts['packages']} installed packages checked.")
        print("\n".join(f"FOUND  {f}" for f in found) if found else "Nothing known found.")
        result, summary = found, {"paths": args.paths}
    else:
        if args.repo:
            repo, _ = get(f"/repos/{args.repo}")
            repos = [repo] if repo else sys.exit(f"Can't see {args.repo}")
        elif TOKEN:
            repos = pages("/user/repos?affiliation=owner,collaborator,organization_member&sort=full_name")
        elif args.user:
            print("No GITHUB_TOKEN: public repos only.", file=sys.stderr)
            repos = pages(f"/users/{args.user}/repos?type=owner&sort=full_name")
        else:
            sys.exit("Set GITHUB_TOKEN (see the top of this file), or give --user or --repo.")
        result = []
        for n, repo in enumerate(repos, 1):
            print(f"[{n}/{len(repos)}] {repo['full_name']}", file=sys.stderr)
            result += scan_repo(repo)
        summary = {"repos": len(repos), "branches": branches}
        print(f"{len(repos)} repos, {branches} branches checked.")
        for row in result:
            print(f"FOUND  {row['repo']}" + (f" {row['branch']} ({row['tip'][:7]})" if row["branch"] else ""))
            print("\n".join(f"       - {f}" for f in row["found"]))
        if not result:
            print("Nothing known found.")
        print(f"\n{calls} API requests.", file=sys.stderr)
    if args.out:
        with open(args.out, "w") as f:
            json.dump({**summary, "found": result}, f, indent=2)
    sys.exit(1 if result else 0)


if __name__ == "__main__":
    main()
