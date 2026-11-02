# Contributing to shai-hulud-scan

Thanks for helping keep this useful. Issues and pull requests are both welcome.

## The rules the scanner keeps

- **Read-only.** It never writes to GitHub, and never runs, installs or imports the code it looks at.
- **Standard library only**, Python 3.10 or later, so anyone can run it without installing anything.
- **Every indicator needs a public source**: a vendor report, an advisory, or a write-up. Link it in the pull request.
- **No false alarms on common files.** If a rule matches by name, check a normal project doesn't ship a file with that name.

## Reporting

- **It flagged something that's fine (false positive)**, or **missed something it should catch**: open an issue with the matching template.
- **A security problem in the scanner itself** (for example, it could leak a token, or run code it reads): don't open an issue; see [SECURITY.md](SECURITY.md).
- **You think you've been hit**: follow [If it finds something](../README.md#if-it-finds-something) in the README first.

Never paste a token, a secret, or malware into an issue or pull request. The scanner's output can include private repo names and file paths, so edit those out if they matter to you.

## Changing the code

1. Fork, and make one change per pull request.
2. Add a test to `test_scan.py` for any rule you add or change: one case it should catch, and one it shouldn't.
3. Run the tests, which need no network: `python3 -m unittest test_scan`.
4. Run it on a folder or repo you know, and say what you checked in the pull request.
- Package versions go in `packages.txt`, one `name version` per line, kept sorted. Add the list you took them from to the header.

## Code of conduct

Everyone taking part is expected to follow the [code of conduct](CODE_OF_CONDUCT.md).
