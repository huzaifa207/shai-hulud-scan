# shai-hulud-scan

A read-only check for the **Shai-Hulud** npm worm, including its 2026 wave (**ChainDrop**), which has published 2,300+ infected versions of 490 packages so far, such as `keyv`, `cacheable` and `flat-cache`. One install of an infected version runs a `preinstall` script that steals your credentials (npm, GitHub, cloud, SSH and more), republishes every package your npm token can publish with the worm added, and commits a copy of itself to the GitHub repos it can reach. It changes nothing; it only reads.

It checks a folder on your machine, or your whole GitHub account, for:

- **compromised versions** in your lockfiles (`package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` v1 and Berry, `pnpm-lock.yaml`, `bun.lock`) and in what's installed in `node_modules`, against the 2,343 published versions in [`packages.txt`](packages.txt);
- **the files the worm commits to repos:**
  - `.vscode/tasks.json` with a task that runs `node .claude/setup.mjs` when the folder opens;
  - `.claude/settings.json` with a Claude Code `SessionStart` hook that runs `node .vscode/setup.mjs`;
  - the loader and payload (`setup.mjs`, `math_init.js`, `Math_Symbol.js`, and `setup_bun.js` / `bun_environment.js` from the previous wave), matched by name where the worm puts them, and by hash or marker strings anywhere;
  - a GitHub Actions workflow that dumps all your secrets with `toJSON(secrets)` (the worm names it `codeql_analysis.yml`);
- **a `package.json` that runs the loader** on `preinstall`, `install` or `postinstall`;
- with `--github`, **repos the worm created under your account** to upload what it stole, with the description "Shai-Hulud: Here We Go Again" (or "Sha1-Hulud: The Second Coming" from the previous wave).

## Run it

Python 3.10 or later, no packages to install. Don't run `npm install` in a project you suspect: this scanner reads the lockfile, so it doesn't need anything installed.

```bash
git clone https://github.com/huzaifa207/shai-hulud-scan.git && cd shai-hulud-scan
python3 scan.py ~/code
```

Point it at the folder that holds your projects; it goes through all of them, `node_modules` included, in a few seconds. Check your global packages too:

```bash
python3 scan.py "$(npm root -g)"
```

### Your GitHub repos

This checks the latest commit of every branch of every repo your token can see, so it also covers repos you don't have cloned.

1. Create a token: GitHub → Settings → Developer settings → Fine-grained tokens → Generate new token. Repository access **All repositories**; repository permissions **Contents: Read-only** (Metadata is added automatically); expiry: a day. Delete it when you're done.
2. Run the scan. The token is read without echoing and never lands in your shell history.

   ```bash
   read -rs "GITHUB_TOKEN?GitHub token: " && export GITHUB_TOKEN && python3 scan.py --github; unset GITHUB_TOKEN
   ```

   That's zsh, the macOS default. In bash: `read -rsp "GitHub token: " GITHUB_TOKEN && export GITHUB_TOKEN && python3 scan.py --github; unset GITHUB_TOKEN`.

| Option | What it does |
|---|---|
| `--github` | check GitHub instead of a folder |
| `--repo owner/name` | with `--github`, check one repo |
| `--user name` | with `--github` and no token, check a user's public repos (GitHub allows 60 requests an hour without one, enough for a repo or two) |
| `--out file.json` | also save the findings as JSON |

It exits with status 1 when it finds something, so it can fail a CI job. To check every pull request, add a step to a workflow:

```yaml
- run: git clone --depth 1 https://github.com/huzaifa207/shai-hulud-scan.git /tmp/shs && python3 /tmp/shs/scan.py .
```

## If it finds something

1. **Treat the machine as compromised.** If a compromised version was installed, its `preinstall` script already ran. Don't keep working there; rebuild it, or at least check for a stray `bun` download and any `node setup.mjs` process.
2. **Rotate every credential the machine or CI runner could reach**, from a clean device: npm tokens, GitHub tokens and SSH keys, cloud keys (AWS, GCP, Azure), Kubernetes, Terraform and Vault credentials, and anything in `.env` files. Check for npm package versions you didn't publish, and revoke tokens before you clean anything else, or the worm comes back.
3. **Delete what it created on GitHub** once you've saved what you need for the record: repos with the descriptions above (they hold your stolen secrets, encrypted, and may be public), Actions artifacts named `format-results.txt` (your secrets in plain form), and the planted workflow.
4. **Remove the planted files** from every branch (`.vscode/tasks.json`, `.claude/settings.json`, `.claude/setup.mjs`, `.vscode/setup.mjs`, `.claude/math_init.js`), and don't open those branches in VS Code or start Claude Code in them until you have: both run the loader.
5. **Pin a clean version** of each compromised package, delete `node_modules`, and reinstall with scripts off: `npm ci --ignore-scripts`.

## Keep it out

- Turn install scripts off by default: `npm config set ignore-scripts true` (pnpm 10 already does, unless you allow a package).
- Wait a few days before taking new versions, so a bad release is caught before it reaches you: pnpm's `minimumReleaseAge` does it for you.
- Commit your lockfile and install with `npm ci`, so a new version doesn't arrive without a commit.
- Use short-lived, single-purpose tokens, and publish npm packages through trusted publishing rather than a long-lived token on your machine.

## Limits

- It knows the versions and files published so far. A new wave won't be flagged until `packages.txt` is updated, so treat "nothing found" as "nothing known found".
- It covers this wave's package list; the earlier waves are covered by their files and repo descriptions only.
- With `--github` it reads only the files it needs, so a huge repo's file list may come back truncated; it says when.

## Sources

- [CSA advisory AD-2026-009](https://www.csa.gov.sg/alerts-and-advisories/advisories/ad-2026-009/) (Cyber Security Agency of Singapore)
- [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/npm-worm-compromises-popular-npm-packages/) and its [package list](https://github.com/DataDog/indicators-of-compromise/tree/keyv-campaign/keyv-campaign)
- [Unit 42](https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/) and its [package list](https://github.com/PaloAltoNetworks/Unit42-Threat-Intelligence-Article-Information/blob/main/List-of-packages-affected-by-the-ChainDrop-worm.txt)
- [Elastic Security Labs](https://www.elastic.co/security-labs/shai-hulud-chaindrop-npm-supply-chain)

Also from me: [polinrider-scan](https://github.com/huzaifa207/polinrider-scan), for the force-push campaign that injects malware into your latest commit.

MIT licence.
