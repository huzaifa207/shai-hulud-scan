# Security policy

## Reporting a vulnerability in shai-hulud-scan

Please report it privately: open the repo's **Security** tab and choose **Report a vulnerability**. Don't open a public issue.

In scope: anything that makes the scanner unsafe to run, such as leaking or logging the token, writing to GitHub or the disk, or running, importing or installing code it reads.

I'll reply within a few days, fix it on `main`, and credit you in the advisory if you'd like. Only the latest `main` is supported; there are no releases to patch.

## Not a vulnerability

- **Your repos or machine are infected**: follow [If it finds something](../README.md#if-it-finds-something) in the README, and rotate your credentials first.
- **It missed an indicator, or flagged something harmless**: open an issue with the matching template.
