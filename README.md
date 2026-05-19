# Lightroom catalog statistics

`lightroom.py` is a dependency-free Python 3 CLI that uses Adobe Lightroom Partner APIs to count photos and summarize focal length/lens usage across a user catalog.

## Authentication options

### Option A: existing access token

If you already have an Adobe IMS user access token authorized for Lightroom Partner APIs:

```bash
export LIGHTROOM_API_KEY="your-adobe-client-id"
export LIGHTROOM_ACCESS_TOKEN="your-user-access-token"
python3 /Users/muralivp/scripts/lightroom.py
```

### Option B: OAuth Native App / public-client flow with PKCE

The script can perform the Adobe IMS Authorization Code + PKCE flow for OAuth Native App credentials. It opens an Adobe authorization URL, then asks you to paste the full redirect URL or just the returned authorization code.

```bash
python3 /Users/muralivp/scripts/lightroom.py \
  --client-id "your-adobe-client-id" \
  --redirect-uri "https://your-registered-redirect.example/callback" \
  --login
```

If your Adobe credential has a default redirect URI configured, you can omit `--redirect-uri`:

```bash
python3 /Users/muralivp/scripts/lightroom.py --client-id "your-adobe-client-id" --login
```

## If the terminal does not accept pasted input

The script now tries to read from stdin first, then from `/dev/tty`. If your runner still will not accept input at this prompt:

```text
Authorization response URL or code:
```

Use this two-step fallback:

1. Start login once. This prints the Adobe URL and saves the matching PKCE verifier/state to `~/.lightroom_catalog_stats_token.json.pending`.

```bash
python3 /Users/muralivp/scripts/lightroom.py \
  --client-id "your-adobe-client-id" \
  --redirect-uri "https://your-registered-redirect.example/callback" \
  --login
```

2. Complete login in the browser, copy the full redirect URL, press `Ctrl-C` in the waiting script if needed, then rerun with the same options plus `--authorization-response-url`:

```bash
python3 /Users/muralivp/scripts/lightroom.py \
  --client-id "your-adobe-client-id" \
  --redirect-uri "https://your-registered-redirect.example/callback" \
  --authorization-response-url "https://your-registered-redirect.example/callback?code=...&state=..."
```

You may pass only the code instead, as long as you use the same token cache from step 1:

```bash
python3 /Users/muralivp/scripts/lightroom.py \
  --client-id "your-adobe-client-id" \
  --redirect-uri "https://your-registered-redirect.example/callback" \
  --authorization-code "code-from-adobe"
```

Important: because Adobe Native App OAuth uses PKCE, a code from a previous run requires the saved pending cache or an explicit `--pkce-code-verifier`. Do not delete the `.pending` file between step 1 and step 2.

## Scopes

By default, the script requests these scopes:

```text
openid,lr_partner_apis,offline_access
```

`offline_access` lets Adobe return a refresh token when supported and consented to. If your integration rejects that scope, override it:

```bash
python3 /Users/muralivp/scripts/lightroom.py \
  --client-id "your-adobe-client-id" \
  --scopes "openid,lr_partner_apis" \
  --login
```

Tokens are cached at `~/.lightroom_catalog_stats_token.json` with user-only file permissions. Use `--no-token-cache` to disable caching or `--login` to force a fresh login.


## SSL certificate errors on macOS

If token exchange fails with `CERTIFICATE_VERIFY_FAILED`, your Python install probably does not have an OpenSSL CA bundle configured. The script now auto-detects `certifi` when installed and common macOS/Homebrew CA bundle locations such as `/etc/ssl/cert.pem`.

Recommended fixes:

```bash
python3 -m pip install --user certifi
```

Or pass the system CA bundle explicitly:

```bash
python3 /Users/muralivp/scripts/lightroom.py \
  --client-id "your-adobe-client-id" \
  --redirect-uri "https://your-registered-redirect.example/callback" \
  --authorization-response-url "https://your-registered-redirect.example/callback?code=...&state=..." \
  --ca-bundle /etc/ssl/cert.pem
```

For python.org macOS installs, you can also run the certificate installer if present:

```bash
open "/Applications/Python 3.12/Install Certificates.command"
```

Last resort for temporary local debugging only:

```bash
python3 /Users/muralivp/scripts/lightroom.py --insecure-skip-ssl-verify ...
```


## Progress logging

The script prints progress/status messages to stderr by default so it is clear whether it is authenticating, fetching the catalog, paging through assets, or aggregating metadata. JSON and human-readable results still go to stdout.

Examples of status messages:

```text
[20:15:01] Exchanging authorization code for Adobe IMS access token...
[20:15:02] Authentication step completed.
[20:15:03] Fetching Lightroom catalog metadata...
[20:15:04] Fetching Lightroom assets page 1 (limit=500)...
[20:15:05] Processed 500 photo(s); missing focal length=12, missing lens=8...
```

Suppress progress messages for automation:

```bash
python3 /Users/muralivp/scripts/lightroom.py --quiet --json
```

Show low-level request URLs and retry details in addition to progress messages:

```bash
python3 /Users/muralivp/scripts/lightroom.py --verbose
```

## Run modes

Human-readable output:

```bash
python3 /Users/muralivp/scripts/lightroom.py
```

JSON output:

```bash
python3 /Users/muralivp/scripts/lightroom.py --json --top 20
```

Small test run:

```bash
python3 /Users/muralivp/scripts/lightroom.py --max-assets 100 --verbose
```

Offline validation:

```bash
python3 /Users/muralivp/scripts/lightroom.py --self-test
```

## Output metrics

- Total number of photos
- Most common focal lengths
- Most used lens
- Total number of photos for each focal length
- Total number of photos for each lens
- Counts of photos missing focal length/lens metadata
