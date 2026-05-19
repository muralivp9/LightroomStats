#!/usr/bin/env python3
"""
Collect catalog statistics from Adobe Lightroom Partner APIs.

Metrics collected:
  1. Total number of photos
  2. Most common focal lengths
  3. Most used lens
  4. Total number of photos for each focal length
  5. Total number of photos for each lens

Required credentials:
  - An Adobe Lightroom Partner API key/client id
  - Either a user OAuth access token or permission to perform the Adobe IMS
    OAuth Native App / public-client Authorization Code + PKCE flow.

You can pass credentials as CLI flags or environment variables:
  LIGHTROOM_CLIENT_ID / LIGHTROOM_API_KEY / LR_API_KEY / ADOBE_CLIENT_ID
  LIGHTROOM_ACCESS_TOKEN / LR_ACCESS_TOKEN / ADOBE_ACCESS_TOKEN optional
  LIGHTROOM_REDIRECT_URI required for interactive OAuth if your Adobe
    credential does not have a default redirect URI
  LIGHTROOM_CATALOG_ID optional; otherwise /v2/catalog is used

Examples:
  python3 /Users/muralivp/scripts/lightroom.py --client-id "your-client-id" --login
  python3 /Users/muralivp/scripts/lightroom.py --client-id "your-client-id" --redirect-uri "https://example.com/callback"
  python3 /Users/muralivp/scripts/lightroom.py --client-id "your-client-id" --authorization-code "code-from-adobe"
  export LIGHTROOM_CLIENT_ID="your-client-id"
  export LIGHTROOM_ACCESS_TOKEN="your-user-access-token"
  python3 /Users/muralivp/scripts/lightroom.py
  python3 /Users/muralivp/scripts/lightroom.py --json --top 20
  python3 /Users/muralivp/scripts/lightroom.py --max-assets 100 --verbose

Notes:
  - This script reads only catalog/asset metadata. It does not download media.
  - Lightroom asset payload metadata is open-ended and may vary by asset/source.
    The extraction code checks common EXIF/XMP-style names recursively, including
    focalLength, FocalLength, exif:FocalLength, lensModel, LensModel, aux:Lens, etc.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import ssl
import stat
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from collections import Counter
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple

DEFAULT_HOST = "lr.adobe.io"
DEFAULT_PAGE_LIMIT = 500
DEFAULT_IMS_HOST = "ims-na1.adobelogin.com"
AUTHORIZE_PATH = "/ims/authorize/v2"
TOKEN_PATH = "/ims/token/v3"
DEFAULT_SCOPES = "openid,lr_partner_apis,offline_access"
DEFAULT_TOKEN_CACHE = os.path.expanduser("~/.lightroom_catalog_stats_token.json")
TOKEN_EXPIRY_SKEW_SECONDS = 120
DEFAULT_CA_BUNDLE_CANDIDATES = (
    "/etc/ssl/cert.pem",
    "/opt/homebrew/etc/openssl@3/cert.pem",
    "/usr/local/etc/openssl@3/cert.pem",
    "/usr/local/etc/openssl/cert.pem",
)
USER_AGENT = "lightroom-catalog-stats/1.0"
JSON_PREFIX = re.compile(r"^\s*while\s*\(\s*1\s*\)\s*\{\s*\}\s*")

FOCAL_KEYS = (
    # Prefer actual focal length fields before 35mm-equivalent variants.
    "focallength",
    "focal_length",
    "focallengthmm",
    "exiffocallength",
    "auxfocallength",
    "focallengthin35mmfilm",
    "focallength35mm",
    "exiffocallengthin35mmfilm",
)

LENS_KEYS = (
    # Prefer human-readable model/name fields. Lens ID is a fallback.
    "lensmodel",
    "exiflensmodel",
    "lensname",
    "auxlens",
    "lens",
    "lensid",
    "auxlensid",
)

UNKNOWN = "Unknown"


def env_first(*names: str) -> Optional[str]:
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return None


def progress(args_or_quiet: Any, message: str) -> None:
    """Print safe status messages to stderr unless --quiet is enabled."""
    quiet = bool(args_or_quiet) if isinstance(args_or_quiet, bool) else bool(getattr(args_or_quiet, "quiet", False))
    if quiet:
        return
    timestamp = time.strftime("%H:%M:%S")
    print(f"[{timestamp}] {message}", file=sys.stderr, flush=True)


def normalize_key(key: str) -> str:
    """Normalize JSON/XMP-ish keys for fuzzy matching."""
    return re.sub(r"[^a-z0-9]", "", key.lower())


def strip_json_prefix(raw: bytes) -> bytes:
    text = raw.decode("utf-8")
    return JSON_PREFIX.sub("", text).encode("utf-8")


def now_seconds() -> int:
    return int(time.time())


def make_pkce_verifier() -> str:
    # RFC 7636 verifier: 43-128 chars from the unreserved URI character set.
    return secrets.token_urlsafe(64)[:96]


def make_pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def build_authorize_url(
    client_id: str,
    redirect_uri: Optional[str],
    scopes: str,
    state: str,
    code_challenge: str,
    ims_host: str,
) -> str:
    params = {
        "client_id": client_id,
        "scope": scopes,
        "state": state,
        "response_type": "code",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "response_mode": "query",
    }
    if redirect_uri:
        params["redirect_uri"] = redirect_uri
    return f"https://{ims_host}{AUTHORIZE_PATH}?{urllib.parse.urlencode(params)}"


def parse_authorization_response(value: str) -> Dict[str, str]:
    """Accept either a raw code or a full redirect URL containing code/state."""
    value = value.strip()
    if not value:
        raise LightroomAPIError("Empty authorization response")
    if re.fullmatch(r"[A-Za-z0-9._~+/=-]+", value) and "code=" not in value:
        return {"code": value}
    parsed = urllib.parse.urlparse(value)
    query = urllib.parse.parse_qs(parsed.query)
    fragment = urllib.parse.parse_qs(parsed.fragment)
    combined = {**query, **fragment}
    if "error" in combined:
        error = combined.get("error", ["authorization_error"])[0]
        description = combined.get("error_description", [""])[0]
        raise LightroomAPIError(f"Authorization failed: {error} {description}".strip())
    code = combined.get("code", [None])[0]
    state = combined.get("state", [None])[0]
    if not code:
        raise LightroomAPIError("Authorization response did not contain a code")
    return {"code": code, "state": state or ""}


def load_token_cache(cache_path: str) -> Dict[str, Any]:
    try:
        with open(os.path.expanduser(cache_path), "r", encoding="utf-8") as handle:
            data = json.load(handle)
            return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError) as exc:
        raise LightroomAPIError(f"Could not read token cache {cache_path}: {exc}") from exc


def save_token_cache(cache_path: str, token: Mapping[str, Any], client_id: str, scopes: str, redirect_uri: Optional[str]) -> None:
    path = os.path.expanduser(cache_path)
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, mode=0o700, exist_ok=True)
    data = dict(token)
    data["client_id"] = client_id
    data["scope"] = data.get("scope") or scopes
    data["redirect_uri"] = redirect_uri or ""
    if "expires_in" in data:
        try:
            data["expires_at"] = now_seconds() + int(float(data["expires_in"]))
        except (TypeError, ValueError):
            pass
    tmp_path = path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
    os.chmod(tmp_path, stat.S_IRUSR | stat.S_IWUSR)
    os.replace(tmp_path, path)


def pending_auth_cache_path(token_cache_path: str) -> str:
    return os.path.expanduser(token_cache_path) + ".pending"


def save_pending_authorization(
    token_cache_path: str,
    client_id: str,
    scopes: str,
    redirect_uri: Optional[str],
    code_verifier: str,
    state: str,
    authorize_url: str,
) -> None:
    path = pending_auth_cache_path(token_cache_path)
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, mode=0o700, exist_ok=True)
    data = {
        "client_id": client_id,
        "scope": scopes,
        "redirect_uri": redirect_uri or "",
        "code_verifier": code_verifier,
        "state": state,
        "authorize_url": authorize_url,
        "created_at": now_seconds(),
    }
    tmp_path = path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
    os.chmod(tmp_path, stat.S_IRUSR | stat.S_IWUSR)
    os.replace(tmp_path, path)


def load_pending_authorization(token_cache_path: str) -> Dict[str, Any]:
    path = pending_auth_cache_path(token_cache_path)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
            return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError) as exc:
        raise LightroomAPIError(f"Could not read pending OAuth cache {path}: {exc}") from exc


def clear_pending_authorization(token_cache_path: str) -> None:
    try:
        os.remove(pending_auth_cache_path(token_cache_path))
    except FileNotFoundError:
        pass


def pending_authorization_matches(pending: Mapping[str, Any], client_id: str, scopes: str, redirect_uri: Optional[str]) -> bool:
    return (
        pending.get("client_id") == client_id
        and pending.get("scope") == scopes
        and (pending.get("redirect_uri") or "") == (redirect_uri or "")
    )


def cached_access_token(cache: Mapping[str, Any], client_id: str, scopes: str, redirect_uri: Optional[str]) -> Optional[str]:
    if cache.get("client_id") != client_id:
        return None
    if (cache.get("redirect_uri") or "") != (redirect_uri or ""):
        return None
    # Adobe may omit scope on refresh responses. Do not reject such cache entries.
    cached_scope = cache.get("scope")
    if cached_scope and cached_scope != scopes:
        return None
    access_token = cache.get("access_token")
    expires_at = cache.get("expires_at")
    if access_token and isinstance(expires_at, (int, float)) and expires_at > now_seconds() + TOKEN_EXPIRY_SKEW_SECONDS:
        return str(access_token)
    return None


def find_default_ca_bundle() -> Optional[str]:
    env_bundle = env_first("LIGHTROOM_CA_BUNDLE", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE")
    if env_bundle and os.path.exists(os.path.expanduser(env_bundle)):
        return os.path.expanduser(env_bundle)

    try:
        import certifi  # type: ignore

        certifi_path = certifi.where()
        if certifi_path and os.path.exists(certifi_path):
            return certifi_path
    except Exception:
        pass

    for candidate in DEFAULT_CA_BUNDLE_CANDIDATES:
        if os.path.exists(candidate):
            return candidate
    return None


def build_ssl_context(args: argparse.Namespace) -> ssl.SSLContext:
    if args.insecure_skip_ssl_verify:
        print(
            "WARNING: SSL certificate verification is disabled. Use only for temporary local debugging.",
            file=sys.stderr,
        )
        return ssl._create_unverified_context()

    ca_bundle = os.path.expanduser(args.ca_bundle) if args.ca_bundle else find_default_ca_bundle()
    try:
        return ssl.create_default_context(cafile=ca_bundle) if ca_bundle else ssl.create_default_context()
    except ssl.SSLError as exc:
        raise LightroomAPIError(format_ssl_help(exc, ca_bundle)) from exc


def format_ssl_help(exc: BaseException, ca_bundle: Optional[str] = None) -> str:
    python_major_minor = f"{sys.version_info.major}.{sys.version_info.minor}"
    installer = f"/Applications/Python {python_major_minor}/Install Certificates.command"
    ca_hint = f"\nCurrent CA bundle: {ca_bundle}" if ca_bundle else ""
    installer_hint = (
        f"\nOn macOS python.org installs, run:\n  open '{installer}'"
        if os.path.exists(installer)
        else ""
    )
    return (
        f"SSL certificate verification failed: {exc}{ca_hint}\n"
        "Fix options:\n"
        "  1. Install certifi and retry: python3 -m pip install --user certifi\n"
        "  2. Or pass a CA bundle: --ca-bundle /etc/ssl/cert.pem\n"
        "  3. Or set LIGHTROOM_CA_BUNDLE, SSL_CERT_FILE, or REQUESTS_CA_BUNDLE."
        f"{installer_hint}\n"
        "Temporary debug only: --insecure-skip-ssl-verify"
    )

def is_ssl_verification_error(exc: urllib.error.URLError) -> bool:
    reason = getattr(exc, "reason", None)
    if isinstance(reason, ssl.SSLCertVerificationError):
        return True
    if isinstance(reason, ssl.SSLError) and "CERTIFICATE_VERIFY_FAILED" in str(reason):
        return True
    return "CERTIFICATE_VERIFY_FAILED" in str(exc)


def post_form(url: str, fields: Mapping[str, str], timeout: float, ssl_context: Optional[ssl.SSLContext]) -> Dict[str, Any]:
    body = urllib.parse.urlencode(fields).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_context) as response:
            raw = response.read()
            return json.loads(strip_json_prefix(raw).decode("utf-8")) if raw else {}
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="replace")
        raise LightroomAPIError(f"HTTP {exc.code} from Adobe IMS token endpoint: {body_text}") from exc
    except urllib.error.URLError as exc:
        if is_ssl_verification_error(exc):
            raise LightroomAPIError(format_ssl_help(exc)) from exc
        raise LightroomAPIError(f"Network error calling Adobe IMS token endpoint: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise LightroomAPIError(f"Invalid JSON from Adobe IMS token endpoint: {exc}") from exc


def exchange_authorization_code(
    client_id: str,
    code: str,
    code_verifier: str,
    redirect_uri: Optional[str],
    ims_host: str,
    timeout: float,
    ssl_context: Optional[ssl.SSLContext],
) -> Dict[str, Any]:
    url = f"https://{ims_host}{TOKEN_PATH}?{urllib.parse.urlencode({'client_id': client_id})}"
    fields = {
        "code": code,
        "grant_type": "authorization_code",
        "code_verifier": code_verifier,
    }
    if redirect_uri:
        fields["redirect_uri"] = redirect_uri
    token = post_form(url, fields, timeout, ssl_context)
    if not token.get("access_token"):
        raise LightroomAPIError("Adobe IMS token response did not contain access_token")
    return token


def refresh_access_token(client_id: str, refresh_token: str, ims_host: str, timeout: float, ssl_context: Optional[ssl.SSLContext]) -> Dict[str, Any]:
    url = f"https://{ims_host}{TOKEN_PATH}?{urllib.parse.urlencode({'client_id': client_id})}"
    token = post_form(url, {"grant_type": "refresh_token", "refresh_token": refresh_token}, timeout, ssl_context)
    if not token.get("access_token"):
        raise LightroomAPIError("Adobe IMS refresh response did not contain access_token")
    if "refresh_token" not in token:
        token["refresh_token"] = refresh_token
    return token


def read_authorization_response(args: argparse.Namespace) -> str:
    """Read the OAuth redirect URL/code without relying only on stdin input()."""
    if args.authorization_response_url:
        return args.authorization_response_url.strip()
    if args.authorization_code:
        return args.authorization_code.strip()

    prompt = "Authorization response URL or code: "
    if sys.stdin.isatty():
        return input(prompt).strip()

    # Some runners/IDEs pipe stdin, so input() either blocks or cannot receive
    # keystrokes. In that case, try the controlling terminal directly.
    try:
        with open("/dev/tty", "r+", encoding="utf-8") as tty:
            tty.write(prompt)
            tty.flush()
            return tty.readline().strip()
    except OSError as exc:
        raise LightroomAPIError(
            "Cannot read interactive OAuth input from this terminal. Re-run with "
            "--authorization-response-url '<full redirect URL>' or "
            "--authorization-code '<code>'."
        ) from exc


def resolve_access_token(args: argparse.Namespace) -> str:
    if args.access_token:
        progress(args, "Using access token supplied via CLI/environment.")
        return args.access_token

    client_id = args.client_id or args.api_key
    if not client_id:
        raise SystemExit("Missing required credential: --client-id/--api-key or LIGHTROOM_CLIENT_ID/LIGHTROOM_API_KEY/ADOBE_CLIENT_ID")

    progress(args, "Resolving Adobe IMS access token...")
    cache = {} if args.no_token_cache else load_token_cache(args.token_cache)
    if args.no_token_cache:
        progress(args, "Token cache disabled (--no-token-cache).")
    elif cache:
        progress(args, f"Loaded token cache from {args.token_cache}.")
    else:
        progress(args, f"No usable token cache found at {args.token_cache}.")
    cached = None if args.login else cached_access_token(cache, client_id, args.scopes, args.redirect_uri)
    if cached:
        progress(args, "Using valid cached Adobe IMS access token.")
        return cached
    if args.login:
        progress(args, "Forced login requested; skipping cached access token.")
    else:
        progress(args, "No valid cached access token available.")

    refresh_token = cache.get("refresh_token") if not args.login else None
    if refresh_token:
        try:
            progress(args, "Refreshing Adobe IMS access token...")
            token = refresh_access_token(client_id, str(refresh_token), args.ims_host, args.timeout, args.ssl_context)
            if not args.no_token_cache:
                save_token_cache(args.token_cache, token, client_id, args.scopes, args.redirect_uri)
                progress(args, f"Updated token cache at {args.token_cache}.")
            progress(args, "Adobe IMS access token refreshed successfully.")
            return str(token["access_token"])
        except LightroomAPIError as exc:
            progress(args, f"Refresh failed; starting OAuth login: {exc}")

    supplied_authorization_response = bool(args.authorization_response_url or args.authorization_code)
    pending = {} if args.no_token_cache else load_pending_authorization(args.token_cache)

    if supplied_authorization_response:
        progress(args, "Authorization response supplied; preparing Adobe IMS token exchange...")
        verifier = args.pkce_code_verifier or pending.get("code_verifier")
        expected_state = pending.get("state") if pending_authorization_matches(pending, client_id, args.scopes, args.redirect_uri) else None
        if pending and not expected_state and not args.pkce_code_verifier:
            raise LightroomAPIError(
                "Found a pending OAuth login, but it was created for different client/scopes/redirect URI. "
                "Re-run the login with the same options or pass --pkce-code-verifier explicitly."
            )
        if not verifier:
            raise LightroomAPIError(
                "Cannot exchange this authorization code because the matching PKCE code_verifier is unavailable. "
                "Start with --login once, then paste into the same prompt; or interrupt and re-run with "
                "--authorization-response-url/--authorization-code using the same --token-cache; or pass --pkce-code-verifier."
            )
        response_value = read_authorization_response(args)
        parsed = parse_authorization_response(response_value)
        returned_state = parsed.get("state")
        if expected_state and returned_state and returned_state != expected_state:
            raise LightroomAPIError("Authorization state mismatch; aborting for safety")
        progress(args, "Exchanging authorization code for Adobe IMS access token...")
        token = exchange_authorization_code(client_id, parsed["code"], str(verifier), args.redirect_uri, args.ims_host, args.timeout, args.ssl_context)
        progress(args, "Adobe IMS token exchange completed successfully.")
        if not args.no_token_cache:
            save_token_cache(args.token_cache, token, client_id, args.scopes, args.redirect_uri)
            clear_pending_authorization(args.token_cache)
            progress(args, f"Saved Adobe IMS token cache to {args.token_cache}.")
        return str(token["access_token"])

    verifier = make_pkce_verifier()
    challenge = make_pkce_challenge(verifier)
    state = secrets.token_urlsafe(24)
    authorize_url = build_authorize_url(client_id, args.redirect_uri, args.scopes, state, challenge, args.ims_host)
    if not args.no_token_cache:
        save_pending_authorization(args.token_cache, client_id, args.scopes, args.redirect_uri, verifier, state, authorize_url)
        progress(args, f"Saved pending OAuth PKCE state to {pending_auth_cache_path(args.token_cache)}.")

    progress(args, "Starting interactive Adobe IMS OAuth login...")
    print("Open this Adobe IMS authorization URL in your browser:")
    print(authorize_url)
    if args.open_browser:
        webbrowser.open(authorize_url)
    print("\nAfter Adobe redirects you, copy the full redirect URL here.")
    print("You may also paste just the authorization code if the redirect page is not reachable.")
    print("If your terminal cannot accept input, press Ctrl-C and re-run with --authorization-response-url or --authorization-code.")
    print(f"Pending PKCE verifier/state saved in: {pending_auth_cache_path(args.token_cache)}")
    response_value = read_authorization_response(args)
    parsed = parse_authorization_response(response_value)
    returned_state = parsed.get("state")
    if returned_state and returned_state != state:
        raise LightroomAPIError("Authorization state mismatch; aborting for safety")

    progress(args, "Exchanging authorization code for Adobe IMS access token...")
    token = exchange_authorization_code(client_id, parsed["code"], verifier, args.redirect_uri, args.ims_host, args.timeout, args.ssl_context)
    progress(args, "Adobe IMS token exchange completed successfully.")
    if not args.no_token_cache:
        save_token_cache(args.token_cache, token, client_id, args.scopes, args.redirect_uri)
        clear_pending_authorization(args.token_cache)
        progress(args, f"Saved Adobe IMS token cache to {args.token_cache}.")
    return str(token["access_token"])


class LightroomAPIError(RuntimeError):
    pass


@dataclass(frozen=True)
class LightroomConfig:
    api_key: str
    access_token: str
    host: str = DEFAULT_HOST
    timeout: float = 30.0
    retries: int = 3
    ssl_context: Optional[ssl.SSLContext] = None
    quiet: bool = False


class LightroomClient:
    def __init__(self, config: LightroomConfig, verbose: bool = False) -> None:
        self.config = config
        self.verbose = verbose

    @property
    def base_url(self) -> str:
        return f"https://{self.config.host}"

    def get_json(self, path_or_url: str) -> Dict[str, Any]:
        url = self._to_url(path_or_url)
        headers = {
            "X-API-Key": self.config.api_key,
            "Authorization": f"Bearer {self.config.access_token}",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        }
        last_error: Optional[BaseException] = None
        for attempt in range(self.config.retries + 1):
            if self.verbose:
                print(f"GET {url}", file=sys.stderr)
            req = urllib.request.Request(url, headers=headers, method="GET")
            try:
                with urllib.request.urlopen(req, timeout=self.config.timeout, context=self.config.ssl_context) as response:
                    raw = response.read()
                    if not raw:
                        return {}
                    try:
                        return json.loads(strip_json_prefix(raw).decode("utf-8"))
                    except json.JSONDecodeError as exc:
                        raise LightroomAPIError(f"Invalid JSON response from {url}: {exc}") from exc
            except urllib.error.HTTPError as exc:
                body = exc.read().decode("utf-8", errors="replace")
                last_error = exc
                if exc.code in (429, 500, 502, 503, 504) and attempt < self.config.retries:
                    delay = self._retry_delay(exc, attempt)
                    if self.verbose:
                        print(f"HTTP {exc.code}; retrying in {delay:.1f}s", file=sys.stderr)
                    time.sleep(delay)
                    continue
                raise LightroomAPIError(f"HTTP {exc.code} for {url}: {body}") from exc
            except urllib.error.URLError as exc:
                last_error = exc
                if is_ssl_verification_error(exc):
                    raise LightroomAPIError(format_ssl_help(exc)) from exc
                if attempt < self.config.retries:
                    delay = min(2 ** attempt, 10)
                    if self.verbose:
                        print(f"Network error {exc}; retrying in {delay:.1f}s", file=sys.stderr)
                    time.sleep(delay)
                    continue
                raise LightroomAPIError(f"Network error for {url}: {exc}") from exc
        raise LightroomAPIError(f"Request failed for {url}: {last_error}")

    def get_catalog_id(self) -> str:
        progress(self.config.quiet, "Fetching Lightroom catalog metadata...")
        catalog = self.get_json("/v2/catalog")
        catalog_id = catalog.get("id")
        if not catalog_id:
            raise LightroomAPIError("/v2/catalog response did not contain an id")
        progress(self.config.quiet, f"Found Lightroom catalog id: {catalog_id}")
        return str(catalog_id)

    def iter_assets(
        self,
        catalog_id: str,
        subtype: str = "image",
        page_limit: int = DEFAULT_PAGE_LIMIT,
        max_pages: Optional[int] = None,
    ) -> Iterator[Dict[str, Any]]:
        params = urllib.parse.urlencode({"subtype": subtype, "limit": page_limit})
        path_or_url = f"/v2/catalogs/{urllib.parse.quote(catalog_id)}/assets?{params}"
        page_count = 0

        while path_or_url:
            page_count += 1
            progress(self.config.quiet, f"Fetching Lightroom assets page {page_count} (limit={page_limit})...")
            response = self.get_json(path_or_url)
            resources = response.get("resources") or []
            if not isinstance(resources, list):
                raise LightroomAPIError("Assets response contained non-list resources")
            progress(self.config.quiet, f"Received {len(resources)} asset(s) on page {page_count}.")
            for asset in resources:
                if isinstance(asset, dict):
                    yield asset

            if max_pages is not None and page_count >= max_pages:
                progress(self.config.quiet, f"Stopping after --max-pages={max_pages}.")
                return

            next_href = ((response.get("links") or {}).get("next") or {}).get("href")
            if not next_href:
                progress(self.config.quiet, f"No more asset pages after page {page_count}.")
                return
            base = response.get("base") or self.base_url
            next_url = urllib.parse.urljoin(base, next_href)
            parsed = urllib.parse.urlparse(next_url)
            path_or_url = parsed.path + (f"?{parsed.query}" if parsed.query else "")

    def _to_url(self, path_or_url: str) -> str:
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            return path_or_url
        if not path_or_url.startswith("/"):
            path_or_url = "/" + path_or_url
        return self.base_url + path_or_url

    @staticmethod
    def _retry_delay(exc: urllib.error.HTTPError, attempt: int) -> float:
        retry_after = exc.headers.get("Retry-After")
        if retry_after:
            try:
                return max(float(retry_after), 0.0)
            except ValueError:
                pass
        return min(2 ** attempt, 30)


@dataclass
class CatalogStats:
    total_photos: int
    focal_length_counts: Counter
    lens_counts: Counter
    missing_focal_length: int = 0
    missing_lens: int = 0

    @property
    def most_common_focal_lengths(self) -> List[Tuple[str, int]]:
        return self.focal_length_counts.most_common()

    @property
    def most_used_lens(self) -> Optional[Tuple[str, int]]:
        common = self.lens_counts.most_common(1)
        return common[0] if common else None


def walk_values(data: Any) -> Iterator[Tuple[str, Any]]:
    """Yield all key/value pairs recursively from nested JSON-like data."""
    if isinstance(data, Mapping):
        for key, value in data.items():
            if isinstance(key, str):
                yield key, value
            yield from walk_values(value)
    elif isinstance(data, list):
        for value in data:
            yield from walk_values(value)


def first_matching_value(data: Any, key_names: Iterable[str]) -> Optional[Any]:
    """Return the first value matching the preferred key order."""
    pairs = [(normalize_key(key), value) for key, value in walk_values(data)]
    for wanted_key in key_names:
        for key, value in pairs:
            if key == wanted_key and value not in (None, ""):
                return value
    return None


def rational_to_float(value: Any) -> Optional[float]:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, (list, tuple)) and len(value) == 2:
        numerator = rational_to_float(value[0])
        denominator = rational_to_float(value[1])
        if numerator is not None and denominator not in (None, 0):
            return numerator / denominator
    if isinstance(value, Mapping):
        for keys in (("value",), ("numerator", "denominator"), ("n", "d")):
            if len(keys) == 1 and keys[0] in value:
                result = rational_to_float(value[keys[0]])
                if result is not None:
                    return result
            elif all(k in value for k in keys):
                numerator = rational_to_float(value[keys[0]])
                denominator = rational_to_float(value[keys[1]])
                if numerator is not None and denominator not in (None, 0):
                    return numerator / denominator
    if isinstance(value, str):
        text = value.strip()
        fraction_match = re.search(r"(-?\d+(?:\.\d+)?)\s*/\s*(-?\d+(?:\.\d+)?)", text)
        if fraction_match:
            denominator = float(fraction_match.group(2))
            if denominator:
                return float(fraction_match.group(1)) / denominator
        number_match = re.search(r"-?\d+(?:\.\d+)?", text)
        if number_match:
            return float(number_match.group(0))
    return None


def normalize_focal_length(value: Any) -> Optional[str]:
    number = rational_to_float(value)
    if number is None or number <= 0:
        return None
    if abs(number - round(number)) < 0.05:
        return f"{int(round(number))}mm"
    return f"{number:.1f}mm"


def normalize_lens(value: Any) -> Optional[str]:
    if value is None or value == "":
        return None
    if isinstance(value, (list, tuple)):
        parts = [normalize_lens(item) for item in value]
        parts = [part for part in parts if part]
        return " ".join(parts) if parts else None
    if isinstance(value, Mapping):
        for preferred_key in ("model", "name", "value", "lens", "lensModel", "LensModel"):
            if preferred_key in value:
                normalized = normalize_lens(value[preferred_key])
                if normalized:
                    return normalized
        return None
    text = str(value).strip()
    text = re.sub(r"\s+", " ", text)
    return text or None


def extract_photo_metadata(asset: Mapping[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    payload = asset.get("payload") if isinstance(asset.get("payload"), Mapping) else asset
    focal = normalize_focal_length(first_matching_value(payload, FOCAL_KEYS))
    lens = normalize_lens(first_matching_value(payload, LENS_KEYS))
    return focal, lens


def collect_stats(
    assets: Iterable[Mapping[str, Any]],
    max_assets: Optional[int] = None,
    include_unknown: bool = False,
    progress_every: int = 500,
    quiet: bool = False,
) -> CatalogStats:
    focal_counts: Counter = Counter()
    lens_counts: Counter = Counter()
    total = 0
    missing_focal = 0
    missing_lens = 0

    progress(quiet, "Starting photo metadata aggregation...")

    for asset in assets:
        if max_assets is not None and total >= max_assets:
            progress(quiet, f"Stopping after --max-assets={max_assets}.")
            break
        total += 1
        focal, lens = extract_photo_metadata(asset)
        if focal:
            focal_counts[focal] += 1
        else:
            missing_focal += 1
            if include_unknown:
                focal_counts[UNKNOWN] += 1
        if lens:
            lens_counts[lens] += 1
        else:
            missing_lens += 1
            if include_unknown:
                lens_counts[UNKNOWN] += 1
        if progress_every and total % progress_every == 0:
            progress(
                quiet,
                f"Processed {total} photo(s); missing focal length={missing_focal}, missing lens={missing_lens}...",
            )

    progress(quiet, f"Finished aggregation for {total} photo(s).")
    return CatalogStats(
        total_photos=total,
        focal_length_counts=focal_counts,
        lens_counts=lens_counts,
        missing_focal_length=missing_focal,
        missing_lens=missing_lens,
    )


def stats_to_dict(stats: CatalogStats, top: int) -> Dict[str, Any]:
    most_used_lens = stats.most_used_lens
    return {
        "total_photos": stats.total_photos,
        "most_common_focal_lengths": [
            {"focal_length": key, "count": count}
            for key, count in stats.focal_length_counts.most_common(top)
        ],
        "most_used_lens": (
            {"lens": most_used_lens[0], "count": most_used_lens[1]}
            if most_used_lens
            else None
        ),
        "photos_by_focal_length": dict(sorted(stats.focal_length_counts.items(), key=sort_focal_item)),
        "photos_by_lens": dict(stats.lens_counts.most_common()),
        "missing_focal_length": stats.missing_focal_length,
        "missing_lens": stats.missing_lens,
    }


def sort_focal_item(item: Tuple[str, int]) -> Tuple[float, str]:
    key, _ = item
    number = rational_to_float(key)
    return (number if number is not None else float("inf"), key)


def print_human(stats: CatalogStats, top: int) -> None:
    print("Lightroom catalog statistics")
    print("=" * 30)
    print(f"Total photos: {stats.total_photos}")
    print(f"Photos missing focal length metadata: {stats.missing_focal_length}")
    print(f"Photos missing lens metadata: {stats.missing_lens}")

    print("\nMost common focal lengths:")
    if stats.focal_length_counts:
        for focal, count in stats.focal_length_counts.most_common(top):
            print(f"  {focal}: {count}")
    else:
        print("  No focal length metadata found")

    print("\nMost used lens:")
    most_used_lens = stats.most_used_lens
    if most_used_lens:
        print(f"  {most_used_lens[0]}: {most_used_lens[1]}")
    else:
        print("  No lens metadata found")

    print("\nPhotos by focal length:")
    if stats.focal_length_counts:
        for focal, count in sorted(stats.focal_length_counts.items(), key=sort_focal_item):
            print(f"  {focal}: {count}")
    else:
        print("  No focal length metadata found")

    print("\nPhotos by lens:")
    if stats.lens_counts:
        for lens, count in stats.lens_counts.most_common():
            print(f"  {lens}: {count}")
    else:
        print("  No lens metadata found")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect Lightroom catalog photo statistics using Adobe Lightroom Partner APIs."
    )
    parser.add_argument("--client-id", "--clientid", dest="client_id", default=env_first("LIGHTROOM_CLIENT_ID", "LR_CLIENT_ID"), help="Adobe OAuth Native App client id. Env: LIGHTROOM_CLIENT_ID, LR_CLIENT_ID")
    parser.add_argument("--api-key", default=env_first("LIGHTROOM_API_KEY", "LR_API_KEY", "ADOBE_CLIENT_ID"), help="Adobe API key/client id used for Lightroom API X-API-Key. Defaults to --client-id when omitted. Env: LIGHTROOM_API_KEY, LR_API_KEY, ADOBE_CLIENT_ID")
    parser.add_argument("--access-token", default=env_first("LIGHTROOM_ACCESS_TOKEN", "LR_ACCESS_TOKEN", "ADOBE_ACCESS_TOKEN"), help="Existing Adobe OAuth user access token. If omitted, the script performs Adobe IMS Native App OAuth with PKCE. Env: LIGHTROOM_ACCESS_TOKEN, LR_ACCESS_TOKEN, ADOBE_ACCESS_TOKEN")
    parser.add_argument("--redirect-uri", default=env_first("LIGHTROOM_REDIRECT_URI", "ADOBE_REDIRECT_URI"), help="Redirect URI registered for the Adobe OAuth credential. If omitted, Adobe uses the credential default redirect URI.")
    parser.add_argument("--authorization-code", default=env_first("LIGHTROOM_AUTHORIZATION_CODE", "ADOBE_AUTHORIZATION_CODE"), help="Authorization code returned by Adobe IMS. Useful when the terminal cannot accept interactive input.")
    parser.add_argument("--authorization-response-url", default=env_first("LIGHTROOM_AUTHORIZATION_RESPONSE_URL", "ADOBE_AUTHORIZATION_RESPONSE_URL"), help="Full redirect URL returned by Adobe IMS. Useful when the terminal cannot accept interactive input.")
    parser.add_argument("--pkce-code-verifier", default=env_first("LIGHTROOM_PKCE_CODE_VERIFIER", "ADOBE_PKCE_CODE_VERIFIER"), help="Advanced: PKCE code_verifier matching --authorization-code when no pending OAuth cache exists.")
    parser.add_argument("--ca-bundle", default=env_first("LIGHTROOM_CA_BUNDLE", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"), help="CA certificate bundle for HTTPS verification. Useful on macOS Python installs with missing certificates.")
    parser.add_argument("--insecure-skip-ssl-verify", "--insecure-no-verify", action="store_true", help="Disable HTTPS certificate verification. Temporary local debugging only; not recommended.")
    parser.add_argument("--scopes", default=os.environ.get("LIGHTROOM_SCOPES", DEFAULT_SCOPES), help=f"OAuth scopes. Default: {DEFAULT_SCOPES}")
    parser.add_argument("--ims-host", default=os.environ.get("ADOBE_IMS_HOST", DEFAULT_IMS_HOST), help=f"Adobe IMS host. Default: {DEFAULT_IMS_HOST}")
    parser.add_argument("--token-cache", default=os.environ.get("LIGHTROOM_TOKEN_CACHE", DEFAULT_TOKEN_CACHE), help=f"Token cache path. Default: {DEFAULT_TOKEN_CACHE}")
    parser.add_argument("--no-token-cache", action="store_true", help="Do not read or write the OAuth token cache.")
    parser.add_argument("--login", action="store_true", help="Force an interactive Adobe IMS OAuth login even if a cached token exists.")
    parser.add_argument("--open-browser", action=argparse.BooleanOptionalAction, default=True, help="Open the Adobe authorization URL in the default browser. Default: true")
    parser.add_argument("--catalog-id", default=env_first("LIGHTROOM_CATALOG_ID", "LR_CATALOG_ID"), help="Catalog id. If omitted, the script calls /v2/catalog.")
    parser.add_argument("--host", default=os.environ.get("LIGHTROOM_HOST", DEFAULT_HOST), help=f"Lightroom API host. Default: {DEFAULT_HOST}")
    parser.add_argument("--page-limit", type=int, default=DEFAULT_PAGE_LIMIT, help="Assets per API page; API maximum is 500. Default: 500")
    parser.add_argument("--max-pages", type=int, default=None, help="Optional page limit for test runs.")
    parser.add_argument("--max-assets", type=int, default=None, help="Optional asset limit for test runs.")
    parser.add_argument("--timeout", type=float, default=30.0, help="HTTP timeout in seconds. Default: 30")
    parser.add_argument("--retries", type=int, default=3, help="Retries for transient HTTP/network failures. Default: 3")
    parser.add_argument("--top", type=int, default=10, help="Number of top focal lengths to display. Default: 10")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON output.")
    parser.add_argument("--include-unknown", action="store_true", help="Include Unknown bucket in focal length/lens counts.")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress/status messages on stderr. Errors still print.")
    parser.add_argument("--verbose", action="store_true", help="Also print low-level request URLs/retry details to stderr.")
    parser.add_argument("--self-test", action="store_true", help="Run an offline aggregation self-test and exit.")
    return parser


def validate_args(args: argparse.Namespace) -> None:
    if args.self_test:
        return
    if not args.api_key and args.client_id:
        args.api_key = args.client_id
    if not args.client_id and args.api_key:
        args.client_id = args.api_key
    if not args.api_key:
        raise SystemExit("Missing required credential: --client-id/--api-key or LIGHTROOM_CLIENT_ID/LIGHTROOM_API_KEY/ADOBE_CLIENT_ID")
    if not args.access_token and not args.client_id:
        raise SystemExit("Missing required credential: --client-id is needed for OAuth login when --access-token is omitted")
    if args.page_limit < 1 or args.page_limit > 500:
        raise SystemExit("--page-limit must be between 1 and 500")
    if args.top < 1:
        raise SystemExit("--top must be at least 1")
    if not args.scopes.strip():
        raise SystemExit("--scopes must not be empty")


def run_self_test() -> None:
    assets = [
        {"payload": {"exif": {"FocalLength": "50/1", "LensModel": "Sony FE 50mm F1.8"}}},
        {"payload": {"focalLength": 35, "lens": "Sony FE 35mm F1.8"}},
        {"payload": {"camera": {"focal_length": "35 mm", "lensModel": "Sony FE 35mm F1.8"}}},
        {"payload": {"aux:Lens": "Sony FE 50mm F1.8", "exif:FocalLength": [50, 1]}},
        {"payload": {"importSource": {"fileName": "missing-metadata.jpg"}}},
    ]
    stats = collect_stats(assets, include_unknown=False, progress_every=0, quiet=True)
    assert stats.total_photos == 5, stats
    assert stats.focal_length_counts == Counter({"50mm": 2, "35mm": 2}), stats.focal_length_counts
    assert stats.lens_counts == Counter({"Sony FE 50mm F1.8": 2, "Sony FE 35mm F1.8": 2}), stats.lens_counts
    assert stats.missing_focal_length == 1, stats.missing_focal_length
    assert stats.missing_lens == 1, stats.missing_lens

    verifier = make_pkce_verifier()
    challenge = make_pkce_challenge(verifier)
    assert 43 <= len(verifier) <= 128, len(verifier)
    assert re.fullmatch(r"[A-Za-z0-9_-]+", challenge), challenge
    parsed = parse_authorization_response("https://example.com/callback?code=abc123&state=xyz")
    assert parsed == {"code": "abc123", "state": "xyz"}, parsed
    parsed_code = parse_authorization_response("rawCode123")
    assert parsed_code == {"code": "rawCode123"}, parsed_code
    fake_args = argparse.Namespace(authorization_response_url="https://example.com/callback?code=from-url", authorization_code=None)
    assert read_authorization_response(fake_args) == "https://example.com/callback?code=from-url"
    fake_args = argparse.Namespace(authorization_response_url=None, authorization_code="from-code")
    assert read_authorization_response(fake_args) == "from-code"
    with tempfile.TemporaryDirectory() as tmp:
        cache_path = os.path.join(tmp, "token.json")
        save_pending_authorization(cache_path, "client123", DEFAULT_SCOPES, "https://example.com/callback", verifier, "state123", "https://auth.example")
        pending = load_pending_authorization(cache_path)
        assert pending_authorization_matches(pending, "client123", DEFAULT_SCOPES, "https://example.com/callback")
        assert pending["code_verifier"] == verifier
        clear_pending_authorization(cache_path)
        assert load_pending_authorization(cache_path) == {}
    url = build_authorize_url("client123", "https://example.com/callback", DEFAULT_SCOPES, "state123", challenge, DEFAULT_IMS_HOST)
    url_parts = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(url_parts.query)
    assert url_parts.scheme == "https", url
    assert url_parts.netloc == DEFAULT_IMS_HOST, url
    assert params["client_id"] == ["client123"], params
    assert params["response_type"] == ["code"], params
    assert params["code_challenge_method"] == ["S256"], params
    assert params["redirect_uri"] == ["https://example.com/callback"], params
    ssl_args = argparse.Namespace(ca_bundle=None, insecure_skip_ssl_verify=False)
    assert isinstance(build_ssl_context(ssl_args), ssl.SSLContext)
    valid_cache = {
        "client_id": "client123",
        "scope": DEFAULT_SCOPES,
        "redirect_uri": "https://example.com/callback",
        "access_token": "cached-token",
        "expires_at": now_seconds() + 3600,
    }
    assert cached_access_token(valid_cache, "client123", DEFAULT_SCOPES, "https://example.com/callback") == "cached-token"
    assert cached_access_token(valid_cache, "other", DEFAULT_SCOPES, "https://example.com/callback") is None
    print("Self-test passed")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    validate_args(args)

    if args.self_test:
        run_self_test()
        return 0

    progress(args, "Starting Lightroom catalog statistics run.")
    progress(args, "Preparing HTTPS certificate verification context...")
    ssl_context = build_ssl_context(args)
    args.ssl_context = ssl_context
    access_token = resolve_access_token(args)
    progress(args, "Authentication step completed.")

    config = LightroomConfig(
        api_key=args.api_key,
        access_token=access_token,
        host=args.host,
        timeout=args.timeout,
        retries=args.retries,
        ssl_context=ssl_context,
        quiet=args.quiet,
    )
    client = LightroomClient(config, verbose=args.verbose)

    if args.catalog_id:
        catalog_id = args.catalog_id
        progress(args, f"Using catalog id from arguments: {catalog_id}")
    else:
        catalog_id = client.get_catalog_id()

    progress(args, "Beginning Lightroom asset retrieval and metadata analysis...")
    assets = client.iter_assets(
        catalog_id=catalog_id,
        subtype="image",
        page_limit=args.page_limit,
        max_pages=args.max_pages,
    )
    stats = collect_stats(
        assets,
        max_assets=args.max_assets,
        include_unknown=args.include_unknown,
        progress_every=500,
        quiet=args.quiet,
    )
    progress(
        args,
        f"Analysis complete: total photos={stats.total_photos}, focal-length buckets={len(stats.focal_length_counts)}, lens buckets={len(stats.lens_counts)}.",
    )
    progress(args, "Writing JSON output to stdout." if args.json else "Writing human-readable output to stdout.")

    if args.json:
        print(json.dumps(stats_to_dict(stats, args.top), indent=2, sort_keys=True))
    else:
        print_human(stats, args.top)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        raise SystemExit(130)
    except LightroomAPIError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
