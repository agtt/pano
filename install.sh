#!/bin/sh
# Install pano from a GitHub release (run as root on the server):
#
#   curl -fsSL https://raw.githubusercontent.com/agtt/pano/main/install.sh | sh
#
# Environment:
#   PANO_VERSION   release to install, like 0.2.0 or v0.2.0 (default: the latest, which must be
#                  at least MIN_VERSION below; an explicit PANO_VERSION is installed as asked)
#   PANO_REPO      owner/name of the repository (default: agtt/pano)
#   PANO_RELEASE_PUBKEY  the PEM public key releases are signed with (a fork's own)
#   PANO_INSECURE_SKIP_SIGNATURE=1  install without OpenSSL 3 (checksum only, not the signature)
#   GITHUB_TOKEN   optional. While the repository is private, the raw script and the
#                  release assets can only be fetched with a token that can read it:
#                  curl -fsSL -H "Authorization: Bearer $GITHUB_TOKEN" \
#                    -H "Accept: application/vnd.github.raw" \
#                    https://api.github.com/repos/agtt/pano/contents/install.sh | GITHUB_TOKEN=... sh
#
# The binary is checked against the release's signed SHA256SUMS before it runs, then
# `pano install` sets up users, directories and systemd units.

set -eu

REPO="${PANO_REPO:-agtt/pano}"
VERSION="${PANO_VERSION:-}"
TOKEN="${GITHUB_TOKEN:-}"
# keep in step with src/shared/release-key.ts
RELEASE_PUBKEY="-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA9lt4OZWuOwWbBaaBlgtzcuzVwi3T/LZDJTpM0Q3wa8Y=
-----END PUBLIC KEY-----"

# The oldest release a plain install (no PANO_VERSION) accepts. The release workflow raises it to
# each new release; a validly signed but old release (known holes) is refused, not installed.
MIN_VERSION="0.1.0"

fail() { printf 'pano install: %s\n' "$1" >&2; exit 1; }
# version_lt A B: succeeds when A is an older release than B (major.minor.patch, a leading v and any -pre/+build ignored).
version_lt() {
  awk -v a="$1" -v b="$2" 'function n(s) { sub(/^v/, "", s); sub(/[-+].*/, "", s); return s }
    BEGIN { split(n(a), x, "."); split(n(b), y, ".")
      for (i = 1; i <= 3; i++) { if (x[i] + 0 < y[i] + 0) exit 0; if (x[i] + 0 > y[i] + 0) exit 1 }
      exit 1 }'
}
need() { command -v "$1" >/dev/null 2>&1 || fail "$1 is required but not installed"; }

[ "$(id -u)" -eq 0 ] || fail "run as root (curl ... | sudo sh)"
[ "$(uname -s)" = "Linux" ] || fail "pano runs on Linux only"
need curl
need sha256sum
case "$REPO" in
  *[!A-Za-z0-9._/-]* | */*/* | /* | */ | "") fail "PANO_REPO must look like owner/name" ;;
  */*) ;;
  *) fail "PANO_REPO must look like owner/name" ;;
esac

case "$(uname -m)" in
  x86_64 | amd64) ARCH=x64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  *) fail "unsupported CPU architecture: $(uname -m) (x86_64 and aarch64 only)" ;;
esac
ASSET="pano-linux-$ARCH"

if [ -n "$VERSION" ]; then
  case "$VERSION" in
    v[0-9]*) ;;
    [0-9]*) VERSION="v$VERSION" ;;
    *) fail "PANO_VERSION must look like 0.2.0" ;;
  esac
  case "$VERSION" in *[!A-Za-z0-9.+-]*) fail "PANO_VERSION has odd characters" ;; esac
  BASE="https://github.com/$REPO/releases/download/$VERSION"
else
  BASE="https://github.com/$REPO/releases/latest/download"
fi

TMP="$(mktemp -d)" || fail "cannot create a temporary directory"
trap 'rm -rf "$TMP"' EXIT INT TERM

# Public repositories need no token; a private one is read through the API,
# which serves the asset bytes when asked for application/octet-stream.
get() { # <asset name> <output file>
  if [ -n "$TOKEN" ]; then
    if [ -n "$VERSION" ]; then rel="tags/$VERSION"; else rel="latest"; fi
    json="$(curl -fsSL -H "Authorization: Bearer $TOKEN" -H "Accept: application/vnd.github+json" \
      "https://api.github.com/repos/$REPO/releases/$rel")" || return 1
    # asset id: the "id" printed right before the matching "name" inside the assets array
    id="$(printf '%s' "$json" | tr ',' '\n' | awk -v n="\"name\":\"$1\"" '
      /"url":"https:\/\/api.github.com\/repos\/[^"]*\/releases\/assets\/[0-9]+"/ { u = $0; sub(/.*assets\//, "", u); sub(/".*/, "", u) }
      index($0, n) && u != "" { print u; exit }')"
    [ -n "$id" ] || return 1
    curl -fsSL -H "Authorization: Bearer $TOKEN" -H "Accept: application/octet-stream" \
      -o "$2" "https://api.github.com/repos/$REPO/releases/assets/$id"
  else
    curl -fsSL -o "$2" "$BASE/$1"
  fi
}

echo "Downloading $ASSET (${VERSION:-latest}) from $REPO"
get "$ASSET" "$TMP/$ASSET" || fail "cannot download $ASSET from $REPO (no such release, or the repository is private: set GITHUB_TOKEN)"
get SHA256SUMS "$TMP/SHA256SUMS" || fail "cannot download SHA256SUMS from $REPO"
get SHA256SUMS.sig "$TMP/SHA256SUMS.sig" || fail "cannot download SHA256SUMS.sig from $REPO (releases are signed)"

# SHA256SUMS must be signed by the release key (the same key is built into pano
# for `pano update --latest`); a fork sets PANO_RELEASE_PUBKEY to its own.
if command -v openssl >/dev/null 2>&1 && openssl pkeyutl -help 2>&1 | grep -q rawin; then
  printf '%s\n' "${PANO_RELEASE_PUBKEY:-$RELEASE_PUBKEY}" > "$TMP/release.pub"
  openssl pkeyutl -verify -pubin -inkey "$TMP/release.pub" -rawin -in "$TMP/SHA256SUMS" -sigfile "$TMP/SHA256SUMS.sig" >/dev/null 2>&1 ||
    fail "SHA256SUMS is not signed by the pano release key; nothing was installed"
  echo "signature ok"
elif [ "${PANO_INSECURE_SKIP_SIGNATURE:-}" = "1" ]; then
  echo "warning: PANO_INSECURE_SKIP_SIGNATURE=1, the release signature was not checked (only the checksum)"
else
  fail "checking the release signature needs OpenSSL 3 (apt install openssl / dnf install openssl), or PANO_INSECURE_SKIP_SIGNATURE=1 to skip it"
fi
# The signed file names its release: an old signed release cannot be served as the one asked for.
SIGNED_TAG="$(sed -n 's/^# pano \(v[0-9][A-Za-z0-9.+-]*\)$/\1/p' "$TMP/SHA256SUMS" | head -n 1)"
[ -n "$SIGNED_TAG" ] || fail "SHA256SUMS names no release"
[ -z "$VERSION" ] || [ "$SIGNED_TAG" = "$VERSION" ] || fail "asked for $VERSION but the signed SHA256SUMS is for $SIGNED_TAG"
if [ -z "$VERSION" ] && version_lt "$SIGNED_TAG" "$MIN_VERSION"; then
  fail "the latest release served is $SIGNED_TAG, older than $MIN_VERSION, the oldest this installer accepts (a stale or replayed release); nothing was installed. Set PANO_VERSION to install a specific release anyway"
fi
echo "release $SIGNED_TAG"

WANT="$(awk -v f="$ASSET" '{ n = $2; sub(/^\*/, "", n); if (n == f) { print $1; exit } }' "$TMP/SHA256SUMS")"
[ -n "$WANT" ] || fail "$ASSET is not listed in SHA256SUMS"
HAVE="$(sha256sum "$TMP/$ASSET" | awk '{ print $1 }')"
[ "$WANT" = "$HAVE" ] || fail "checksum mismatch for $ASSET (expected $WANT, got $HAVE); nothing was installed"
echo "sha256 ok: $HAVE"

chmod 755 "$TMP/$ASSET"
"$TMP/$ASSET" version >/dev/null 2>&1 || fail "the downloaded binary does not run on this machine"
"$TMP/$ASSET" install
