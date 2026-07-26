#!/bin/sh
# Install Draugr.
#
#   curl -fsSL https://draugr.dev/install.sh | sh
#
# Pipe-to-shell is a convenience with a cost: you are trusting whatever the host served. This
# script tries to earn that back rather than assume it. It always checks the archive's SHA-256
# against the release's checksums file, and when cosign is available it verifies that the
# checksums file was signed by Draugr's release workflow — which is the check that actually
# means something, since a host able to serve you this script could serve you a matching
# checksums file too.
#
# It says which of those two happened. It never installs anything it could not verify, and it
# never uses sudo.
#
#   DRAUGR_VERSION=v0.36.1     install a specific release instead of the latest
#   DRAUGR_INSTALL_DIR=~/bin   install somewhere other than ~/.local/bin
#   DRAUGR_REQUIRE_SIGNATURE=1 fail rather than continue when cosign is unavailable
#
# Prefer not to pipe an unread script? Read it first, or follow the manual steps at
# https://draugr.dev/docs/latest/getting-started/install/ — they do the same thing by hand.
set -eu

REPO="draugr-dev/draugr"
INSTALL_DIR="${DRAUGR_INSTALL_DIR:-$HOME/.local/bin}"
# Matches the keyless identity the release workflow signs with. Anything else is not our release.
IDENTITY_RE="^https://github\.com/draugr-dev/draugr/\.github/workflows/release\.yml@refs/tags/v.*\$"
OIDC_ISSUER="https://token.actions.githubusercontent.com"

err()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
note() { printf '  %s\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }

need() { command -v "$1" >/dev/null 2>&1 || err "$1 is required but not installed"; }
need curl
need tar

# --- what to fetch -----------------------------------------------------------------------

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$arch" in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) err "unsupported architecture: $arch (releases cover amd64 and arm64)" ;;
esac
case "$os" in
  linux | darwin) ;;
  mingw* | msys* | cygwin*)
    err "this script is for Linux and macOS. On Windows, download the .zip from
       https://github.com/$REPO/releases/latest" ;;
  *) err "unsupported OS: $os" ;;
esac

tag="${DRAUGR_VERSION:-}"
if [ -z "$tag" ]; then
  # Resolve "latest" by following the redirect rather than parsing the API, so this works
  # unauthenticated and without jq.
  tag=$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
        "https://github.com/$REPO/releases/latest" | sed 's#.*/tag/##')
  [ -n "$tag" ] || err "could not determine the latest release"
fi
version="${tag#v}"
archive="draugr_${version}_${os}_${arch}.tar.gz"
base="https://github.com/$REPO/releases/download/$tag"

printf '\ndraugr %s (%s/%s)\n' "$tag" "$os" "$arch"

tmp=$(mktemp -d)
# shellcheck disable=SC2064  # expand tmp now: it must be removed even if the variable changes
trap "rm -rf '$tmp'" EXIT INT TERM

# --- download ----------------------------------------------------------------------------

curl -fsSL "$base/$archive" -o "$tmp/$archive" \
  || err "could not download $archive from $base
       (if $tag is a real release, check that it publishes a $os/$arch build)"
curl -fsSL "$base/checksums.txt" -o "$tmp/checksums.txt" \
  || err "could not download checksums.txt — refusing to install unverified"

# --- verify ---------------------------------------------------------------------------------

# 1. Signature. This is the check that matters: it ties checksums.txt to Draugr's release
#    workflow, so a compromised mirror can't hand you a consistent set of bad files.
signed=no
if command -v cosign >/dev/null 2>&1; then
  if curl -fsSL "$base/checksums.txt.sigstore.json" -o "$tmp/checksums.txt.sigstore.json"; then
    if (cd "$tmp" && cosign verify-blob \
          --bundle checksums.txt.sigstore.json \
          --certificate-identity-regexp "$IDENTITY_RE" \
          --certificate-oidc-issuer "$OIDC_ISSUER" \
          checksums.txt >/dev/null 2>&1); then
      signed=yes
      ok "checksums.txt signed by the Draugr release workflow (cosign)"
    else
      err "checksums.txt failed signature verification.
       This is not a normal failure. Do not install; please report it at
       https://github.com/$REPO/issues"
    fi
  else
    warn "no signature published for $tag; falling back to checksum only"
  fi
else
  warn "cosign not installed — checking the archive's checksum, but not who signed it"
  note "for full verification: https://draugr.dev/docs/latest/trust-and-operations/verifying-releases/"
fi

if [ "$signed" != yes ] && [ -n "${DRAUGR_REQUIRE_SIGNATURE:-}" ]; then
  err "DRAUGR_REQUIRE_SIGNATURE is set and the signature could not be verified"
fi

# 2. Checksum. Confirms the archive matches the checksums file, whatever that file's provenance.
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$tmp/$archive" | cut -d' ' -f1)
elif command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "$tmp/$archive" | cut -d' ' -f1)
else
  err "need sha256sum or shasum to verify the download"
fi
expected=$(grep " $archive\$" "$tmp/checksums.txt" | cut -d' ' -f1)
[ -n "$expected" ] || err "$archive is not listed in checksums.txt"
[ "$actual" = "$expected" ] || err "checksum mismatch for $archive
       expected $expected
       got      $actual
       Do not use this download."
ok "SHA-256 matches"

# --- install -----------------------------------------------------------------------------

tar -xzf "$tmp/$archive" -C "$tmp" draugr || err "could not extract draugr from $archive"
mkdir -p "$INSTALL_DIR" || err "could not create $INSTALL_DIR"
mv "$tmp/draugr" "$INSTALL_DIR/draugr" || err "could not write to $INSTALL_DIR"
chmod +x "$INSTALL_DIR/draugr"
ok "installed $INSTALL_DIR/draugr"

if [ "$signed" != yes ]; then
  printf '\n\033[33mVerified the checksum, but not the signature.\033[0m Install cosign and re-run\n'
  printf 'for the stronger check, or verify by hand:\n'
  printf '  https://draugr.dev/docs/latest/trust-and-operations/verifying-releases/\n'
fi

# PATH advice, since installing somewhere unreachable is the most common way this "works" and
# then appears not to.
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) printf '\n\033[33m%s is not on your PATH.\033[0m Add it:\n' "$INSTALL_DIR"
     printf '  export PATH="%s:$PATH"\n' "$INSTALL_DIR" ;;
esac

printf '\nNext:\n'
printf '  draugr init          scaffold a draugr.saga.yaml for this project\n'
printf '  draugr tools install provision the scanners your controls need\n'
printf '  draugr scan .        scan without a descriptor, to see what it does\n\n'
