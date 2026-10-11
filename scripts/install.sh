#!/bin/sh
# SignField installer, published as https://signfield.thallium81.dev/install.sh
#
#   curl -fsSL https://signfield.thallium81.dev/install.sh | sh
#
# Adds a pinned APT source for SignField on Debian 13 and installs it. Asks
# for your password itself; never pipe it into sudo.
set -eu

repository_url="${SIGNFIELD_REPOSITORY:-https://signfield.thallium81.dev}"
repository_url="${repository_url%/}"
key_fingerprint="BC075A23F742C83BCF6F309D221A85B5FA2D560D"
key_sha256="5a2edfdeb1a160bc1984e0b52ec62fb32a73ba9d076c832b530dee22ec19b6b4"
keyring_path="/etc/apt/keyrings/signfield-archive-keyring.pgp"
source_path="/etc/apt/sources.list.d/signfield.sources"
preferences_path="/etc/apt/preferences.d/signfield"

fail() {
  printf 'signfield installer: %s\n' "$*" >&2
  exit 1
}

command -v curl >/dev/null 2>&1 || fail "curl is required"
[ -r /etc/os-release ] || fail "/etc/os-release is missing"
command -v apt-get >/dev/null 2>&1 || fail "APT is required; SignField is packaged for Debian 13"
command -v dpkg >/dev/null 2>&1 || fail "dpkg is required"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required"

# shellcheck disable=SC1091
. /etc/os-release
suite="${DEBIAN_CODENAME:-${VERSION_CODENAME:-}}"
[ "$suite" = "trixie" ] \
  || fail "unsupported release '${suite:-unknown}'; SignField is built for Debian 13 (trixie) and Python 3.13"

architecture="$(dpkg --print-architecture)"
[ "$architecture" = "amd64" ] || fail "unsupported architecture '$architecture'; only amd64 is published"

# Adding an APT source needs root. Ask for it here, once.
if [ "$(id -u)" -ne 0 ]; then
  case " $* " in *" --as-root "*) fail "could not get root" ;; esac
  if command -v sudo >/dev/null 2>&1; then elevate=sudo
  elif command -v pkexec >/dev/null 2>&1; then elevate=pkexec
  else fail "adding the APT source needs sudo or pkexec"
  fi
  printf '>> adding the SignField APT source; %s will ask for your password\n' "$elevate"
  self="$(mktemp)"
  curl -fsSL --proto '=https' --tlsv1.2 "$repository_url/install.sh" -o "$self" \
    || fail "could not download the installer"
  exec "$elevate" env SIGNFIELD_REPOSITORY="$repository_url" sh "$self" --as-root
fi

temporary_key="$(mktemp)"
trap 'rm -f "$temporary_key"' EXIT HUP INT TERM

curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  "$repository_url/signfield-archive-keyring.pgp" --output "$temporary_key"
printf '%s  %s\n' "$key_sha256" "$temporary_key" | sha256sum --check --status \
  || fail "archive signing key checksum did not match fingerprint $key_fingerprint"

install -d -m 0755 /etc/apt/keyrings /etc/apt/sources.list.d /etc/apt/preferences.d
install -m 0644 "$temporary_key" "$keyring_path"

cat > "$source_path" <<SRC
Types: deb
URIs: $repository_url
Suites: $suite
Components: main
Architectures: $architecture
Signed-By: $keyring_path
SRC

# Only SignField gets normal priority from this source, so it can never
# replace an unrelated system package.
cat > "$preferences_path" <<'PIN'
Package: *
Pin: release o=SignField
Pin-Priority: 1

Package: signfield
Pin: release o=SignField
Pin-Priority: 500
PIN

apt-get update
apt-get install -y signfield

printf '\nSignField is installed and will update through APT.\n'
printf 'Launch it from the application menu or run: signfield\n'
