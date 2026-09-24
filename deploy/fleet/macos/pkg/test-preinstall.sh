#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TEST_ROOT=$(mktemp -d)
trap 'rm -rf "$TEST_ROOT"' EXIT HUP INT TERM

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$TEST_ROOT/old-private.pem" >/dev/null 2>&1
openssl pkey -in "$TEST_ROOT/old-private.pem" -pubout -out "$TEST_ROOT/old-public.pem" >/dev/null 2>&1
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$TEST_ROOT/new-private.pem" >/dev/null 2>&1
openssl pkey -in "$TEST_ROOT/new-private.pem" -pubout -out "$TEST_ROOT/new-public.pem" >/dev/null 2>&1

fingerprint() {
	openssl pkey -pubin -in "$1" -outform DER > "$TEST_ROOT/key.der"
	openssl dgst -sha256 -r "$TEST_ROOT/key.der" | awk '{print $1}'
}
OLD_SHA256=$(fingerprint "$TEST_ROOT/old-public.pem")
NEW_SHA256=$(fingerprint "$TEST_ROOT/new-public.pem")
OPENSSL_DIR=$(dirname "$(command -v openssl)")
mkdir "$TEST_ROOT/pin"

render() {
	sed -e "s|^PATH=.*|PATH=$OPENSSL_DIR:/usr/sbin:/usr/bin:/sbin:/bin|" \
		-e "s|^ROOT=.*|ROOT=\"$TEST_ROOT/install\"|" \
		-e "s|^PIN_DIR=.*|PIN_DIR=\"$TEST_ROOT/pin\"|" \
		-e "s|^ROOT_UID=0$|ROOT_UID=$(id -u)|" \
		-e "s|@RELEASE_KEY_SHA256@|$1|" \
		"$SCRIPT_DIR/scripts/preinstall" > "$TEST_ROOT/preinstall"
	chmod 700 "$TEST_ROOT/preinstall"
}
expect_reject() {
	if "$TEST_ROOT/preinstall" fixture.pkg / / >/dev/null 2>&1; then
		echo "preinstall unexpectedly accepted: $1" >&2
		exit 1
	fi
}

render "$OLD_SHA256"
expect_reject 'missing independent pin'
printf 'invalid\n' > "$TEST_ROOT/pin/release-public.sha256"
expect_reject 'malformed independent pin'
printf '%s' "$OLD_SHA256" > "$TEST_ROOT/pin/release-public.sha256"
expect_reject 'fingerprint without required newline'
printf '%s\n' "$OLD_SHA256" > "$TEST_ROOT/pin/release-public.sha256"
if "$TEST_ROOT/preinstall" fixture.pkg / /Volumes/Other >/dev/null 2>&1; then
	echo 'preinstall accepted an alternate target volume' >&2
	exit 1
fi
if sh "$SCRIPT_DIR/scripts/postinstall" fixture.pkg / /Volumes/Other >/dev/null 2>&1; then
	echo 'postinstall accepted an alternate target volume' >&2
	exit 1
fi
"$TEST_ROOT/preinstall" fixture.pkg / /

render "$NEW_SHA256"
expect_reject 'unapproved candidate key'
render "$OLD_SHA256"
mkdir -p "$TEST_ROOT/install/config"
cp "$TEST_ROOT/old-public.pem" "$TEST_ROOT/install/config/release-public.pem"
"$TEST_ROOT/preinstall" fixture.pkg / /

cp "$TEST_ROOT/new-public.pem" "$TEST_ROOT/install/config/release-public.pem"
cp "$TEST_ROOT/install/config/release-public.pem" "$TEST_ROOT/before-rejection.pem"
expect_reject 'unexpected installed-key rotation'
cmp "$TEST_ROOT/before-rejection.pem" "$TEST_ROOT/install/config/release-public.pem"
rm "$TEST_ROOT/install/config/release-public.pem"
expect_reject 'missing installed key on upgrade'
echo 'macOS PKG preinstall trust checks passed'
