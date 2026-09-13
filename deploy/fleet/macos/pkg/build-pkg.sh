#!/bin/sh
set -eu
umask 077
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
FLEET_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
ARTIFACT=${1:?usage: build-pkg.sh ARTIFACT SHA256 SIGNATURE PUBLIC_KEY SIGNING_IDENTITY VERSION OUTPUT_PKG}
SHA256=${2:?missing SHA256}; SIGNATURE=${3:?missing SIGNATURE}; PUBLIC_KEY=${4:?missing PUBLIC_KEY}
SIGNING_IDENTITY=${5:?missing Apple Installer signing identity}; VERSION=${6:?missing package version}; OUTPUT=${7:?missing output pkg}
printf '%s' "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$' || { echo "invalid package version" >&2; exit 64; }
command -v pkgbuild >/dev/null 2>&1 || { echo "pkgbuild is required" >&2; exit 1; }
command -v productsign >/dev/null 2>&1 || { echo "productsign is required" >&2; exit 1; }
[ ! -e "$OUTPUT" ] || { echo "output already exists" >&2; exit 1; }
"$FLEET_DIR/verify.sh" --artifact "$ARTIFACT" --sha256 "$SHA256" --signature "$SIGNATURE" --public-key "$PUBLIC_KEY"
STAGING=$(mktemp -d); trap 'rm -rf "$STAGING"' EXIT HUP INT TERM
PAYLOAD="$STAGING/payload/Library/Application Support/Singularity AIDR"
mkdir -p "$PAYLOAD/fleet/macos" "$PAYLOAD/fleet/unix" "$PAYLOAD/fleet/libexec" "$PAYLOAD/payload" "$PAYLOAD/config"
cp "$FLEET_DIR"/*.sh "$PAYLOAD/fleet/macos/"
cp "$FLEET_DIR/README.md" "$PAYLOAD/fleet/macos/"
cp "$FLEET_DIR/../unix/"* "$PAYLOAD/fleet/unix/"
cp "$FLEET_DIR/../../../scripts/endpoint-install.mjs" "$PAYLOAD/fleet/libexec/endpoint-install.mjs"
cp "$ARTIFACT" "$PAYLOAD/payload/connector.tgz"
cp "$SIGNATURE" "$PAYLOAD/payload/connector.tgz.sig"
cp "$PUBLIC_KEY" "$PAYLOAD/config/release-public.pem"
printf '%s\n' "$SHA256" > "$PAYLOAD/payload/connector.tgz.sha256"
find "$STAGING/payload" -type d -exec chmod 755 {} \;
find "$STAGING/payload" -type f -exec chmod 644 {} \;
find "$PAYLOAD/fleet" -name '*.sh' -exec chmod 755 {} \;
mkdir "$STAGING/scripts"
cp "$SCRIPT_DIR/scripts/preinstall" "$SCRIPT_DIR/scripts/postinstall" "$STAGING/scripts/"
chmod 755 "$STAGING/scripts/preinstall" "$STAGING/scripts/postinstall"
pkgbuild --root "$STAGING/payload" --scripts "$STAGING/scripts" --identifier com.singularity.aidr.fleet --version "$VERSION" --install-location / "$STAGING/unsigned.pkg"
productsign --sign "$SIGNING_IDENTITY" "$STAGING/unsigned.pkg" "$OUTPUT"
pkgutil --check-signature "$OUTPUT"
echo "Created signed macOS fleet package: $OUTPUT"
