#!/bin/sh
set -eu
umask 077
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
FLEET_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
ARTIFACT=${1:?usage: build-pkg.sh ARTIFACT SHA256 SIGNATURE PUBLIC_KEY SIGNING_IDENTITY VERSION OUTPUT_PKG [BUNDLE_PUBLIC_KEY]}
SHA256=${2:?missing SHA256}; SIGNATURE=${3:?missing SIGNATURE}; PUBLIC_KEY=${4:?missing PUBLIC_KEY}
SIGNING_IDENTITY=${5:?missing Apple Installer signing identity}; VERSION=${6:?missing package version}; OUTPUT=${7:?missing output pkg}
# Optional: the Ed25519 release key a signed standalone bundle's manifests verify against.
BUNDLE_PUBLIC_KEY=${8:-}
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
if [ -n "$BUNDLE_PUBLIC_KEY" ]; then
	openssl pkey -pubin -in "$BUNDLE_PUBLIC_KEY" -noout 2>/dev/null || { echo "invalid bundle release public key" >&2; exit 1; }
	cp "$BUNDLE_PUBLIC_KEY" "$PAYLOAD/config/bundle-release-public.pem"
fi
openssl pkey -pubin -in "$PAYLOAD/config/release-public.pem" -outform DER > "$STAGING/release-public.der" 2>/dev/null || { echo "invalid release public key" >&2; exit 1; }
KEY_SHA256=$(openssl dgst -sha256 -r "$STAGING/release-public.der" | awk '{print $1}')
printf '%s' "$KEY_SHA256" | grep -Eq '^[a-f0-9]{64}$' || { echo "invalid release public key fingerprint" >&2; exit 1; }
printf '%s\n' "$SHA256" > "$PAYLOAD/payload/connector.tgz.sha256"
find "$STAGING/payload" -type d -exec chmod 755 {} \;
find "$STAGING/payload" -type f -exec chmod 644 {} \;
find "$PAYLOAD/fleet" -name '*.sh' -exec chmod 755 {} \;
mkdir "$STAGING/scripts"
sed "s/@RELEASE_KEY_SHA256@/$KEY_SHA256/" "$SCRIPT_DIR/scripts/preinstall" > "$STAGING/scripts/preinstall"
cp "$SCRIPT_DIR/scripts/postinstall" "$STAGING/scripts/"
chmod 755 "$STAGING/scripts/preinstall" "$STAGING/scripts/postinstall"
pkgbuild --root "$STAGING/payload" --scripts "$STAGING/scripts" --identifier com.singularity.aidr.fleet --version "$VERSION" --install-location / "$STAGING/unsigned.pkg"
productsign --sign "$SIGNING_IDENTITY" "$STAGING/unsigned.pkg" "$OUTPUT"
pkgutil --check-signature "$OUTPUT"
echo "Created signed macOS fleet package: $OUTPUT"
