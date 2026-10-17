#!/bin/sh
set -eu
umask 077
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ARTIFACT=${1:?usage: build-offline-bundle.sh ARTIFACT SHA256 SIGNATURE PUBLIC_KEY OUTPUT [BUNDLE_PUBLIC_KEY]}
SHA256=${2:?missing SHA256}; SIGNATURE=${3:?missing SIGNATURE}; PUBLIC_KEY=${4:?missing PUBLIC_KEY}; OUTPUT=${5:?missing OUTPUT}
# Optional: the Ed25519 release key a signed standalone bundle's manifests verify against.
BUNDLE_PUBLIC_KEY=${6:-}
[ ! -e "$OUTPUT" ] || { echo "output already exists" >&2; exit 1; }
"$SCRIPT_DIR/verify.sh" --artifact "$ARTIFACT" --sha256 "$SHA256" --signature "$SIGNATURE" --public-key "$PUBLIC_KEY"
STAGING=$(mktemp -d)
trap 'rm -rf "$STAGING"' EXIT HUP INT TERM
mkdir -p "$STAGING/aidr-fleet/linux" "$STAGING/aidr-fleet/unix" "$STAGING/aidr-fleet/libexec" "$STAGING/aidr-fleet/payload"
cp "$SCRIPT_DIR"/*.sh "$STAGING/aidr-fleet/linux/"
cp "$SCRIPT_DIR/README.md" "$STAGING/aidr-fleet/linux/"
cp -R "$SCRIPT_DIR/systemd" "$STAGING/aidr-fleet/linux/"
cp "$SCRIPT_DIR/../unix/"* "$STAGING/aidr-fleet/unix/"
cp "$SCRIPT_DIR/../../../scripts/endpoint-install.mjs" "$STAGING/aidr-fleet/libexec/endpoint-install.mjs"
cp "$ARTIFACT" "$STAGING/aidr-fleet/payload/connector.tgz"
cp "$SIGNATURE" "$STAGING/aidr-fleet/payload/connector.tgz.sig"
cp "$PUBLIC_KEY" "$STAGING/aidr-fleet/payload/release-public.pem"
[ -z "$BUNDLE_PUBLIC_KEY" ] || cp "$BUNDLE_PUBLIC_KEY" "$STAGING/aidr-fleet/payload/bundle-release-public.pem"
printf '%s\n' "$SHA256" > "$STAGING/aidr-fleet/payload/connector.tgz.sha256"
find "$STAGING" -type d -exec chmod 755 {} \;
find "$STAGING" -type f -exec chmod 644 {} \;
find "$STAGING" -name '*.sh' -exec chmod 755 {} \;
tar -C "$STAGING" -czf "$OUTPUT" aidr-fleet
echo "Created verified offline Linux fleet bundle: $OUTPUT"
