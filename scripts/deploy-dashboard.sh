#!/usr/bin/env bash
# Deploy the AIDR dashboard to Vercel.
#
# Usage: scripts/deploy-dashboard.sh [preview|production]
#
# Only the environments listed below are accepted. A production deploy also
# requires a clean working tree (no modified, staged or untracked files), HEAD
# exactly at a release tag, and an explicit confirmation: type "production" at
# the interactive prompt, or set AIDR_DEPLOY_CONFIRM=production when running
# without a terminal. Dependencies are installed from the lockfile only.

set -euo pipefail

die() {
	echo "ERROR: $*" >&2
	exit 1
}

usage() {
	echo "Usage: $0 [preview|production]" >&2
}

if [ "$#" -gt 1 ]; then
	usage
	exit 2
fi

ENV="${1:-preview}"
case "$ENV" in
preview | production) ;;
*)
	echo "ERROR: unknown environment '$ENV' (expected preview or production)" >&2
	usage
	exit 2
	;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DASHBOARD_DIR="$REPO_ROOT/packages/dashboard"

command -v vercel >/dev/null 2>&1 || die "Vercel CLI not found. Install with: npm i -g vercel"
command -v pnpm >/dev/null 2>&1 || die "pnpm not found"
[ -d "$DASHBOARD_DIR" ] || die "dashboard directory not found: $DASHBOARD_DIR"

if [ "$ENV" = "production" ]; then
	git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1 ||
		die "production deploys must run from a git checkout"
	dirty="$(git -C "$REPO_ROOT" status --porcelain --untracked-files=all)" ||
		die "unable to read git status"
	if [ -n "$dirty" ]; then
		echo "$dirty" >&2
		die "working tree is not clean; commit or remove the changes above before a production deploy"
	fi
	tag="$(git -C "$REPO_ROOT" describe --exact-match --tags HEAD 2>/dev/null)" ||
		die "HEAD is not exactly at a tag; production deploys only ship tagged releases"

	if [ -n "${AIDR_DEPLOY_CONFIRM:-}" ]; then
		answer="$AIDR_DEPLOY_CONFIRM"
	elif [ -t 0 ]; then
		read -r -p "Deploying tag $tag to PRODUCTION. Type 'production' to continue: " answer || answer=""
	else
		die "production deploy not confirmed; run interactively or set AIDR_DEPLOY_CONFIRM=production"
	fi
	[ "$answer" = "production" ] || die "production deploy not confirmed"
	echo "Deploying tag $tag to PRODUCTION..."
else
	echo "Deploying PREVIEW..."
fi

cd "$DASHBOARD_DIR"

echo "Installing dependencies from the lockfile..."
pnpm install --frozen-lockfile
echo "Building dashboard..."
pnpm build

if [ "$ENV" = "production" ]; then
	vercel --prod
else
	vercel
fi

echo "Deployment complete."
echo ""
echo "Next steps:"
echo "1. Update DNS to point dashboard.aidr.singularityrd.com to Vercel"
echo "2. Add environment variables in Vercel dashboard"
echo "3. Update aidr-landing/.env.production with new dashboard URL"
