#!/bin/bash
# Deploy AIDR Dashboard to Vercel
# Usage: ./deploy-dashboard.sh [preview|production]

set -e

ENV=${1:-preview}
DASHBOARD_DIR="$(dirname "$0")/../packages/dashboard"

echo "🚀 Deploying AIDR Dashboard to Vercel ($ENV)..."

# Check if vercel CLI is installed
if ! command -v vercel &> /dev/null; then
    echo "❌ Vercel CLI not found. Install with: npm i -g vercel"
    exit 1
fi

# Navigate to dashboard directory
cd "$DASHBOARD_DIR"

# Build the project
echo "📦 Building dashboard..."
pnpm install
pnpm build

# Deploy to Vercel
if [ "$ENV" == "production" ]; then
    echo "🌍 Deploying to PRODUCTION..."
    vercel --prod
else
    echo "🔍 Deploying PREVIEW..."
    vercel
fi

echo "✅ Deployment complete!"
echo ""
echo "Next steps:"
echo "1. Update DNS to point dashboard.aidr.singularityrd.com to Vercel"
echo "2. Add environment variables in Vercel dashboard"
echo "3. Update aidr-landing/.env.production with new dashboard URL"
