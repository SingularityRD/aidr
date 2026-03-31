# AIDR Dashboard Deployment Guide

## Deployment Options

### Option 1: Vercel Deployment (Recommended)

**Why Vercel?**
- Same platform as landing page
- Automatic deploys from git
- Edge network (fast globally)
- Free tier available

**Setup Steps:**

1. **Create Vercel Project:**
   ```bash
   cd packages/dashboard
   vercel
   ```

2. **Environment Variables:**
   ```env
   VITE_SUPABASE_URL=https://qacrbrailtemkzgwrxrt.supabase.co
   VITE_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   VITE_TURNSTILE_SITE_KEY=0x4AAAAAA... (optional)
   ```

3. **Domain Setup:**
   - Add custom domain: `dashboard.aidr.singularityrd.com`
   - Or use Vercel subdomain: `aidr-dashboard.vercel.app`

4. **Update Landing Page Links:**
   - In `aidr-landing/.env.production`:
   ```env
   NEXT_PUBLIC_DASHBOARD_URL=https://dashboard.aidr.singularityrd.com
   ```

### Option 2: Netlify Deployment

```bash
cd packages/dashboard
netlify deploy --build --prod
```

### Option 3: Static Hosting (S3, Cloudflare Pages, etc.)

```bash
cd packages/dashboard
pnpm build
# Upload dist/ folder to your static host
```

---

## Auth Configuration

### Supabase Settings

1. **Authentication → URL Configuration:**
   - Site URL: `https://dashboard.aidr.singularityrd.com`
   - Redirect URLs: 
     ```
     https://dashboard.aidr.singularityrd.com/auth/callback
     http://localhost:5173/auth/callback
     ```

2. **Providers:**
   - GitHub OAuth: Enable (for dashboard login)
   - Google OAuth: Optional
   - Email/Magic Link: Enabled by default

### CORS Settings

Add to Supabase → Settings → API:
```
https://dashboard.aidr.singularityrd.com
https://aidr.singularityrd.com
```

---

## Integration with Landing Page

### Flow Architecture

```
User → Landing Page (Vercel)
         ↓
      Login/Signup
         ↓
    Supabase Auth (shared)
         ↓
   Onboarding (device code)
         ↓
   Click "Open Dashboard"
         ↓
   Dashboard (deployed SPA)
         ↓
   Verify Device / Manage Agents
```

### Session Sharing

Both apps use SAME Supabase project:
- Same JWT tokens
- Same user database
- Session persists across domains
- Auto-login in dashboard if logged in landing

---

## Post-Deployment Checklist

- [ ] Dashboard loads without errors
- [ ] Login works (GitHub/Google/Magic Link)
- [ ] Auth callback redirects correctly
- [ ] Session persists after refresh
- [ ] Device verification flow works
- [ ] API keys can be generated
- [ ] Agent list displays correctly
- [ ] Incidents page loads

---

## Local Development

```bash
# Terminal 1: Landing page
cd aidr-landing
npm run dev
# http://localhost:4567

# Terminal 2: Dashboard
cd aidr/packages/dashboard
pnpm dev
# http://localhost:5173
```

Both can run simultaneously with shared auth!
