# Device Auth (Browser Verification)

Singularity AIDR uses a device-style authorization flow to make onboarding fast without copying API keys into prompts.

## How it works (v1)

1. Install the connector for your runtime (Claude Code / Cursor / VS Code / OpenClaw / OpenCode).
2. Start the agent once.
3. If the installation is not enrolled yet, Singularity AIDR shows:
   - a short **verification code**
   - a **verification URL**
4. Open the URL in your browser and sign in (Google OAuth via Supabase).
5. Enter the code and approve the device.
6. Restart the agent (or rerun the "Enable protection" command).

After approval, Singularity AIDR completes enrollment and caches the resulting managed state locally under `~/.singularity-aidr/managed.json`.

## Offline behavior

- Device authorization requires network access.
- After a successful enrollment, the agent can continue operating during the configured offline grace window (see `control_plane.grace_period_hours`).

## Security notes

- Verification codes are short-lived and single-use.
- Enrollment is gated by pilot approval in early launch phases (see [Pilot Program](pilot-program.md)).
- API keys and enrollment tokens are stored hash-only server-side; plaintext is shown only at issuance.

