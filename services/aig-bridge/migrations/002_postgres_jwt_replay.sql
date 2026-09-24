BEGIN;

CREATE TABLE IF NOT EXISTS public.aig_bridge_jwt_replay (
    jti text PRIMARY KEY,
    expires_at bigint NOT NULL CHECK (expires_at > 0)
);

CREATE INDEX IF NOT EXISTS idx_aig_bridge_jwt_replay_expires_at
    ON public.aig_bridge_jwt_replay (expires_at);

COMMIT;
