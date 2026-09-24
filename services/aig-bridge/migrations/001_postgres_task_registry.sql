BEGIN;

CREATE TABLE IF NOT EXISTS public.aig_bridge_registry_meta (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    schema_version integer NOT NULL CHECK (schema_version > 0)
);

INSERT INTO public.aig_bridge_registry_meta (singleton, schema_version)
VALUES (true, 1)
ON CONFLICT (singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS public.aig_bridge_tasks (
    task_id text PRIMARY KEY,
    tenant_id text NOT NULL,
    created_at double precision NOT NULL,
    request_hash text,
    idempotency_key text,
    status text NOT NULL DEFAULT 'queued'
        CHECK (status IN ('reserved', 'queued', 'running', 'completed', 'failed', 'cancelled', 'expired')),
    task_type text,
    lease_owner text,
    lease_expires_at double precision,
    cancel_requested boolean NOT NULL DEFAULT false,
    updated_at double precision NOT NULL,
    UNIQUE (tenant_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_aig_bridge_tasks_created_at
    ON public.aig_bridge_tasks (created_at);

CREATE INDEX IF NOT EXISTS idx_aig_bridge_tasks_tenant_state
    ON public.aig_bridge_tasks (tenant_id, status);

COMMIT;
