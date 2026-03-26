-- ============================================================
-- W46 — PostgreSQL Schema
-- Production-ready with immutable audit, advisory locks, triggers
-- ============================================================

-- Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================
-- SECTION 1: Core Enums
-- ============================================================

CREATE TYPE env_mode AS ENUM ('sandbox', 'live');
CREATE TYPE kyb_status AS ENUM ('not_started', 'pending', 'approved', 'rejected');
CREATE TYPE wallet_status AS ENUM ('active', 'frozen', 'closed');
CREATE TYPE tx_status AS ENUM (
    'pending_policy', 'policy_rejected', 'policy_approved',
    'pending_settlement', 'settling', 'settled',
    'failed', 'deferred', 'reversed'
);
CREATE TYPE tx_rail AS ENUM ('solana', 'base', 'internal', 'budget_auth');
CREATE TYPE audit_action AS ENUM (
    'org_created', 'org_updated', 'kyb_submitted', 'kyb_approved', 'kyb_rejected',
    'api_key_created', 'api_key_rotated', 'api_key_revoked',
    'wallet_created', 'wallet_frozen', 'wallet_closed',
    'policy_created', 'policy_updated',
    'tx_initiated', 'tx_policy_checked', 'tx_settled', 'tx_failed', 'tx_deferred',
    'human_approval_requested', 'human_approval_granted', 'human_approval_denied',
    'reconciliation_mismatch', 'anchor_published',
    'fee_swept', 'reputation_updated'
);

-- ============================================================
-- SECTION 2: Organizations & Auth
-- ============================================================

CREATE TABLE organizations (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            TEXT NOT NULL,
    email           TEXT NOT NULL UNIQUE,
    email_verified  BOOLEAN NOT NULL DEFAULT FALSE,
    email_token     TEXT,
    email_token_exp TIMESTAMPTZ,
    password_hash   TEXT NOT NULL,
    mode            env_mode NOT NULL DEFAULT 'sandbox',
    kyb_status      kyb_status NOT NULL DEFAULT 'not_started',
    kyb_data        JSONB,
    kyb_reviewed_at TIMESTAMPTZ,
    tos_accepted_at TIMESTAMPTZ,
    tos_ip          INET,
    tos_version     TEXT,
    metadata        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE api_keys (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    key_hash        TEXT NOT NULL UNIQUE,
    key_prefix      TEXT NOT NULL,          -- first 8 chars for display: "w46_live_abc..."
    label           TEXT DEFAULT 'default',
    mode            env_mode NOT NULL,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    last_used_at    TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at      TIMESTAMPTZ
);

CREATE INDEX idx_api_keys_hash ON api_keys(key_hash) WHERE is_active = TRUE;
CREATE INDEX idx_api_keys_org ON api_keys(org_id);

-- ============================================================
-- SECTION 3: Wallets
-- ============================================================

CREATE TABLE wallets (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id          UUID NOT NULL REFERENCES organizations(id),
    agent_id        TEXT NOT NULL,          -- developer-chosen identifier
    label           TEXT,
    status          wallet_status NOT NULL DEFAULT 'active',
    
    -- Blockchain addresses (populated on creation)
    solana_address  TEXT,
    base_address    TEXT,
    
    -- KMS key references (never the actual private key)
    solana_key_ref  TEXT,
    base_key_ref    TEXT,
    
    -- Ledger mirror (operational cache — blockchain is source of truth)
    balance_usdc    NUMERIC(20,6) NOT NULL DEFAULT 0,
    
    -- Reputation
    trust_score     INTEGER NOT NULL DEFAULT 50 CHECK (trust_score BETWEEN 0 AND 100),
    
    -- AFID (Agent Financial Identity)
    afid_public_key TEXT,
    afid_metadata   JSONB DEFAULT '{}',
    
    -- Counters for policy engine (denormalized for speed)
    daily_spent     NUMERIC(20,6) NOT NULL DEFAULT 0,
    daily_reset_at  DATE NOT NULL DEFAULT CURRENT_DATE,
    monthly_spent   NUMERIC(20,6) NOT NULL DEFAULT 0,
    monthly_reset_at DATE NOT NULL DEFAULT date_trunc('month', CURRENT_DATE)::DATE,
    
    metadata        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE(org_id, agent_id)
);

CREATE INDEX idx_wallets_org ON wallets(org_id);
CREATE INDEX idx_wallets_solana ON wallets(solana_address) WHERE solana_address IS NOT NULL;
CREATE INDEX idx_wallets_base ON wallets(base_address) WHERE base_address IS NOT NULL;

-- ============================================================
-- SECTION 4: Policies
-- ============================================================

CREATE TABLE policies (
    id                          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    wallet_id                   UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    
    max_per_tx_usdc             NUMERIC(20,6) NOT NULL DEFAULT 1000,
    daily_limit_usdc            NUMERIC(20,6) NOT NULL DEFAULT 10000,
    monthly_limit_usdc          NUMERIC(20,6) NOT NULL DEFAULT 100000,
    
    allowed_categories          TEXT[] DEFAULT '{}',    -- empty = all allowed
    blocked_destinations        TEXT[] DEFAULT '{}',
    
    human_approval_threshold    NUMERIC(20,6) NOT NULL DEFAULT 5000,
    verified_rail_threshold     NUMERIC(20,6) NOT NULL DEFAULT 500,
    
    require_memo                BOOLEAN NOT NULL DEFAULT FALSE,
    is_active                   BOOLEAN NOT NULL DEFAULT TRUE,
    
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_policies_wallet ON policies(wallet_id) WHERE is_active = TRUE;

-- ============================================================
-- SECTION 5: Transactions
-- ============================================================

CREATE TABLE transactions (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id              UUID NOT NULL REFERENCES organizations(id),
    from_wallet_id      UUID NOT NULL REFERENCES wallets(id),
    to_address          TEXT NOT NULL,           -- blockchain address or W46 wallet id
    to_wallet_id        UUID REFERENCES wallets(id),  -- set if internal
    
    amount_usdc         NUMERIC(20,6) NOT NULL CHECK (amount_usdc > 0),
    fee_usdc            NUMERIC(20,6) NOT NULL DEFAULT 0,
    
    rail                tx_rail,
    status              tx_status NOT NULL DEFAULT 'pending_policy',
    
    -- Blockchain proof
    tx_hash             TEXT,
    block_number        BIGINT,
    settled_at          TIMESTAMPTZ,
    
    -- Policy snapshot at evaluation time
    policy_snapshot     JSONB,
    policy_result       JSONB,
    
    -- Budget authorization (for budget_auth rail)
    budget_auth_token   TEXT,
    budget_reconciled   BOOLEAN DEFAULT FALSE,
    
    -- Proof chain
    proof_hash          TEXT,
    prev_proof_hash     TEXT,
    
    -- Metadata
    memo                TEXT,
    category            TEXT,
    idempotency_key     TEXT UNIQUE,
    metadata            JSONB DEFAULT '{}',
    error_message       TEXT,
    
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tx_org ON transactions(org_id);
CREATE INDEX idx_tx_from ON transactions(from_wallet_id);
CREATE INDEX idx_tx_to_wallet ON transactions(to_wallet_id) WHERE to_wallet_id IS NOT NULL;
CREATE INDEX idx_tx_status ON transactions(status);
CREATE INDEX idx_tx_created ON transactions(created_at);
CREATE INDEX idx_tx_idempotency ON transactions(idempotency_key) WHERE idempotency_key IS NOT NULL;

-- ============================================================
-- SECTION 6: Proof Anchoring
-- ============================================================

CREATE TABLE anchor_batches (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    merkle_root     TEXT NOT NULL,
    tx_count        INTEGER NOT NULL,
    first_tx_id     UUID REFERENCES transactions(id),
    last_tx_id      UUID REFERENCES transactions(id),
    
    -- Anchoring targets
    solana_tx_hash  TEXT,
    solana_slot     BIGINT,
    base_tx_hash    TEXT,
    base_block      BIGINT,
    
    anchored_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- SECTION 7: Audit Log (IMMUTABLE)
-- ============================================================

CREATE TABLE audit_log (
    id              BIGSERIAL PRIMARY KEY,
    org_id          UUID REFERENCES organizations(id),
    wallet_id       UUID REFERENCES wallets(id),
    tx_id           UUID REFERENCES transactions(id),
    action          audit_action NOT NULL,
    actor           TEXT NOT NULL,           -- 'system', 'api_key:<prefix>', 'admin:<id>'
    details         JSONB DEFAULT '{}',
    ip_address      INET,
    
    -- Hash chain for tamper detection
    record_hash     TEXT NOT NULL,
    prev_hash       TEXT NOT NULL,
    
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_org ON audit_log(org_id);
CREATE INDEX idx_audit_wallet ON audit_log(wallet_id);
CREATE INDEX idx_audit_action ON audit_log(action);
CREATE INDEX idx_audit_created ON audit_log(created_at);

-- ============================================================
-- SECTION 8: Fee Tracking
-- ============================================================

CREATE TABLE fee_ledger (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tx_id           UUID NOT NULL REFERENCES transactions(id),
    wallet_id       UUID NOT NULL REFERENCES wallets(id),
    amount_usdc     NUMERIC(20,6) NOT NULL,
    rail            tx_rail NOT NULL,
    swept           BOOLEAN NOT NULL DEFAULT FALSE,
    swept_at        TIMESTAMPTZ,
    sweep_tx_hash   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_fees_unswept ON fee_ledger(swept) WHERE swept = FALSE;

-- ============================================================
-- SECTION 9: Reconciliation
-- ============================================================

CREATE TABLE reconciliation_runs (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    wallet_id       UUID NOT NULL REFERENCES wallets(id),
    ledger_balance  NUMERIC(20,6) NOT NULL,
    chain_balance   NUMERIC(20,6) NOT NULL,
    chain           TEXT NOT NULL,           -- 'solana' or 'base'
    matches         BOOLEAN NOT NULL,
    drift_usdc      NUMERIC(20,6) NOT NULL DEFAULT 0,
    resolved        BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_recon_mismatches ON reconciliation_runs(matches) WHERE matches = FALSE;

-- ============================================================
-- SECTION 10: Triggers — Immutability Guards
-- ============================================================

-- Prevent UPDATE on audit_log
CREATE OR REPLACE FUNCTION fn_audit_immutable()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is immutable: UPDATE not allowed';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_no_update
    BEFORE UPDATE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION fn_audit_immutable();

-- Prevent DELETE on audit_log
CREATE OR REPLACE FUNCTION fn_audit_no_delete()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is immutable: DELETE not allowed';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_no_delete
    BEFORE DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION fn_audit_no_delete();

-- Auto-update updated_at
CREATE OR REPLACE FUNCTION fn_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_org_updated_at
    BEFORE UPDATE ON organizations FOR EACH ROW EXECUTE FUNCTION fn_updated_at();
CREATE TRIGGER trg_wallet_updated_at
    BEFORE UPDATE ON wallets FOR EACH ROW EXECUTE FUNCTION fn_updated_at();
CREATE TRIGGER trg_policy_updated_at
    BEFORE UPDATE ON policies FOR EACH ROW EXECUTE FUNCTION fn_updated_at();
CREATE TRIGGER trg_tx_updated_at
    BEFORE UPDATE ON transactions FOR EACH ROW EXECUTE FUNCTION fn_updated_at();

-- Reset daily/monthly counters automatically on wallet access
CREATE OR REPLACE FUNCTION fn_reset_spending_counters()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.daily_reset_at < CURRENT_DATE THEN
        NEW.daily_spent := 0;
        NEW.daily_reset_at := CURRENT_DATE;
    END IF;
    IF NEW.monthly_reset_at < date_trunc('month', CURRENT_DATE)::DATE THEN
        NEW.monthly_spent := 0;
        NEW.monthly_reset_at := date_trunc('month', CURRENT_DATE)::DATE;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_wallet_reset_counters
    BEFORE UPDATE ON wallets FOR EACH ROW EXECUTE FUNCTION fn_reset_spending_counters();
