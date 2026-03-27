# W46

**Your AI agents can't pay for anything. W46 fixes that.**

W46 gives autonomous AI agents their own USDC wallets with real blockchain addresses on Solana and Base. Your agent calls `w.wallets.pay()`, W46 handles the keys, the policy checks, the routing, the settlement, and the proof trail. You set spending limits. You get billed per USDC moved. The agent gets work done.

---

## The Problem

Your AI agent needs to:
- Call a paid API ($0.03 per request, 10,000 times a day)
- Rent compute on Akash or GPU marketplaces
- Pay another agent for data
- Subscribe to a service on behalf of your users

But it can't. It has no bank account. No card. Stripe won't KYC a Python script. So you hardcode your personal card, build brittle workarounds, or just... don't let the agent pay.

W46 is the wallet infrastructure that sits between your agent and the money it needs to spend.

---

## How It Works

Developer signs up → gets API key → creates wallet → agent pays


```python
from w46_sdk import W46Client

w = W46Client(api_key="w46_live_R7xK9a2bC4...")

# Create a wallet for your agent
wallet = w.wallets.create(agent_id="research-bot")
# → Real Solana address: 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU
# → Real Base address:   0x4a2E8C39b6768a8f0F1d8e5B2aD3c1F7e9D0b5A3

# Fund it (send USDC to either address)

# Agent pays for a service
tx = w.wallets.pay(
    wallet_id=wallet["id"],
    to_address="recipient_address",
    amount_usdc=5.00,
    memo="GPT-4 API calls batch #47",
    category="compute",
)
# → Real USDC transfer on Solana (< 1 second, $0.005 fee)

# Verify the proof chain hasn't been tampered with
proof = w.proof.verify_chain(wallet_id=wallet["id"])
# → {"chain_valid": True, "records_checked": 847}
```

That's it. Five lines. Your agent can now pay for anything, anywhere, with real money.

# What Happens Under the Hood

When your agent calls pay(), here's what W46 does in ~800ms:

```text
1. Advisory lock      → Prevents race conditions on this wallet
2. Idempotency check  → Won't double-spend on retry
3. Policy engine      → Checks 9 rules deterministically:
                         per-tx limit, daily cap, monthly cap,
                         allowed categories, blocked destinations,
                         memo requirement, human approval threshold,
                         verified rail threshold
                         If ANY rule fails → nothing moves. No gas. No fee.
4. Routing engine     → Picks the best rail:
                         Solana for ≤$50 (sub-second, $0.005/USDC)
                         Base for ≥$500 (~2s, $0.05/USDC)
                         Internal for same-org transfers (free, instant)
                         Auto-fallback if a chain is down
5. Settlement         → Real SPL Token or ERC-20 transfer on-chain
                         Verifies on-chain balance before sending
6. Proof chain        → SHA-256 hash of the record, chained to previous
                         Merkle root anchored on-chain periodically
7. Ledger update      → PostgreSQL mirror updated (blockchain = source of truth)
8. Fee recorded       → Your cut, swept to your wallet hourly
9. Audit log          → Immutable, hash-chained, tamper-detectable
```

# Architecture 

```text
┌──────────────┐     ┌───────────────────────────────────────────┐
│  Your Agent  │     │                 W46                       │
│  (Python,    │────▶│                                           │
│   LangChain, │     │  ┌─────────┐  ┌────────┐  ┌──────────┐  │
│   CrewAI,    │     │  │ Policy  │→│Routing │→│Settlement│  │
│   n8n,       │     │  │ Engine  │  │ Engine │  │  Engine  │  │
│   custom)    │     │  └─────────┘  └────────┘  └──────────┘  │
│              │     │       │            │            │         │
└──────────────┘     │  ┌────┴────────────┴────────────┴────┐   │
                     │  │         KMS (GCP / Fireblocks)     │   │
                     │  │    Private keys never leave HSM    │   │
                     │  └────────────┬──────────┬────────────┘   │
                     └───────────────┼──────────┼────────────────┘
                                     │          │
                              ┌──────┴──┐  ┌───┴────┐
                              │ Solana  │  │  Base  │
                              │ Mainnet │  │  (L2)  │
                              └─────────┘  └────────┘
```
W46 does NOT store money. USDC lives on-chain in the agent's wallet. W46 holds the signing keys via KMS and orchestrates transactions. The PostgreSQL ledger is a read-speed mirror — blockchain is the source of truth.

# Key Concepts
## Wallets
Each wallet gets real blockchain addresses (Solana + Base). Private keys are generated and stored in the KMS — never in application code, never in the database. The wallet can receive USDC immediately on either chain.

## Policy Engine
Deterministic rules evaluated before every transaction. If the policy says no, absolutely nothing happens — no blockchain transaction, no gas burned, no fees charged. You control:

## Max amount per transaction
Daily and monthly spending caps
Allowed/blocked categories and destinations
Human approval threshold (above X → needs manual approval)
Verified rail threshold (above X → must use Base for settlement)

## Routing Engine
Automatically picks the cheapest/fastest rail. Circuit breakers detect when a chain's RPC is down and reroute traffic. If everything is down, the transaction is deferred — not lost.

## Proof Chain
Every settled transaction gets a SHA-256 hash that chains to the previous one (per wallet). Batches are aggregated into Merkle trees and the root is anchored on-chain. If someone modifies a database record, the chain breaks and verify_chain catches it.

## Reputation (Trust Score)
Each wallet gets a 0-100 trust score based on settlement rate, policy compliance, volume maturity, account age, and incident history. Recalculated periodically.

## AFID (Agent Financial Identity)
Portable identity document that lets a wallet prove its capabilities and reputation to external platforms. Signed cryptographically.

## API Reference
### Authentication

```text
POST /v1/auth/signup              Create organization
POST /v1/auth/login               Get session JWT
POST /v1/auth/verify-email        Verify email address
POST /v1/auth/accept-tos          Accept Terms of Service
POST /v1/auth/api-keys            Create API key
POST /v1/auth/api-keys/:id/rotate Rotate API key
```

### Wallets

```text
POST   /v1/wallets                Create wallet
GET    /v1/wallets                List wallets
GET    /v1/wallets/:id            Get wallet details
POST   /v1/wallets/:id/freeze     Freeze wallet
POST   /v1/wallets/:id/close      Close wallet
```

### Payments

```text
POST   /v1/wallets/:id/payments   Execute payment
GET    /v1/wallets/:id/payments   List wallet payments
```
Transactions

```text
GET    /v1/transactions           List all transactions
GET    /v1/transactions/:id       Get transaction details
POST   /v1/transactions/:id/approve  Approve/deny human review
```

### Policy

```text
GET    /v1/wallets/:id/policy     Get active policy
PUT    /v1/wallets/:id/policy     Update policy
```

### Proof & Integrity

```text
GET    /v1/proof/wallets/:id/verify  Verify proof chain
GET    /v1/proof/audit/verify        Verify audit chain
GET    /v1/proof/anchors             List anchor batches
```
### Reputation & AFID

```text
GET    /v1/wallets/:id/reputation    Get trust score
GET    /v1/wallets/:id/afid          Get AFID document
POST   /v1/wallets/:id/afid/verify   Verify AFID
```

### Admin

```text
POST   /v1/admin/reconcile          Reconcile all wallets
POST   /v1/admin/reconcile/:id      Reconcile specific wallet
GET    /v1/admin/fees                Get pending fees
POST   /v1/admin/fees/sweep          Sweep fees to operator
GET    /v1/admin/circuit-breakers    Circuit breaker states
```

## Deployment

### Quick Start (Development)

```bash
git clone https://github.com/yourorg/w46.git
cd w46
cp .env.example .env
# Edit .env with your values
docker-compose up --build
# API available at http://localhost:8046
# Docs at http://localhost:8046/docs
```
### Production

```bash
# 1. Set up GCP KMS keyring
gcloud kms keyrings create w46-prod --location=europe-west1
gcloud kms keys create master-key --keyring=w46-prod \
  --location=europe-west1 --purpose=encryption

# 2. Configure .env for production
W46_ENV=production
W46_KMS_PROVIDER=gcp
W46_GCP_PROJECT_ID=your-project
W46_GCP_LOCATION=europe-west1
W46_GCP_KEYRING=w46-prod
W46_GCP_KEY_ID=master-key
W46_OPERATOR_SOLANA_ADDRESS=your_solana_wallet
W46_OPERATOR_BASE_ADDRESS=0xyour_base_wallet

# 3. Deploy
docker-compose -f docker-compose.yml up -d
```

## Fee Structure


| Rail | Speed | Fee | Best For |
|---|---|---|---|
| Solana | < 1 second | $0.005 / USDC | Micro-payments ≤ $50 |
| Base | ~2 seconds | $0.05 / USDC | Large settlements ≥ $500 |
| Internal | Instant | Free | Same-org wallet transfers |

Fees are collected per USDC transferred, *not per transaction*. Swept to operator wallets hourly.

## Security Model

Private keys: Never in application code. KMS-managed (GCP HSM or Fireblocks MPC).

Advisory locks: PostgreSQL per-wallet locks prevent race conditions.

Policy-first: Rejected transactions never touch the blockchain.

Proof chain: Cryptographic hash chain per wallet, Merkle-anchored on-chain.

Audit log: Immutable (PostgreSQL triggers block UPDATE/DELETE), hash-chained.

Reconciliation: Periodic ledger-vs-blockchain comparison with alerts.

Circuit breakers: Automatic failover between chains.
