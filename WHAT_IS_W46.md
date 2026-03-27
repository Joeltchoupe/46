
# What W46 Actually Does

## One Sentence

W46 lets AI agents spend USDC autonomously, with guardrails, on real blockchains.

## The Gap

AI agents are getting good at doing work. They can research, code, analyze, negotiate, trade. But the moment they need to pay for something — an API call, a dataset, compute time, another agent's service — they hit a wall.

No bank will open an account for a Python process. Stripe requires a human with a passport. Payment processors need a legal entity. Your agent has none of that.

So today, developers do one of three things:
1. **Hardcode their own credit card** into the agent's config. The agent has unlimited access to their personal funds. No spending controls. No audit trail. Terrifying.
2. **Build a bespoke payment wrapper** around their own wallet. Weeks of work. No policy engine. No proof chain. Breaks when the RPC changes.
3. **Don't let the agent pay.** The agent does 95% of the job, then stops and asks a human to click "confirm payment." Defeats the purpose of autonomy.

## What W46 Is

W46 is wallet infrastructure. It gives each agent its own USDC wallet with:

- **Real blockchain addresses** (Solana and Base). Not simulated. Not custodial pool accounting. Actual keypairs, actual on-chain balances.
- **Policy controls** set by the developer. "This agent can spend max $50 per transaction, $500 per day, only on compute and data categories, never to addresses on the blocklist, and anything over $200 needs my manual approval."
- **Automatic routing** to the cheapest chain. Small payment? Solana, sub-second, half a cent. Large settlement? Base, two seconds, five cents.
- **Cryptographic proof** that every transaction happened as recorded. Hash chain per wallet, Merkle trees, roots anchored on-chain. Tamper-evident by construction.

## What W46 Is NOT

- **Not a bank.** W46 doesn't hold deposits, pay interest, or lend money. USDC sits on-chain in the agent's own wallet. W46 holds the signing keys and orchestrates transfers.
- **Not a payment processor.** There's no fiat on-ramp or off-ramp. USDC in, USDC out. If the recipient only takes fiat, W46's budget authorization rail reserves the budget and gives the agent a green light — the actual fiat payment is handled outside W46.
- **Not a blockchain.** W46 uses existing blockchains (Solana and Base) for settlement and anchoring. The PostgreSQL database is a performance mirror, not the source of truth.

## How Money Flows

1-Developer funds the agent's wallet
(sends USDC to the wallet's Solana or Base address)

2-Agent calls w.wallets.pay(to_address, amount)

3-W46 checks policy → routes to best chain → executes transfer on-chain

4-Recipient receives USDC on-chain

5-W46 takes a fee (0.5% on Solana, 5% on Base)
Fee stays in the agent's wallet on-chain until hourly sweep

6-Proof hash is computed and chained to the wallet's history



The developer's USDC goes directly to the recipient on-chain. W46 never pools funds. Each wallet is an independent on-chain address.

## The KMS Question

"Who holds the private keys?"

W46 does, via a Key Management Service:
- **Development:** Encrypted files on disk (AES). Fast, local, not for production.
- **Staging:** Google Cloud KMS. The private key is generated locally, encrypted (wrapped) by a Google HSM master key, and stored as ciphertext. To sign a transaction, W46 calls GCP to decrypt, signs in memory for ~1ms, then zeros the memory. The raw key never rests on disk.
- **Production:** Fireblocks MPC. The private key is split across multiple parties and never exists in one place. Signing is a multi-party computation. Even if W46's server is fully compromised, the attacker gets nothing usable.

## The Trust Model

The developer trusts W46 to:
1. Generate keypairs correctly (verified by checking the resulting on-chain address)
2. Enforce policies before signing (verified by the audit log and proof chain)
3. Not sign unauthorized transactions (verified by reconciliation: ledger must match on-chain balance)
4. Not lose keys (mitigated by KMS architecture: GCP HSM or Fireblocks MPC)

The developer does NOT need to trust W46's database. The blockchain is the source of truth. The proof chain and reconciliation system exist specifically to catch any divergence between what W46 says happened and what actually happened on-chain.

## Who Pays W46

The developer pays W46 indirectly through per-USDC fees:
- 0.5% on Solana transfers ($0.005 per $1 USDC)
- 5% on Base transfers ($0.05 per $1 USDC)
- Free for internal transfers between wallets in the same organization

Fees accumulate in a ledger and are swept hourly from the agent wallets to the W46 operator's wallets on-chain. The operator (you, if you're running W46) receives real USDC to their own Solana/Base addresses.

## Integration Surface

W46 is an API. It works with anything that can make HTTP requests:
- **Python SDK** for LangChain, CrewAI, AutoGPT, custom agents
- **REST API** for n8n, Make, Zapier, or any language
- **Webhook-compatible** for event-driven architectures

Five lines of Python. That's the integration cost.
