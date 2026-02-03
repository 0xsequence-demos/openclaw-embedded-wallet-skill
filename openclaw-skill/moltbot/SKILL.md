---
name: moltbot
description: Sequence WaaS (Embedded Wallet) demo tooling: create/link wallets by nickname, maintain a nickname registry (list/remove), query balances via Sequence indexer, and send native + ERC20 transfers on Polygon/Base/Arbitrum using stored sessions.
---

# Moltbot (Sequence WaaS) skill

Use this skill when Taylan asks to:
- create/link a new Sequence embedded wallet (nickname)
- list/remove nicknames (wallet registry)
- show wallet address or balances
- send native token or ERC20 transfers on Polygon/Base/Arbitrum

## Source of truth
Use the local CLI:

`/Users/taylan/.openclaw/workspace/tools/sequence-waas/seq.mjs`

Config:
- `~/.openclaw/secrets/sequence/waas.env`
- Keychain service: `openclaw.sequence-waas`
  - `session:<name>` (session private key)
  - `sessionId:<name>`
  - `wallet:<name>`

## Create/link a wallet (nickname)
1) Generate a link:

```bash
node /Users/taylan/.openclaw/workspace/tools/sequence-waas/seq.mjs create-request --name <nickname> [--chain polygon|base|arbitrum]
```

2) Send Taylan the returned `/link?...` URL.

3) Taylan completes email auth and sends back the ciphertext.

4) Ingest + store in Keychain:

```bash
node /Users/taylan/.openclaw/workspace/tools/sequence-waas/seq.mjs ingest-session --name <nickname> --rid <rid> --ciphertext '<...>'
```

### Response copy (after ingest)
Default:
> Your wallet is now securely stored with the nickname <nickname>. Here is the address: <0x...>

If Taylan explicitly requests a minimal response, follow that (e.g., “wallet address only”).

## Show wallet address
```bash
node /Users/taylan/.openclaw/workspace/tools/sequence-waas/seq.mjs address --name <nickname>
```

## Wallet registry
List known nicknames:
```bash
node /Users/taylan/.openclaw/workspace/tools/sequence-waas/seq.mjs wallets
```

Remove a nickname (destructive; confirm):
```bash
node /Users/taylan/.openclaw/workspace/tools/sequence-waas/seq.mjs wallet-remove --name <nickname> --yes
```

## Query balances
```bash
node /Users/taylan/.openclaw/workspace/tools/sequence-waas/seq.mjs balances --name <nickname> [--chain polygon|base|arbitrum]
```

## Send native token
Dry-run:
```bash
node /Users/taylan/.openclaw/workspace/tools/sequence-waas/seq.mjs send-pol --name <nickname> --to <address> --amount <native> [--chain polygon|base|arbitrum]
```

Broadcast:
```bash
node /Users/taylan/.openclaw/workspace/tools/sequence-waas/seq.mjs send-pol --name <nickname> --to <address> --amount <native> [--chain polygon|base|arbitrum] [--fee-token <symbol>] --broadcast
```

## Send ERC20
Dry-run:
```bash
node /Users/taylan/.openclaw/workspace/tools/sequence-waas/seq.mjs send-erc20 --name <nickname> --token <erc20> --to <address> --amount <units> --decimals <n>
```

Broadcast:
```bash
node /Users/taylan/.openclaw/workspace/tools/sequence-waas/seq.mjs send-erc20 --name <nickname> --token <erc20> --to <address> --amount <units> --decimals <n> [--chain polygon|base|arbitrum] [--fee-token <symbol>] --broadcast
```

## Transaction reply rule
When Taylan requests a transaction (native/ERC20): always reply with the block explorer link (Polygonscan) after sending.

## Suggestions / next improvements
- `wallets list` + `wallet remove` (manage nicknames)
- optional `--fee-token` selection (pay fees in POL vs stable)
- optional `--chain` support beyond Polygon (Base/Arbitrum/etc.)
