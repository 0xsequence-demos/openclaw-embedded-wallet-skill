#!/usr/bin/env node
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import keytar from 'keytar'
import nacl from 'tweetnacl'
import sealedbox from 'tweetnacl-sealedbox-js'

// v1 goals:
// - generate ephemeral pub/priv keypair for a wallet auth request
// - build Cloudflare Worker URL (email auth) with requestId + pubkey
// - ingest encrypted session key, decrypt, store in macOS Keychain

const SERVICE = 'openclaw.sequence-waas'

function usage() {
  console.log(`Usage:
  seq.mjs wallets
  seq.mjs wallet-remove --name <walletName> --yes

  seq.mjs create-request --name <walletName> [--chain polygon|base|arbitrum]
  seq.mjs ingest-session --name <walletName> --rid <requestId> --ciphertext '<base64url>'

  seq.mjs address --name <walletName>
  seq.mjs balances --name <walletName> [--chain polygon|base|arbitrum]

  seq.mjs send-pol --name <walletName> --to <address> --amount <native> [--chain polygon|base|arbitrum] [--fee-token <symbol>] [--broadcast]
  seq.mjs send-erc20 --name <walletName> --token <address> --to <address> --amount <units> [--decimals <n>] [--chain polygon|base|arbitrum] [--fee-token <symbol>] [--broadcast]

Notes:
- Config file: ~/.openclaw/secrets/sequence/waas.env
  - SEQUENCE_WAAS_PROJECT_ACCESS_KEY=...
  - SEQUENCE_WAAS_CONFIG_KEY=...
  - (optional) SEQUENCE_WAAS_WORKER_URL=https://<your-worker>.workers.dev

Keychain:
- service: ${SERVICE}
- session key stored under account: session:<walletName>
`)
}

function b64urlEncode(buf) {
  return Buffer.from(buf)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '')
}

function b64urlDecode(str) {
  const norm = str.replace(/-/g, '+').replace(/_/g, '/')
  const pad = norm.length % 4 === 0 ? '' : '='.repeat(4 - (norm.length % 4))
  return Buffer.from(norm + pad, 'base64')
}

function randomId(bytes = 16) {
  return b64urlEncode(nacl.randomBytes(bytes))
}

function requestsDir() {
  return path.join(os.homedir(), '.openclaw', 'state', 'sequence-waas', 'requests')
}

function walletsRegistryPath() {
  return path.join(os.homedir(), '.openclaw', 'state', 'sequence-waas', 'wallets.json')
}

function loadWalletsRegistry() {
  const fp = walletsRegistryPath()
  if (!fs.existsSync(fp)) return { wallets: {} }
  return JSON.parse(fs.readFileSync(fp, 'utf8'))
}

function saveWalletsRegistry(reg) {
  const fp = walletsRegistryPath()
  ensureDir(path.dirname(fp))
  fs.writeFileSync(fp, JSON.stringify(reg, null, 2), { mode: 0o600 })
}

const CHAIN_CONFIG = {
  polygon: {
    waasNetwork: 'polygon',
    indexerUrl: 'https://polygon-indexer.sequence.app/rpc/Indexer/GetTokenBalancesSummary',
    explorerBase: 'https://polygonscan.com/tx/',
    nativeSymbol: 'POL'
  },
  base: {
    waasNetwork: 'base',
    indexerUrl: 'https://base-indexer.sequence.app/rpc/Indexer/GetTokenBalancesSummary',
    explorerBase: 'https://basescan.org/tx/',
    nativeSymbol: 'ETH'
  },
  arbitrum: {
    waasNetwork: 'arbitrum',
    indexerUrl: 'https://arbitrum-indexer.sequence.app/rpc/Indexer/GetTokenBalancesSummary',
    explorerBase: 'https://arbiscan.io/tx/',
    nativeSymbol: 'ETH'
  }
}

function normalizeChain(raw) {
  const c = String(raw || '').toLowerCase()
  if (c === 'arb' || c === 'arbitrum-one' || c === 'arbitrumone') return 'arbitrum'
  if (c === 'matic') return 'polygon'
  return c || 'polygon'
}

function chainConfig(chain) {
  const key = normalizeChain(chain)
  return CHAIN_CONFIG[key] || CHAIN_CONFIG.polygon
}

function ensureDir(p) {
  fs.mkdirSync(p, { recursive: true })
}

function writePrivateRequest(rid, obj) {
  const dir = requestsDir()
  ensureDir(dir)
  const fp = path.join(dir, `${rid}.json`)
  fs.writeFileSync(fp, JSON.stringify(obj, null, 2), { mode: 0o600 })
  return fp
}

function readPrivateRequest(rid) {
  const fp = path.join(requestsDir(), `${rid}.json`)
  if (!fs.existsSync(fp)) throw new Error(`Missing request state for rid=${rid} at ${fp}`)
  return { fp, obj: JSON.parse(fs.readFileSync(fp, 'utf8')) }
}

function deletePrivateRequest(rid) {
  const fp = path.join(requestsDir(), `${rid}.json`)
  if (fs.existsSync(fp)) fs.unlinkSync(fp)
}

function getArg(args, k) {
  const i = args.indexOf(k)
  if (i === -1) return null
  return args[i + 1] ?? null
}

function ensureSecretFile(filePath) {
  if (!fs.existsSync(filePath)) {
    throw new Error(`Missing secret file: ${filePath}`)
  }
  return fs.readFileSync(filePath, 'utf8').trim()
}

function parseDotEnv(text) {
  // Tiny .env parser: supports KEY=VALUE, ignores blank lines and # comments.
  const out = {}
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim()
    if (!line || line.startsWith('#')) continue
    const idx = line.indexOf('=')
    if (idx === -1) continue
    const k = line.slice(0, idx).trim()
    let v = line.slice(idx + 1).trim()
    // strip surrounding quotes
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
      v = v.slice(1, -1)
    }
    out[k] = v
  }
  return out
}

function loadSequenceConfig() {
  // Preferred: single env file
  const envPath = path.join(os.homedir(), '.openclaw/secrets/sequence/waas.env')
  if (fs.existsSync(envPath)) {
    const env = parseDotEnv(fs.readFileSync(envPath, 'utf8'))
    const projectAccessKey = env.SEQUENCE_WAAS_PROJECT_ACCESS_KEY || env.WAAS_PROJECT_ACCESS_KEY || ''
    const waasConfigKey = env.SEQUENCE_WAAS_CONFIG_KEY || env.WAAS_CONFIG_KEY || ''
    const workerUrl = env.SEQUENCE_WAAS_WORKER_URL || env.WAAS_WORKER_URL || ''
    return { projectAccessKey, waasConfigKey, workerUrl, source: envPath }
  }

  // Back-compat: two secret files
  const projectAccessKeyPath = path.join(os.homedir(), '.openclaw/secrets/sequence/waas-project-access-key')
  const waasConfigKeyPath = path.join(os.homedir(), '.openclaw/secrets/sequence/waas-config-key')
  const projectAccessKey = fs.existsSync(projectAccessKeyPath) ? ensureSecretFile(projectAccessKeyPath) : ''
  const waasConfigKey = fs.existsSync(waasConfigKeyPath) ? ensureSecretFile(waasConfigKeyPath) : ''
  return { projectAccessKey, waasConfigKey, workerUrl: '', source: `${projectAccessKeyPath} + ${waasConfigKeyPath}` }
}

async function main() {
  const args = process.argv.slice(2)
  const cmd = args[0]
  if (!cmd || cmd === '--help' || cmd === '-h') {
    usage()
    process.exit(0)
  }

  // Some commands don't need --name
  const name = getArg(args, '--name')

  // Load project config. Preferred: ~/.openclaw/secrets/sequence/waas.env
  const { projectAccessKey, waasConfigKey, workerUrl, source: configSource } = loadSequenceConfig()
  if (!projectAccessKey || !waasConfigKey) {
    throw new Error(
      `Missing Sequence config keys. Create ~/.openclaw/secrets/sequence/waas.env with:\n` +
        `  SEQUENCE_WAAS_PROJECT_ACCESS_KEY=...\n` +
        `  SEQUENCE_WAAS_CONFIG_KEY=...\n` +
        `\n(loaded from: ${configSource})`
    )
  }

  if (cmd === 'wallets') {
    const reg = loadWalletsRegistry()
    const wallets = Object.values(reg.wallets || {}).sort((a, b) => String(a.name).localeCompare(String(b.name)))
    console.log(JSON.stringify({ ok: true, wallets }, null, 2))
    return
  }

  if (cmd === 'wallet-remove') {
    if (!name) throw new Error('Missing --name <walletName>')
    if (!args.includes('--yes')) throw new Error('Refusing to delete without --yes')

    // Remove Keychain entries
    await keytar.deletePassword(SERVICE, `session:${name}`)
    await keytar.deletePassword(SERVICE, `sessionId:${name}`)
    await keytar.deletePassword(SERVICE, `wallet:${name}`)

    // Remove from registry
    const reg = loadWalletsRegistry()
    if (reg.wallets && reg.wallets[name]) {
      delete reg.wallets[name]
      saveWalletsRegistry(reg)
    }

    console.log(JSON.stringify({ ok: true, removed: name }, null, 2))
    return
  }

  if (!name) throw new Error('Missing --name <walletName>')

  if (cmd === 'create-request') {
    const baseUrl = workerUrl || 'http://localhost:4444'
    const chain = normalizeChain(getArg(args, '--chain') || 'polygon')
    const rid = randomId(16)

    // X25519 keypair for sealed box
    const kp = nacl.box.keyPair()
    const pub = b64urlEncode(kp.publicKey)
    const priv = b64urlEncode(kp.secretKey)

    const createdAt = new Date().toISOString()
    const expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString() // 30 min

    const statePath = writePrivateRequest(rid, {
      rid,
      walletName: name,
      chain,
      createdAt,
      expiresAt,
      publicKeyB64u: pub,
      privateKeyB64u: priv,
    })

    const url = new URL(baseUrl)
    // we’ll use /link on the Worker, but keep it flexible
    url.pathname = url.pathname.replace(/\/$/, '') + '/link'
    url.searchParams.set('rid', rid)
    url.searchParams.set('wallet', name)
    url.searchParams.set('pub', pub)
    url.searchParams.set('chain', chain)

    console.log(JSON.stringify({
      ok: true,
      walletName: name,
      chain,
      rid,
      url: url.toString(),
      expiresAt,
      storedState: statePath,
      projectAccessKeyPresent: !!projectAccessKey,
      waasConfigKeyPresent: !!waasConfigKey,
      configSource
    }, null, 2))
    return
  }

  if (cmd === 'ingest-session') {
    const ciphertext = getArg(args, '--ciphertext')
    if (!ciphertext) throw new Error('Missing --ciphertext')

    const rid = getArg(args, '--rid')
    if (!rid) throw new Error('Missing --rid (from create-request output)')

    const { fp, obj } = readPrivateRequest(rid)
    const chain = normalizeChain(obj.chain || 'polygon')

    if (obj.walletName !== name) {
      throw new Error(`Request rid=${rid} was created for walletName=${obj.walletName}, not ${name}`)
    }

    const exp = Date.parse(obj.expiresAt)
    if (Number.isFinite(exp) && Date.now() > exp) {
      throw new Error(`Request rid=${rid} is expired (expiresAt=${obj.expiresAt}). Create a new request.`)
    }

    const privKey = b64urlDecode(obj.privateKeyB64u)
    const pubKey = b64urlDecode(obj.publicKeyB64u)

    const cipherBytes = b64urlDecode(ciphertext)

    // Sealed box open. Worker should use sealedbox.seal on its side.
    const opened = sealedbox.open(cipherBytes, pubKey, privKey)
    if (!opened) throw new Error('Failed to decrypt ciphertext (sealed box open returned null)')
    const decrypted = Buffer.from(opened).toString('utf8')

    // Expect a JSON blob from the worker:
    // { wallet, sessionId, sessionPrivateKey, rid, walletName }
    let payload
    try {
      payload = JSON.parse(decrypted)
    } catch {
      // Back-compat: worker might have sent raw session private key string.
      payload = { sessionPrivateKey: decrypted }
    }

    const sessionPrivateKey = payload.sessionPrivateKey
    const walletAddress = payload.wallet
    const sessionId = payload.sessionId

    if (!sessionPrivateKey || typeof sessionPrivateKey !== 'string') {
      throw new Error('Decrypted payload did not contain sessionPrivateKey')
    }

    const sessionAccount = `session:${name}`
    await keytar.setPassword(SERVICE, sessionAccount, sessionPrivateKey)

    let walletAccount = null
    if (walletAddress && typeof walletAddress === 'string') {
      walletAccount = `wallet:${name}`
      await keytar.setPassword(SERVICE, walletAccount, walletAddress)
    }

    let sessionIdAccount = null
    if (sessionId && typeof sessionId === 'string') {
      sessionIdAccount = `sessionId:${name}`
      await keytar.setPassword(SERVICE, sessionIdAccount, sessionId)
    }

    // Cleanup request state (one-time use)
    deletePrivateRequest(rid)

    // Update wallet registry
    const reg = loadWalletsRegistry()
    if (!reg.wallets) reg.wallets = {}
    reg.wallets[name] = {
      name,
      chain,
      walletAddress: walletAddress || null,
      updatedAt: new Date().toISOString()
    }
    saveWalletsRegistry(reg)

    console.log(JSON.stringify({
      ok: true,
      walletName: name,
      chain,
      rid,
      walletAddress: walletAddress || null,
      storedInKeychain: {
        service: SERVICE,
        sessionAccount,
        walletAccount,
        sessionIdAccount
      },
      deletedState: fp,
      note: 'Next: wire this session key into waas client and send transactions.'
    }, null, 2))

    return
  }

  async function makeWaasClient(walletName, chain) {
    // Load session key + wallet from Keychain
    const sessionPrivateKey = await keytar.getPassword(SERVICE, `session:${walletName}`)
    const walletAddress = await keytar.getPassword(SERVICE, `wallet:${walletName}`)
    const savedSessionId = await keytar.getPassword(SERVICE, `sessionId:${walletName}`)
    if (!sessionPrivateKey) throw new Error(`Missing session private key in Keychain: session:${walletName}`)
    if (!walletAddress) throw new Error(`Missing wallet address in Keychain: wallet:${walletName} (re-run ingest-session)`)

    // Node environment: SequenceWaaS uses window.fetch internally.
    if (!globalThis.window) {
      globalThis.window = { fetch: globalThis.fetch }
    } else if (!globalThis.window.fetch) {
      globalThis.window.fetch = globalThis.fetch
    }

    // Minimal SecureStoreBackend for Node
    class MemorySecureStoreBackend {
      constructor() {
        this.dbs = new Map()
      }
      _store(dbName, storeName) {
        if (!this.dbs.has(dbName)) this.dbs.set(dbName, new Map())
        const db = this.dbs.get(dbName)
        if (!db.has(storeName)) db.set(storeName, new Map())
        return db.get(storeName)
      }
      async get(dbName, storeName, key) {
        const s = this._store(dbName, storeName)
        return s.has(key) ? s.get(key) : null
      }
      async set(dbName, storeName, key, value) {
        const s = this._store(dbName, storeName)
        s.set(key, value)
        return true
      }
      async delete(dbName, storeName, key) {
        const s = this._store(dbName, storeName)
        s.delete(key)
        return true
      }
    }

    const { SequenceWaaS, store: waasStore } = await import('@0xsequence/waas')
    const { Wallet } = await import('ethers')

    const secureStore = new MemorySecureStoreBackend()

    const derivedSessionId = new Wallet(sessionPrivateKey).address
    const sessionId = savedSessionId || derivedSessionId

    await secureStore.set('seq-waas-session-p256k1', 'seq-waas-session', sessionId, sessionPrivateKey)

    const store = new waasStore.MemoryStore()
    await store.set('@0xsequence.waas.status', 'signed-in')
    await store.set('@0xsequence.waas.wallet', walletAddress)
    await store.set('@0xsequence.waas.session_id', sessionId)

    const cfg = chainConfig(chain)

    const waas = new SequenceWaaS(
      { projectAccessKey, waasConfigKey, network: cfg.waasNetwork },
      store,
      null,
      secureStore
    )

    return { waas, walletAddress, sessionId, chain: normalizeChain(chain) }
  }

  function explorerTxUrl(chain, txHash) {
    return `${chainConfig(chain).explorerBase}${txHash}`
  }

  function pickFeeOption(feeResponse, chain, feeTokenSymbol) {
    const opts = feeResponse?.data?.feeOptions || []
    if (!opts.length) return null

    if (feeTokenSymbol) {
      const want = String(feeTokenSymbol).toUpperCase()
      const match = opts.find(o => String(o?.token?.symbol || '').toUpperCase() === want)
      if (match) return match
    }

    // Prefer paying fees with native token, else fall back to first.
    const nativeSym = chainConfig(chain).nativeSymbol
    const native = opts.find(o => o?.token?.contractAddress == null && String(o?.token?.symbol || '').toUpperCase() === nativeSym)
    return native || opts[0]
  }

  if (cmd === 'send-pol') {
    const to = getArg(args, '--to')
    const amount = getArg(args, '--amount')
    const chain = normalizeChain(getArg(args, '--chain') || loadWalletsRegistry().wallets?.[name]?.chain || 'polygon')
    const feeToken = getArg(args, '--fee-token')
    const broadcast = args.includes('--broadcast')
    if (!to || !amount) throw new Error('Missing --to and/or --amount')

    const { waas, walletAddress, sessionId } = await makeWaasClient(name, chain)
    const { ethers } = await import('ethers')

    const valueWei = ethers.parseEther(String(amount))
    const tx = { to, value: valueWei, data: '0x' }

    if (!broadcast) {
      console.log(JSON.stringify({
        ok: true,
        dryRun: true,
        walletName: name,
        walletAddress,
        sessionId,
        to,
        amount,
        note: 'Re-run with --broadcast to submit via WaaS',
        transaction: { to, value: valueWei.toString(), data: '0x' }
      }, null, 2))
      return
    }

    const fee = await waas.feeOptions({ network: chainConfig(chain).waasNetwork, transactions: [tx] })
    const feeOpt = pickFeeOption(fee, chain, feeToken)
    if (!feeOpt) throw new Error('No fee options returned by WaaS')

    const res = await waas.sendTransaction({
      network: chainConfig(chain).waasNetwork,
      transactions: [tx],
      transactionsFeeQuote: fee.data.feeQuote,
      transactionsFeeOption: feeOpt
    })

    const txHash = res?.data?.txHash

    console.log(JSON.stringify({
      ok: true,
      walletName: name,
      chain,
      walletAddress,
      sessionId,
      to,
      amount,
      txHash: txHash || null,
      explorerUrl: txHash ? explorerTxUrl(chain, txHash) : null,
      response: res
    }, null, 2))
    return
  }

  if (cmd === 'send-erc20' || cmd === 'send-usdc') {
    const token = getArg(args, '--token') || (cmd === 'send-usdc' ? '0x3c499c542cef5e3811e1192ce70d8cc03d5c3359' : null)
    const to = getArg(args, '--to')
    const amount = getArg(args, '--amount')
    const decimalsRaw = getArg(args, '--decimals')
    const chain = normalizeChain(getArg(args, '--chain') || loadWalletsRegistry().wallets?.[name]?.chain || 'polygon')
    const feeToken = getArg(args, '--fee-token')
    const broadcast = args.includes('--broadcast')
    if (!token || !to || !amount) throw new Error('Missing --token, --to and/or --amount')

    const decimals = decimalsRaw ? Number(decimalsRaw) : 6
    if (!Number.isFinite(decimals) || decimals < 0 || decimals > 36) throw new Error('Invalid --decimals')

    const { waas, walletAddress, sessionId } = await makeWaasClient(name, chain)
    const { ethers } = await import('ethers')

    const value = ethers.parseUnits(String(amount), decimals)

    // feeOptions requires a transaction list, so we simulate the ERC20.transfer call.
    const erc20 = new ethers.Interface(['function transfer(address to, uint256 value) returns (bool)'])
    const data = erc20.encodeFunctionData('transfer', [to, value])
    const feeTx = { to: token, value: 0n, data }

    if (!broadcast) {
      console.log(JSON.stringify({
        ok: true,
        dryRun: true,
        walletName: name,
        walletAddress,
        sessionId,
        token,
        to,
        amount,
        decimals,
        note: 'Re-run with --broadcast to submit via WaaS',
        transaction: { to: token, value: '0', data }
      }, null, 2))
      return
    }

    const fee = await waas.feeOptions({ network: chainConfig(chain).waasNetwork, transactions: [feeTx] })
    const feeOpt = pickFeeOption(fee, chain, feeToken)
    if (!feeOpt) throw new Error('No fee options returned by WaaS')

    const res = await waas.sendERC20({
      network: chainConfig(chain).waasNetwork,
      token,
      to,
      value,
      transactionsFeeQuote: fee.data.feeQuote,
      transactionsFeeOption: feeOpt
    })

    const txHash = res?.data?.txHash

    console.log(JSON.stringify({
      ok: true,
      walletName: name,
      chain,
      walletAddress,
      sessionId,
      token,
      to,
      amount,
      decimals,
      txHash: txHash || null,
      explorerUrl: txHash ? explorerTxUrl(chain, txHash) : null,
      response: res
    }, null, 2))
    return
  }

  if (cmd === 'address') {
    const walletAddress = await keytar.getPassword(SERVICE, `wallet:${name}`)
    if (!walletAddress) throw new Error(`Missing wallet address in Keychain: wallet:${name}`)
    console.log(JSON.stringify({ ok: true, walletName: name, walletAddress }, null, 2))
    return
  }

  if (cmd === 'balances') {
    const walletAddress = await keytar.getPassword(SERVICE, `wallet:${name}`)
    if (!walletAddress) throw new Error(`Missing wallet address in Keychain: wallet:${name}`)

    const reg = loadWalletsRegistry()
    const chain = normalizeChain(getArg(args, '--chain') || reg.wallets?.[name]?.chain || 'polygon')
    const cfg = chainConfig(chain)

    // Sequence Indexer
    const indexerKey = process.env.SEQUENCE_INDEXER_ACCESS_KEY
    if (!indexerKey) throw new Error('Missing SEQUENCE_INDEXER_ACCESS_KEY env var')
    const indexerUrl = process.env.SEQUENCE_INDEXER_URL || cfg.indexerUrl

    const res = await fetch(indexerUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Access-Key': indexerKey
      },
      body: JSON.stringify({
        chainID: cfg.waasNetwork,
        omitMetadata: false,
        filter: {
          contractStatus: 'VERIFIED',
          accountAddresses: [walletAddress]
        }
      })
    })

    if (!res.ok) {
      const text = await res.text().catch(() => '')
      throw new Error(`Indexer error: ${res.status} ${text}`)
    }

    const json = await res.json()

    // Compact, human-friendly normalization
    const { formatUnits } = await import('ethers')

    const native = (json.nativeBalances || []).map((b) => ({
      type: 'native',
      symbol: b.symbol || b.name || 'NATIVE',
      balance: formatUnits(b.balance || '0', 18)
    }))

    const erc20 = (json.balances || []).map((b) => ({
      type: 'erc20',
      symbol: b.contractInfo?.symbol || 'ERC20',
      contractAddress: b.contractAddress,
      balance: formatUnits(b.balance || '0', b.contractInfo?.decimals ?? 0)
    }))

    console.log(JSON.stringify({
      ok: true,
      walletName: name,
      walletAddress,
      balances: [...native, ...erc20]
    }, null, 2))
    return
  }

  throw new Error(`Unknown command: ${cmd}`)
}

main().catch((err) => {
  console.error(err?.stack || String(err))
  process.exit(1)
})
