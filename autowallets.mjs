// Auto wallets: create N WalletTg wallets, fund them from a main wallet, deploy them, return the rest.
//
//   npm i @ton/core @ton/crypto @ton/ton @ton/sandbox
//   node autowallets.mjs
//
// Local web UI on 127.0.0.1 with a random access key in the link. Mnemonics stay in this process;
// only signed messages go to the network (toncenter.com, tonapi.io as a fallback).
// New wallets use the standard 24-word TON mnemonic (the "old scheme" WalletTg wallets).

import os from 'node:os';
process.env.UV_THREADPOOL_SIZE ||= String(Math.max(4, os.cpus().length));

import http from 'node:http';
import crypto from 'node:crypto';
import { exec } from 'node:child_process';
import { Cell, beginCell, contractAddress, Address, Dictionary, internal, external, storeMessage, storeMessageRelaxed, toNano, fromNano } from '@ton/core';
import { mnemonicNew, mnemonicToPrivateKey, mnemonicValidate, sign, keyPairFromSeed } from '@ton/crypto';
import { WalletContractV5R1, WalletContractV4 } from '@ton/ton';
import bip39 from 'bip39';
import hdkey from 'ed25519-hd-key';

// ------------------------------------------------------------------ WalletTg
const TRAMPOLINE = Cell.fromBoc(Buffer.from('b5ee9c7241010101001a000030ff00209821d7498308b9f240df8085f833d0ed1e20ed53d969427e39', 'hex'))[0];
// WalletTg bytecode (config param -123, revision 0 from ton-blockchain/tg-wallet-contract), used only for local fee emulation
const WALLETTG_CODE_B64 = 'te6ccgECFwEAA20AART/APSkE/S88sgLAQIBIAgCAvjygwjXGO1E0NcLB5LwAd7tRNDXLAgE8r/TH9Mf1wv/I8jO+RZUEFX5EJPywIfhAtcsIxxLc6yOOtMf0x/TH9MH10xRJbry4IVRNbry4IYB+CO88uCI+AACpMjPhALLHxPLHxPL/8ntVPgPIHKw8uCJ+wDg1ywjnEtzrOMCBwMCEonXJ+MChA/y8AYEAf7TH9Mf0x/T/9TXTFE2uvLghVFGuvLghgL4I7zy4IhRUb3y4JT4KPpEyIvEtFWV9ST1RBVElPTozxYSygfL//kWAtCDCNcY0VQSAvkQ8uCVA9DW/9H4AAGkyM+EAssfEssfEsv/ye1UiwLIz4cgzoIQ66GZSM8LgSHXS/JJgwe6BQAO8onOyXD7AAAI+7qZyAC00x/TH9MfURS68uCFUSS68uCG+CO88uCI+AABpMjPhALLHxLLHxLL/8ntVPgPcAHTB/QFjhvQ9AQg10pRRKAEnNMH1CJysPLgiQL7AOTRIG7mMCHy4JO68uCTAgFIEAkCASALCgARvjcvaiaGuFg8AgEgDQwAMbjJftRNDXCweS8AHe7UTQ1ywIBPK/1wsfgCAW4PDgA3rx32omhrhYPJeADvdqJoa5YEAnlf6Y+Y64WPwAA9rc52omhrhYPJeADvdqJoa5YEAnlf6Y+Y6Y+Y64X/wAICzxIRAAEgA/cgwjXGO1E0NcLB5LwAd7tRNDXLAgE8r/TH9Mf1wv/I8jO+RZUEFX5EJJfBOEC1ywjHEtzpI4w0x/TH9Mf0wfXTFEluvLghVE1uvLghgH4I7zy4IgCpMjPhALLHxPLHxPL/8ntVPsA4NcsI5xLc6TjAtcsJ93UzjzjAoQPgFhQTAATy8AH+0x/TH9Mf0//U10xRNrry4IVRRrry4IYC+CO88uCIUVG98uCU+Cj6RMiLxLRVlfUk9UQVRJT06M8WEsoHy//5FgLQgwjXGNFUEgL5EPLglQPQ1v/RAaTIz4QCyx8Syx8Sy//J7VSLAsjPhyDOghDroZlIzwuBIddL8kmDB7ryiRUACs7JcPsAAKDTH9Mf0x9RFLry4IVRJLry4Ib4I7zy4IgBpMjPhALLHxLLHxLL/8ntVHAB0wf0BY4V0PQEINdKUUSgBJbTB9QC+wDk0SBu5jAh8uCTuvLgkw==';
const OP_SEND_ONE_E = 0x63896e75;
const OP_SEND_BULK_E = 0x73896e75;
export const NETS = {
  mainnet: { subwallet: 0x7fff7f11, toncenter: 'https://toncenter.com/api/v2', tonapi: 'https://tonapi.io', testOnly: false, v5id: -239 },
  testnet: { subwallet: 0x7fff7ffd, toncenter: 'https://testnet.toncenter.com/api/v2', tonapi: 'https://testnet.tonapi.io', testOnly: true, v5id: -3 },
};
const MODE = 3;                 // pay fees separately + ignore errors
const RESERVE = toNano('0.001'); // left on every new wallet

export function tgWallet(publicKey, net) {
  const data = beginCell().storeUint(0, 8).storeUint(0, 32).storeUint(NETS[net].subwallet, 32).storeBuffer(publicKey).endCell();
  const init = { code: TRAMPOLINE, data };
  return { address: contractAddress(0, init), init };
}
export const fmt = (a, net) => a.toString({ bounceable: false, urlSafe: true, testOnly: NETS[net].testOnly });

export async function keyFromPhrase(phrase) {
  const words = phrase.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (words.length !== 24) throw new Error(`нужно 24 слова, а здесь ${words.length}`);
  if (!(await mnemonicValidate(words))) throw new Error('фраза не проходит проверку TON (опечатка или не тот порядок слов)');
  return mnemonicToPrivateKey(words);
}

// WalletTg message array for bulk sends (same encoding as MyTonWallet)
function tgMessageArray(items) {
  let next, k = items.length;
  while (k > 0) {
    const from = Math.max(0, k - (next ? 3 : 4));
    const chunk = beginCell().storeMaybeRef(next);
    for (let i = from; i < k; i++) chunk.storeUint(items[i].mode, 8).storeRef(items[i].cell);
    next = chunk.endCell();
    k = from;
  }
  return beginCell().storeUint(items.length, 8).storeMaybeRef(next).endCell();
}

// ------------------------------------------------------------------ network
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function fetchJson(url, opts = {}) {
  const r = await fetch(url, { ...opts, signal: AbortSignal.timeout(20000) });
  const t = await r.text();
  let j;
  try { j = JSON.parse(t); } catch { throw new Error(`HTTP ${r.status}`); }
  if (r.status === 429) throw new Error('слишком частые запросы');
  return { status: r.status, j };
}

export function makeProviders(net, apiKey) {
  const N = NETS[net];
  const H = apiKey ? { 'X-API-Key': apiKey } : {};
  return [
    {
      name: 'toncenter',
      async state(a) {
        const { j } = await fetchJson(`${N.toncenter}/getAddressInformation?address=${a}`, { headers: H });
        if (!j.ok) throw new Error(j.error);
        return { balance: BigInt(j.result.balance), active: j.result.state === 'active', status: j.result.state };
      },
      async get(a, method) {
        const { j } = await fetchJson(`${N.toncenter}/runGetMethod`, {
          method: 'POST', headers: { ...H, 'Content-Type': 'application/json' }, body: JSON.stringify({ address: a, method, stack: [] }) });
        if (!j.ok || j.result.exit_code !== 0) throw new Error(j.error || `exit ${j.result?.exit_code}`);
        return BigInt(j.result.stack[0][1]);
      },
      async send(boc) {
        const { j } = await fetchJson(`${N.toncenter}/sendBoc`, {
          method: 'POST', headers: { ...H, 'Content-Type': 'application/json' }, body: JSON.stringify({ boc }) });
        if (!j.ok) throw new Error(j.error);
      },
    },
    {
      name: 'tonapi',
      async state(a) {
        const { status, j } = await fetchJson(`${N.tonapi}/v2/accounts/${a}`);
        if (status === 404) return { balance: 0n, active: false, status: 'nonexist' };
        if (j.error) throw new Error(j.error);
        return { balance: BigInt(j.balance), active: j.status === 'active', status: j.status };
      },
      async get(a, method) {
        const { j } = await fetchJson(`${N.tonapi}/v2/blockchain/accounts/${a}/methods/${method}`);
        if (!j.success) throw new Error(j.error || 'get method failed');
        return BigInt(j.stack[0].num);
      },
      async send(boc) {
        const { status, j } = await fetchJson(`${N.tonapi}/v2/blockchain/message`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ boc }) });
        if (status >= 400) throw new Error(j.error || `HTTP ${status}`);
      },
    },
  ];
}

async function call(ctx, what, ...a) {
  let last;
  for (let round = 0; round < 3; round++) {
    for (const p of ctx.providers) {
      if (!p[what]) continue;
      try { return await p[what](...a); } catch (e) { last = e; }
    }
    await sleep(1500 * (round + 1));
  }
  throw new Error(`сеть недоступна (${last?.cause?.code || last?.message}); проверь интернет, токен или включи VPN`);
}

// Waits until the wallet's seqno passes `seqno` (the transaction is in the blockchain)
async function waitSeqno(ctx, addr, seqno) {
  for (let i = 0; i < (ctx.confirmTries ?? 40); i++) {
    await sleep(ctx.pollMs ?? 3000);
    try {
      const s = await call(ctx, 'state', addr);
      if (s.active && (await call(ctx, 'get', addr, 'seqno')) > BigInt(seqno)) return;
    } catch (_) { /* keep waiting */ }
  }
  throw new Error('транзакция не подтвердилась за 2 минуты');
}

// ------------------------------------------------------------------ wallets that can send
// Main wallet: WalletTg, W5 or V4 from the same 24 words. Each kind: max messages per transaction + a builder.
// For a Gram Wallet (12+12) the WalletTg address comes from the anchor key while `key` signs.
export function senders(key, net, anchorPub = key.publicKey) {
  const tg = tgWallet(anchorPub, net);
  const v5 = WalletContractV5R1.create({ workchain: 0, publicKey: key.publicKey, walletId: { networkGlobalId: NETS[net].v5id } });
  const v4 = WalletContractV4.create({ workchain: 0, publicKey: key.publicKey });
  const validUntil = () => Math.floor(Date.now() / 1000) + 120;
  return [
    {
      kind: 'WalletTg', address: tg.address, init: tg.init, max: 255,
      body(seqno, msgs) {
        const items = msgs.map((m) => ({ mode: MODE, cell: beginCell().store(storeMessageRelaxed(m)).endCell() }));
        const head = beginCell().storeUint(items.length === 1 ? OP_SEND_ONE_E : OP_SEND_BULK_E, 32)
          .storeUint(NETS[net].subwallet, 32).storeUint(validUntil(), 32).storeUint(seqno, 32);
        const req = items.length === 1
          ? head.storeUint(items[0].mode, 8).storeRef(items[0].cell).endCell()
          : head.storeSlice(tgMessageArray(items).beginParse()).endCell();
        return beginCell().storeBuffer(sign(req.hash(), key.secretKey)).storeSlice(req.beginParse()).endCell();
      },
    },
    {
      kind: 'W5', address: v5.address, init: v5.init, max: 255,
      body: (seqno, msgs) => v5.createTransfer({ seqno, secretKey: key.secretKey, messages: msgs, sendMode: MODE, timeout: validUntil() }),
    },
    {
      kind: 'V4', address: v4.address, init: v4.init, max: 4,
      body: (seqno, msgs) => v4.createTransfer({ seqno, secretKey: key.secretKey, messages: msgs, sendMode: MODE, timeout: validUntil() }),
    },
  ];
}

// Send messages from a wallet in as few transactions as it allows; waits for each one
export async function sendMany(ctx, w, msgs, onChunk = () => {}) {
  const addr = fmt(w.address, ctx.net);
  for (let i = 0; i < msgs.length; i += w.max) {
    const part = msgs.slice(i, i + w.max);
    const st = await call(ctx, 'state', addr);
    const seqno = st.active ? Number(await call(ctx, 'get', addr, 'seqno')) : 0;
    const ext = external({ to: w.address, init: st.active ? undefined : w.init, body: w.body(seqno, part) });
    await call(ctx, 'send', beginCell().store(storeMessage(ext)).endCell().toBoc().toString('base64'));
    await waitSeqno(ctx, addr, seqno);
    onChunk(i + part.length);
  }
}

// ------------------------------------------------------------------ new wallets
// Both formats are deployed by the funding message itself (it carries the StateInit), so the new
// wallet never sends a deploy transaction. Gram Wallet format also switches the key in that message.
const OP_CHANGE_KEY_I = 0xfbba99c7;
const ROTATION_TAG = 0x4b45595f524f544154494f4en; // "KEY_ROTATION"

// Same derivation as Gram Wallet / MyTonWallet: BIP39 seed -> SLIP-10 m/44'/607'/0'
function halfKey(words) {
  const seed = bip39.mnemonicToSeedSync(words).toString('hex');
  return keyPairFromSeed(Buffer.from(hdkey.derivePath("m/44'/607'/0'", seed).key));
}

const OP_CHANGE_KEY_E = 0xfbba99c8;

// Signed ChangePublicKey request: signed by the current (anchor) key, proven by the new (signing) key.
// internal = sent inside a message from another wallet; external = sent by the wallet itself.
export function rotationBody({ anchor, signing, address, net, seqno = 0, internal: isInternal = true, ttl = 86400 }) {
  const proofPayload = beginCell().storeUint(ROTATION_TAG, 96).storeInt(0, 8).storeBuffer(address.hash).endCell();
  const req = beginCell()
    .storeUint(isInternal ? OP_CHANGE_KEY_I : OP_CHANGE_KEY_E, 32).storeUint(NETS[net].subwallet, 32)
    .storeUint(Math.floor(Date.now() / 1000) + ttl, 32).storeUint(seqno, 32)
    .storeBuffer(signing.publicKey)
    .storeRef(beginCell().storeBuffer(sign(proofPayload.hash(), signing.secretKey)).endCell())
    .storeRef(beginCell().storeBuffer(Buffer.alloc(32)).endCell()) // no old encrypted comments on a fresh wallet
    .endCell();
  return beginCell().storeBuffer(sign(req.hash(), anchor.secretKey)).storeSlice(req.beginParse()).endCell();
}

export async function newWallet(format, net) {
  if (format === 'gram') {
    const rnd = (n) => crypto.randomBytes(n);
    const anchorWords = bip39.generateMnemonic(128, rnd), signingWords = bip39.generateMnemonic(128, rnd);
    const anchor = halfKey(anchorWords), signing = halfKey(signingWords);
    const w = tgWallet(anchor.publicKey, net);
    const body = rotationBody({ anchor, signing, address: w.address, net });
    return { phrase: `${anchorWords} ${signingWords}`, address: w.address, init: w.init, body, signKey: signing, anchorPub: anchor.publicKey, seqnoAfter: 1n };
  }
  const words = await mnemonicNew(24);
  const key = await mnemonicToPrivateKey(words);
  const w = tgWallet(key.publicKey, net);
  return { phrase: words.join(' '), address: w.address, init: w.init, body: undefined, signKey: key, anchorPub: key.publicKey, seqnoAfter: 0n };
}

// ------------------------------------------------------------------ fee emulation
// Runs funding-with-deploy + return on a local copy of the chain (same WalletTg code and fee rules).
// deploy = what the incoming funding message loses on the way in; ret = fee of the refund transaction.
export async function estimateFees(ctx, format) {
  const { Blockchain } = await import('@ton/sandbox');
  const bc = await Blockchain.create();
  const code = Cell.fromBase64(WALLETTG_CODE_B64);
  const cfg = Dictionary.loadDirect(Dictionary.Keys.Int(32), Dictionary.Values.Cell(), bc.config);
  cfg.set(-123, code);
  bc.setConfig(beginCell().storeDictDirect(cfg).endCell());
  const sim = {
    name: 'emulator',
    async state(a) { const c = await bc.getContract(Address.parse(a)); return { balance: c.balance, active: c.accountState?.type === 'active' }; },
    async get(a, m) { return (await bc.runGetMethod(Address.parse(a), m)).stackReader.readBigNumber(); },
    async send(boc) { await bc.sendMessage(Cell.fromBase64(boc)); },
  };
  const sctx = { net: ctx.net, providers: [sim], pollMs: 1, confirmTries: 3 };
  const nw = await newWallet(format, ctx.net);
  const w = senders(nw.signKey, ctx.net, nw.anchorPub)[0];
  const addr = fmt(w.address, ctx.net);
  const start = toNano('0.1');
  await (await bc.treasury('main')).send({ to: nw.address, value: start, bounce: false, init: nw.init, body: nw.body });
  const b0 = (await sim.state(addr)).balance;
  if (!(await sim.state(addr)).active) throw new Error('эмуляция: кошелёк не развернулся входящим сообщением');
  const back = (await bc.treasury('main')).address;
  await sendMany(sctx, w, [internal({ to: back, value: 1n, bounce: false })]);
  const b1 = (await sim.state(addr)).balance;
  return { deploy: start - b0, ret: b0 - b1 - 1n };
}

// ------------------------------------------------------------------ the pipeline
async function pool(items, limit, fn) {
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (i < items.length) { const k = i++; await fn(items[k], k); }
  }));
}

export async function inspectMain(ctx, phrase) {
  const key = await keyFromPhrase(phrase);
  const list = senders(key, ctx.net);
  const out = [];
  for (const w of list) {
    const st = await call(ctx, 'state', fmt(w.address, ctx.net));
    out.push({ kind: w.kind, address: fmt(w.address, ctx.net), balance: st.balance, active: st.active });
  }
  // the wallet with money; prefer a deployed one
  out.sort((a, b) => (b.balance > a.balance ? 1 : b.balance < a.balance ? -1 : 0) || Number(b.active) - Number(a.active));
  return out;
}

export async function runPipeline(job, { ctx, phrase, mainKind, amount, count, format = 'ton', refund = true }) {
  const log = (s) => { job.log.push(`${new Date().toLocaleTimeString()} ${s}`); };
  const key = await keyFromPhrase(phrase);
  const main = senders(key, ctx.net).find((w) => w.kind === mainKind);
  const mainAddr = fmt(main.address, ctx.net);
  const value = toNano(amount);

  job.stage = 'Считаю комиссии';
  const fees = await estimateFees(ctx, format);
  job.fees = { deploy: fromNano(fees.deploy), ret: fromNano(fees.ret) };
  log(`Комиссии по эмуляции: развёртывание (из входящего платежа) ${fromNano(fees.deploy)}, возврат ${fromNano(fees.ret)} TON`);
  const minimum = fees.deploy + (refund ? fees.ret + RESERVE : 0n);
  if (value <= minimum) throw new Error(`сумма слишком мала: нужно больше ${fromNano(minimum)} TON на кошелёк`);

  job.stage = 'Создаю кошельки';
  job.rows = Array.from({ length: count }, (_, i) => ({ n: i + 1, status: 'создаю' }));
  const wallets = [];
  await pool(job.rows, os.cpus().length, async (row, k) => {
    wallets[k] = await newWallet(format, ctx.net);
    row.phrase = wallets[k].phrase;
    row.address = fmt(wallets[k].address, ctx.net);
    row.status = 'создан';
  });
  log(`Создано кошельков: ${count} (${format === 'gram' ? 'Gram Wallet, 12+12 слов' : 'TON, 24 слова'})`);
  if (job.cancel) throw new Error('остановлено');

  // every funding message carries the StateInit (and for Gram Wallet the key switch): it deploys the wallet
  job.stage = 'Рассылка и развёртывание';
  const msgs = wallets.map((nw) => internal({ to: nw.address, value, bounce: false, init: nw.init, body: nw.body }));
  job.rows.forEach((r) => (r.status = 'жду пополнения'));
  await sendMany(ctx, main, msgs, (done) => log(`Отправлено ${done} из ${count}`));
  log(`Рассылка с ${mainAddr} завершена`);

  job.stage = refund ? 'Проверка и возврат' : 'Проверка';
  await pool(job.rows, ctx.concurrency, async (row, k) => {
    if (job.cancel) { row.status = 'остановлено'; return; }
    const nw = wallets[k];
    const w = senders(nw.signKey, ctx.net, nw.anchorPub)[0];
    try {
      row.status = 'жду развёртывания';
      for (let i = 0; ; i++) {
        const st = await call(ctx, 'state', row.address);
        if (st.active && (await call(ctx, 'get', row.address, 'seqno')) >= nw.seqnoAfter) break;
        if (i > 60) throw new Error('кошелёк не развернулся за 3 минуты (проверь адрес на tonviewer.com)');
        await sleep(ctx.pollMs ?? 3000);
      }
      if (format === 'gram') {
        const pk = await call(ctx, 'get', row.address, 'get_public_key');
        if (pk !== BigInt('0x' + Buffer.from(nw.signKey.publicKey).toString('hex'))) throw new Error('ключ не переключился на слова 13–24');
      }
      if (!refund) { row.status = 'готово'; row.left = fromNano((await call(ctx, 'state', row.address)).balance); return; }
      row.status = 'возвращаю';
      let margin = fees.ret + RESERVE;
      for (let attempt = 0; attempt < 2; attempt++) {
        const b = (await call(ctx, 'state', row.address)).balance;
        const back = b - margin;
        if (back <= 0n) { row.status = 'готово'; row.returned = '0'; return; }
        await sendMany(ctx, w, [internal({ to: main.address, value: back, bounce: false })]);
        const after = (await call(ctx, 'state', row.address)).balance;
        if (after < b - back / 2n) { row.returned = fromNano(back); row.left = fromNano(after); row.status = 'готово'; return; }
        margin = fees.ret * 2n + RESERVE * 2n;  // the transfer did not go through: retry with a bigger margin
      }
      throw new Error('возврат не прошёл (не хватило на комиссию)');
    } catch (e) { row.status = 'ошибка'; row.error = e.message; }
  });
  const returned = job.rows.reduce((s, r) => s + (r.returned ? toNano(r.returned) : 0n), 0n);
  job.summary = { sent: fromNano(value * BigInt(count)), returned: fromNano(returned) };
  log(`Готово. Разослано ${fromNano(value * BigInt(count))}, вернулось ${fromNano(returned)} TON`);
  job.stage = 'Готово';
}

// ------------------------------------------------------------------ finishing a mined (vanity) address
// Words 1-12 come from the miner; words 13-24 are generated here. One message deploys the wallet and
// switches it to words 13-24 — paid either by the main wallet (internal message, the address needs no
// balance) or by the wallet itself (external message, the address needs ~0.02 TON).
function parse12(text) {
  const w = String(text || '').trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (w.length !== 12) throw new Error(`нужно 12 слов, а здесь ${w.length}`);
  if (!bip39.validateMnemonic(w.join(' '))) throw new Error('это не BIP39-фраза из 12 слов (опечатка или не тот порядок слов)');
  return w.join(' ');
}
const keyNum = (pub) => BigInt('0x' + Buffer.from(pub).toString('hex'));

export async function finPrepare(ctx, anchorText) {
  const anchor = halfKey(parse12(anchorText));
  const addr = fmt(tgWallet(anchor.publicKey, ctx.net).address, ctx.net);
  const st = await call(ctx, 'state', addr);
  let status = st.active ? 'развёрнут' : st.balance > 0n ? 'не развёрнут, есть баланс' : 'не развёрнут, пустой';
  let rotated = false;
  if (st.active) {
    rotated = (await call(ctx, 'get', addr, 'get_public_key')) !== keyNum(anchor.publicKey);
    status = rotated ? 'уже переключён на другие слова 13–24' : 'развёрнут, ключ пока из слов 1–12';
  }
  return { address: addr, balance: st.balance, active: st.active, status, rotated, signing: bip39.generateMnemonic(128, (n) => crypto.randomBytes(n)) };
}

export async function finRun(job, { ctx, anchorText, signingText, payer, phrase }) {
  const log = (s) => { job.log.push(`${new Date().toLocaleTimeString()} ${s}`); };
  const anchor = halfKey(parse12(anchorText)), signing = halfKey(parse12(signingText));
  const w = tgWallet(anchor.publicKey, ctx.net);
  const addr = fmt(w.address, ctx.net);
  const row = { n: 1, address: addr, status: 'проверяю' };
  job.rows = [row];
  job.stage = 'Финализация';
  const st = await call(ctx, 'state', addr);
  let seqno = 0;
  if (st.active) {
    const pk = await call(ctx, 'get', addr, 'get_public_key');
    if (pk === keyNum(signing.publicKey)) { row.status = 'готово'; job.stage = 'Уже готово'; return; }
    if (pk !== keyNum(anchor.publicKey)) throw new Error('кошелёк уже переключён на другие слова 13–24; слова 1–12 им больше не управляют');
    seqno = Number(await call(ctx, 'get', addr, 'seqno'));
  }
  row.status = 'отправляю';
  if (payer === 'main') {
    const key = await keyFromPhrase(phrase);
    const best = (await inspectMain(ctx, phrase))[0];
    if (best.balance < toNano('0.02')) throw new Error('на основном кошельке меньше 0.02 TON');
    const main = senders(key, ctx.net).find((s) => s.kind === best.kind);
    const body = rotationBody({ anchor, signing, address: w.address, net: ctx.net, seqno, internal: true, ttl: 900 });
    // 0.01 TON: covers the gas, the rest stays on the new wallet
    await sendMany(ctx, main, [internal({ to: w.address, value: toNano('0.01'), bounce: false, init: st.active ? undefined : w.init, body })]);
    log(`Оплачено с основного кошелька ${best.kind} ${best.address}`);
  } else {
    if (!st.active && st.balance < toNano('0.015')) throw new Error('на адресе нужно хотя бы 0.02 TON (или выбери оплату с основного кошелька)');
    const body = rotationBody({ anchor, signing, address: w.address, net: ctx.net, seqno, internal: false, ttl: 120 });
    const ext = external({ to: w.address, init: st.active ? undefined : w.init, body });
    await call(ctx, 'send', beginCell().store(storeMessage(ext)).endCell().toBoc().toString('base64'));
    log('Транзакция отправлена с самого кошелька');
  }
  row.status = 'жду подтверждения';
  for (let i = 0; i < (ctx.confirmTries ?? 40); i++) {
    await sleep(ctx.pollMs ?? 3000);
    try {
      const s2 = await call(ctx, 'state', addr);
      if (s2.active && (await call(ctx, 'get', addr, 'get_public_key')) === keyNum(signing.publicKey)) {
        row.status = 'готово';
        row.left = fromNano(s2.balance);
        log('Кошелёк развёрнут и переключён на слова 13–24');
        job.stage = 'Готово';
        return;
      }
    } catch (_) { /* keep waiting */ }
  }
  throw new Error('не подтвердилось за 2 минуты; проверь адрес на tonviewer.com и повтори (повтор безопасен)');
}

// ------------------------------------------------------------------ server
const TOKEN = crypto.randomBytes(16).toString('hex');
const jobs = new Map();

async function readBody(req) {
  let s = '';
  for await (const c of req) { s += c; if (s.length > 1e6) throw new Error('слишком большой запрос'); }
  return JSON.parse(s || '{}');
}
function ctxFrom(b) {
  const net = b.net === 'testnet' ? 'testnet' : 'mainnet';
  const apiKey = (b.apiKey || '').trim();
  return { net, providers: makeProviders(net, apiKey), concurrency: apiKey ? 4 : 1 };
}
function parseInput(b) {
  const amount = String(b.amount || '').replace(',', '.').trim();
  if (!/^\d+(\.\d{1,9})?$/.test(amount) || Number(amount) <= 0) throw new Error('укажи сумму на кошелёк, например 0.05');
  const count = Math.floor(Number(b.count));
  if (!(count >= 1 && count <= 1000)) throw new Error('количество кошельков от 1 до 1000');
  return { amount, count, format: b.format === 'gram' ? 'gram' : 'ton', refund: b.refund !== false };
}

function handler(req, res) {
  const url = new URL(req.url, 'http://x');
  const send = (code, obj, type = 'application/json') => {
    res.writeHead(code, { 'Content-Type': type + '; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(type === 'application/json' ? JSON.stringify(obj, (k, v) => (typeof v === 'bigint' ? fromNano(v) : v)) : obj);
  };
  if (req.method === 'GET' && url.pathname === '/') {
    if (url.searchParams.get('t') !== TOKEN) return send(403, 'Открой ссылку из консоли (в ней есть ключ доступа).', 'text/plain');
    return send(200, PAGE, 'text/html');
  }
  if (req.headers['x-token'] !== TOKEN) return send(403, { error: 'нет доступа' });
  (async () => {
    try {
      if (req.method === 'GET' && url.pathname.startsWith('/api/job/')) {
        const job = jobs.get(url.pathname.slice(9));
        return job ? send(200, job) : send(404, { error: 'нет такой задачи' });
      }
      const b = await readBody(req);
      if (url.pathname === '/api/inspect') {
        const ctx = ctxFrom(b);
        const { amount, count, format, refund } = parseInput(b);
        const mains = await inspectMain(ctx, b.phrase || '');
        return send(200, { mains, amount, count, format, refund });
      }
      if (url.pathname === '/api/run') {
        const ctx = ctxFrom(b);
        const { amount, count, format, refund } = parseInput(b);
        if (!['WalletTg', 'W5', 'V4'].includes(b.mainKind)) throw new Error('не выбран основной кошелёк');
        const id = crypto.randomBytes(6).toString('hex');
        const job = { id, rows: [], log: [], stage: 'Запуск', done: false, error: null };
        jobs.set(id, job);
        runPipeline(job, { ctx, phrase: b.phrase, mainKind: b.mainKind, amount, count, format, refund })
          .catch((e) => { job.error = e.message; }).finally(() => { job.done = true; });
        return send(200, { id });
      }
      if (url.pathname === '/api/fin/prepare') {
        return send(200, await finPrepare(ctxFrom(b), b.anchor));
      }
      if (url.pathname === '/api/fin/run') {
        const ctx = ctxFrom(b);
        parse12(b.anchor); parse12(b.signing);
        if (b.payer === 'main') await keyFromPhrase(b.phrase || '');
        const id = crypto.randomBytes(6).toString('hex');
        const job = { id, rows: [], log: [], stage: 'Запуск', done: false, error: null };
        jobs.set(id, job);
        finRun(job, { ctx, anchorText: b.anchor, signingText: b.signing, payer: b.payer, phrase: b.phrase })
          .catch((e) => { job.error = e.message; }).finally(() => { job.done = true; });
        return send(200, { id });
      }
      if (url.pathname === '/api/cancel') { const j = jobs.get(b.id); if (j) j.cancel = true; return send(200, { ok: true }); }
      send(404, { error: 'not found' });
    } catch (e) { send(400, { error: e.message }); }
  })();
}

const PAGE = /* html */ `<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Auto Wallets</title>
<style>
:root { --bg:#eef2f5; --surface:#fff; --fg:#13202b; --muted:#5a6a79; --line:#d6dee6; --accent:#0b7899; --soft:#d8eef5; --ok:#1f7a4a; --warn:#9a5b00; --bad:#b3261e;
  --mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace; }
@media (prefers-color-scheme: dark) { :root { --bg:#0c1319; --surface:#131d26; --fg:#e3ebf1; --muted:#8b9cab; --line:#233240; --accent:#45b8db; --soft:#123445; --ok:#5fc98f; --warn:#e3a34a; --bad:#ff8a80; color-scheme: dark; } }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--fg); font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
.wrap { max-width: 980px; margin: 0 auto; padding: 20px 16px 48px; display: grid; gap: 14px; }
h1 { margin: 0; font-size: 1.4rem; }
.hint { margin: 0; color: var(--muted); font-size: .9rem; }
.panel { background:var(--surface); border:1px solid var(--line); border-radius:12px; padding:16px; display:grid; gap:12px; }
label { display:grid; gap:4px; font-size:.88rem; color: var(--muted); }
input[type=text], input[type=number], input[type=password] { font: 14px var(--mono); color: var(--fg); background: var(--bg); border:1px solid var(--line); border-radius:8px; padding:8px 10px; width:100%; }
.row { display:flex; gap:12px; flex-wrap:wrap; align-items:flex-end; }
.row > label { flex: 1 1 180px; }
button { font: inherit; padding:9px 18px; border-radius:8px; cursor:pointer; }
.act { font-weight:600; border:1px solid var(--accent); background:var(--accent); color:var(--surface); }
.sec { border:1px solid var(--line); background:var(--surface); color:var(--fg); }
button:disabled { opacity:.45; cursor: default; }
.msg.err { color: var(--bad); }
.mains { display:grid; gap:6px; }
.mains label { display:flex; gap:10px; align-items:center; color: var(--fg); font-size: .9rem; padding:8px 10px; border:1px solid var(--line); border-radius:8px; background: var(--bg); }
.mains label:has(input:checked) { border-color: var(--accent); background: var(--soft); }
.mono { font-family: var(--mono); word-break: break-all; }
.warn { border-left: 3px solid var(--warn); padding: 8px 12px; font-size: .9rem; background: var(--bg); border-radius: 0 6px 6px 0; }
.tablewrap { overflow-x:auto; }
table { width:100%; border-collapse: collapse; font-size: .84rem; }
th, td { text-align:left; padding: 6px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: 600; }
td.num { font-variant-numeric: tabular-nums; white-space: nowrap; }
.st { font-weight: 600; white-space: nowrap; }
.st.ok { color: var(--ok); } .st.bad { color: var(--bad); } .st.run { color: var(--accent); }
.err-text { color: var(--bad); font-size: .8rem; }
.log { font: 12px/1.6 var(--mono); color: var(--muted); max-height: 160px; overflow-y: auto; white-space: pre-wrap; }
.tabs { display:flex; gap:6px; flex-wrap:wrap; }
.tabs button { border:1px solid var(--line); background:var(--surface); color:var(--fg); padding:8px 14px; border-radius:8px; }
.tabs button[aria-selected=true] { border-color: var(--accent); background: var(--soft); color: var(--accent); font-weight: 600; }
.words { display:grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap:6px; margin:0; padding:0; list-style:none; counter-reset: w; }
@media (max-width: 440px) { .words { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
.words li { counter-increment: w; font: 14px var(--mono); padding: 5px 8px; background: var(--bg); border-radius: 6px; white-space: nowrap; }
.words li::before { content: counter(w) "."; color: var(--muted); margin-right: 6px; font-size: .78rem; }
.words li.new { border: 1px solid var(--accent); }
[hidden] { display:none !important; }
</style></head><body>
<div class="wrap">
  <h1>Auto Wallets</h1>
  <p class="hint">Создаёт кошельки WalletTg и пополняет их с основного кошелька. Пополнение само разворачивает кошелёк: отдельной транзакции развёртывания нет. По желанию остаток возвращается назад, на каждом остаётся 0.001 TON. Всё считается на этом компьютере; в сеть уходят только подписанные транзакции.</p>

  <section class="panel">
    <label>Фраза основного кошелька (24 слова) <input type="password" id="phrase" autocomplete="off" spellcheck="false"></label>
    <div class="row">
      <label>Токен toncenter (API-ключ, необязательно) <input type="password" id="apikey" autocomplete="off" placeholder="без токена — медленнее, по одному кошельку"></label>
      <label style="flex:0 0 auto;display:flex;gap:6px;align-items:center;color:var(--fg)"><input type="checkbox" id="testnet"> Тестовая сеть</label>
    </div>
  </section>

  <nav class="tabs" role="tablist">
    <button role="tab" data-tab="auto" aria-selected="true">Кошельки</button>
    <button role="tab" data-tab="fin" aria-selected="false">Доделать свой адрес</button>
  </nav>

  <section class="panel" data-panel="auto">
    <div class="row">
      <label>Сумма на каждый кошелёк, TON <input type="text" id="amount" value="0.05" inputmode="decimal"></label>
      <label>Количество кошельков <input type="number" id="count" min="1" max="1000" value="5"></label>
    </div>
    <div class="row">
      <label>Формат новых кошельков
        <select id="format" style="font:inherit;color:var(--fg);background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:8px 10px">
          <option value="gram" selected>Gram Wallet (12 + 12 слов, импортируется в Gram Wallet)</option>
          <option value="ton">TON, 24 слова (старый формат)</option>
        </select>
      </label>
      <label style="flex:0 0 auto;display:flex;gap:6px;align-items:center;color:var(--fg)"><input type="checkbox" id="refund" checked> Вернуть остаток на основной</label>
    </div>
    <div class="row"><button class="act" id="check">Проверить</button></div>
    <p class="msg" id="msg"></p>
  </section>

  <section class="panel" data-panel="fin" hidden>
    <p class="hint">Для адреса из майнера: вставь его 12 слов. Здесь создадутся слова 13–24, и одна транзакция развернёт кошелёк и переключит его на них. После этого все 24 слова импортируются в Gram Wallet, а слова 1–12 больше ничего не подписывают.</p>
    <label>12 слов из майнера <input type="password" id="fin-anchor" autocomplete="off" spellcheck="false"></label>
    <div class="row"><button class="act" id="fin-check">Проверить адрес</button></div>
    <p class="msg" id="fin-msg"></p>
    <div id="fin-step2" hidden style="display:grid;gap:12px">
      <div class="warn" id="fin-info"></div>
      <strong>Твоя фраза для Gram Wallet, 24 слова. Перепиши все: без слов 13–24 доступ будет потерян.</strong>
      <ol class="words" id="fin-words"></ol>
      <div class="row">
        <label id="fin-q1-label">Слово № <input type="text" id="fin-q1" autocomplete="off" autocapitalize="off" spellcheck="false"></label>
        <label id="fin-q2-label">Слово № <input type="text" id="fin-q2" autocomplete="off" autocapitalize="off" spellcheck="false"></label>
      </div>
      <div class="mains">
        <label><input type="radio" name="payer" value="main" checked><span><b>Оплатить с основного кошелька</b> (фраза сверху). На адрес ничего заранее отправлять не нужно, уйдёт ~0.01 TON, остаток останется на новом кошельке.</span></label>
        <label><input type="radio" name="payer" value="self"><span><b>Оплатить с самого кошелька</b>. На адресе уже должно быть ~0.02 TON.</span></label>
      </div>
      <div class="row"><button class="act" id="fin-go">Развернуть и переключить</button></div>
      <p class="msg" id="fin-status"></p>
    </div>
  </section>

  <section class="panel" id="confirm" hidden>
    <strong>Основной кошелёк</strong>
    <div class="mains" id="mains"></div>
    <div class="warn" id="plan"></div>
    <div class="row"><button class="act" id="go">Запустить</button><button class="sec" id="back">Отмена</button></div>
  </section>

  <section class="panel" id="result" hidden>
    <div class="row" style="justify-content:space-between;align-items:center">
      <strong id="stage"></strong>
      <div class="row">
        <button class="sec" id="save">Скачать кошельки (.txt)</button>
        <button class="sec" id="stop">Остановить</button>
      </div>
    </div>
    <p class="msg" id="summary"></p>
    <div class="tablewrap"><table id="table"></table></div>
    <div class="log" id="log"></div>
  </section>
</div>
<script>
(() => {
  const T = new URLSearchParams(location.search).get('t');
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  let job = null, jobId = null;
  async function api(path, body) {
    const r = await fetch('/api/' + path, body === undefined ? { headers: { 'x-token': T } } :
      { method: 'POST', headers: { 'x-token': T, 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const j = await r.json();
    if (!r.ok) throw new Error(j.error || 'ошибка');
    return j;
  }
  const input = () => ({ phrase: $('phrase').value, amount: $('amount').value, count: $('count').value,
    apiKey: $('apikey').value, net: $('testnet').checked ? 'testnet' : 'mainnet', format: $('format').value, refund: $('refund').checked });
  const msg = (t, err) => { $('msg').textContent = t || ''; $('msg').className = 'msg' + (err ? ' err' : ''); };

  // tabs
  document.querySelectorAll('.tabs button').forEach((b) => b.addEventListener('click', () => {
    document.querySelectorAll('.tabs button').forEach((x) => x.setAttribute('aria-selected', String(x === b)));
    document.querySelectorAll('[data-panel]').forEach((p) => (p.hidden = p.dataset.panel !== b.dataset.tab));
    if (b.dataset.tab === 'fin') { $('confirm').hidden = true; $('result').hidden = true; }
  }));

  // ---- finishing a mined address
  let fin = null;
  const finMsg = (el, t, err) => { $(el).textContent = t || ''; $(el).className = 'msg' + (err ? ' err' : ''); };
  $('fin-check').addEventListener('click', async () => {
    finMsg('fin-msg', 'Проверяю…'); $('fin-step2').hidden = true; $('fin-check').disabled = true;
    try {
      const r = await api('fin/prepare', { anchor: $('fin-anchor').value, apiKey: $('apikey').value, net: $('testnet').checked ? 'testnet' : 'mainnet' });
      const anchor = $('fin-anchor').value.trim().toLowerCase().split(/\\s+/);
      if (r.rotated) { finMsg('fin-msg', 'Адрес ' + r.address + ' уже переключён на другие слова 13–24. Используй те 24 слова, которые получил тогда.', true); return; }
      const all = anchor.concat(r.signing.split(' '));
      const q = [13 + Math.floor(Math.random() * 6), 19 + Math.floor(Math.random() * 6)];
      fin = { anchor: anchor.join(' '), signing: r.signing, all, q };
      $('fin-info').innerHTML = 'Адрес: <span class="mono">' + esc(r.address) + '</span><br>Баланс: ' + esc(r.balance) + ' TON · ' + esc(r.status);
      $('fin-words').innerHTML = all.map((w, i) => '<li' + (i >= 12 ? ' class="new"' : '') + '>' + esc(w) + '</li>').join('');
      $('fin-q1-label').firstChild.textContent = 'Проверка: слово № ' + q[0] + ' ';
      $('fin-q2-label').firstChild.textContent = 'Слово № ' + q[1] + ' ';
      $('fin-q1').value = ''; $('fin-q2').value = '';
      $('fin-step2').hidden = false; finMsg('fin-msg', ''); finMsg('fin-status', '');
    } catch (e) { finMsg('fin-msg', e.message, true); }
    finally { $('fin-check').disabled = false; }
  });
  $('fin-go').addEventListener('click', async () => {
    if (!fin) return;
    const a1 = $('fin-q1').value.trim().toLowerCase(), a2 = $('fin-q2').value.trim().toLowerCase();
    if (a1 !== fin.all[fin.q[0] - 1] || a2 !== fin.all[fin.q[1] - 1]) return finMsg('fin-status', 'Слова не совпали. Перепиши фразу внимательно и введи проверочные слова ещё раз.', true);
    const payer = (document.querySelector('input[name=payer]:checked') || {}).value;
    if (payer === 'main' && !$('phrase').value.trim()) return finMsg('fin-status', 'Вставь фразу основного кошелька в поле сверху или выбери оплату с самого кошелька.', true);
    $('fin-go').disabled = true; finMsg('fin-status', 'Отправляю…');
    try {
      const { id } = await api('fin/run', { anchor: fin.anchor, signing: fin.signing, payer, phrase: $('phrase').value,
        apiKey: $('apikey').value, net: $('testnet').checked ? 'testnet' : 'mainnet' });
      for (;;) {
        const j = await api('job/' + id);
        const row = j.rows[0] || {};
        if (j.error) { finMsg('fin-status', 'Ошибка: ' + j.error, true); break; }
        if (j.done) { finMsg('fin-status', 'Готово: кошелёк развёрнут и переключён на слова 13–24' + (row.left ? ', на нём ' + row.left + ' TON' : '') + '. Импортируй все 24 слова в Gram Wallet.'); break; }
        finMsg('fin-status', row.status ? row.status.charAt(0).toUpperCase() + row.status.slice(1) + '…' : 'Выполняется…');
        await new Promise((r) => setTimeout(r, 1500));
      }
    } catch (e) { finMsg('fin-status', e.message, true); }
    finally { $('fin-go').disabled = false; }
  });

  $('check').addEventListener('click', async () => {
    msg('Проверяю основной кошелёк…'); $('check').disabled = true;
    try {
      const r = await api('inspect', input());
      $('mains').innerHTML = r.mains.map((m, i) =>
        '<label><input type="radio" name="main" value="' + m.kind + '"' + (i === 0 ? ' checked' : '') + '>' +
        '<span><b>' + m.kind + '</b> · ' + esc(m.balance) + ' TON' + (m.active ? '' : ' · не развёрнут') +
        '<br><span class="mono">' + esc(m.address) + '</span></span></label>').join('');
      const total = Number(r.amount) * Number(r.count);
      $('plan').innerHTML = 'Сеть: <b>' + ($('testnet').checked ? 'тестовая' : 'ОСНОВНАЯ') + '</b>. Будет создано <b>' + r.count +
        '</b> кошельков, на каждый уйдёт <b>' + esc(r.amount) + ' TON</b> (всего ' + total.toFixed(4) +
        ' TON плюс комиссии рассылки), формат <b>' + (r.format === 'gram' ? 'Gram Wallet 12+12' : 'TON 24 слова') + '</b>. Кошельки развернутся этой же рассылкой. ' +
        (r.refund ? 'Затем остаток вернётся на основной кошелёк, на каждом новом останется ~0.001 TON.' : 'Деньги останутся на новых кошельках.');
      $('confirm').hidden = false; msg('');
    } catch (e) { msg(e.message, true); }
    $('check').disabled = false;
  });
  $('back').addEventListener('click', () => { $('confirm').hidden = true; });

  const cls = (s) => /готово/.test(s) ? 'ok' : /ошибка|остановлено/.test(s) ? 'bad' : 'run';
  function render() {
    $('stage').textContent = job.error ? 'Ошибка: ' + job.error : job.stage;
    $('stage').style.color = job.error ? 'var(--bad)' : '';
    $('table').innerHTML = '<tr><th>#</th><th>Адрес</th><th>Статус</th><th>Вернулось</th></tr>' + job.rows.map((r) =>
      '<tr><td class="num">' + r.n + '</td><td class="mono">' + esc(r.address) + '</td><td><span class="st ' + cls(r.status) + '">' + esc(r.status) +
      '</span>' + (r.error ? '<div class="err-text">' + esc(r.error) + '</div>' : '') + '</td><td class="num">' + esc(r.returned ?? (r.left ? 'осталось ' + r.left : '')) + '</td></tr>').join('');
    $('log').textContent = job.log.join('\\n');
    $('log').scrollTop = $('log').scrollHeight;
    const done = job.rows.filter((r) => /готово|ошибка|остановлено/.test(r.status)).length;
    $('summary').textContent = job.summary ? 'Разослано ' + job.summary.sent + ' TON, вернулось ' + job.summary.returned + ' TON.'
      : (job.rows.length ? 'Обработано ' + done + ' из ' + job.rows.length : '');
    $('stop').hidden = job.done;
    $('save').hidden = !job.rows.some((r) => r.phrase);
  }
  $('go').addEventListener('click', async () => {
    const b = { ...input(), mainKind: (document.querySelector('input[name=main]:checked') || {}).value };
    $('confirm').hidden = true;
    try { ({ id: jobId } = await api('run', b)); } catch (e) { return msg(e.message, true); }
    $('result').hidden = false;
    for (;;) {
      job = await api('job/' + jobId);
      render();
      if (job.done) break;
      await new Promise((r) => setTimeout(r, 1000));
    }
  });
  $('stop').addEventListener('click', () => jobId && api('cancel', { id: jobId }).catch(() => {}));
  $('save').addEventListener('click', () => {
    const text = job.rows.filter((r) => r.phrase).map((r) => r.address + ' ' + r.phrase).join('\\n') + '\\n';
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
    a.download = 'wallets-' + new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-') + '.txt';
    a.click();
  });
})();
</script>
</body></html>`;

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/').split('/').pop())) {
  const server = http.createServer(handler);
  server.listen(Number(process.env.PORT) || 0, '127.0.0.1', () => {
    const link = `http://127.0.0.1:${server.address().port}/?t=${TOKEN}`;
    console.log('Auto Wallets is running. Open this link (it contains the access key):\n\n  ' + link + '\n\nStop with Ctrl+C.');
    const opener = process.platform === 'win32' ? `start "" "${link}"` : process.platform === 'darwin' ? `open "${link}"` : `xdg-open "${link}"`;
    exec(opener, () => {});
  });
}
