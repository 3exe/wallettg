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
import { mnemonicNew, mnemonicToPrivateKey, mnemonicValidate, sign } from '@ton/crypto';
import { WalletContractV5R1, WalletContractV4 } from '@ton/ton';

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
export function senders(key, net) {
  const tg = tgWallet(key.publicKey, net);
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

// ------------------------------------------------------------------ fee emulation
// Runs deploy + return on a local copy of the chain (same WalletTg code and fee rules) and measures fees.
export async function estimateFees(ctx) {
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
  const key = await mnemonicToPrivateKey(await mnemonicNew());
  const w = senders(key, ctx.net)[0];
  const addr = fmt(w.address, ctx.net);
  const start = toNano('0.1');
  await (await bc.treasury('main')).send({ to: w.address, value: start, bounce: false });
  await sendMany(sctx, w, [internal({ to: w.address, value: 0n, bounce: false, body: 'deploy' })]);
  const b0 = (await sim.state(addr)).balance;
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

export async function runPipeline(job, { ctx, phrase, mainKind, amount, count }) {
  const log = (s) => { job.log.push(`${new Date().toLocaleTimeString()} ${s}`); };
  const key = await keyFromPhrase(phrase);
  const main = senders(key, ctx.net).find((w) => w.kind === mainKind);
  const mainAddr = fmt(main.address, ctx.net);
  const value = toNano(amount);

  job.stage = 'Считаю комиссии';
  const fees = await estimateFees(ctx);
  job.fees = { deploy: fromNano(fees.deploy), ret: fromNano(fees.ret) };
  log(`Комиссии по эмуляции: развёртывание ${fromNano(fees.deploy)}, возврат ${fromNano(fees.ret)} TON`);
  if (value <= fees.deploy + fees.ret + RESERVE) throw new Error(`сумма слишком мала: нужно больше ${fromNano(fees.deploy + fees.ret + RESERVE)} TON на кошелёк`);

  job.stage = 'Создаю кошельки';
  job.rows = Array.from({ length: count }, (_, i) => ({ n: i + 1, status: 'создаю' }));
  const keys = [];
  await pool(job.rows, os.cpus().length, async (row, k) => {
    const words = await mnemonicNew(24);
    keys[k] = await mnemonicToPrivateKey(words);
    row.phrase = words.join(' ');
    row.address = fmt(tgWallet(keys[k].publicKey, ctx.net).address, ctx.net);
    row.status = 'создан';
  });
  log(`Создано кошельков: ${count}`);
  if (job.cancel) throw new Error('остановлено');

  job.stage = 'Рассылка';
  const msgs = job.rows.map((r) => internal({ to: Address.parse(r.address), value, bounce: false }));
  job.rows.forEach((r) => (r.status = 'жду пополнения'));
  await sendMany(ctx, main, msgs, (done) => log(`Отправлено ${done} из ${count}`));
  log(`Рассылка с ${mainAddr} завершена`);

  job.stage = 'Развёртывание и возврат';
  await pool(job.rows, ctx.concurrency, async (row, k) => {
    if (job.cancel) { row.status = 'остановлено'; return; }
    const w = senders(keys[k], ctx.net)[0];
    try {
      row.status = 'жду пополнения';
      let st;
      for (let i = 0; ; i++) {
        st = await call(ctx, 'state', row.address);
        if (st.balance >= value / 2n) break;
        if (i > 60) throw new Error('пополнение не пришло за 3 минуты');
        await sleep(ctx.pollMs ?? 3000);
      }
      if (!st.active) {
        row.status = 'разворачиваю';
        await sendMany(ctx, w, [internal({ to: w.address, value: 0n, bounce: false, body: 'deploy' })]);
      }
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
  return { amount, count };
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
        const { amount, count } = parseInput(b);
        const mains = await inspectMain(ctx, b.phrase || '');
        return send(200, { mains, amount, count });
      }
      if (url.pathname === '/api/run') {
        const ctx = ctxFrom(b);
        const { amount, count } = parseInput(b);
        if (!['WalletTg', 'W5', 'V4'].includes(b.mainKind)) throw new Error('не выбран основной кошелёк');
        const id = crypto.randomBytes(6).toString('hex');
        const job = { id, rows: [], log: [], stage: 'Запуск', done: false, error: null };
        jobs.set(id, job);
        runPipeline(job, { ctx, phrase: b.phrase, mainKind: b.mainKind, amount, count })
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
[hidden] { display:none !important; }
</style></head><body>
<div class="wrap">
  <h1>Auto Wallets</h1>
  <p class="hint">Создаёт кошельки WalletTg, пополняет их с основного кошелька, разворачивает и возвращает остаток назад, оставляя на каждом 0.001 TON. Всё считается на этом компьютере; в сеть уходят только подписанные транзакции.</p>

  <section class="panel">
    <label>Фраза основного кошелька (24 слова) <input type="password" id="phrase" autocomplete="off" spellcheck="false"></label>
    <div class="row">
      <label>Сумма на каждый кошелёк, TON <input type="text" id="amount" value="0.05" inputmode="decimal"></label>
      <label>Количество кошельков <input type="number" id="count" min="1" max="1000" value="5"></label>
    </div>
    <div class="row">
      <label>Токен toncenter (API-ключ, необязательно) <input type="password" id="apikey" autocomplete="off" placeholder="без токена — медленнее, по одному кошельку"></label>
      <label style="flex:0 0 auto;display:flex;gap:6px;align-items:center;color:var(--fg)"><input type="checkbox" id="testnet"> Тестовая сеть</label>
    </div>
    <div class="row"><button class="act" id="check">Проверить</button></div>
    <p class="msg" id="msg"></p>
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
    apiKey: $('apikey').value, net: $('testnet').checked ? 'testnet' : 'mainnet' });
  const msg = (t, err) => { $('msg').textContent = t || ''; $('msg').className = 'msg' + (err ? ' err' : ''); };

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
        ' TON плюс комиссии рассылки). После развёртывания остаток вернётся на основной кошелёк, на каждом новом останется ~0.001 TON.';
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
      '</span>' + (r.error ? '<div class="err-text">' + esc(r.error) + '</div>' : '') + '</td><td class="num">' + esc(r.returned ?? '') + '</td></tr>').join('');
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
