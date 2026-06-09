// Native-JS challenger for the garbled lottery settle verifier (no WASM). Mirrors
// cube::transmutative::garble: rebuild the PUBLIC circuit structure from the bands,
// pin the public draw via the rg label commitments, propagate the engine's revealed
// input labels through the garbled tables, and read the output label. On a WRONG
// winner that output is the "invalid" label = the disprove secret. Byte-compatible
// with the Rust lib (same keyed-sha256 gate eval), so the secret opens the on-chain
// disprove lock. A browser tab can challenge a settle with this alone.

import { sha256 } from '@noble/hashes/sha2.js';

const VALUE_BITS = 64;
const enc = new TextEncoder();
const cat = (...a) => { const n = a.reduce((s, x) => s + x.length, 0); const o = new Uint8Array(n); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };
const u32le = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };
const eqBytes = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const toBytes = (arr) => Uint8Array.from(arr); // JSON number-array -> bytes
const xor = (a, b) => { const o = new Uint8Array(32); for (let i = 0; i < 32; i++) o[i] = a[i] ^ b[i]; return o; };
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

// keyed hash, == cube ks(a,b,gate,kind) = sha256(a||b||gate_le_u32||kind)
const TAG = enc.encode('tag');
const ENC = enc.encode('enc');
const ks = (a, b, gate, kind) => sha256(cat(a, b, u32le(gate), kind));

const bitsFor = (n) => { let b = 1; while ((1 << b) < n) b += 1; return b; };
// gate truth tables (index i*2+j), matching cube.
const XOR = [0, 1, 1, 0];
const AND = [0, 0, 0, 1];
const OR = [0, 1, 1, 1];

// Rebuild the WinnerVerifier gate STRUCTURE for bands lo[]/hi[] — identical wire
// allocation + gate creation order to cube, so gate ids/tables align.
export function buildVerifier(lo, hi) {
  const n = Math.max(lo.length, 1);
  const wBits = bitsFor(n);
  let nw = 0;
  const gates = [];
  const wire = () => nw++;
  const gate = (a, b, truth) => { const o = wire(); const id = gates.length; gates.push({ a, b, o, id, truth }); return o; };
  const one = wire();
  const zero = wire();
  const rg = Array.from({ length: VALUE_BITS }, wire);
  const w = Array.from({ length: wBits }, wire);
  // selW_i = (W == i)
  const sel = [];
  for (let i = 0; i < n; i++) {
    let term = null;
    for (let bit = 0; bit < wBits; bit++) {
      const want1 = (i >> bit) & 1;
      const lit = want1 ? w[bit] : gate(w[bit], one, XOR); // !w_bit = XOR(w_bit, one)
      term = term === null ? lit : gate(term, lit, AND);
    }
    sel.push(term);
  }
  const mux = (consts) => Array.from({ length: VALUE_BITS }, (_, k) => {
    const act = [];
    for (let i = 0; i < n; i++) if ((BigInt(consts[i]) >> BigInt(k)) & 1n) act.push(sel[i]);
    if (act.length === 0) return zero;
    let acc = act[0];
    for (let j = 1; j < act.length; j++) acc = gate(acc, act[j], OR);
    return acc;
  });
  const loW = mux(lo);
  const hiW = mux(hi);
  const lessThan = (a, b) => {
    let lt = zero;
    for (let i = 0; i < VALUE_BITS; i++) {
      const na = gate(a[i], one, XOR);
      const alb = gate(na, b[i], AND);
      const axb = gate(a[i], b[i], XOR);
      const eq = gate(axb, one, XOR);
      const eal = gate(eq, lt, AND);
      lt = gate(alb, eal, OR);
    }
    return lt;
  };
  const rgLtLo = lessThan(rg, loW);
  const rgLtHi = lessThan(rg, hiW);
  const geLo = gate(rgLtLo, one, XOR);
  const valid = gate(geLo, rgLtHi, AND);
  return { gates, rg, w, one, zero, valid };
}

// Propagate active input labels through the garbled tables -> output label.
function evalActive(v, tables, active) {
  for (let gi = 0; gi < v.gates.length; gi++) {
    const g = v.gates[gi];
    const la = active.get(g.a);
    const lb = active.get(g.b);
    const tag = ks(la, lb, g.id, TAG);
    const row = tables[gi].find((r) => eqBytes(toBytes(r.tag), tag));
    if (!row) throw new Error(`no row opens at gate ${gi}`);
    active.set(g.o, xor(toBytes(row.ct), ks(la, lb, g.id, ENC)));
  }
  return active.get(v.valid);
}

// Re-garble all gates from revealed wires (== cube garble), to verify an opened
// cut-and-choose instance. `wires` is [[label0,label1], …] of Uint8Array.
function garbleTables(v, wires) {
  return v.gates.map((g) => {
    const rows = [];
    for (let i = 0; i < 2; i++) for (let j = 0; j < 2; j++) {
      const aL = wires[g.a][i], bL = wires[g.b][j];
      const outL = wires[g.o][g.truth[i * 2 + j]];
      rows.push({ tag: ks(aL, bL, g.id, TAG), ct: xor(ks(aL, bL, g.id, ENC), outL) });
    }
    const k = g.id % 4; // rotate_left
    return rows.slice(k).concat(rows.slice(0, k));
  });
}
function tablesCommit(tables) {
  const parts = [];
  for (const tab of tables) for (const r of tab) { parts.push(r.tag, r.ct); }
  return sha256(cat(...parts));
}

// Verify the cut-and-choose opening: re-garble every OPENED instance from its
// revealed wires and confirm its committed tables hash + disprove hash. Throws if
// any opened instance was dishonestly garbled. Returns the number opened.
export function verifyCutChoose(settle) {
  const v = buildVerifier(settle.assertion.lo, settle.assertion.hi);
  let opened = 0;
  for (let i = 0; i < settle.instances.length; i++) {
    const inst = settle.instances[i];
    if (!inst.opened) continue;
    opened += 1;
    const wires = inst.wires.map((p) => [toBytes(p[0]), toBytes(p[1])]);
    const tables = garbleTables(v, wires);
    if (hex(tablesCommit(tables)) !== inst.tables_commit) throw new Error(`cut-and-choose: instance ${i} tables mismatch (dishonest garbler)`);
    if (hex(sha256(wires[v.valid][0])) !== inst.disprove_hash) throw new Error(`cut-and-choose: instance ${i} disprove hash mismatch (dishonest garbler)`);
    // valid label (index 1) integrity too — protects the winner-sweep lock from a
    // garbler that fakes it to grief the winner. Older engines omit it; skip then.
    if (inst.valid_hash !== undefined && hex(sha256(wires[v.valid][1])) !== inst.valid_hash) throw new Error(`cut-and-choose: instance ${i} valid hash mismatch (dishonest garbler)`);
  }
  // the settle instance must be unopened and its locks must match the assertion.
  const si = settle.settle_instance;
  if (settle.instances[si].opened) throw new Error('cut-and-choose: settle used an opened instance');
  if (settle.instances[si].disprove_hash !== settle.disprove_hash) throw new Error('cut-and-choose: settle disprove hash mismatch');
  if (settle.valid_hash !== undefined && settle.instances[si].valid_hash !== settle.valid_hash) throw new Error('cut-and-choose: settle valid hash mismatch');
  return opened;
}

// The MIRROR of `challenge`: on an HONEST settle the evaluated output IS the valid
// label — returned here (hex) as the WINNER-SWEEP secret the proven winner uses to
// open each loser leaf's winner-sweep lock. Returns null on a wrong settle (no
// sweep; use `challenge` for the disprove secret). Throws on a faked draw.
export function winnerLabel(a, trueRg) {
  const v = buildVerifier(a.lo, a.hi);
  const active = new Map();
  for (const [wireIdx, lab] of a.revealed) active.set(wireIdx, toBytes(lab));
  const rg = BigInt(trueRg);
  for (let k = 0; k < VALUE_BITS; k++) {
    const lab = active.get(v.rg[k]);
    if (!lab) throw new Error('missing rg label');
    const bit = Number((rg >> BigInt(k)) & 1n);
    const want = toBytes(a.rg_commitments[k][bit]);
    if (!eqBytes(sha256(lab), want)) throw new Error('revealed rg does not match the true public draw');
  }
  const out = evalActive(v, a.tables, active);
  const validHash = toBytes(a.valid_hash);
  return eqBytes(sha256(out), validHash) ? hex(out) : null;
}

// Challenge a SettleAssertion (parsed JSON from /api/settle[_assertion]) against the
// challenger's independently-known true draw `trueRg`. Returns the disprove secret
// (hex) if the asserted winner is WRONG, or null if honest. Throws if the engine
// revealed a draw that doesn't match the commitments (faked rg).
export function challenge(a, trueRg) {
  const v = buildVerifier(a.lo, a.hi);
  const active = new Map();
  for (const [wireIdx, lab] of a.revealed) active.set(wireIdx, toBytes(lab));
  // pin the public draw: each rg-bit label must hash to the commitment for the true bit.
  const rg = BigInt(trueRg);
  for (let k = 0; k < VALUE_BITS; k++) {
    const lab = active.get(v.rg[k]);
    if (!lab) throw new Error('missing rg label');
    const bit = Number((rg >> BigInt(k)) & 1n);
    const want = toBytes(a.rg_commitments[k][bit]);
    if (!eqBytes(sha256(lab), want)) throw new Error('revealed rg does not match the true public draw');
  }
  const out = evalActive(v, a.tables, active);
  const disproveHash = toBytes(a.disprove_hash);
  return eqBytes(sha256(out), disproveHash) ? hex(out) : null;
}
