// sc_entxd_request_hook.js
// Target: StarCitizen.exe
// RVA of Invoke: 0x143AC55B0 - imageBase  (computed at runtime)
// RVA of gate qword_14A285485 likewise.
//
// Usage: frida -l sc_entxd_request_hook.js -n StarCitizen.exe
//        or via spawn; set CONFIG below.

'use strict';

const CONFIG = {
    moduleName: 'StarCitizen.exe',

    // Fill these from your IDB. Either both RVAs, or a symbol.
    // RVA = VA_in_IDA - preferredImageBase_in_IDA (0x140000000 for SC).
    invokeRVA: 0x03AC55B0,            // 0x143AC55B0 - 0x140000000
    gateRVA:   0x0A285485,            // 0x14A285485 - 0x140000000
    invokeSymbol: '?Invoke@?$CreateEventHandlerThunkSCEvt_EntXD_XDRequest@AEBVCEntityComponentEntXDInterface@@@CEntityComponentEntXDInterface@@SAXPEAUIComponent@@PEBX@Z',

    forceGateOn:    false,            // write 1 to qword_14A285485 byte at attach
    mutateAmount:   true,            // rewrite currencyAmount before dispatch
    mutateAmountTo: -2000,                // int64
    mutateCurrency: true,
    mutateCurrencyTo: 0,              // ECurrencyType (uint8)

    logVtblWalk: true,                // log dispatcher vtbl[0] target
    backtraceDepth: 6                 // 0 to disable
};

const ECurrencyType = {
    0: 'aUEC', 1: 'UEC', 2: 'REC', 3: 'AUEC_TEST', 4: 'MERIT'
    // adjust to your reversed enum
};

function resolveInvoke(mod) {
    if (CONFIG.invokeSymbol) {
        const s = DebugSymbol.fromName(CONFIG.invokeSymbol);
        if (s && !s.address.isNull()) return s.address;
        const exp = Process.findModuleByName(mod.name).findExportByName(CONFIG.invokeSymbol);
        if (exp && !exp.isNull()) return exp;
    }
    return mod.base.add(CONFIG.invokeRVA);
}

function readSEntXDRequest(p) {
    // struct { uint8 currencyType; uint8 pad[7]; int64 currencyAmount; }
    const ct  = p.readU8();
    const amt = p.add(8).readS64();
    return { currencyType: ct, currencyAmount: amt };
}

function fmtReq(r) {
    const name = ECurrencyType[r.currencyType] || `0x${r.currencyType.toString(16)}`;
    return `{type=${name}(${r.currencyType}) amount=${r.currencyAmount.toString()}}`;
}

function safeReadPtr(p) { try { return p.readPointer(); } catch (e) { return null; } }

function main() {
    const mod = Process.getModuleByName(CONFIG.moduleName);
    const invoke = resolveInvoke(mod);
    const gate   = mod.base.add(CONFIG.gateRVA);

    console.log(`[entxd] module base = ${mod.base}`);
    console.log(`[entxd] Invoke      = ${invoke}  (${invoke.sub(mod.base)} RVA)`);
    console.log(`[entxd] gate byte   = ${gate}    current=${gate.readU8()}`);

    if (CONFIG.forceGateOn) {
        Memory.protect(gate, 1, 'rw-');
        gate.writeU8(1);
        console.log(`[entxd] gate forced to 1`);
    }

    Interceptor.attach(invoke, {
        onEnter(args) {
            // __fastcall(rcx=pComponent, rdx=pEvent)
            const pComponent = args[0];
            const pEvent     = args[1];

            if (pComponent.isNull() || pEvent.isNull()) return;

            const gateVal = gate.readU8();
            const receiverId = pEvent.readU32();
            const req = readSEntXDRequest(pEvent.add(8));

            // pComponent[9].lpVtbl  -> tagged ptr (low 48 bits = real ptr, top 16 = tag)
            // layout: IComponent has vtbl @+0, then array of IComponent members; [9] is +0x48.
            const taggedRaw = pComponent.add(0x48).readPointer();
            const tagged    = ptr(taggedRaw.toString());
            const MASK48    = ptr('0xFFFFFFFFFFFF');
            const real      = tagged.and(MASK48);
            const tag14     = taggedRaw.shr(48).and(0x3FFF).toInt32();

            // pComponent[10].lpVtbl @ +0x50  -> m_pDispatcher (or 0)
            // pComponent[11].lpVtbl @ +0x58  -> dispatch-mode discriminator (==1 vs !=1)
            const pDispatcher = pComponent.add(0x50).readPointer();
            const dispMode    = pComponent.add(0x58).readPointer();

            this.ctx = { pComponent, pEvent, receiverId, req,
                         tagged: taggedRaw, real, tag14,
                         pDispatcher, dispMode, gateVal };

            if (CONFIG.mutateAmount) {
                pEvent.add(0x10).writeS64(CONFIG.mutateAmountTo);
                this.ctx.mutatedAmount = CONFIG.mutateAmountTo;
            }
            if (CONFIG.mutateCurrency) {
                pEvent.add(0x08).writeU8(CONFIG.mutateCurrencyTo & 0xff);
                this.ctx.mutatedCurrency = CONFIG.mutateCurrencyTo & 0xff;
            }

            // Post-mutation snapshot for log
            const reqAfter = readSEntXDRequest(pEvent.add(8));

            let line =
                `[entxd] Invoke gate=${gateVal} comp=${pComponent} ev=${pEvent}` +
                ` recv=0x${receiverId.toString(16)} req=${fmtReq(reqAfter)}` +
                ` tagged=${taggedRaw} real=${real} tag=${tag14}` +
                ` disp=${pDispatcher} mode=${dispMode}`;
            if (this.ctx.mutatedAmount !== undefined)   line += ` [amt->${this.ctx.mutatedAmount}]`;
            if (this.ctx.mutatedCurrency !== undefined) line += ` [cur->${this.ctx.mutatedCurrency}]`;
            console.log(line);

            if (CONFIG.logVtblWalk && !real.isNull()) {
                const vt = safeReadPtr(real);
                if (vt) {
                    const fn = safeReadPtr(vt);
                    const sym = fn ? DebugSymbol.fromAddress(fn) : null;
                    console.log(`        vtbl[0] -> ${fn} ${sym ? '('+sym.name+')' : ''}`);
                }
            }

            if (CONFIG.backtraceDepth > 0) {
                const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
                                 .slice(0, CONFIG.backtraceDepth)
                                 .map(DebugSymbol.fromAddress).join('\n          ');
                console.log(`        bt:\n          ${bt}`);
            }
        },

        onLeave(retval) {
            // void return; nothing to mutate here, but we can observe the post-dispatch
            // state of v19 (assert flag) by re-reading rsp-relative locals — not portable.
            // Skip; rely on follow-up hook of m_pDispatcher::Dispatch if you need confirmation.
        }
    });

    console.log('[entxd] hook installed');
}

setImmediate(main);
