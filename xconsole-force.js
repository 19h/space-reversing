const ShouldAutoComplete = ptr('0x14757EA60');
const ShouldRegister     = ptr('0x14757EF80');
const ShouldExecute      = ptr('0x14757EBC0');
const CigMalloc = new NativeFunction(ptr('0x14807E43B'), 'pointer', ['uint64']);

Interceptor.replace(ptr('0x146E04FB0'), new NativeCallback((a1, a2, a3, a4) => {
    const cell = CigMalloc(0x18);
    cell.writePointer(cell);
    cell.add(8).writePointer(cell);
    return cell;
}, 'pointer', ['pointer', 'pointer', 'char', 'char']));

Interceptor.replace(ShouldAutoComplete, new NativeCallback(
    (_this, _badge, _name) => 1,
    'uint8', ['pointer', 'uint8', 'pointer']
));
Interceptor.replace(ShouldRegister, new NativeCallback(
    (_this, _name, _flags) => 1,
    'uint8', ['pointer', 'pointer', 'uint32']
));


// ---------- CIGDevelopmentTools version gate bypass ----------

const TARGET_DEVTOOLS_FILE_VERSION = {
    major: 4,
    minor: 7,
    build: 178,
    revision: 50402,
    ms: (4 << 16) | 7,
    ls: (178 << 16) | 50402
};

const fakeDevToolsVersionBlocks = new Set();
function findExport(name) {
    const address = Module.findGlobalExportByName(name);
    if (address === null) {
        throw new Error(`Unable to find export ${name}`);
    }
    return address;
}

function isCigDevelopmentToolsName(name) {
    if (!name) return false;
    const normalized = name.replace(/\\/g, '/').toLowerCase();
    return normalized.endsWith('/cigdevelopmenttools') ||
        normalized.endsWith('/cigdevelopmenttools.dll') ||
        normalized === 'cigdevelopmenttools' ||
        normalized === 'cigdevelopmenttools.dll';
}

function writeFixedFileInfo(block) {
    block.add(0x00).writeU32(0xFEEF04BD);
    block.add(0x04).writeU32(0x00010000);
    block.add(0x08).writeU32(TARGET_DEVTOOLS_FILE_VERSION.ms);
    block.add(0x0c).writeU32(TARGET_DEVTOOLS_FILE_VERSION.ls);
    block.add(0x10).writeU32(TARGET_DEVTOOLS_FILE_VERSION.ms);
    block.add(0x14).writeU32(TARGET_DEVTOOLS_FILE_VERSION.ls);
    block.add(0x18).writeU32(0x0000003F);
    block.add(0x1c).writeU32(0x00000000);
    block.add(0x20).writeU32(0x00040004);
    block.add(0x24).writeU32(0x00000002);
    block.add(0x28).writeU32(0x00000000);
    block.add(0x2c).writeU32(0x00000000);
    block.add(0x30).writeU32(0x00000000);
}

function rememberFakeVersionBlock(block) {
    const key = block.toString();
    fakeDevToolsVersionBlocks.add(key);
}

Interceptor.attach(findExport('GetFileVersionInfoSizeA'), {
    onEnter(args) {
        this.name = safeReadAnsi(args[0]);
        this.handle = args[1];
        this.isDevTools = isCigDevelopmentToolsName(this.name);
    },
    onLeave(retval) {
        if (!this.isDevTools) return;
        if (!this.handle.isNull()) this.handle.writeU32(0);
        retval.replace(0x100);
        console.log(`[version-bypass] GetFileVersionInfoSizeA(${this.name}) -> 0x100`);
    }
});

Interceptor.attach(findExport('GetFileVersionInfoA'), {
    onEnter(args) {
        this.name = safeReadAnsi(args[0]);
        this.length = args[2].toUInt32();
        this.data = args[3];
        this.isDevTools = isCigDevelopmentToolsName(this.name);
    },
    onLeave(retval) {
        if (!this.isDevTools) return;
        this.data.writeByteArray(Array(Math.min(this.length, 0x100)).fill(0));
        writeFixedFileInfo(this.data);
        rememberFakeVersionBlock(this.data);
        retval.replace(1);
        console.log(`[version-bypass] GetFileVersionInfoA(${this.name}) -> FileVersion ${TARGET_DEVTOOLS_FILE_VERSION.major}.${TARGET_DEVTOOLS_FILE_VERSION.minor}.${TARGET_DEVTOOLS_FILE_VERSION.build}.${TARGET_DEVTOOLS_FILE_VERSION.revision}`);
    }
});

Interceptor.attach(findExport('VerQueryValueA'), {
    onEnter(args) {
        this.block = args[0];
        this.subBlock = safeReadAnsi(args[1]);
        this.outBuffer = args[2];
        this.outLen = args[3];
        this.isDevToolsRootQuery = this.subBlock === '\\' && fakeDevToolsVersionBlocks.has(this.block.toString());
    },
    onLeave(retval) {
        if (!this.isDevToolsRootQuery) return;
        this.outBuffer.writePointer(this.block);
        this.outLen.writeU32(0x34);
        retval.replace(1);
        console.log(`[version-bypass] VerQueryValueA("\\") -> forged VS_FIXEDFILEINFO @ ${this.block}`);
    }
});

// ---------- module load tracing ----------

const kernel32 = Process.getModuleByName('kernel32.dll');
const ntdll    = Process.getModuleByName('ntdll.dll');

// Treat anything below 64K as "not a real string pointer" (atom/ordinal/flags-encoded).
const MIN_VALID_PTR = ptr(0x10000);

function isProbablyStringPtr(p) {
    try {
        return !p.isNull() && p.compare(MIN_VALID_PTR) >= 0;
    } catch (_) {
        return false;
    }
}

function safeReadAnsi(p) {
    if (!isProbablyStringPtr(p)) return `<atom:${p}>`;
    try { return p.readCString(); } catch (e) { return `<bad:${p}>`; }
}

function safeReadWide(p) {
    if (!isProbablyStringPtr(p)) return `<atom:${p}>`;
    try { return p.readUtf16String(); } catch (e) { return `<bad:${p}>`; }
}

function readUnicodeString(pUS) {
    if (!isProbablyStringPtr(pUS)) return '<null>';
    try {
        const len = pUS.readU16();
        if (len === 0) return '';
        const buf = pUS.add(8).readPointer();
        if (!isProbablyStringPtr(buf)) return '<null buf>';
        return buf.readUtf16String(len / 2);
    } catch (_) { return '<bad us>'; }
}

function backtrace(ctx) {
    return Thread.backtrace(ctx, Backtracer.ACCURATE)
        .slice(0, 6)
        .map(DebugSymbol.fromAddress)
        .map(s => `  ${s}`)
        .join('\n');
}

Interceptor.attach(kernel32.getExportByName('LoadLibraryA'), {
    onEnter(args) {
        this.name = safeReadAnsi(args[0]);
        console.log(`[LoadLibraryA] ${this.name}\n${backtrace(this.context)}`);
    },
    onLeave(retval) {
        console.log(`[LoadLibraryA] ${this.name} -> ${retval}`);
    }
});

Interceptor.attach(kernel32.getExportByName('LoadLibraryW'), {
    onEnter(args) {
        this.name = safeReadWide(args[0]);
        console.log(`[LoadLibraryW] ${this.name}\n${backtrace(this.context)}`);
    },
    onLeave(retval) {
        console.log(`[LoadLibraryW] ${this.name} -> ${retval}`);
    }
});

Interceptor.attach(kernel32.getExportByName('LoadLibraryExA'), {
    onEnter(args) {
        this.name  = safeReadAnsi(args[0]);
        this.flags = args[2].toUInt32();
        console.log(`[LoadLibraryExA] ${this.name} flags=0x${this.flags.toString(16)}\n${backtrace(this.context)}`);
    },
    onLeave(retval) {
        console.log(`[LoadLibraryExA] ${this.name || '?'} -> ${retval}`);
    }
});

Interceptor.attach(kernel32.getExportByName('LoadLibraryExW'), {
    onEnter(args) {
        this.name  = safeReadWide(args[0]);
        this.flags = args[2].toUInt32();
        console.log(`[LoadLibraryExW] ${this.name} flags=0x${this.flags.toString(16)}\n${backtrace(this.context)}`);
    },
    onLeave(retval) {
        console.log(`[LoadLibraryExW] ${this.name || '?'} -> ${retval}`);
    }
});

Interceptor.attach(ntdll.getExportByName('LdrLoadDll'), {
    onEnter(args) {
        this.path   = isProbablyStringPtr(args[0]) ? safeReadWide(args[0]) : '<default>';
        this.flags  = isProbablyStringPtr(args[1]) ? args[1].readU32() : 0;
        this.module = readUnicodeString(args[2]);
        this.outHandle = args[3];
        console.log(`[LdrLoadDll] module="${this.module}" path="${this.path}" flags=0x${this.flags.toString(16)}\n${backtrace(this.context)}`);
    },
    onLeave(retval) {
        let handle = ptr(0);
        if (this.outHandle && isProbablyStringPtr(this.outHandle)) {
            try { handle = this.outHandle.readPointer(); } catch (_) {}
        }
        console.log(`[LdrLoadDll] "${this.module || '?'}" -> NTSTATUS=0x${retval.toUInt32().toString(16)} handle=${handle}`);
    }
});

Interceptor.attach(ntdll.getExportByName('LdrGetProcedureAddress'), {
    onEnter(args) {
        this.hmod    = args[0];
        this.ordinal = args[2].toUInt32();
        if (isProbablyStringPtr(args[1])) {
            try {
                const len = args[1].readU16();
                const buf = args[1].add(8).readPointer();
                this.proc = (len && isProbablyStringPtr(buf)) ? buf.readCString(len) : `#${this.ordinal}`;
            } catch (_) { this.proc = `#${this.ordinal}`; }
        } else {
            this.proc = `#${this.ordinal}`;
        }
    },
    onLeave(retval) {
        if (retval.toUInt32() !== 0) {
            console.log(`[LdrGetProcedureAddress] ${this.hmod} ${this.proc} -> NTSTATUS=0x${retval.toUInt32().toString(16)}`);
        }
    }
});

//Interceptor.attach(kernel32.getExportByName('GetProcAddress'), {
//    onEnter(args) {
//        this.hmod = args[0];
//        const lp = args[1];
//        if (lp.compare(MIN_VALID_PTR) < 0) {
//            this.proc = `#${lp.toUInt32()}`;
//        } else {
//            this.proc = safeReadAnsi(lp);
//        }
//    },
//    onLeave(retval) {
//        if (!retval.isNull()) {
//            console.log(`[GetProcAddress] ${this.hmod} ${this.proc} -> ${retval}`);
//        }
//    }
//});
