/*
 *  Project-to-Screen stalker
 *  ------------------------
 *  Target prototype (x64 / Windows, fastcall):
 *
 *    bool ProjectToScreenStub(
 *           void*   renderer_or_this,   // RCX
 *           double  x,                  // RDX
 *           double  y,                  // R8
 *           double  z,                  // R9
 *           float*  outX,               // [rsp+0x20]
 *           float*  outY,               // [rsp+0x28]
 *           float*  outZ,               // [rsp+0x30]
 *           char    someFlag,           // [rsp+0x38]
 *           int64_t maybeContext );     // [rsp+0x40]  <-- 9th parameter
 *
 *  Only when the ninth argument (`maybeContext`) == 0 we follow the thread
 *  with Stalker until the function returns.
 */

'use strict';

 /*** ─────────── Configuration ─────────── ***/

// IMAGE name that contains ProjectToScreenStub.
// Update this to the correct module (main EXE or DLL).
const IMAGE_NAME  = 'StarCitizen.exe';

// RVA inside IMAGE_NAME where the routine starts.
const RVA_PROJECT_TO_SCREEN = 0x977a60;   // FIXME: change if different

// Choose what Stalker should record.
// We're adding 'exec' events but with throttling to prevent crashes
const STALKER_EVENTS = {
    compile: true,
    call   : true,
    ret    : true,
    exec   : true    // Added exec events to track individual instructions
};

// Limit how many exec events we process to avoid overwhelming the system
const MAX_EXEC_EVENTS_PER_BATCH = 1000;
let execEventCounter = 0;

/*** ─────────── Helpers ─────────── ***/

// Resolve final absolute address
function resolveProjectToScreen () {
    const base = Module.findBaseAddress(IMAGE_NAME);
    if (base === null)
        throw new Error('Module "' + IMAGE_NAME + '" not loaded – adjust IMAGE_NAME');

    return base.add(RVA_PROJECT_TO_SCREEN);
}

// Pretty-print a native pointer as hex
function ptrFmt (p) { return p.isNull() ? 'NULL' : p.toString(16); }

const y = [];

// Ship stalker packets to host immediately
function makeReceiver (threadId, label) {
    return function (events) {
        const packets = Stalker.parse(events, { stringify: true });

        const stack = [];

        for (const p of packets) {
            const [kind, from, to] = p;

            // Skip compile events completely
            if (kind === 'compile') continue;

            // For exec events, implement throttling to prevent crashes
            if (kind === 'exec') {
                execEventCounter++;
                // Only process a limited number of exec events to avoid overwhelming the system
                if (execEventCounter > MAX_EXEC_EVENTS_PER_BATCH) continue;
            }

            p.push(DebugSymbol.fromAddress(ptr(from)).name || '?');

            // Only add the 'to' symbol for call and ret events since exec events don't have a 'to' field
            if (kind === 'call' || kind === 'ret') {
                p.push(DebugSymbol.fromAddress(ptr(to)).name || '?');
            } else {
                p.push('N/A'); // For exec events, no 'to' field exists
            }

            stack.push(p);
        }

        // Reset exec counter after each batch
        if (execEventCounter > 0) {
            console.log(`[*] Processed ${execEventCounter} exec events in this batch`);
            execEventCounter = 0;
        }

        y.push(stack);
    };
}

setInterval(() => {
    if (y.length) {
        console.log(y.shift().map(r => {
            // Add field names to the log output
            return `kind: ${r[0]}, ${r[1]}${r[3] ? ' (' + r[3] + ')' : ''} -> ${r[2]}${r[4] ? ' (' + r[4] + ')' : ''}`;
        }).join('\n'));
    }
}, 1000);

/*** ─────────── Main ─────────── ***/

const target = resolveProjectToScreen();
console.log('[+] ProjectToScreenStub @ 0x' + ptrFmt(target));

let is_active = false;

const p = Interceptor.attach(target, {
    onEnter (args) {
        if (is_active) return;
        is_active = true;
        this.owner = true;

        /*
         *   args index mapping (x64 Windows):
         *     0  RCX  -> renderer/this
         *     1  RDX  -> x (double)
         *     2  R8   -> y (double)
         *     3  R9   -> z (double)
         *     4  [rsp+0x20] -> outX
         *     ...
         *     8  [rsp+0x40] -> ninth parameter  (int64_t maybeContext)
         */
        const ninth = args[8];   // Already **NativePointer**

        if (ninth.isNull()) {
            const tid = this.threadId;

            // Begin stalking
            Stalker.follow(tid, {
                events: STALKER_EVENTS,
                onReceive: makeReceiver(tid, 'ProjectToScreenStub(' + tid + ')')
            });

            console.log(
              '[*] Stalker attached (tid=' + tid +
              ', ninth=NULL)  → entering ProjectToScreenStub');
        }
    },

    onLeave (retval) {
        if (is_active && !this.owner) return;

        const tid = this.threadId;
        if (tid !== undefined && activeThreads.has(tid)) {
            Stalker.unfollow(tid);
            Stalker.garbageCollect();

            console.log('[*] Stalker detached (tid=' + tid + ') ← returning '
                        + retval.toInt32());
        }
    }
});
