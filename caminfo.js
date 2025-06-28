/*─────────────────────────────────────────────────────────────────────────*\
  Hook : display_camera_and_location_info        (RVA 0x147098860)
  Dump : – pCameraState raw address
         – Parsed high-value fields
         – Derived optics (pitch/yaw/roll, F-stop)
         – Annotated back-trace
\*─────────────────────────────────────────────────────────────────────────*/

'use strict';

(function () {

    /*-------------------------  helpers  -------------------------------*/
    const rva                = 0x7098860;
    const host               = Process.enumerateModules()[0];
    const fnDisplayCamInfo   = host.base.add(rva);

    const d2r = Math.PI / 180;
    const r2d = 180 / Math.PI;

    const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));

    /* read helpers inside CameraState (double-words) */
    const dAt = (base, idx) => Memory.readDouble(base.add(idx * 8));
    const fAt = (base, off) => Memory.readFloat (base.add(off));

    console.log('[+] Module: ', host.name, ' base:', host.base);
    console.log('[+] Hook @ ', fnDisplayCamInfo, '\n');

    /*-------------------------  hook  ---------------------------------*/
    Interceptor.attach(fnDisplayCamInfo, {

        onEnter(args) {
            const pCamState   = args[0];          // RCX (Win64 first arg)
            const pDisplayPos = args[1];
            const displayMode = args[2].toInt32();

            /* --------------------------------------------------------- *
             *  A)  extract core values
             * --------------------------------------------------------- */
            const pitchDotRaw = dAt(pCamState, 0xA2);
            const pitchRad    = Math.asin(clamp(-pitchDotRaw, -1, 1));
            const yawRad      = Math.atan2(dAt(pCamState, 0xA3),
                                           dAt(pCamState, 0xA4));
            const rollRad     = Math.atan2(dAt(pCamState, 0x9E),
                                           dAt(pCamState, 0x9B));

            /* camera-specific sub-structure starting at +0x9A*8 */
            const pCamData    = pCamState.add(0x9A * 8);

            const posX        = dAt(pCamData, 3);      // [3]  x
            const posY        = dAt(pCamData, 7);      // [7]  y
            const posZ        = dAt(pCamData, 0xB);    // [11] z

            const fovRad      = fAt(pCamData, 0xF0);   // radians
            const sensorWidth = fAt(pCamData, 0x334);  // mm or units
            const focalLen    = fAt(pCamData, 0x338);  // mm

            /* derived f-stop exactly as game does */
            let fStop = NaN;
            try {
                fStop = 0.0066849999 /
                        (Math.tan(fovRad * 0.5) * sensorWidth);
            } catch (e) { /* divide by 0 etc. */ }

            /* --------------------------------------------------------- *
             *  B)  pretty-print JSON blob
             * --------------------------------------------------------- */
            const dump = {
                cameraStatePtr : pCamState,
                displayMode    : displayMode,

                orientation : {
                    pitchDeg : pitchRad * r2d,
                    yawDeg   : yawRad   * r2d,
                    rollDeg  : rollRad  * r2d,

                    raw : {
                        dotPitch : pitchDotRaw,
                        vec9E    : dAt(pCamState, 0x9E),
                        vec9F    : dAt(pCamState, 0x9F),
                        vec9B    : dAt(pCamState, 0x9B),
                        vecA3    : dAt(pCamState, 0xA3),
                        vecA4    : dAt(pCamState, 0xA4)
                    }
                },

                position : { x : posX, y : posY, z : posZ },

                optics : {
                    fovRad,               // in radians
                    fovDeg : fovRad * r2d,
                    sensorWidth,
                    focalLen,
                    fStop
                }
            };

            console.log('──────────────────────────────────────────────');
            console.log(JSON.stringify(dump, null, 2));

            /* optional: tiny hexdump of first 256 bytes */
            console.log(hexdump(pCamState, { length : 0x100 }));

            /* --------------------------------------------------------- *
             *  C)  accurate annotated back-trace
             * --------------------------------------------------------- */
            const trace = Thread.backtrace(this.context,
                                           Backtracer.ACCURATE)
                         .map(a => ({
                             addr : a,
                             mod  : (Process.findModuleByAddress(a) || {}).name || '?',
                             off  : (Process.findModuleByAddress(a) || { base: ptr(0) }).base ?
                                    a.sub(Process.findModuleByAddress(a).base) : ptr(0),
                             sym  : DebugSymbol.fromAddress(a).name || ''
                         }));
            console.log('[*] backtrace:\n' + JSON.stringify(trace, null, 2));
            console.log('──────────────────────────────────────────────\n');
        }
    });

})();
