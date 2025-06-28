// Frida script to extract camera state from sub_147097AF0
// Hooks the function once to get the camera state pointer,
// then uses it to calculate camera orientation and position in real-time

(function() {
    'use strict';

    // Configuration - adjust based on your target
    const config = {
        // Module containing target function (set to null for auto-detection)
        moduleName: null,

        // Offset of sub_147097AF0 within module
        functionOffset: "0x147097AF0",

        // Update interval for camera state calculation (ms)
        updateInterval: 100,

        // Camera state structure offsets from decompiled code
        offsets: {
            // Camera data pointer base (pCameraState + 0x9A*8)
            cameraDataBase: 0x9A * 8,

            // Rotation value offsets (relative to pCameraState)
            rotation: {
                xmm0: 0xA2 * 8, // pitch related
                xmm7: 0x9E * 8, // roll related
                xmm8: 0x9F * 8, // roll related
                xmm10: 0x9B * 8,
                xmm11: 0xA3 * 8, // yaw related
                xmm12: 0xA4 * 8  // yaw related
            },

            // Position offsets (relative to pCameraData)
            position: {
                x: 3 * 8,
                y: 7 * 8,
                z: 0xB * 8
            }
        }
    };

    // State variables
    let cameraStatePtr = null;
    let intervalId = null;
    let isHooked = false;

    // Constants
    const RAD_TO_DEG = 57.295776;

    // Calculate camera state from stored pointer
    function calculateCameraState() {
        if (!cameraStatePtr) {
            console.log("[!] Camera state pointer not extracted yet");
            return null;
        }

        try {
            // Extract camera data pointer
            const pCameraData = cameraStatePtr.add(config.offsets.cameraDataBase);

            // Read rotation values
            const xmm0Val = cameraStatePtr.add(config.offsets.rotation.xmm0).readDouble();
            const xmm7Val = cameraStatePtr.add(config.offsets.rotation.xmm7).readDouble();
            const xmm8Val = cameraStatePtr.add(config.offsets.rotation.xmm8).readDouble();
            const xmm10Val = cameraStatePtr.add(config.offsets.rotation.xmm10).readDouble();
            const xmm11Val = cameraStatePtr.add(config.offsets.rotation.xmm11).readDouble();
            const xmm12Val = cameraStatePtr.add(config.offsets.rotation.xmm12).readDouble();

            // Convert to float as per original code
            const xmm0Float = Math.fround(xmm0Val);
            const xmm7Float = Math.fround(xmm7Val);
            const xmm8Float = Math.fround(xmm8Val);
            const xmm10Float = Math.fround(xmm10Val);
            const xmm11Float = Math.fround(xmm11Val);
            const xmm12Float = Math.fround(xmm12Val);

            // Calculate pitch angle
            // Original code: negate xmm0, clamp between -1 and 1, then asin
            const xmm1 = -xmm0Float;  // Negate (equivalent to XOR with sign bit)
            const xmm4 = Math.max(Math.min(xmm1, 1.0), -1.0); // Clamp
            const pitchRad = Math.asin(xmm4);

            // Calculate yaw angle
            // Check if we're not at the poles (pitch ~= ±90°)
            let yawRad = 0;
            if (Math.abs(Math.abs(pitchRad) - 1.5707964) >= 0.0099999998) {
                // Not at poles, use arctan2
                yawRad = Math.atan2(xmm11Float, xmm12Float);
            }

            // Calculate roll angle
            const rollRad = Math.atan2(xmm7Float, Math.fround(xmm8Val));

            // Convert angles to degrees
            const pitchDeg = pitchRad * RAD_TO_DEG;
            const yawDeg = yawRad * RAD_TO_DEG;
            const rollDeg = rollRad * RAD_TO_DEG;

            // Read position values
            const posX = pCameraData.add(config.offsets.position.x).readDouble();
            const posY = pCameraData.add(config.offsets.position.y).readDouble();
            const posZ = pCameraData.add(config.offsets.position.z).readDouble();

            return {
                position: { x: posX, y: posY, z: posZ },
                rotation: { pitch: pitchDeg, yaw: yawDeg, roll: rollDeg },
                timestamp: Date.now()
            };
        } catch (e) {
            console.error(`[-] Error calculating camera state: ${e.message}`);
            return null;
        }
    }

    // Start periodic monitoring
    function startMonitoring(intervalMs) {
        intervalMs = intervalMs || config.updateInterval;

        if (intervalId) {
            clearInterval(intervalId);
        }

        intervalId = setInterval(() => {
            try {
                const state = calculateCameraState();
                if (state) {
                    console.log(
                        `[+] Pos: (${state.position.x.toFixed(2)}, ${state.position.y.toFixed(2)}, ${state.position.z.toFixed(2)}) | ` +
                        `Rot: Pitch=${state.rotation.pitch.toFixed(1)}°, Yaw=${state.rotation.yaw.toFixed(1)}°, Roll=${state.rotation.roll.toFixed(1)}°`
                    );
                }
            } catch (e) {
                console.error(`[-] Monitoring error: ${e.message}`);
            }
        }, intervalMs);

        console.log(`[*] Monitoring camera state every ${intervalMs}ms`);
    }

    // Stop monitoring
    function stopMonitoring() {
        if (intervalId) {
            clearInterval(intervalId);
            intervalId = null;
            console.log("[*] Camera monitoring stopped");
        }
    }

    // Hook the camera function
    function hookCameraFunction() {
        if (isHooked) {
            console.log("[!] Camera function already hooked");
            return;
        }

        try {
            const targetFunc = ptr(config.functionOffset);
            console.log(`[*] Hooking camera function at ${targetFunc}`);
            if (!targetFunc) return;

            const x = Interceptor.attach(targetFunc, {
                onEnter: function(args) {
                    // Extract camera state pointer from first argument
                    cameraStatePtr = args[0];
                    console.log(`[+] Captured camera state pointer: ${cameraStatePtr}`);

                    // Calculate initial state
                    const initialState = calculateCameraState();
                    if (initialState) {
                        console.log("[+] Initial camera state captured");
                        console.log(
                            `[+] Pos: (${initialState.position.x.toFixed(2)}, ${initialState.position.y.toFixed(2)}, ${initialState.position.z.toFixed(2)}) | ` +
                            `Rot: Pitch=${initialState.rotation.pitch.toFixed(1)}°, Yaw=${initialState.rotation.yaw.toFixed(1)}°, Roll=${initialState.rotation.roll.toFixed(1)}°`
                        );
                    }

                    // Start monitoring if not already running
                    if (!intervalId) {
                        x.detach();

                        startMonitoring();
                    }
                }
            });

            isHooked = true;
            console.log("[+] Successfully hooked camera function");
        } catch (e) {
            console.error(`[-] Failed to hook camera function: ${e.message}`);
        }
    }

    // Export functions for REPL/Python use
    rpc.exports = {
        hook: hookCameraFunction,
        start: startMonitoring,
        stop: stopMonitoring,
        getState: calculateCameraState,

        // Configuration functions
        setUpdateInterval: function(ms) {
            config.updateInterval = ms;
            if (intervalId) {
                stopMonitoring();
                startMonitoring(ms);
            }
            return true;
        },

        setModuleName: function(name) {
            config.moduleName = name;
            return true;
        },

        setFunctionOffset: function(offset) {
            config.functionOffset = offset;
            return true;
        },

        // Utility to dump memory around camera state for debugging
        dumpCameraState: function(size) {
            if (!cameraStatePtr) return "Camera state pointer not available";
            size = size || 0x200;
            return hexdump(cameraStatePtr, { length: size, header: true });
        }
    };

    // Auto-start when script is loaded
    hookCameraFunction();
})();
