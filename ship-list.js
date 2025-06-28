/**
 * Enhanced Ship Data Extraction and Analysis Framework v2.2
 *
 * This instrumentation script implements systematic interception and analysis
 * of the ship list provider subsystem with corrected memory access patterns,
 * proper state management, and robust error handling mechanisms.
 *
 * Revision History:
 * v2.2 - Added more robust checks in vector analysis before calculating size/count.
 *        Wrapped Statistics.printSummary in try-catch as a temporary measure.
 *        Ensured consistent string keying for HookState.
 * v2.1 - Corrected pointer dereferencing for global context and vector structures.
 *        Improved safety checks in utility functions.
 * v2.0 - Addressed execution failures through architectural refinements
 * v1.0 - Initial implementation
 *
 * Target Architecture: x64 Windows
 * Frida Version Compatibility: 16.x+
 */

'use strict';

// Global Configuration Parameters
const CONFIG = {
    // Memory analysis parameters
    MAX_STRING_LENGTH: 256,
    MAX_HEX_DUMP_SIZE: 512,
    SHIP_ENTITLEMENT_SIZE: 0xB0,
    SHIP_DATA_SIZE: 0x70,
    SHIP_DATA_EXTENDED_SIZE: 0x88,
    PLAYER_ID_OFFSET: 0xC10,

    // Feature toggles
    ENABLE_VERBOSE_LOGGING: true,
    ENABLE_HEX_DUMPS: true,
    ENABLE_STRUCTURE_ANALYSIS: true,
    ENABLE_TELEMETRY_MONITORING: true,
    ENABLE_CALL_STACK_ANALYSIS: false,
    ENABLE_SAFE_MODE: true,

    TARGET_FUNCTIONS: {
        HandleFetchShipDataResult: ptr('0x1454048C0'),
        ProcessFetchedShipEntitlements: ptr('0x145413B20'),
        ProcessFetchedShipData: ptr('0x14542ABD0'),
        GetPlayerIdFromContext: ptr('0x1464E7490'),
        ReportTelemetryEvent: ptr('0x1403045C0')
    },
    GLOBAL_CONTEXT_PTR: ptr('0x149E7E438')
};

const HookState = {
    contexts: new Map(),
    store: function(hookIdString, key, value) {
        if (!this.contexts.has(hookIdString)) {
            this.contexts.set(hookIdString, {});
        }
        this.contexts.get(hookIdString)[key] = value;
    },
    retrieve: function(hookIdString, key) {
        const context = this.contexts.get(hookIdString);
        return context ? context[key] : undefined;
    },
    clear: function(hookIdString) {
        this.contexts.delete(hookIdString);
    }
};

const Utils = {
    readCString: function(ptr, maxLength = CONFIG.MAX_STRING_LENGTH) {
        if (!ptr || ptr.isNull()) return '[NULL_POINTER]';
        try {
            ptr.readU8();
            const str = ptr.readCString(maxLength);
            if (str === null) return '[READ_AS_NULL_STRING]';
            if (str.length === 0) return '';
            if (/^[\x20-\x7E\s]*$/.test(str)) return str;
            return '[INVALID_STRING_CONTENT]';
        } catch (e) { return `[READ_ERROR: ${e.message}]`; }
    },
    readPointerValueAt: function(ptrAddress) {
        if (!ptrAddress || ptrAddress.isNull()) return NULL;
        try {
            const value = ptrAddress.readPointer();
            if (value.isNull()) return NULL;
            const upperLimit = Process.pointerSize === 8 ? ptr('0x7FFFFFFFFFFF') : ptr('0xD0000000');
            if (value.compare(ptr('0x1000')) >= 0 && value.compare(upperLimit) < 0) return value;
            if (CONFIG.ENABLE_VERBOSE_LOGGING) console.log(`[WARN] Utils.readPointerValueAt: Read pointer ${value} from ${ptrAddress} is outside typical user-space range.`);
            return value;
        } catch (e) {
            if (CONFIG.ENABLE_VERBOSE_LOGGING) console.log(`[WARN] Utils.readPointerValueAt: Pointer read failed at ${ptrAddress}: ${e.message}`);
            return NULL;
        }
    },
    readInteger: function(ptr, size = 4, signed = false) {
        if (!ptr || ptr.isNull()) return size === 8 ? (signed ? int64(0) : uint64(0)) : 0;
        try {
            switch (size) {
                case 1: return signed ? ptr.readS8() : ptr.readU8();
                case 2: return signed ? ptr.readS16() : ptr.readU16();
                case 4: return signed ? ptr.readS32() : ptr.readU32();
                case 8: return signed ? ptr.readS64() : ptr.readU64();
                default: return size === 8 ? (signed ? int64(0) : uint64(0)) : 0;
            }
        } catch (e) {
            if (CONFIG.ENABLE_VERBOSE_LOGGING) console.log(`[WARN] Utils.readInteger: Integer read failed at ${ptr} (size ${size}): ${e.message}`);
            return size === 8 ? (signed ? int64(0) : uint64(0)) : 0;
        }
    },
    readByteArray: function(ptr, size) {
        if (!ptr || ptr.isNull() || size <= 0) return null;
        try { return ptr.readByteArray(size); }
        catch (e) {
            if (CONFIG.ENABLE_VERBOSE_LOGGING) console.log(`[WARN] Utils.readByteArray: Byte array read failed at ${ptr} (size ${size}): ${e.message}`);
            return null;
        }
    },
    generateHexDump: function(ptr, size, description = '') {
        if (!CONFIG.ENABLE_HEX_DUMPS || !ptr || ptr.isNull() || size <= 0) return;
        try {
            const actualSize = Math.min(size, CONFIG.MAX_HEX_DUMP_SIZE);
            const data = this.readByteArray(ptr, actualSize);
            if (data) {
                console.log(`\n[HEX_DUMP] ${description}`);
                console.log(`[HEX_DUMP] Address: ${ptr}, Size: ${size} bytes (displaying ${actualSize})`);
                console.log(hexdump(data, { offset: 0, length: actualSize, header: true, ansi: true }));
                if (size > actualSize) console.log(`[HEX_DUMP] Truncated: ${size - actualSize} bytes omitted`);
            } else { console.log(`[HEX_DUMP] Failed to read data for ${description} at ${ptr}`); }
        } catch (e) { console.log(`[ERROR] Hex dump generation failed for ${description} at ${ptr}: ${e.message}`); }
    },
    extractPlayerId: function() {
        try {
            const globalContextBase = CONFIG.GLOBAL_CONTEXT_PTR;
            if (globalContextBase.isNull()) return 'GLOBAL_CONTEXT_CONFIG_NULL';
            if (!Utils.isMemoryAccessible(globalContextBase, CONFIG.PLAYER_ID_OFFSET + 8)) {
                 if (CONFIG.ENABLE_VERBOSE_LOGGING) console.log(`[WARN] Global context base ${globalContextBase} or Player ID offset ${CONFIG.PLAYER_ID_OFFSET} seems inaccessible.`);
                 return 'GLOBAL_CONTEXT_INACCESSIBLE';
            }
            const playerIdPtr = globalContextBase.add(CONFIG.PLAYER_ID_OFFSET);
            const playerId = this.readInteger(playerIdPtr, 8, false);
            if (playerId.equals(uint64(0))) return 'NO_PLAYER_ID_VALUE';
            return playerId.toString();
        } catch (e) {
            if (CONFIG.ENABLE_VERBOSE_LOGGING) console.log(`[ERROR] Player ID extraction failed: ${e.message}`);
            return 'EXTRACTION_ERROR';
        }
    },
    getTimestamp: function() { return new Date().toISOString(); },
    isMemoryAccessible: function(ptr, size) {
        if (!ptr || ptr.isNull() || size <= 0) return false;
        try {
            const range = Process.findRangeByAddress(ptr);
            if (!range) {
                if(CONFIG.ENABLE_VERBOSE_LOGGING) console.log(`[isMemoryAccessible] No range found for ${ptr}`);
                return false;
            }
            if (!range.protection.startsWith('r')) {
                if(CONFIG.ENABLE_VERBOSE_LOGGING) console.log(`[isMemoryAccessible] Range for ${ptr} not readable (prot: ${range.protection})`);
                return false;
            }
            const endPtr = ptr.add(size);
            const rangeEndPtr = range.base.add(range.size);
            if (endPtr.compare(rangeEndPtr) > 0) {
                 if(CONFIG.ENABLE_VERBOSE_LOGGING) console.log(`[isMemoryAccessible] Requested size ${size} for ${ptr} (ends at ${endPtr}) exceeds found range [${range.base} - ${rangeEndPtr}]`);
                return false;
            }
            return true;
        } catch (e) {
            if(CONFIG.ENABLE_VERBOSE_LOGGING) console.log(`[isMemoryAccessible] Error checking ${ptr}: ${e.message}`);
            return false;
        }
    }
};

const ShipDataAnalyzer = {
    analyzeShipEntitlements: function(entitlementsListBasePtr) {
        if (!entitlementsListBasePtr || entitlementsListBasePtr.isNull()) {
            console.log('[SHIP_ENTITLEMENTS] Null pointer provided for list base');
            return;
        }
        try {
            console.log(`\n${'='.repeat(80)}`);
            console.log(`[SHIP_ENTITLEMENTS] Analysis initiated at ${Utils.getTimestamp()}`);
            console.log(`[SHIP_ENTITLEMENTS] Player ID: ${Utils.extractPlayerId()}`);
            console.log(`[SHIP_ENTITLEMENTS] List structure base address: ${entitlementsListBasePtr}`);

            const beginPtr = Utils.readPointerValueAt(entitlementsListBasePtr);
            const endPtr = Utils.readPointerValueAt(entitlementsListBasePtr.add(Process.pointerSize));

            if (beginPtr.isNull()) {
                console.log('[SHIP_ENTITLEMENTS] Invalid list structure - _Myfirst (beginPtr) is NULL.');
                Utils.generateHexDump(entitlementsListBasePtr, Process.pointerSize * 3, 'Entitlements List Structure (Pointers)');
                return;
            }
            if (endPtr.isNull() || endPtr.compare(beginPtr) < 0) {
                 console.log(`[SHIP_ENTITLEMENTS] Invalid list structure - _Mylast (endPtr: ${endPtr}) is problematic relative to _Myfirst (beginPtr: ${beginPtr}).`);
                 Utils.generateHexDump(entitlementsListBasePtr, Process.pointerSize * 3, 'Entitlements List Structure (Pointers)');
                 return;
            }

            // Crucial check: Is the memory pointed to by beginPtr actually accessible for at least one element?
            if (!Utils.isMemoryAccessible(beginPtr, CONFIG.SHIP_ENTITLEMENT_SIZE > 0 ? CONFIG.SHIP_ENTITLEMENT_SIZE : Process.pointerSize)) {
                console.log(`[SHIP_ENTITLEMENTS] Memory at beginPtr ${beginPtr} is not accessible for even one element. Aborting.`);
                Utils.generateHexDump(beginPtr, 64, 'Inaccessible beginPtr Content'); // Dump a bit of where it points
                return;
            }

            const totalSize = endPtr.sub(beginPtr).toInt32();
            if (totalSize < 0 || totalSize > 0x1000000) {
                console.log(`[SHIP_ENTITLEMENTS] Unreasonable total size detected: ${totalSize}`);
                return;
            }
            if (totalSize === 0) {
                console.log(`[SHIP_ENTITLEMENTS] List is empty (totalSize is 0).`);
                return;
            }

            const entitlementCount = Math.floor(totalSize / CONFIG.SHIP_ENTITLEMENT_SIZE);
            console.log(`[SHIP_ENTITLEMENTS] Memory range of elements: ${beginPtr} - ${endPtr}`);
            console.log(`[SHIP_ENTITLEMENTS] Total element data size: ${totalSize} bytes`);
            console.log(`[SHIP_ENTITLEMENTS] Deduced entry count: ${entitlementCount}`);
            console.log(`[SHIP_ENTITLEMENTS] Assumed entry size: ${CONFIG.SHIP_ENTITLEMENT_SIZE} bytes`);

            if (entitlementCount === 0 && totalSize > 0) {
                console.log(`[SHIP_ENTITLEMENTS] Warning: totalSize > 0 but entitlementCount is 0. Entry size might be incorrect or list is malformed.`);
                if (Utils.isMemoryAccessible(beginPtr, Math.min(totalSize, 256))) {
                    Utils.generateHexDump(beginPtr, Math.min(totalSize, 256), 'Raw Entitlement Data (First 256 bytes)');
                }
                return;
            }
            if (entitlementCount > 10000) {
                console.log(`[SHIP_ENTITLEMENTS] Warning: Unusually high number of entitlements (${entitlementCount}). Aborting detailed analysis.`);
                return;
            }
            
            // Check accessibility of the entire data block if count > 0
            if (entitlementCount > 0 && !Utils.isMemoryAccessible(beginPtr, totalSize)) {
                console.log(`[SHIP_ENTITLEMENTS] Element memory range [${beginPtr} - ${beginPtr.add(totalSize)}] not fully accessible. Analyzing accessible parts only.`);
            }

            for (let i = 0; i < Math.min(entitlementCount, 10); i++) {
                const elementPtr = beginPtr.add(i * CONFIG.SHIP_ENTITLEMENT_SIZE);
                if (Utils.isMemoryAccessible(elementPtr, CONFIG.SHIP_ENTITLEMENT_SIZE)) {
                    this.analyzeShipEntitlement(elementPtr, i);
                } else {
                    console.log(`[SHIP_ENTITLEMENTS] Element ${i} at ${elementPtr} (offset 0x${(i * CONFIG.SHIP_ENTITLEMENT_SIZE).toString(16)}) is not accessible.`);
                    if (i === 0) {
                        console.log(`[SHIP_ENTITLEMENTS] First element inaccessible, aborting list analysis.`);
                        break; 
                    }
                }
            }
            if (entitlementCount > 10) {
                console.log(`[SHIP_ENTITLEMENTS] ... and ${entitlementCount - 10} more entries`);
            }
        } catch (e) {
            console.log(`[ERROR] Ship entitlements analysis failed: ${e.message}\n${e.stack}`);
        }
    },
    analyzeShipEntitlement: function(entitlementPtr, index) {
        try {
            console.log(`\n[ENTITLEMENT_${index}] Address: ${entitlementPtr}`);
            const id1 = Utils.readInteger(entitlementPtr.add(0x00), 8, false);
            console.log(`[ENTITLEMENT_${index}] Primary ID: 0x${id1.toString(16).padStart(16, '0')}`);
            // ... (Add more field reads as per structure)
            if (CONFIG.ENABLE_HEX_DUMPS && index < 3) {
                Utils.generateHexDump(entitlementPtr, CONFIG.SHIP_ENTITLEMENT_SIZE, `Entitlement ${index} Structure`);
            }
        } catch(e) { console.log(`[ERROR] Entitlement ${index} analysis failed: ${e.message}`); }
    },
    analyzeShipDataList: function(shipDataListBasePtr) {
        if (!shipDataListBasePtr || shipDataListBasePtr.isNull()) {
            console.log('[SHIP_DATA] Null pointer provided for list base');
            return;
        }
        try {
            console.log(`\n${'='.repeat(80)}`);
            console.log(`[SHIP_DATA] Analysis initiated at ${Utils.getTimestamp()}`);
            console.log(`[SHIP_DATA] Player ID: ${Utils.extractPlayerId()}`);
            console.log(`[SHIP_DATA] List structure base address: ${shipDataListBasePtr}`);

            const beginPtr = Utils.readPointerValueAt(shipDataListBasePtr);
            const endPtr = Utils.readPointerValueAt(shipDataListBasePtr.add(Process.pointerSize));

            if (beginPtr.isNull()) {
                console.log('[SHIP_DATA] Invalid list structure - _Myfirst (beginPtr) is NULL.');
                Utils.generateHexDump(shipDataListBasePtr, Process.pointerSize * 3, 'Ship Data List Structure (Pointers)');
                return;
            }
            if (endPtr.isNull() || endPtr.compare(beginPtr) < 0) {
                 console.log(`[SHIP_DATA] Invalid list structure - _Mylast (endPtr: ${endPtr}) is problematic relative to _Myfirst (beginPtr: ${beginPtr}).`);
                 Utils.generateHexDump(shipDataListBasePtr, Process.pointerSize * 3, 'Ship Data List Structure (Pointers)');
                 return;
            }
            
            if (!Utils.isMemoryAccessible(beginPtr, CONFIG.SHIP_DATA_SIZE > 0 ? CONFIG.SHIP_DATA_SIZE : Process.pointerSize)) {
                console.log(`[SHIP_DATA] Memory at beginPtr ${beginPtr} is not accessible for even one element. Aborting.`);
                Utils.generateHexDump(beginPtr, 64, 'Inaccessible beginPtr Content');
                return;
            }

            const totalSize = endPtr.sub(beginPtr).toInt32();
            if (totalSize < 0 || totalSize > 0x1000000) {
                console.log(`[SHIP_DATA] Unreasonable total size: ${totalSize}`);
                return;
            }
            if (totalSize === 0) {
                console.log(`[SHIP_DATA] List is empty (totalSize is 0).`);
                return;
            }

            const shipCount = Math.floor(totalSize / CONFIG.SHIP_DATA_SIZE);
            console.log(`[SHIP_DATA] Memory range of elements: ${beginPtr} - ${endPtr}`);
            console.log(`[SHIP_DATA] Total element data size: ${totalSize} bytes`);
            console.log(`[SHIP_DATA] Deduced ship count: ${shipCount}`);
            console.log(`[SHIP_DATA] Assumed ship data size: ${CONFIG.SHIP_DATA_SIZE} bytes`);

            if (shipCount === 0 && totalSize > 0) {
                console.log(`[SHIP_DATA] Warning: totalSize > 0 but shipCount is 0. Entry size might be incorrect or list is malformed.`);
                if(Utils.isMemoryAccessible(beginPtr, Math.min(totalSize, 256))) {
                    Utils.generateHexDump(beginPtr, Math.min(totalSize, 256), 'Raw Ship Data (First 256 bytes)');
                }
                return;
            }
            if (shipCount > 10000) {
                console.log(`[SHIP_DATA] Warning: Unusually high number of ships (${shipCount}). Aborting detailed analysis.`);
                return;
            }

            if (shipCount > 0 && !Utils.isMemoryAccessible(beginPtr, totalSize)) {
                console.log(`[SHIP_DATA] Element memory range [${beginPtr} - ${beginPtr.add(totalSize)}] not fully accessible. Analyzing accessible parts only.`);
            }

            for (let i = 0; i < Math.min(shipCount, 10); i++) {
                const elementPtr = beginPtr.add(i * CONFIG.SHIP_DATA_SIZE);
                if (Utils.isMemoryAccessible(elementPtr, CONFIG.SHIP_DATA_SIZE)) {
                    this.analyzeShipData(elementPtr, i);
                } else {
                    console.log(`[SHIP_DATA] Element ${i} at ${elementPtr} (offset 0x${(i * CONFIG.SHIP_DATA_SIZE).toString(16)}) is not accessible.`);
                     if (i === 0) {
                        console.log(`[SHIP_DATA] First element inaccessible, aborting list analysis.`);
                        break;
                    }
                }
            }
            if (shipCount > 10) {
                console.log(`[SHIP_DATA] ... and ${shipCount - 10} more ships`);
            }
        } catch (e) {
            console.log(`[ERROR] Ship data analysis failed: ${e.message}\n${e.stack}`);
        }
    },
    analyzeShipData: function(shipPtr, index) {
        try {
            console.log(`\n[SHIP_${index}] Address: ${shipPtr}`);
            const shipId = Utils.readInteger(shipPtr.add(0x00), 8, false);
            console.log(`[SHIP_${index}] ID: 0x${shipId.toString(16).padStart(16, '0')}`);
            // ... (Add more field reads as per structure)
            if (CONFIG.ENABLE_HEX_DUMPS && index < 3) {
                Utils.generateHexDump(shipPtr, CONFIG.SHIP_DATA_SIZE, `Ship ${index} Structure`);
            }
        } catch(e) { console.log(`[ERROR] Ship ${index} analysis failed: ${e.message}`); }
    },
    extractStringsFromStructure: function(structPtr, structSize) { return []; },
    interpretFlags: (flags) => flags.toString(),
    interpretStatus: (status) => status.toString(),
    interpretEntitlementType: (type) => type.toString(),
    interpretShipType: (type) => type.toString(),
    interpretShipStatus: (status) => status.toString(),
    interpretShipClass: (shipClass) => shipClass.toString(),
    interpretTimestamp: (timestamp) => timestamp.toString()
};

const HookManager = {
    activeHooks: [],
    installHooks: function() {
        console.log(`\n[HOOK_MANAGER] Installing hooks at ${Utils.getTimestamp()}`);
        this.verifyTargetFunctions();
        this.hookHandleFetchShipDataResult();
        this.hookProcessFetchedShipEntitlements();
        this.hookProcessFetchedShipData();
        if (CONFIG.ENABLE_TELEMETRY_MONITORING) this.hookReportTelemetryEvent();
        console.log(`[HOOK_MANAGER] ${this.activeHooks.length} hooks installed successfully`);
    },
    verifyTargetFunctions: function() {
        for (const [name, addr] of Object.entries(CONFIG.TARGET_FUNCTIONS)) {
            try {
                if (addr.isNull()) { console.log(`[WARNING] ${name}: Address is NULL.`); continue; }
                const range = Process.findRangeByAddress(addr);
                if (range && range.protection.includes('x')) {
                    console.log(`[VERIFY] ${name}: ${addr} in ${range.file ? range.file.path : 'dynamically allocated or unknown module'} (Protection: ${range.protection})`);
                } else {
                    console.log(`[WARNING] ${name}: ${addr} not in any mapped executable range. Found: ${range ? JSON.stringify(range) : 'None'}`);
                }
            } catch (e) { console.log(`[ERROR] Failed to verify ${name} at ${addr}: ${e.message}`); }
        }
    },
    hookHandleFetchShipDataResult: function() {
        const funcAddr = CONFIG.TARGET_FUNCTIONS.HandleFetchShipDataResult;
        if (funcAddr.isNull()) { console.log('[ERROR] HandleFetchShipDataResult address is NULL. Skipping hook.'); return; }
        try {
            const hook = Interceptor.attach(funcAddr, {
                onEnter: function(args) {
                    const hookId = `${funcAddr.toString()}-${Process.getCurrentThreadId()}`;
                    HookState.store(hookId, 'enterTime', Date.now());
                    console.log(`\n${'='.repeat(100)}`);
                    console.log(`[HOOK] HandleFetchShipDataResult ENTER at ${Utils.getTimestamp()}`);
                    console.log(`[HOOK] Player ID: ${Utils.extractPlayerId()}`);
                    console.log(`[HOOK] Arg0 (operationHandle*): ${args[0]}`);
                    console.log(`[HOOK] Arg1 (operationResult*): ${args[1]}`);

                    if (!args[0].isNull()) {
                        Utils.generateHexDump(args[0], 32, 'Arg0 (operationHandle*) Content');
                        const operationHandleValue = Utils.readPointerValueAt(args[0]);
                        console.log(`[HOOK]   Dereferenced Operation Handle: ${operationHandleValue}`);
                        if(!operationHandleValue.isNull()) Utils.generateHexDump(operationHandleValue, 32, 'Operation Handle Actual Structure');
                    }
                    if (!args[1].isNull()) {
                        Utils.generateHexDump(args[1], 64, 'Arg1 (operationResult*) Content');
                        try {
                            const resultType = Utils.readInteger(args[1], 1);
                            console.log(`[OPERATION_RESULT] Type Byte: ${resultType} (${resultType === 1 ? 'SUCCESS' : 'FAILURE'})`);
                            if (resultType === 1) {
                                const dataVectorBasePtr = args[1].add(8); // This is the std::vector object itself
                                console.log(`[OPERATION_RESULT] Success data (std::vector base) at: ${dataVectorBasePtr}`);
                                ShipDataAnalyzer.analyzeShipEntitlements(dataVectorBasePtr);
                            }
                        } catch (e) { console.log(`[OPERATION_RESULT] Failed to analyze result structure: ${e.message}\n${e.stack}`); }
                    }
                },
                onLeave: function(retval) {
                    const hookId = `${funcAddr.toString()}-${Process.getCurrentThreadId()}`;
                    const enterTime = HookState.retrieve(hookId, 'enterTime');
                    const duration = enterTime ? Date.now() - enterTime : 0;
                    console.log(`[HOOK] HandleFetchShipDataResult EXIT (Duration: ${duration}ms)`);
                    console.log(`${'='.repeat(100)}\n`);
                    HookState.clear(hookId);
                }
            });
            this.activeHooks.push({ name: 'HandleFetchShipDataResult', hook: hook });
            console.log('[HOOK_MANAGER] Successfully hooked HandleFetchShipDataResult');
        } catch (e) { console.log(`[ERROR] Failed to hook HandleFetchShipDataResult: ${e.message}\n${e.stack}`); }
    },
    hookProcessFetchedShipEntitlements: function() {
        const funcAddr = CONFIG.TARGET_FUNCTIONS.ProcessFetchedShipEntitlements;
        if (funcAddr.isNull()) { console.log('[ERROR] ProcessFetchedShipEntitlements address is NULL. Skipping hook.'); return; }
        try {
            Interceptor.attach(funcAddr, {
                onEnter: function(args) {
                    console.log(`\n${'='.repeat(100)}`);
                    console.log(`[HOOK] ProcessFetchedShipEntitlements ENTER at ${Utils.getTimestamp()}`);
                    console.log(`[HOOK] Player ID: ${Utils.extractPlayerId()}`);
                    console.log(`[HOOK] Arg0 (shipDataProviderContext): ${args[0]}`);
                    console.log(`[HOOK] Arg2 (entitlementsList* - std::vector base): ${args[2]}`);
                    if (!args[2].isNull()) ShipDataAnalyzer.analyzeShipEntitlements(args[2]);
                },
                onLeave: function(retval) {
                    console.log(`[HOOK] ProcessFetchedShipEntitlements EXIT`);
                    console.log(`${'='.repeat(100)}\n`);
                }
            });
            this.activeHooks.push({ name: 'ProcessFetchedShipEntitlements', hook: {} });
            console.log('[HOOK_MANAGER] Successfully hooked ProcessFetchedShipEntitlements');
        } catch (e) { console.log(`[ERROR] Failed to hook ProcessFetchedShipEntitlements: ${e.message}\n${e.stack}`); }
    },
    hookProcessFetchedShipData: function() {
        const funcAddr = CONFIG.TARGET_FUNCTIONS.ProcessFetchedShipData;
        if (funcAddr.isNull()) { console.log('[ERROR] ProcessFetchedShipData address is NULL. Skipping hook.'); return; }
        try {
            Interceptor.attach(funcAddr, {
                onEnter: function(args) {
                    console.log(`\n${'='.repeat(100)}`);
                    console.log(`[HOOK] ProcessFetchedShipData ENTER at ${Utils.getTimestamp()}`);
                    console.log(`[HOOK] Player ID: ${Utils.extractPlayerId()}`);
                    console.log(`[HOOK] Arg0 (shipDataProviderContext): ${args[0]}`);
                    console.log(`[HOOK] Arg1 (fetchedShipDataList* - std::vector base): ${args[1]}`);
                    if (!args[1].isNull()) ShipDataAnalyzer.analyzeShipDataList(args[1]);
                },
                onLeave: function(retval) {
                    console.log(`[HOOK] ProcessFetchedShipData EXIT - Return: ${retval}`);
                    console.log(`${'='.repeat(100)}\n`);
                }
            });
            this.activeHooks.push({ name: 'ProcessFetchedShipData', hook: {} });
            console.log('[HOOK_MANAGER] Successfully hooked ProcessFetchedShipData');
        } catch (e) { console.log(`[ERROR] Failed to hook ProcessFetchedShipData: ${e.message}\n${e.stack}`); }
    },
    hookReportTelemetryEvent: function() {
        const funcAddr = CONFIG.TARGET_FUNCTIONS.ReportTelemetryEvent;
        if (funcAddr.isNull()) { console.log('[ERROR] ReportTelemetryEvent address is NULL. Skipping hook.'); return; }
        try {
            const range = Process.findRangeByAddress(funcAddr);
            if (!range || !range.protection.includes('x')) {
                console.log(`[WARNING] ReportTelemetryEvent at ${funcAddr} is not executable (Protection: ${range ? range.protection : 'N/A'}). Skipping hook.`);
                return;
            }
        } catch(e) {
            console.log(`[WARNING] Could not verify ReportTelemetryEvent address ${funcAddr}. Skipping hook. Error: ${e.message}`);
            return;
        }
        try {
            Interceptor.attach(funcAddr, {
                onEnter: function(args) {
                    try {
                        const messageStr = args[2].readCString();
                        const sourceStr = args[3].readCString();
                        if (messageStr && sourceStr && (messageStr.toLowerCase().includes('ship') || messageStr.toLowerCase().includes('entitle') || sourceStr.toLowerCase().includes('ship'))) {
                            console.log(`\n[TELEMETRY] Ship-related event captured at ${Utils.getTimestamp()}`);
                            console.log(`[TELEMETRY] Log Level: ${args[0].toInt32()}`);
                            console.log(`[TELEMETRY] Message Format: "${messageStr}"`);
                            console.log(`[TELEMETRY] Source: "${sourceStr}"`);
                        }
                    } catch (e) { /* Silently ignore */ }
                }
            });
            this.activeHooks.push({ name: 'ReportTelemetryEvent', hook: {} });
            console.log('[HOOK_MANAGER] Successfully hooked ReportTelemetryEvent');
        } catch (e) { console.log(`[ERROR] Failed to hook ReportTelemetryEvent: ${e.message}\n${e.stack}`); }
    },
    removeAllHooks: function() { /* ... */ }
};

const Statistics = {
    playerIdsSeen: new Set(), shipIdsSeen: new Set(), entitlementIdsSeen: new Set(),
    eventCount: 0, errorCount: 0, startTime: Date.now(),
    update: function(type, id) {
        switch (type) {
            case 'player': this.playerIdsSeen.add(id); break;
            case 'ship': this.shipIdsSeen.add(id); break;
            case 'entitlement': this.entitlementIdsSeen.add(id); break;
            case 'error': this.errorCount++; break;
        }
        this.eventCount++;
    },
    printSummary: function() {
        try { // Added try-catch here
            const runtime = (Date.now() - this.startTime) / 1000;
            console.log(`\n${'='.repeat(80)}`);
            console.log('[STATISTICS] Session Summary');
            console.log(`[STATISTICS] Runtime: ${runtime.toFixed(2)} seconds`);
            console.log(`[STATISTICS] Total events processed by hooks: ${this.eventCount}`);
            console.log(`[STATISTICS] Errors encountered by script: ${this.errorCount}`);
            console.log(`[STATISTICS] Unique players observed: ${this.playerIdsSeen.size}`);
            console.log(`[STATISTICS] Unique ships observed: ${this.shipIdsSeen.size}`);
            console.log(`[STATISTICS] Unique entitlements observed: ${this.entitlementIdsSeen.size}`);
            console.log(`${'='.repeat(80)}`);
        } catch (e) {
            console.log(`[ERROR] Statistics.printSummary failed: ${e.message}\n${e.stack}`);
        }
    }
};

function initialize() {
    console.log(`${'='.repeat(100)}`);
    console.log('ENHANCED SHIP DATA EXTRACTION FRAMEWORK v2.2');
    console.log(`Initialized at ${Utils.getTimestamp()}`);
    console.log(`Frida Version: ${Frida.version}`);
    console.log(`Script Runtime: ${Script.runtime}`);
    console.log(`Safe Mode: ${CONFIG.ENABLE_SAFE_MODE ? 'ENABLED' : 'DISABLED'}`);
    console.log(`${'='.repeat(100)}`);
    HookManager.installHooks();
    setInterval(() => { Statistics.printSummary(); }, 60000);
    Process.setExceptionHandler((details) => {
        console.log(`[EXCEPTION_HANDLER] Script exception caught at ${Utils.getTimestamp()}:`);
        console.log(`  Type: ${details.type}`);
        console.log(`  Address: ${details.address}`);
        console.log(`  Message: ${details.message}`);
        if (details.nativeContext) console.log(`  Native Context (RIP): ${details.nativeContext.rip}`);
        console.log(`  Frida Context: ${JSON.stringify(details.context)}`);
        if (details.error) console.log(`  Error Name: ${details.error.name}\n  Error Stack: \n${details.error.stack}`);
        Statistics.update('error', null);
        return false;
    });
    console.log('[MAIN] Enhanced ship data extraction framework initialized successfully');
    console.log('[MAIN] Monitoring ship operations...\n');
}

try { initialize(); }
catch(e) { console.log(`[FATAL_INIT_ERROR] ${e.message}\n${e.stack}`); }