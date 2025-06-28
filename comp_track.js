//centityx.js

//
// Frida script to mirror the game's C++ entity system in idiomatic JavaScript,
// providing rich, object-oriented wrappers around native memory structures.
// This version includes an advanced component usage and vtable tracking system.

"use strict";

// ==================================================================
// ===           CORE CLASSES AND HELPERS (UNCHANGED)             ===
// ==================================================================

const PTR_SIZE = Process.pointerSize;

function extractLower48(ptrVal) {
    return ptrVal.and(ptr("0xFFFFFFFFFFFF"));
}

function readCString(ptr) {
    return ptr.isNull() ? null : ptr.readUtf8String();
}

function callVFunc(thisPtr, index, returnType, argTypes, args = [], name = null) {
    try {
        if (thisPtr.isNull()) {
            throw new Error("Null pointer passed to callVFunc");
        }
        const vtable = thisPtr.readPointer();
        if (vtable.isNull()) {
            throw new Error("Null vtable pointer");
        }
        const fnPtr = vtable.add(index * PTR_SIZE).readPointer();
        if (fnPtr.isNull()) {
            throw new Error(`Null function pointer at vtable index ${index}`);
        }
        const fn = new NativeFunction(fnPtr, returnType, ["pointer", ...argTypes]);
        return fn(thisPtr, ...args);
    } catch (e) {
        console.log(`callVFunc error at index ${index}${name ? ` (${name})` : ''}: ${e.message}`);
        throw e;
    }
}

class DVec3 {
    constructor(x = 0, y = 0, z = 0) {
        this.x = x;
        this.y = y;
        this.z = z;
    }
}

class CEntityClass {
    constructor(ptr) {
        this.ptr = ptr;
    }
    get flags() {
        return this.ptr.add(0x08).readS64();
    }
    get name() {
        const namePtr = this.ptr.add(0x10).readPointer();
        return readCString(namePtr);
    }
}

class CEngineComponentScheduler {
    constructor(ptr) {
        this.ptr = ptr;
    }
    getComponentIdByName(componentName) {
        try {
            const componentIdPtr = Memory.alloc(2);
            const componentNamePtr = Memory.allocUtf8String(componentName);
            const result = callVFunc(this.ptr, 2, "pointer", ["pointer", "pointer"], [componentIdPtr, componentNamePtr]);
            const componentId = componentIdPtr.readU16();
            return { success: !result.isNull(), componentId: componentId };
        } catch (e) {
            return { success: false, componentId: 0 };
        }
    }
}

class IComponentRender {
    constructor(ptr) {
        this.ptr = ptr;
    }
    addGlow(glowParams, glowStyle = 0, slotIndex = -1) {
        const addGlowFuncAddr = Module.findBaseAddress("StarCitizen.exe").add(0x6A7D230);
        const addGlowFunc = new NativeFunction(addGlowFuncAddr, 'char', ['pointer', 'pointer', 'uint32', 'uint32']);
        const glowParamsPtr = Memory.alloc(16);
        glowParamsPtr.writeU8(glowParams.type || 1);
        glowParamsPtr.add(4).writeFloat(glowParams.r || 1.0);
        glowParamsPtr.add(8).writeFloat(glowParams.g || 1.0);
        glowParamsPtr.add(12).writeFloat(glowParams.b || 1.0);
        const nativeSlotIndex = (slotIndex === -1) ? 0xFFFFFFFF : slotIndex;
        return addGlowFunc(this.ptr, glowParamsPtr, glowStyle, nativeSlotIndex);
    }
}

class CRenderProxy {
    constructor(ptr) {
        this.ptr = ptr;
    }
    get renderHandlePtr() {
        return this.ptr.add(0x8);
    }
    get componentRender() {
        return new IComponentRender(this.ptr.add(0x78));
    }
}

class CEntity {
    constructor(ptr) {
        this.ptr = ptr;
    }
    get id() {
        return this.ptr.add(0x10).readS64();
    }
    get entityClassPtr() {
        return extractLower48(this.ptr.add(0x20).readPointer());
    }
    get entityClass() {
        const clsPtr = this.entityClassPtr;
        return clsPtr.isNull() ? null : new CEntityClass(clsPtr);
    }
    isHiddenOrDestroyed() {
        try {
            return callVFunc(this.ptr, 11, "bool", [], [], 'isHiddenOrDestroyed');
        } catch (e) { return true; }
    }
    getWorldPos(flags = 0) {
        try {
            const outPos = Memory.alloc(24);
            callVFunc(this.ptr, 89, "void", ["pointer", "uint32"], [outPos, flags]);
            return new DVec3(outPos.readDouble(), outPos.add(8).readDouble(), outPos.add(16).readDouble());
        } catch (e) {
            return new DVec3(this.ptr.add(0xF8).readDouble(), this.ptr.add(0x100).readDouble(), this.ptr.add(0x108).readDouble());
        }
    }
    getComponentAddrById(componentId) {
        try {
            const componentAddrPtr = Memory.alloc(PTR_SIZE);
            const componentIdPtr = Memory.alloc(2);
            componentIdPtr.writeU16(componentId);
            const result = callVFunc(this.ptr, 104, "pointer", ["pointer", "pointer"], [componentAddrPtr, componentIdPtr]);
            return { success: !result.isNull(), componentPtr: componentAddrPtr.readPointer() };
        } catch (e) {
            return { success: false, componentPtr: NULL };
        }
    }
    getComponentByName(componentName) {
        try {
            const scheduler = gEnv.engineComponentScheduler;
            if (!scheduler) return null;
            const idResult = scheduler.getComponentIdByName(componentName);
            if (!idResult.success || idResult.componentId === 0) return null;
            const componentResult = this.getComponentAddrById(idResult.componentId);
            return componentResult.success ? componentResult.componentPtr : null;
        } catch (e) {
            return null;
        }
    }
    get renderProxy() {
        const ptr = this.getComponentByName("RenderProxy");
        return ptr && !ptr.isNull() ? new CRenderProxy(ptr) : null;
    }
    addGlow(glowParams = { r: 1.0, g: 0.0, b: 0.0 }, slotIndex = -1, glowStyle = 0) {
        try {
            const pRenderProxy = this.renderProxy;
            if (!pRenderProxy) return;
            const isHandleValidFunc = new NativeFunction(Module.findBaseAddress("StarCitizen.exe").add(0x30EC00), 'bool', ['pointer']);
            if (!isHandleValidFunc(pRenderProxy.renderHandlePtr)) return;
            if (this.isHiddenOrDestroyed()) return;
            pRenderProxy.componentRender.addGlow(glowParams, glowStyle, slotIndex);
        } catch (e) {}
    }
}

class CEntityArray {
    constructor(ptr) {
        this.ptr = ptr;
    }
    get maxSize() {
        return this.ptr.readS64();
    }
    get dataPtr() {
        return this.ptr.add(0x18).readPointer();
    }
    at(i) {
        if (i < 0 || i >= this.maxSize) return null;
        const realPtr = extractLower48(this.dataPtr.add(i * PTR_SIZE).readPointer());
        return realPtr.isNull() ? null : new CEntity(realPtr);
    }
    toArray() {
        const out = [];
        const size = this.maxSize;
        for (let i = 0; i < size; i++) {
            const e = this.at(i);
            if (e) out.push(e);
        }
        return out;
    }
}

class CEntitySystem {
    constructor(ptr) {
        this.ptr = ptr;
    }
    get entityArray() {
        return new CEntityArray(this.ptr.add(0x148));
    }
}

class GEnv {
    constructor(ptr) {
        this.ptr = ptr;
    }
    get entitySystem() {
        const sysPtr = this.ptr.add(0x00a0).readPointer();
        return sysPtr.isNull() ? null : new CEntitySystem(sysPtr);
    }
    get engineComponentScheduler() {
        const ptr = this.ptr.add(0x00A8).readPointer();
        return ptr.isNull() ? null : new CEngineComponentScheduler(ptr);
    }
}

const GENV_ADDR = Process.enumerateModulesSync()[0].base.add("0x9B4FBE0");
const gEnv = new GEnv(GENV_ADDR);

console.log("[*] Frida Entity System bridge initialized.");

// Process.setExceptionHandler((exception) => {
//     console.log(`=== EXCEPTION: ${exception.type} at ${exception.address} ===`);
//     return true;
// });

// ==================================================================
// ===        ADVANCED: Component Usage & VTable Tracking         ===
// ==================================================================

let componentUsageStats = {};
const componentIdToNameMap = new Map();
let isTrackingActive = false;
let getComponentIdHook = null;
let getComponentAddrHook = null;

/**
 * [MODIFIED] Records a component lookup, including its vtable address.
 * @param {string} className The name of the entity's class.
 * @param {string} componentName The name of the component being accessed.
 * @param {string} vtableAddr The address of the component's vtable as a string.
 */
function recordComponentLookup(className, componentName, vtableAddr) {
    if (!className || !componentName || !vtableAddr) return;

    // Init class entry
    if (!componentUsageStats[className]) {
        componentUsageStats[className] = {};
    }
    // Init component entry
    if (!componentUsageStats[className][componentName]) {
        componentUsageStats[className][componentName] = { totalCount: 0, vtables: {} };
    }
    // Init vtable entry
    if (!componentUsageStats[className][componentName].vtables[vtableAddr]) {
        componentUsageStats[className][componentName].vtables[vtableAddr] = 0;
    }

    // Increment counts
    componentUsageStats[className][componentName].totalCount++;
    componentUsageStats[className][componentName].vtables[vtableAddr]++;
}

function startComponentTracking() {
    if (isTrackingActive) {
        console.log("[*] Component usage tracking is already active.");
        return { success: true, message: "Tracking already active." };
    }
    try {
        const moduleBase = Module.findBaseAddress("StarCitizen.exe");
        const getComponentIdAddr = moduleBase.add(0x6A320C0);
        const getComponentAddrAddr = moduleBase.add(0x6B49D80);

        // Hook 1: Map component name to ID
        getComponentIdHook = Interceptor.attach(getComponentIdAddr, {
            onEnter: function(args) {
                this.componentIdPtr = args[1];
                try { this.componentName = args[2].readUtf8String(); } catch (e) { this.componentName = null; }

                // If component name is EntityComponentEAPlayableAreaController, force return 0xFFFF
                if (this.componentName === "EntityComponentEAPlayableAreaController") {
                    console.log('killed');
                    console.log(`Backtrace: ${Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join('\n')}`);
                    this.componentIdPtr.writeU16(0xFFFF);
                }
            },
            onLeave: function(retval) {
                if (this.componentName && this.componentIdPtr) {
                    try {
                        const componentId = this.componentIdPtr.readU16();
                        if (componentId !== 0xFFFF) {
                            //console.log(`Component ID ${componentId} corresponds to ${this.componentName}`);
                            componentIdToNameMap.set(componentId, this.componentName)
                        };
                    } catch (e) {}
                }
            }
        });

        // Hook 2: [MODIFIED] Track lookups and capture vtable
        getComponentAddrHook = Interceptor.attach(getComponentAddrAddr, {
            onEnter: function(args) {
                // Store context for onLeave. We need the output pointer.
                this.entityPtr = args[0];
                this.componentAddrOutputPtr = args[1]; // This is where the result will be written
                this.componentIdPtr = args[2];
            },
            onLeave: function(retval) {
                try {
                    // Check if context from onEnter is valid
                    if (!this.entityPtr || this.entityPtr.isNull() || !this.componentIdPtr || !this.componentAddrOutputPtr) return;

                    // Read the component pointer from the output argument
                    const componentPtr = this.componentAddrOutputPtr.readPointer();
                    if (componentPtr.isNull()) return;

                    // The vtable is the first pointer in the component's object memory
                    const vtableAddr = componentPtr.readPointer();
                    if (vtableAddr.isNull()) return;

                    const componentId = this.componentIdPtr.readU16();
                    const componentName = componentIdToNameMap.get(componentId);

                    if (componentName) {
                        const entity = new CEntity(this.entityPtr);
                        const entityClass = entity.entityClass;
                        if (entityClass) {
                            const className = entityClass.name;
                            if (className) {
                                // Record the lookup with the vtable address
                                recordComponentLookup(className, componentName, vtableAddr.toString());
                            }
                        }
                    }
                } catch (e) {}
            }
        });
        isTrackingActive = true;
        console.log("[+] Component usage and vtable tracking started successfully.");
        return { success: true, message: "Tracking started." };
    } catch (e) {
        console.log(`[!] Failed to start component tracking: ${e.message}`);
        return { success: false, error: e.message };
    }
}

function stopComponentTracking() {
    if (!isTrackingActive) return { success: true, message: "Tracking was not active." };
    if (getComponentIdHook) getComponentIdHook.detach();
    if (getComponentAddrHook) getComponentAddrHook.detach();
    getComponentIdHook = getComponentAddrHook = null;
    isTrackingActive = false;
    console.log("[*] Component usage tracking stopped.");
    return { success: true, message: "Tracking stopped." };
}

function resetComponentUsageStats() {
    componentUsageStats = {};
    console.log("[*] Component usage statistics have been reset.");
    return { success: true, message: "Stats reset." };
}

/**
 * [MODIFIED] A focused report that now includes vtable information.
 */
function reportComponentUsageFocused(topN = 1000, minLookups = 0, excludedComponents = []) {
    if (Object.keys(componentUsageStats).length === 0) {
        console.log("[!] No component usage data has been collected yet.");
        return {};
    }

    console.log("\n--- Focused Component & VTable Usage Report ---");
    console.log(`(Excluding: ${excludedComponents.join(', ') || 'None'}) | (Min Lookups: ${minLookups})`);

    const reportData = {};
    const sortedClasses = Object.keys(componentUsageStats).sort((a, b) => {
        const totalA = Object.values(componentUsageStats[a]).reduce((sum, comp) => sum + comp.totalCount, 0);
        const totalB = Object.values(componentUsageStats[b]).reduce((sum, comp) => sum + comp.totalCount, 0);
        return totalB - totalA;
    });

    for (const className of sortedClasses) {
        const components = componentUsageStats[className];
        const totalLookups = Object.values(components).reduce((sum, comp) => sum + comp.totalCount, 0);

        if (totalLookups < minLookups) continue;

        const filteredComponents = Object.entries(components)
            .filter(([name]) => !excludedComponents.includes(name))
            .sort(([, a], [, b]) => b.totalCount - a.totalCount);

        if (filteredComponents.length === 0) continue;

        console.log(`\n[+] Class: ${className} (Total Lookups: ${totalLookups})`);
        console.log("--------------------------------------------------");

        reportData[className] = { totalLookups, components: {} };

        filteredComponents.slice(0, topN).forEach(([componentName, data]) => {
            console.log(`    - ${componentName.padEnd(35)}: ${data.totalCount} lookups`);
            reportData[className].components[componentName] = { totalCount: data.totalCount, vtables: {} };

            // Print vtables for this component
            for (const vtable in data.vtables) {
                const count = data.vtables[vtable];
                console.log(`        > VTable: ${vtable} (${count} hits)`);
                reportData[className].components[componentName].vtables[vtable] = count;
            }
        });
    }
    console.log("\n--- End of Report ---");
    return reportData;
}

/**
 * [MODIFIED] Reverse lookup report, now includes vtable info.
 */
function reportComponentUsers(componentName) {
    if (!componentName) {
        console.log("[!] Please provide a component name.");
        return {};
    }
    console.log(`\n--- Report for users of component: ${componentName} ---`);

    const users = [];
    for (const className in componentUsageStats) {
        if (componentUsageStats[className][componentName]) {
            users.push({
                className: className,
                count: componentUsageStats[className][componentName].totalCount,
                vtables: Object.keys(componentUsageStats[className][componentName].vtables)
            });
        }
    }

    if (users.length === 0) {
        console.log(`[!] No classes found using '${componentName}'. (Note: Name is case-sensitive)`);
        return { componentName, users: [] };
    }

    users.sort((a, b) => b.count - a.count);

    console.log(`Found ${users.length} class(es) using this component:`);
    users.forEach(user => {
        console.log(`    - ${user.className.padEnd(50)}: ${user.count} lookups`);
        user.vtables.forEach(vtable => {
            console.log(`        > VTable: ${vtable}`);
        });
    });
    console.log("\n--- End of Report ---");
    return { componentName, users };
}

function highlightEntitiesWithComponent(componentName, glowParams = { r: 0.0, g: 1.0, b: 1.0 }) {
    if (!gEnv.entitySystem) {
        console.log("[!] Entity system not available.");
        return { success: false, error: "Entity system not available" };
    }
    console.log(`[*] Highlighting all entities with component: '${componentName}'`);

    const allEntities = gEnv.entitySystem.entityArray.toArray();
    let highlightedCount = 0;

    for (const entity of allEntities) {
        try {
            const componentPtr = entity.getComponentByName(componentName);
            if (componentPtr && !componentPtr.isNull()) {
                entity.addGlow(glowParams);
                highlightedCount++;
            }
        } catch (e) {}
    }

    const result = { success: true, componentName, highlightedCount };
    console.log(`[+] Highlighting complete. Applied glow to ${highlightedCount} entities.`);
    return result;
}


// RPC exports for controlling the system
rpc.exports.startComponentTracking = startComponentTracking;
rpc.exports.stopComponentTracking = stopComponentTracking;
rpc.exports.resetComponentUsageStats = resetComponentUsageStats;
rpc.exports.reportComponentUsage = (topN = 10) => reportComponentUsageFocused(topN);
rpc.exports.reportComponentUsageFocused = reportComponentUsageFocused;
rpc.exports.reportComponentUsers = reportComponentUsers;
rpc.exports.highlightEntitiesWithComponent = highlightEntitiesWithComponent;

//startComponentTracking();

// Hook functions to prevent EntityComponentEAPlayableAreaController lookups
function hookEntityComponentEAFunctions() {
    try {
        const moduleBase = Module.findBaseAddress("StarCitizen.exe");
        const getComponentAddrAddr = moduleBase.add(0x6B49D80);

        // Hook getComponentAddrById to return failure when component ID is 814
        Interceptor.attach(getComponentAddrAddr, {
            onEnter: function(args) {
                this.componentIdPtr = args[2];
                this.componentAddrOutputPtr = args[1];
            },
            onLeave: function(retval) {
                try {
                    if (this.componentIdPtr && this.componentAddrOutputPtr) {
                        const componentId = this.componentIdPtr.readU16();
                        if (componentId === 814) {
                            // Write null pointer to output and return failure
                            this.componentAddrOutputPtr.writePointer(ptr(0));
                            retval.replace(ptr(1)); // Return non-zero to indicate failure
                        }
                    }
                } catch (e) {}
            }
        });

        console.log("[+] Successfully hooked getComponentAddrById to block component ID 814");
        return { success: true, message: "EA component lookup blocked" };
    } catch (e) {
        console.log(`[!] Failed to hook EA component functions: ${e.message}`);
        return { success: false, error: e.message };
    }
}

// Initialize the hooks
hookEntityComponentEAFunctions();

// Export for RPC control
rpc.exports.hookEntityComponentEAFunctions = hookEntityComponentEAFunctions;
