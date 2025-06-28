// --- Frida Script: dumpOffsetsTable.js ---

// Function to reliably get gEnvBase (replace with your actual method)
function getGEnvBasePointer() {
    // !! IMPORTANT !!
    // This is a placeholder. You MUST replace this with a reliable method.
    // Hook a late-init function or the main loop update.
    // Example: Interceptor.attach(ptr("0xLATE_FUNCTION"), { onEnter: function(args) { gEnvBase = ptr("0x14981d200").readPointer(); } });
    try {
        const gEnvPtrAddr = ptr("0x14981d200");
        const gEnvPtr = gEnvPtrAddr.readPointer();
        if (gEnvPtr.isNull()) {
            console.error("[Error] gEnv pointer at " + gEnvPtrAddr + " is NULL. Engine likely not fully initialized yet.");
            return NULL;
        }
        // Add more validation if needed (e.g., check if it points to expected memory range)
        return gEnvPtr;
    } catch (e) {
        console.error("[Error] Failed to read gEnv pointer from " + ptr("0x14981d200") + ": " + e);
        return NULL;
    }
}

// Get the base pointer ONCE after ensuring initialization
const gEnvBase = getGEnvBasePointer();

// Helper to read CryString (adjust based on actual implementation if needed)
function readStringFromCryString(cryStringPtr) {
    if (cryStringPtr.isNull()) return "NULL CryString Ptr";
    try {
        const bufferPtr = cryStringPtr.readPointer();
        if (bufferPtr.isNull()) return "NULL Buffer Ptr";
        // Attempt to read as CString, might need length info for safety
        return bufferPtr.readCString();
    } catch (e) {
        return "[Error Reading String]";
    }
}

// Helper to format table rows
function printTableRow(structName, offset, memberName, description, accessExample, value) {
    const offsetStr = offset >= 0 ? `+0x${offset.toString(16)}` : 'N/A';
    const nameStr = `${structName}::${memberName}`.padEnd(45);
    const offsetPadded = offsetStr.padEnd(10);
    const descPadded = description.padEnd(60);
    const examplePadded = accessExample.padEnd(70);
    console.log(`| ${nameStr} | ${offsetPadded} | ${descPadded} | ${examplePadded} | ${value}`);
}

// --- Main Execution ---
if (gEnvBase.isNull()) {
    console.error("Stopping script execution due to invalid gEnvBase pointer.");
} else {
    console.log("gEnv Base Pointer: " + gEnvBase);
    console.log("\n--- Engine Structure Offsets ---");

    const header = `| ${"Structure::Member".padEnd(45)} | ${"Offset".padEnd(10)} | ${"Description".padEnd(60)} | ${"Frida Access Example".padEnd(70)} | Value / Pointer Address |`;
    const separator = `|-${"-".repeat(45)}-|-${"-".repeat(10)}-|-${"-".repeat(60)}-|-${"-".repeat(70)}-|-${"-".repeat(25)}-|`;

    console.log(separator);
    console.log(header);
    console.log(separator);

    // --- SSystemGlobalEnvironment (gEnv) ---
    printTableRow("SSystemGlobalEnvironment", -1, "(Base)", "Base pointer for global environment", 'const gEnvBase = ptr("0x14981d200");', gEnvBase);
    let currentPtr;
    currentPtr = gEnvBase.add(16).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x10, "pNetwork", "Pointer to INetwork implementation", "gEnvBase.add(0x10).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(24).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x18, "p3DEngine", "Pointer to I3DEngine implementation", "gEnvBase.add(0x18).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(32).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x20, "pPhysicalWorld", "Pointer to IPhysicalWorld implementation", "gEnvBase.add(0x20).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(40).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x28, "pFlowSystem", "Pointer to IFlowSystem implementation", "gEnvBase.add(0x28).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(48).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x30, "pInput", "Pointer to IInput implementation", "gEnvBase.add(0x30).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(56).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x38, "pCryPak", "Pointer to ICryPak implementation", "gEnvBase.add(0x38).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(96).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x60, "pTimer", "Pointer to ITimer implementation", "gEnvBase.add(0x60).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(104).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x68, "pFont", "Pointer to ICryFont implementation", "gEnvBase.add(0x68).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(112).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x70, "pVideoCapture", "Pointer to IVideoCapture implementation", "gEnvBase.add(0x70).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(120).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x78, "pFlashUI", "Pointer to IFlashUI implementation", "gEnvBase.add(0x78).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(128).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x80, "pDataCore", "Pointer to IDataCore implementation", "gEnvBase.add(0x80).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(144).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x90, "pAISystem", "Pointer to IAISystem implementation", "gEnvBase.add(0x90).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(160).readPointer(); printTableRow("SSystemGlobalEnvironment", 0xA0, "pEntitySystem", "Pointer to IEntitySystem implementation", "gEnvBase.add(0xA0).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(176).readPointer(); printTableRow("SSystemGlobalEnvironment", 0xB0, "pConsole", "Pointer to IConsole implementation", "gEnvBase.add(0xB0).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(184).readPointer(); printTableRow("SSystemGlobalEnvironment", 0xB8, "pAudioSystem", "Pointer to IAudioSystem implementation", "gEnvBase.add(0xB8).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(192).readPointer(); printTableRow("SSystemGlobalEnvironment", 0xC0, "pSystem", "Pointer to ISystem implementation (CSystem)", "gEnvBase.add(0xC0).readPointer()", currentPtr);
    const pSystem = currentPtr; // Save for CSystem access
    currentPtr = gEnvBase.add(200).readPointer(); printTableRow("SSystemGlobalEnvironment", 0xC8, "pAnimationSystem", "Pointer to IAnimationSystem implementation", "gEnvBase.add(0xC8).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(208).readPointer(); printTableRow("SSystemGlobalEnvironment", 0xD0, "pLog", "Pointer to ILog implementation", "gEnvBase.add(0xD0).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(216).readPointer(); printTableRow("SSystemGlobalEnvironment", 0xD8, "pLocalizer", "Pointer to ILocalizationManager implementation", "gEnvBase.add(0xD8).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(224).readPointer(); printTableRow("SSystemGlobalEnvironment", 0xE0, "pMovieSystem", "Pointer to IMovieSystem implementation", "gEnvBase.add(0xE0).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(232).readPointer(); printTableRow("SSystemGlobalEnvironment", 0xE8, "pProcess", "Pointer to IProcess implementation", "gEnvBase.add(0xE8).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(248).readPointer(); printTableRow("SSystemGlobalEnvironment", 0xF8, "pRenderer", "Pointer to IRenderer implementation", "gEnvBase.add(0xF8).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(264).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x108, "pHardwareMouse", "Pointer to IHardwareMouse implementation", "gEnvBase.add(0x108).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(272).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x110, "pCompressor", "Pointer to ICompressionHelper implementation", "gEnvBase.add(0x110).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(280).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x118, "pJobManager", "Pointer to IJobManager implementation", "gEnvBase.add(0x118).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(304).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x130, "pCIGBackend", "Pointer to ICIGBackend implementation", "gEnvBase.add(0x130).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(312).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x138, "pNotificationNetwork", "Pointer to INotificationNetwork implementation", "gEnvBase.add(0x138).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(320).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x140, "pStreamEngine", "Pointer to IStreamEngine implementation", "gEnvBase.add(0x140).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(352).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x160, "pProfiler", "Pointer to IProfiler implementation", "gEnvBase.add(0x160).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(360).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x168, "pThreadManager", "Pointer to IThreadManager implementation", "gEnvBase.add(0x168).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(368).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x170, "pSystemDebugStats", "Pointer to ISystemDebugStats implementation", "gEnvBase.add(0x170).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(376).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x178, "pDevTools", "Pointer to IDevTools implementation", "gEnvBase.add(0x178).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(384).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x180, "pCIGSocial", "Pointer to ICIGSocial implementation", "gEnvBase.add(0x180).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(392).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x188, "pCIGServices", "Pointer to ICIGServices implementation", "gEnvBase.add(0x188).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(400).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x190, "pCIGAudio", "Pointer to ICIGAudio implementation", "gEnvBase.add(0x190).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(408).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x198, "pMemoryManager", "Pointer to IMemoryManager implementation", "gEnvBase.add(0x198).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(416).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x1A0, "pCIGUI", "Pointer to ICIGUI implementation", "gEnvBase.add(0x1A0).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(424).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x1A8, "pCIGWorldBuilder", "Pointer to ICIGWorldBuilder implementation", "gEnvBase.add(0x1A8).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(432).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x1B0, "pCIGVFX", "Pointer to ICIGVFX implementation", "gEnvBase.add(0x1B0).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(440).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x1B8, "pCIGMissionSystem", "Pointer to ICIGMissionSystem implementation", "gEnvBase.add(0x1B8).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(448).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x1C0, "pCIGRoomSystem", "Pointer to ICIGRoomSystem implementation", "gEnvBase.add(0x1C0).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(456).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x1C8, "pXML", "Pointer to IXmlUtils implementation", "gEnvBase.add(0x1C8).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(464).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x1D0, "pSystemEventDispatcher", "Pointer to ISystemEventDispatcher implementation", "gEnvBase.add(0x1D0).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(472).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x1D8, "pPlatformOS", "Pointer to IPlatformOS implementation", "gEnvBase.add(0x1D8).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(480).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x1E0, "pCIGCargoSystem", "Pointer to ICIGCargoSystem implementation", "gEnvBase.add(0x1E0).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(488).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x1E8, "pGame", "Pointer to IGame implementation", "gEnvBase.add(0x1E8).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(496).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x1F0, "pUserCallback", "Pointer to ISystemUserCallback implementation", "gEnvBase.add(0x1F0).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(504).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x1F8, "pCIGTinyMachine", "Pointer to ICIGTinyMachine implementation", "gEnvBase.add(0x1F8).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(512).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x200, "pSystemFileLock", "Pointer to ISystemFileLock implementation", "gEnvBase.add(0x200).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(520).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x208, "pWatchdog", "Pointer to IWatchdogTimer implementation", "gEnvBase.add(0x208).readPointer()", currentPtr);
    currentPtr = gEnvBase.add(528).readPointer(); printTableRow("SSystemGlobalEnvironment", 0x210, "pStressTest", "Pointer to IStressTest implementation", "gEnvBase.add(0x210).readPointer()", currentPtr);
    let currentVal = gEnvBase.add(674).readU8(); printTableRow("SSystemGlobalEnvironment", 0x2A2, "bDedicatedServer", "Flag indicating dedicated server mode", "gEnvBase.add(0x2A2).readU8()", currentVal);
    currentVal = gEnvBase.add(677).readU8(); printTableRow("SSystemGlobalEnvironment", 0x2A5, "bEditor", "Flag indicating editor mode", "gEnvBase.add(0x2A5).readU8()", currentVal);
    currentVal = gEnvBase.add(698).readU8(); printTableRow("SSystemGlobalEnvironment", 0x2BA, "bSplashScreen", "Flag indicating splash screen enabled", "gEnvBase.add(0x2BA).readU8()", currentVal);
    currentVal = gEnvBase.add(699).readU8(); printTableRow("SSystemGlobalEnvironment", 0x2BB, "bTestMode", "Flag indicating test mode", "gEnvBase.add(0x2BB).readU8()", currentVal);
    currentVal = gEnvBase.add(700).readU32(); printTableRow("SSystemGlobalEnvironment", 0x2BC, "os.dwMajorVersion", "OS Major Version", "gEnvBase.add(0x2BC).readU32()", currentVal);
    currentVal = gEnvBase.add(704).readU32(); printTableRow("SSystemGlobalEnvironment", 0x2C0, "os.dwMinorVersion", "OS Minor Version", "gEnvBase.add(0x2C0).readU32()", currentVal);
    currentVal = gEnvBase.add(708).readU8(); printTableRow("SSystemGlobalEnvironment", 0x2C4, "os.bWinNT", "OS is NT based flag", "gEnvBase.add(0x2C4).readU8()", currentVal);
    currentVal = gEnvBase.add(709).readU8(); printTableRow("SSystemGlobalEnvironment", 0x2C5, "os.bWinVista", "OS is Vista+ flag", "gEnvBase.add(0x2C5).readU8()", currentVal);
    currentPtr = gEnvBase.add(736); printTableRow("SSystemGlobalEnvironment", 0x2E0, "szCmdLine", "System command line buffer", "gEnvBase.add(0x2E0)", currentPtr);
    currentPtr = gEnvBase.add(992); printTableRow("SSystemGlobalEnvironment", 0x3E0, "szGameName", "Game name buffer", "gEnvBase.add(0x3E0)", currentPtr);
    currentPtr = gEnvBase.add(1248); printTableRow("SSystemGlobalEnvironment", 0x4E0, "szBuildTag", "Build tag buffer", "gEnvBase.add(0x4E0)", currentPtr);
    currentPtr = gEnvBase.add(1504); printTableRow("SSystemGlobalEnvironment", 0x5E0, "szBranchName", "Branch name buffer", "gEnvBase.add(0x5E0)", currentPtr);
    currentVal = gEnvBase.add(1527).readU8(); printTableRow("SSystemGlobalEnvironment", 0x5F7, "bSplunkLogging", "Splunk logging flag", "gEnvBase.add(0x5F7).readU8()", currentVal);
    currentVal = gEnvBase.add(1528).readU8(); printTableRow("SSystemGlobalEnvironment", 0x5F8, "bAnalyticsLogging", "Analytics logging flag", "gEnvBase.add(0x5F8).readU8()", currentVal);
    currentVal = gEnvBase.add(1529).readU8(); printTableRow("SSystemGlobalEnvironment", 0x5F9, "bTraceLogging", "Trace logging flag", "gEnvBase.add(0x5F9).readU8()", currentVal);
    currentVal = gEnvBase.add(1534).readU8(); printTableRow("SSystemGlobalEnvironment", 0x5FE, "bMinimalMode", "Minimal mode flag", "gEnvBase.add(0x5FE).readU8()", currentVal);
    currentVal = gEnvBase.add(1535).readU8(); printTableRow("SSystemGlobalEnvironment", 0x5FF, "bToolMode", "Tool mode flag", "gEnvBase.add(0x5FF).readU8()", currentVal);
    currentPtr = gEnvBase.add(2055); printTableRow("SSystemGlobalEnvironment", 0x807, "szUserPath", "User path buffer", "gEnvBase.add(0x807)", currentPtr);
    console.log(separator);

    // --- CSystem ---
    if (!pSystem.isNull()) {
        printTableRow("CSystem", -1, "(Base)", "Core system implementation", "const pSystem = gEnvBase.add(192).readPointer();", pSystem);
        currentPtr = pSystem.add(24).readPointer(); printTableRow("CSystem", 0x18, "m_pSystemGEnv", "Pointer to &gEnv storage base", "pSystem.add(0x18).readPointer()", currentPtr);
        currentPtr = pSystem.add(32).readPointer(); printTableRow("CSystem", 0x20, "m_pTimer", "Pointer to CTimer instance", "pSystem.add(0x20).readPointer()", currentPtr);
        currentPtr = pSystem.add(40); printTableRow("CSystem", 0x28, "m_cvars", "System CVars structure base", "pSystem.add(0x28)", currentPtr);
        currentPtr = pSystem.add(960).readPointer(); printTableRow("CSystem", 0x3C0, "m_pNotificationNetwork", "Pointer to CNotificationNetwork", "pSystem.add(0x3C0).readPointer()", currentPtr);
        currentPtr = pSystem.add(1008).readPointer(); printTableRow("CSystem", 0x3F0, "m_pUserCallback", "Pointer to CSystemUserCallback", "pSystem.add(0x3F0).readPointer()", currentPtr);
        currentPtr = pSystem.add(1016); printTableRow("CSystem", 0x3F8, "m_sCmdLine", "Command line string object", "pSystem.add(0x3F8)", currentPtr);
        currentPtr = pSystem.add(1032).readPointer(); printTableRow("CSystem", 0x408, "m_pStreamEngine", "Pointer to CStreamEngine", "pSystem.add(0x408).readPointer()", currentPtr);
        currentPtr = pSystem.add(1040).readPointer(); printTableRow("CSystem", 0x410, "m_pMemoryManager", "Pointer to IMemoryManager", "pSystem.add(0x410).readPointer()", currentPtr);
        currentPtr = pSystem.add(1048).readPointer(); printTableRow("CSystem", 0x418, "m_pPlatformOS", "Pointer to CPlatformOS_Windows", "pSystem.add(0x418).readPointer()", currentPtr);
        currentPtr = pSystem.add(1056); printTableRow("CSystem", 0x420, "m_PlatformInformation", "Platform info structure base", "pSystem.add(0x420)", currentPtr);
        currentPtr = pSystem.add(1968).readPointer(); printTableRow("CSystem", 0x7B0, "m_pSystemDebugStats", "Pointer to CSystemDebugStats", "pSystem.add(0x7B0).readPointer()", currentPtr);
        currentPtr = pSystem.add(1992).readPointer(); printTableRow("CSystem", 0x7C8, "m_pSystemEventDispatcherClient", "Pointer to ISystemEventDispatcher", "pSystem.add(0x7C8).readPointer()", currentPtr);
        currentPtr = pSystem.add(2000).readPointer(); printTableRow("CSystem", 0x7D0, "m_pDefaultFont", "Pointer to IFFont", "pSystem.add(0x7D0).readPointer()", currentPtr);
        currentPtr = pSystem.add(2008).readPointer(); printTableRow("CSystem", 0x7D8, "m_pCompressorZlib", "Pointer to IZLibCompressor", "pSystem.add(0x7D8).readPointer()", currentPtr);
        currentPtr = pSystem.add(2016).readPointer(); printTableRow("CSystem", 0x7E0, "m_pDecompressorZlib", "Pointer to IZLibDecompressor", "pSystem.add(0x7E0).readPointer()", currentPtr);
        currentPtr = pSystem.add(2024).readPointer(); printTableRow("CSystem", 0x7E8, "m_pCompressorLZ4", "Pointer to ILZ4Compressor", "pSystem.add(0x7E8).readPointer()", currentPtr);
        currentPtr = pSystem.add(2032).readPointer(); printTableRow("CSystem", 0x7F0, "m_pDecompressorLZ4", "Pointer to ILZ4Decompressor", "pSystem.add(0x7F0).readPointer()", currentPtr);
        currentPtr = pSystem.add(2040).readPointer(); printTableRow("CSystem", 0x7F8, "m_pHttpRequest", "Pointer to CHttpRequest", "pSystem.add(0x7F8).readPointer()", currentPtr);
        currentPtr = pSystem.add(2048).readPointer(); printTableRow("CSystem", 0x800, "m_pXMLUtils", "Pointer to CXmlUtils", "pSystem.add(0x800).readPointer()", currentPtr);
        currentPtr = pSystem.add(2056).readPointer(); printTableRow("CSystem", 0x808, "m_pXMLUtilsInterface", "Pointer to IXmlUtils", "pSystem.add(0x808).readPointer()", currentPtr);
        currentPtr = pSystem.add(2064); printTableRow("CSystem", 0x810, "m_RootPath", "Root path string object", "pSystem.add(0x810)", currentPtr);
        currentPtr = pSystem.add(2112).readPointer(); printTableRow("CSystem", 0x840, "m_pAsyncIOManager", "Pointer to CAsyncIOManager", "pSystem.add(0x840).readPointer()", currentPtr);
        currentPtr = pSystem.add(2144).readPointer(); printTableRow("CSystem", 0x860, "m_pGameNameCVar", "Pointer to ICVar (sys_game_name)", "pSystem.add(0x860).readPointer()", currentPtr);
        currentPtr = pSystem.add(2200).readPointer(); printTableRow("CSystem", 0x898, "m_pExitOnQuitCVar", "Pointer to ICVar (ExitOnQuit)", "pSystem.add(0x898).readPointer()", currentPtr);
        currentPtr = pSystem.add(2208).readPointer(); printTableRow("CSystem", 0x8A0, "m_pKeyboardCVar", "Pointer to ICVar (sys_keyboard)", "pSystem.add(0x8A0).readPointer()", currentPtr);
        currentPtr = pSystem.add(2216).readPointer(); printTableRow("CSystem", 0x8A8, "m_pWarningsCVar", "Pointer to ICVar (sys_warnings)", "pSystem.add(0x8A8).readPointer()", currentPtr);
        currentPtr = pSystem.add(2224).readPointer(); printTableRow("CSystem", 0x8B0, "m_pServerAICVar", "Pointer to ICVar (sv_AISystem)", "pSystem.add(0x8B0).readPointer()", currentPtr);
        currentPtr = pSystem.add(2232).readPointer(); printTableRow("CSystem", 0x8B8, "m_pClientAICVar", "Pointer to ICVar (cl_AISystem)", "pSystem.add(0x8B8).readPointer()", currentPtr);
        currentPtr = pSystem.add(2240).readPointer(); printTableRow("CSystem", 0x8C0, "m_pSpecCVar", "Pointer to ICVar (sys_spec)", "pSystem.add(0x8C0).readPointer()", currentPtr);
        currentPtr = pSystem.add(2248).readPointer(); printTableRow("CSystem", 0x8C8, "m_pFirstLaunchCVar", "Pointer to ICVar (sys_firstlaunch)", "pSystem.add(0x8C8).readPointer()", currentPtr);
        currentPtr = pSystem.add(2256).readPointer(); printTableRow("CSystem", 0x8D0, "m_pPhysicsCPUCVar", "Pointer to ICVar (sys_physics_CPU)", "pSystem.add(0x8D0).readPointer()", currentPtr);
        currentPtr = pSystem.add(2264).readPointer(); printTableRow("CSystem", 0x8D8, "m_pPhysicsEmbedStepCVar", "Pointer to ICVar (sys_physics_embed_step)", "pSystem.add(0x8D8).readPointer()", currentPtr);
        currentPtr = pSystem.add(2272).readPointer(); printTableRow("CSystem", 0x8E0, "m_pAudioDisableCVar", "Pointer to ICVar (sys_audio_disable)", "pSystem.add(0x8E0).readPointer()", currentPtr);
        currentPtr = pSystem.add(2280).readPointer(); printTableRow("CSystem", 0x8E8, "m_pCIGAudioEnableCVar", "Pointer to ICVar (sys_cig_audio_enable)", "pSystem.add(0x8E8).readPointer()", currentPtr);
        currentPtr = pSystem.add(2288).readPointer(); printTableRow("CSystem", 0x8F0, "m_pSocialDisableCVar", "Pointer to ICVar (sys_social_disable)", "pSystem.add(0x8F0).readPointer()", currentPtr);
        currentPtr = pSystem.add(2296).readPointer(); printTableRow("CSystem", 0x8F8, "m_pAutotestProfilerCVar", "Pointer to ICVar (sys_enable_autotest_profiler)", "pSystem.add(0x8F8).readPointer()", currentPtr);
        currentPtr = pSystem.add(2304).readPointer(); printTableRow("CSystem", 0x900, "m_pSimulateTaskCVar", "Pointer to ICVar (sys_SimulateTask)", "pSystem.add(0x900).readPointer()", currentPtr);
        currentPtr = pSystem.add(2312).readPointer(); printTableRow("CSystem", 0x908, "m_pMinStepCVar", "Pointer to ICVar (sys_min_step)", "pSystem.add(0x908).readPointer()", currentPtr);
        currentPtr = pSystem.add(2320).readPointer(); printTableRow("CSystem", 0x910, "m_pMaxStepCVar", "Pointer to ICVar (sys_max_step)", "pSystem.add(0x910).readPointer()", currentPtr);
        currentPtr = pSystem.add(2328).readPointer(); printTableRow("CSystem", 0x918, "m_pMemoryDebugCVar", "Pointer to ICVar (sys_memory_debug)", "pSystem.add(0x918).readPointer()", currentPtr);
        currentPtr = pSystem.add(2336).readPointer(); printTableRow("CSystem", 0x920, "m_pGPUPhysicsCVar", "Pointer to ICVar (gpu_particle_physics)", "pSystem.add(0x920).readPointer()", currentPtr);
        currentPtr = pSystem.add(2344).readPointer(); printTableRow("CSystem", 0x928, "m_pUserCallbackLog", "Pointer to ISystemUserCallback (Log)", "pSystem.add(0x928).readPointer()", currentPtr);
        currentPtr = pSystem.add(2352).readPointer(); printTableRow("CSystem", 0x930, "m_pUserCallbackCrash", "Pointer to ISystemUserCallback (Crash)", "pSystem.add(0x930).readPointer()", currentPtr);
        currentPtr = pSystem.add(2360).readPointer(); printTableRow("CSystem", 0x938, "m_pUserCallbackError", "Pointer to ISystemUserCallback (Error)", "pSystem.add(0x938).readPointer()", currentPtr);
        currentPtr = pSystem.add(2368).readPointer(); printTableRow("CSystem", 0x940, "m_pUserCallbackProgress", "Pointer to ISystemUserCallback (Progress)", "pSystem.add(0x940).readPointer()", currentPtr);
        currentPtr = pSystem.add(2392).readPointer(); printTableRow("CSystem", 0x958, "m_LoadConfigEntries", "Map/List head for CLoadConfigurationEntry", "pSystem.add(0x958).readPointer()", currentPtr);
        currentPtr = pSystem.add(2632); printTableRow("CSystem", 0xA48, "m_loadConfigVariables", "Map/List base for config variables", "pSystem.add(0xA48)", currentPtr);
        currentPtr = pSystem.add(10960).readPointer(); printTableRow("CSystem", 0x2AD8, "m_pLocalizationManager", "Pointer to ILocalizationManager", "pSystem.add(0x2AD8).readPointer()", currentPtr);
        currentPtr = pSystem.add(10976).readPointer(); printTableRow("CSystem", 0x2AE8, "m_pSystemFileLock", "Pointer to CInterprocessLock", "pSystem.add(0x2AE8).readPointer()", currentPtr);
        currentPtr = pSystem.add(10992); printTableRow("CSystem", 0x2AF0, "m_physicsPerformanceData", "SPhysicsPerformanceData base", "pSystem.add(0x2AF0)", currentPtr);
        currentPtr = pSystem.add(16096); printTableRow("CSystem", 0x3F10, "m_physThresholds", "SPhysThresholds base", "pSystem.add(0x3F10)", currentPtr);
        currentPtr = pSystem.add(16192); printTableRow("CSystem", 0x3F70, "m_physicsDebugData", "SPhysicsDebugData base", "pSystem.add(0x3F70)", currentPtr);
        currentPtr = pSystem.add(16248); printTableRow("CSystem", 0x3FA8, "m_physicsEventData", "SPhysicsEventData base", "pSystem.add(0x3FA8)", currentPtr);
        currentPtr = pSystem.add(16256).readPointer(); printTableRow("CSystem", 0x3FB0, "m_pInput", "Pointer to CInput", "pSystem.add(0x3FB0).readPointer()", currentPtr);
        currentPtr = pSystem.add(16264).readPointer(); printTableRow("CSystem", 0x3FB8, "m_pConsole", "Pointer to IConsole", "pSystem.add(0x3FB8).readPointer()", currentPtr);
        currentPtr = pSystem.add(16272).readPointer(); printTableRow("CSystem", 0x3FC0, "m_pNetwork", "Pointer to CNetwork", "pSystem.add(0x3FC0).readPointer()", currentPtr);
        currentPtr = pSystem.add(16280).readPointer(); printTableRow("CSystem", 0x3FC8, "m_pNotificationNetwork", "Pointer to CNotificationNetwork", "pSystem.add(0x3FC8).readPointer()", currentPtr);
        currentPtr = pSystem.add(16288).readPointer(); printTableRow("CSystem", 0x3FD0, "m_pStressTestRunner", "Pointer to CStressTestRunner", "pSystem.add(0x3FD0).readPointer()", currentPtr);
        currentPtr = pSystem.add(16296).readPointer(); printTableRow("CSystem", 0x3FD8, "m_pHardwareMouse", "Pointer to CHardwareMouse", "pSystem.add(0x3FD8).readPointer()", currentPtr);
        currentPtr = pSystem.add(16304).readPointer(); printTableRow("CSystem", 0x3FE0, "m_pWatchdogTimer", "Pointer to CWatchdogTimer", "pSystem.add(0x3FE0).readPointer()", currentPtr);
        currentPtr = pSystem.add(16312).readPointer(); printTableRow("CSystem", 0x3FE8, "m_pStreamEngine", "Pointer to CStreamEngine", "pSystem.add(0x3FE8).readPointer()", currentPtr);
        currentPtr = pSystem.add(16320).readPointer(); printTableRow("CSystem", 0x3FF0, "m_pDownloadManager", "Pointer to IDownloadManager", "pSystem.add(0x3FF0).readPointer()", currentPtr);
        currentPtr = pSystem.add(16328).readPointer(); printTableRow("CSystem", 0x3FF8, "m_pTestProxy", "Pointer to ITestProxy", "pSystem.add(0x3FF8).readPointer()", currentPtr);
        currentPtr = pSystem.add(16336); printTableRow("CSystem", 0x4000, "m_sBuildInfoFile", "Build info file string object", "pSystem.add(0x4000)", currentPtr);
        currentPtr = pSystem.add(16344).readPointer(); printTableRow("CSystem", 0x4008, "m_updateTimes", "Map/List head for update times", "pSystem.add(0x4008).readPointer()", currentPtr);
        currentPtr = pSystem.add(16368).readPointer(); printTableRow("CSystem", 0x4020, "m_updateListeners", "Map/List head for update listeners", "pSystem.add(0x4020).readPointer()", currentPtr);
        currentPtr = pSystem.add(16408); printTableRow("CSystem", 0x4048, "m_interprocessLock", "CInterprocessLock base", "pSystem.add(0x4048)", currentPtr);
        currentPtr = pSystem.add(16464).readPointer(); printTableRow("CSystem", 0x4080, "m_systemUpdateStats", "Map/List head for update stats", "pSystem.add(0x4080).readPointer()", currentPtr);
        console.log(separator);
    } else {
        console.log("  pSystem is NULL, cannot access CSystem members.");
        console.log(separator);
    }

    // --- CStreamEngine ---
    const pStreamEngine = gEnvBase.add(320).readPointer();
    if (!pStreamEngine.isNull()) {
        printTableRow("CStreamEngine", -1, "(Base)", "Manages asset streaming", "const pStreamEngine = gEnvBase.add(320).readPointer();", pStreamEngine);
        currentPtr = pStreamEngine.add(8); printTableRow("CStreamEngine", 0x8, "m_sSourcePakFolder", "Pak folder string object", "pStreamEngine.add(0x8)", currentPtr);
        currentPtr = pStreamEngine.add(72); printTableRow("CStreamEngine", 0x48, "m_pListener", "Pointer to IStreamEngineListener", "pStreamEngine.add(0x48).readPointer()", currentPtr);
        currentPtr = pStreamEngine.add(136).readPointer(); printTableRow("CStreamEngine", 0x88, "m_InMemoryPakList", "List head for in-memory paks", "pStreamEngine.add(0x88).readPointer()", currentPtr);
        currentPtr = pStreamEngine.add(288).readPointer(); printTableRow("CStreamEngine", 0x120, "m_pCryPak", "Pointer to ICryPak", "pStreamEngine.add(0x120).readPointer()", currentPtr);
        console.log(separator);
    } else {
        console.log("  pStreamEngine is NULL");
        console.log(separator);
    }

    // --- CMemoryManager ---
    const pMemoryManager = gEnvBase.add(408).readPointer();
    if (!pMemoryManager.isNull()) {
        printTableRow("CMemoryManager", -1, "(Base)", "Manages memory allocation", "const pMemoryManager = gEnvBase.add(408).readPointer();", pMemoryManager);
        currentPtr = pMemoryManager.add(24); printTableRow("CMemoryManager", 0x18, "m_Allocators", "Array/Map of allocators", "pMemoryManager.add(0x18)", currentPtr); // Offset 24 based on sub_1471F5F20 loop
        currentPtr = pMemoryManager.add(8240); printTableRow("CMemoryManager", 0x2030, "m_sHeapName", "Heap name string object", "pMemoryManager.add(0x2030)", currentPtr);
        console.log(separator);
    } else {
        console.log("  pMemoryManager is NULL");
        console.log(separator);
    }

    // --- CJobManagerDebug ---
    //const pJobManager = gEnvBase.add(280).readPointer();
    //if (!pJobManager.isNull()) {
    //    // Assuming pJobManager points to the CJobManager, and CJobManagerDebug is a member
    //    // Need offset of CJobManagerDebug within CJobManager - let's assume 0 for now (might be wrong)
    //    const pJobManagerDebug = pJobManager.add(0); // Placeholder offset
    //    printTableRow("CJobManagerDebug", 0, "(Base)", "Debug interface for Job Manager", "const pJobManagerDebug = pJobManager.add(0);", pJobManagerDebug);
    //    currentPtr = pJobManagerDebug.add(16).readPointer(); printTableRow("CJobManagerDebug", 0x10, "m_pJobManager", "Pointer back to CJobManager", "pJobManagerDebug.add(0x10).readPointer()", currentPtr);
    //    console.log(separator);
    //} else {
    //    console.log("  pJobManager is NULL, cannot access CJobManagerDebug");
    //    console.log(separator);
    //}

    // --- CFlashUI ---
    const pFlashUI = gEnvBase.add(120).readPointer();
    if (!pFlashUI.isNull()) {
        printTableRow("CFlashUI", -1, "(Base)", "Handles Scaleform GFx UI", "const pFlashUI = gEnvBase.add(120).readPointer();", pFlashUI);
        currentPtr = pFlashUI.add(8).readPointer(); printTableRow("CFlashUI", 0x8, "m_pFlashPlayer", "Pointer to GFx Player", "pFlashUI.add(0x8).readPointer()", currentPtr);
        currentPtr = pFlashUI.add(288).readPointer(); printTableRow("CFlashUI", 0x120, "m_listenerMap", "Map head for listeners", "pFlashUI.add(0x120).readPointer()", currentPtr);
        console.log(separator);
    } else {
        console.log("  pFlashUI is NULL");
        console.log(separator);
    }

    // --- CDataCore ---
    const pDataCore = gEnvBase.add(128).readPointer();
    if (!pDataCore.isNull()) {
        printTableRow("CDataCore", -1, "(Base)", "Manages DataCore assets (DCB)", "const pDataCore = gEnvBase.add(128).readPointer();", pDataCore);
        currentPtr = pDataCore.add(8).readPointer(); printTableRow("CDataCore", 0x8, "m_pSystem", "Pointer back to ISystem", "pDataCore.add(0x8).readPointer()", currentPtr);
        currentPtr = pDataCore.add(24).readPointer(); printTableRow("CDataCore", 0x18, "m_dataTableMap", "Map head for data tables", "pDataCore.add(0x18).readPointer()", currentPtr);
        console.log(separator);
    } else {
        console.log("  pDataCore is NULL");
        console.log(separator);
    }

    // --- CPlatformOS_Windows ---
    //const pPlatformOS = gEnvBase.add(472).readPointer();
    //if (!pPlatformOS.isNull()) {
    //    printTableRow("CPlatformOS_Windows", -1, "(Base)", "Platform specific OS functions", "const pPlatformOS = gEnvBase.add(472).readPointer();", pPlatformOS);
    //    currentPtr = pPlatformOS.add(8).readPointer(); printTableRow("CPlatformOS_Windows", 0x8, "m_listeners", "List head for listeners", "pPlatformOS.add(0x8).readPointer()", currentPtr);
    //    console.log(separator);
    //} else {
    //    console.log("  pPlatformOS is NULL");
    //    console.log(separator);
    //}

    // --- CSystemUserCallback ---
    const pUserCallback = gEnvBase.add(496).readPointer();
    if (!pUserCallback.isNull()) {
        printTableRow("CSystemUserCallback", -1, "(Base)", "Handles user callbacks (progress, errors)", "const pUserCallback = gEnvBase.add(496).readPointer();", pUserCallback);
        // Members are likely function pointers or interfaces, difficult to inspect statically
        console.log(separator);
    } else {
        console.log("  pUserCallback is NULL");
        console.log(separator);
    }

    // --- CNotificationNetwork ---
    const pNotificationNetwork = gEnvBase.add(312).readPointer();
    if (!pNotificationNetwork.isNull()) {
        printTableRow("CNotificationNetwork", -1, "(Base)", "Handles network notifications", "const pNotificationNetwork = gEnvBase.add(312).readPointer();", pNotificationNetwork);
        currentPtr = pNotificationNetwork.add(400).readPointer(); printTableRow("CNotificationNetwork", 0x190, "m_listeners", "List head for listeners", "pNotificationNetwork.add(0x190).readPointer()", currentPtr);
        console.log(separator);
    } else {
        console.log("  pNotificationNetwork is NULL");
        console.log(separator);
    }

    // --- Standard Containers (Conceptual Access) ---
    printTableRow("std::map/list", -1, "(Example)", "Map/List container object", "const pMapHead = pConsole.add(24).readPointer();", "See specific structure");
    printTableRow("std::vector", -1, "(Example)", "Vector container object", "const pVecBase = pSystem.add(4752).readPointer();", "See specific structure");
    printTableRow("CryString", -1, "(Example)", "Custom string object", "const pStrObj = pSystem.add(1016);", "See specific structure");
    console.log(separator);

} // End of if (gEnvBase is valid)
