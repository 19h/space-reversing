/**
 * Frida Script for Comprehensive Component Lookup Analysis - REVISED
 *
 * This version correctly handles arguments passed directly in registers,
 * as discovered from the access violation error. It reads the component ID
 * directly from the R8 register via the InvocationContext.
 */

// --- [1] ADDRESS DEFINITIONS ---
const TARGET_MODULE = 'StarCitizen.exe';
const offsets = {
    // --- Global System ---
    pComponentSystem: ptr('0x9B4FC88'), // qword_149B4FC88
    queryInterface_vtable_index: 2,    // vtable offset 0x10

    // --- Name-to-ID Mapping ---
    // This function takes a name hash and returns the component ID.
    // We will hook this to build our own map of ID -> Name.
    GetComponentIdFromNameHash: ptr('0x6A321C0'), // sub_146A321C0

    // --- High-Level "Get" Wrappers ---
    // These are thin wrappers that call the entity's vtable.
    // Hooking them shows us when specific component types are requested.
    GetIVehicle: ptr('0x33B1A0'),           // sub_14033B1A0
    GetSCItemWeaponComponent: ptr('0x25D69E0'), // sub_1425D69E0
    GetIAttachableComponent: ptr('0x4232A0'),  // sub_1404232A0
    GetIGreenZoneObedience: ptr('0x156A1A0')   // sub_14156A1A0
};

const getterFunctionMap = {
    "IATCTokenComponent": ptr("0x33A250"),
    "IActor": ptr("0x33A380"),
    "IAirTrafficControllerDataManager": ptr("0x33A4B0"),
    "IAttachableComponent": ptr("0x33A530"),
    "IEntityComponentATCSpawnable": ptr("0x33A5B0"),
    "IEntityComponentCarryable": ptr("0x33A630"),
    "IEntityComponentObjectContainer": ptr("0x33A6B0"),
    "IEntityComponentTrackView": ptr("0x33A7E0"),
    "IEntityPhysicalProxy": ptr("0x33A860"),
    "IEntityRenderProxy": ptr("0x33A8E0"),
    "IInventoryContainerComponent": ptr("0x33A960"),
    "IItemPortContainer": ptr("0x33AB40"),
    "ILandingArea": ptr("0x33ABC0"),
    "INavSpline": ptr("0x33ACF0"),
    "ISCActorDNAComponent": ptr("0x33AD70"),
    "ISCItemPurchasable": ptr("0x33ADF0"),
    "ISCLocalPlayerChoiceComponent": ptr("0x33AE70"),
    "ISCPlayer": ptr("0x33AEF0"),
    "ISerializedComponent": ptr("0x33B020"),
    "ISubsumptionConversationComponent": ptr("0x33B0A0"),
    "ISubsumptionMissionLinkComponent": ptr("0x33B120"),
    "IVehicle": ptr("0x33B1A0"),
    "IEntityComponentNetwork": ptr("0x33FE10"),
    "IEntityComponentSuperGUID": ptr("0x3EEC30"),
    "IEntityComponentActorUsable": ptr("0x423360"),
    "IEntityComponentAtmosphereContainer": ptr("0x4233E0"),
    "IEntityComponentDefaultLoadout": ptr("0x423510"),
    "IEntityComponentDegradation": ptr("0x423590"),
    "IEntityComponentResourceContainer": ptr("0x4236C0"),
    "IEntityComponentRoom": ptr("0x423740"),
    "IEntityComponentSequencer": ptr("0x4237C0"),
    "IEntityComponentSolarSystem": ptr("0x423840"),
    "IEntityComponentUniverseHierarchy": ptr("0x4238C0"),
    "IEntityGeometryResource": ptr("0x423940"),
    "IInteractableComponent": ptr("0x4239C0"),
    "IObjectDatabank": ptr("0x423AF0"),
    "IProceduralEntity": ptr("0x423B70"),
    "ISCItemConsumable": ptr("0x423BF0"),
    "ISCItemTurret": ptr("0x423C70"),
    "ISCPlayerMissionLog": ptr("0x423E50"),
    "ISCSignatureSystem": ptr("0x423ED0"),
    "IWallet": ptr("0x423F50"),
    "ISubsumptionComponent": ptr("0x53A440"),
    "IEntityComponentObjectMetadata": ptr("0x597860"),
    "IEntityComponentHealth": ptr("0x83D7C0"),
    "IDockingHub": ptr("0x11E2FC0"),
    "IActionAreaComponent": ptr("0x12A3CF0"),
    "IAnimatedCharacter": ptr("0x12A3D70"),
    "IEntityAreaProxy": ptr("0x12A3EA0"),
    "IEntityAudioProxy": ptr("0x12A3F20"),
    "IEntityComponentCameraSource": ptr("0x12A3FA0"),
    "IEntityComponentUIBindingsVendor": ptr("0x12A40E0"),
    "IGameTokenContainer": ptr("0x12A4160"),
    "IInteractionStateMachine": ptr("0x12A4290"),
    "ISCItemUser": ptr("0x12A43C0"),
    "IEntityComponentFireArea": ptr("0x12A4DE0"),
    "IEntityTraversingTreeComponent": ptr("0x12A4F10"),
    "LawComponent": ptr("0x13578D0"),
    "IPlayerUINetworkComponent": ptr("0x138F730"),
    "MissionEntity": ptr("0x138F7B0"),
    "SubsumptionMissionComponent": ptr("0x13D6C50"),
    "IEntityComponentHostility": ptr("0x13F3740"),
    "IMissionEntity": ptr("0x13F3930"),
    "ISubsumptionMissionComponent": ptr("0x13F3A60"),
    "EntityComponentHostility": ptr("0x13F3AE0"),
    "EntityComponentHostilityComposite": ptr("0x13F3B60"),
    "SubsumptionMissionLinkComponent": ptr("0x13F3EC0"),
    "IEntityComponentUserVariables": ptr("0x1411AA0"),
    "SCPlayerMissionLog": ptr("0x1411BD0"),
    "SubsumptionDataComponent": ptr("0x1411D00"),
    "IAttentionTargetComponent": ptr("0x152AAC0"),
    "IEntityComponentRoomOccupant": ptr("0x152AE40"),
    "ILawComponent": ptr("0x152B030"),
    "ISCPlayerPUSpawningComponent": ptr("0x152C540"),
    "LegalRegistrationComponent": ptr("0x152C790"),
    "IEntityComponentUIBindingsConsumer": ptr("0x1569F00"),
    "IGreenZoneObedience": ptr("0x156A260"),
    "IPersistentComponent": ptr("0x156A5E0"),
    "EntityComponentCriminalRecordUIProvider": ptr("0x156A740"),
    "IDeliveryItemPortComponent": ptr("0x16067F0"),
    "IDialogueComponent": ptr("0x1606870"),
    "IMissionBrokerInterfaceComponent": ptr("0x1606ED0"),
    "IObjectiveMarkerComponent": ptr("0x16070D0"),
    "ISubsumptionEventReceiverComponent": ptr("0x1607210"),
    "IEntityComponentRoomConnector": ptr("0x18720C0"),
    "IEntityPhysicsController": ptr("0x1872140"),
    "IItemControlComponent": ptr("0x1872340"),
    "EntityComponentRoom": ptr("0x19095E0"),
    "IAISeatFlightControllerComponent": ptr("0x1939FD0"),
    "IMovementSystemComponent": ptr("0x193A050"),
    "SubsumptionConversationComponent": ptr("0x193A8E0"),
    "IEntityAnimationController": ptr("0x1960740"),
    "ILookComponent": ptr("0x1960880"),
    "IObservableComponent": ptr("0x1960900"),
    "ISCItemWeaponComponent": ptr("0x1960980"),
    "CoverSystemComponent": ptr("0x1962A30"),
    "IAIWeaponComponent": ptr("0x19E93F0"),
    "ICoverComponent": ptr("0x19E9470"),
    "IEntityPerceptionComponent": ptr("0x1A00590"),
    "IPathingComponent": ptr("0x1BD9460"),
    "IQuantumDrive": ptr("0x1BD94E0"),
    "IAITargetableComponent": ptr("0x1C571C0"),
    "IAmmoContainerComponent": ptr("0x1C57240"),
    "IEntityComponentGasCloud": ptr("0x1C5AB80"),
    "IEntityComponentUIAttachmentCluster": ptr("0x1D56B20"),
    "ISCCommsStageUIProvider": ptr("0x1D9E890"),
    "IEntityComponentUIOwner": ptr("0x1E3F820"),
    "IEntityComponentUIPrimitiveRenderNode": ptr("0x1E3F960"),
    "IEntityComponentUIRenderToTexture": ptr("0x1E3F9E0"),
    "IUIAudioComponent": ptr("0x1E3FB20"),
    "IEntityComponentEffects": ptr("0x1EB14E0"),
    "IEntityComponentBreakable": ptr("0x1EB7D00"),
    "IEntityComponentEMPool": ptr("0x1EB7D80"),
    "IEntityComponentRParticleFieldNode": ptr("0x1EB7EC0"),
    "EntityComponentLightningRegion": ptr("0x1EB89D0"),
    "EntityComponentParticleEffect": ptr("0x1EEDDE0"),
    "IEntityAudioControllerComponent": ptr("0x1F382E0"),
    "IEntityComponentAtmosphericEffects": ptr("0x1F6B960"),
    "IAudioPropagationComponent": ptr("0x1FA7EE0"),
    "IEntityComponentRastarUI": ptr("0x1FAE640"),
    "EntityComponentManagedEntityRegion": ptr("0x1FAE6C0"),
    "ProceduralEntity": ptr("0x1FAE740"),
    "IInteractionLinkController": ptr("0x20E7270"),
    "ISCItemControllableManager": ptr("0x20E7460"),
    "EntityTraversingTreeComponent": ptr("0x20E74E0"),
    "AsteroidFieldComponent": ptr("0x20F8280"),
    "IEntityComponentDistortion": ptr("0x212E420"),
    "IEntityComponentLightBase": ptr("0x212E4A0"),
    "IEntityComponentMisfire": ptr("0x212E520"),
    "IFacialTrackingComponent": ptr("0x212E660"),
    "IInteractorComponent": ptr("0x212E7A0"),
    "IItemResourceComponent": ptr("0x212E8E0"),
    "IItemResourceContainerPlaceholder": ptr("0x212E960"),
    "AttachableComponent": ptr("0x21344F0"),
    "ItemPortContainer": ptr("0x2134630"),
    "IAudioListenerComponent": ptr("0x22E00F0"),
    "IEntityComponentPowerConnection": ptr("0x22E02F0"),
    "AudioPropagationComponent": ptr("0x22E1110"),
    "VoiceChatRxAggregatorComponent": ptr("0x22E1190"),
    "IEntityComponentIFCS": ptr("0x240BB50"),
    "ILegalRegistrationComponent": ptr("0x240BD50"),
    "ISCActorRotationComponent": ptr("0x24BADD0"),
    "AIGroupEntityComponent": ptr("0x25D6160"),
    "AITargetableComponent": ptr("0x25D61E0"),
    "AIWeaponComponent": ptr("0x25D6260"),
    "Actor": ptr("0x25D62E0"),
    "AttentionTargetComponent": ptr("0x25D6360"),
    "EntityComponentExplosiveOrdnance": ptr("0x25D63E0"),
    "EntityPerceptionComponent": ptr("0x25D6460"),
    "Ladder": ptr("0x25D64E0"),
    "MovementSystemComponent": ptr("0x25D6560"),
    "ObjectDataBank": ptr("0x25D65E0"),
    "ObservableComponent": ptr("0x25D6660"),
    "SCActorCollisionAvoidanceComponent": ptr("0x25D66E0"),
    "SCItemAIModule": ptr("0x25D6760"),
    "SCItemMissile": ptr("0x25D67E0"),
    "SCItemNavigation": ptr("0x25D6860"),
    "SCItemQuantumDrive": ptr("0x25D68E0"),
    "SCItemTargetSelectorComponent": ptr("0x25D6960"),
    "SCItemWeaponComponent": ptr("0x25D69E0"),
    "UsableGroupCoordinator": ptr("0x25EA6D0"),
    "ActionAreaComponent": ptr("0x26623B0"),
    "EntityComponentEASpawnLocation": ptr("0x26624E0"),
    "SCActorInteractionHelper": ptr("0x2662560"),
    "SCItemInspectable": ptr("0x26625E0"),
    "SCPlayer": ptr("0x2662660"),
    "SCTransitManager": ptr("0x26626E0"),
    "AimingComponent": ptr("0x26A47E0"),
    "LookComponent": ptr("0x26A4860"),
    "SCActorAbilityComponent": ptr("0x26A48E0"),
    "SCActorRotationComponent": ptr("0x26A4960"),
    "SCItemEnergyController": ptr("0x26A49E0"),
    "SCItemThruster": ptr("0x26A4A60"),
    "SCLocalPlayerUIComponent": ptr("0x26A4B90"),
    "ISubsumptionAssignmentComponent": ptr("0x277DCA0"),
    "SCAirTrafficControllerDataManager": ptr("0x277DE80"),
    "AISpecialActionComponent": ptr("0x2940CA0"),
    "AmmoContainerComponent": ptr("0x2940D20"),
    "VisionComponent": ptr("0x2940DA0"),
    "EntityComponentHackable": ptr("0x29ABF50"),
    "EntityComponentRestrictedArea": ptr("0x29ABFD0"),
    "MagLaunchComponent": ptr("0x29AC050"),
    "RestrictedAreaComponent": ptr("0x29AC0D0"),
    "RestrictedAreaPatchComponent": ptr("0x29AC150"),
    "SCLocalPlayerComponent": ptr("0x29AC1D0"),
    "ArmouryManagerComponent": ptr("0x29F1F90"),
    "EntityComponentCargoController": ptr("0x29F20C0"),
    "EntityComponentHealth": ptr("0x29F2140"),
    "HarvestableComponent": ptr("0x29F2280"),
    "InventoryContainerComponent": ptr("0x29F2300"),
    "SCAirTrafficControllerOperatorComponent": ptr("0x29F2430"),
    "SCItemFlashlight": ptr("0x29F2530"),
    "SCPlayerGameRulesNetworkComponent": ptr("0x2A6B3F0"),
    "IEntityRopeProxy": ptr("0x2AB9680"),
    "IMarkerComponent": ptr("0x2AB9700"),
    "EntityComponentHackingController": ptr("0x2AB9780"),
    "EntityComponentMineable": ptr("0x2AB9800"),
    "EntityComponentPlayerDockingHubController": ptr("0x2AB9880"),
    "ItemControllerComponent": ptr("0x2AB99C0"),
    "ProceduralAimRigComponent": ptr("0x2AB9A40"),
    "SCActorStaminaComponent": ptr("0x2AB9AC0"),
    "SCItemAimableController": ptr("0x2AB9B40"),
    "SCItemSuitArmor": ptr("0x2AB9BC0"),
    "SCSignatureSystem": ptr("0x2AB9C40"),
    "EACriticalMessage": ptr("0x2D3D440"),
    "GameMode": ptr("0x2D3D4C0"),
    "SCElectronicAccessPlayerComponent": ptr("0x2D3D540"),
    "UIAudioComponent": ptr("0x2D3D730"),
    "SCTransitCarriage": ptr("0x2D8EC50"),
    "SCTransitGateway": ptr("0x2D8ECD0"),
    "EntityComponentInstancedInteriorManager": ptr("0x2D93D20"),
    "SCTransitPeripheral": ptr("0x2D93FD0"),
    "EntityComponentAudioEnvironmentFeedback": ptr("0x2F46090"),
    "EntityComponentSimpleRotation": ptr("0x2F46110"),
    "SCBodyHealthComponent": ptr("0x2F46190"),
    "IEntityEffectsController": ptr("0x2F4B230"),
    "AudioCommsSignalComponent": ptr("0x2F4B2B0"),
    "EntityComponentInstancedInterior": ptr("0x301DDD0"),
    "EntityComponentRaceCheckpoint": ptr("0x301DFC0"),
    "EntityComponentServiceBeaconInterface": ptr("0x301E0F0"),
    "GameRulesEAObjectiveRace": ptr("0x301E230"),
    "NavigationLinkComponent": ptr("0x301E2B0"),
    "SCEntityComponentActorMovable": ptr("0x301E3F0"),
    "SubsumptionPlatformComponent": ptr("0x301E600"),
    "EntityComponentInstancedInteriorGateway": ptr("0x302E5C0"),
    "EntityComponentHolographicVolume": ptr("0x3414D70"),
    "SCItemShopRack": ptr("0x3414DF0"),
    "SCCommsComponent": ptr("0x3415900"),
    "ProceduralPlanetAudioComponent": ptr("0x348F0A0"),
    "EntityComponentLoadoutProvider": ptr("0x3502050"),
    "SCLocalPlayerGroupVideoCallComponent": ptr("0x3502390"),
    "SCLocalPlayerMarkerTrackerComponent": ptr("0x3502410"),
    "Wallet": ptr("0x3502490"),
    "IEntityComponentSurfaceRaindrops": ptr("0x3824BB0"),
    "SCActorPhysicsController": ptr("0x3824FF0"),
    "SCItemSuitHelmet": ptr("0x3870030"),
    "EntityComponentRttAspectFocusVehicle": ptr("0x39C4D80"),
    "SCItemHoloDisplay": ptr("0x39C4E00"),
    "EACapturableEntityComponent": ptr("0x3B1F5C0"),
    "SCActorExternalForceResponseComponent": ptr("0x43C5CD0"),
    "SCItemUIViewOwner": ptr("0x43E5740"),
    "SCActorMeleeCombatComponent": ptr("0x4711530"),
    "SCATCCommsComponent": ptr("0x4B9A0A0"),
    "ISCCommsComponent": ptr("0x50ABDB0"),
    "SCCommsReceiverComponent": ptr("0x50ABE30"),
    "SCItemRestraint": ptr("0x546E0C0"),
};

// --- [2] GLOBAL STATE ---
const componentIdToName = {}; // Our map to store resolved component names.

// --- [3] SCRIPT CORE ---
try {
    console.log(`[+] Starting Component Lookup Analyzer (Register-Aware)...`);
    const module = Process.findModuleByName(TARGET_MODULE);
    if (!module) throw new Error(`Module ${TARGET_MODULE} not found.`);
    const base = module.base;

    // --- Hook High-Level Wrappers ---

    function hookGetter(name, address) {
        Interceptor.attach(address, {
            onEnter: function(args) {
                if (name === "IGreenZoneObedience") return ptr(0);

                this.entityPtr = args[0]; // 'this' pointer from RCX

                // --- THE FIX IS HERE ---
                // The component ID is passed in the 3rd argument register, R8.
                // We access it directly from the context. The `.and(0xFFFF)`
                // ensures we only get the 16-bit ID value.
                this.componentId = this.context.r8.and(0xFFFF).toUInt32();
                // --- END OF FIX ---

                // Populate our global map
                if (!componentIdToName[this.componentId]) {
                    componentIdToName[this.componentId] = name;
                }
            },
            onLeave: function(retval) {
                //if (name !== "IInventoryContainerComponent" && name !== "InventoryContainerComponent") return;
                //if (name === "IGreenZoneObedience") return;
                //if (name === "Actor") return;
                //if (name === "IActor") return;
                //if (name === "IEntityAudioControllerComponent") return;
                //if (name === "SCItemAIModule") return;
                //if (name === "IAudioListenerComponent") return;
                //if (name === "IVehicle" || name === "SCItemWeaponComponent") return;

                const componentPtr = retval.readPointer().and(0xFFFFFFFFFFFF);
                console.log(`[${name}] @ ${this.entityPtr}; ${this.componentId} ("${name}") -> ${componentPtr} (${!componentPtr.isNull() ? componentPtr.readPointer() : "NULL"})`);
            }
        });
    }

    // Loop through the comprehensive component map to hook all getters
    let hookCount = 0;
    for (const [componentName, address] of Object.entries(getterFunctionMap)) {
        hookGetter(componentName, base.add(address));
        hookCount++;
        console.log(`[+] Hook ${hookCount}: Get${componentName} at ${base.add(address)}`);
    }

    console.log(`\n[SUCCESS] All ${hookCount} hooks installed. Component lookups should now be logged correctly.`);

} catch (error) {
    console.error(`[-] An error occurred: ${error.message}\n${error.stack}`);
}
