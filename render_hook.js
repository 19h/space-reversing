// Get the base address of the module
const baseAddr = Module.findBaseAddress('StarCitizen.exe');

// Helper function to create a hook with logging
function hookFunction(address, name, implementation) {
    try {
        Interceptor.attach(ptr(baseAddr).add(address), {
            onEnter: function(args) {
                this.functionName = name;
                console.log(`[+] ${name} called from ${this.returnAddress}`);
                if (implementation && implementation.onEnter) {
                    implementation.onEnter.call(this, args);
                }
            },
            onLeave: function(retval) {
                if (implementation && implementation.onLeave) {
                    implementation.onLeave.call(this, retval);
                }
            }
        });
        console.log(`[+] Hooked ${name} at address ${ptr(baseAddr).add(address)}`);
    } catch (e) {
        console.error(`[-] Failed to hook ${name} at address ${ptr(baseAddr).add(address)}: ${e.message}`);
    }
}

// --- Generic/Helper Functions ---

hookFunction(0x1403A73E0 - 0x140000000, 'GenericVTableCall_28', {
    onEnter(args) {
        // a1: some object, a2: pointer to a smart pointer/handle
        console.log(`  - Arg1 (this): ${args[0]}`);
        console.log(`  - Arg2 (ppObject): ${args[1]}`);
        if (!args[1].isNull()) {
            const pObject = args[1].readPointer();
            console.log(`    - *ppObject: ${pObject}`);
        }
    }
});

hookFunction(0x1403B6C30 - 0x140000000, 'GetDefaultFlags', {
    onLeave(retval) {
        console.log(`  - Returned flags: ${retval.toInt32()}`);
    }
});

hookFunction(0x1403E1540 - 0x140000000, 'InitializeRenderParams', {
    onEnter(args) {
        console.log(`  - Arg1 (this): ${args[0]}`);
        console.log(`  - Arg2 (pRenderParams): ${args[1]}`);
    }
});

hookFunction(0x1403E1570 - 0x140000000, 'InitializeLargeRenderParams', {
    onEnter(args) {
        console.log(`  - Arg1 (this): ${args[0]}`);
        console.log(`  - Arg2 (pLargeRenderParams): ${args[1]}`);
    }
});

hookFunction(0x140880470 - 0x140000000, 'GetMaterial_168', {
    onEnter(args) {
        const pRenderProxy = args[0];
        const pMaterial = pRenderProxy.add(0x168).readPointer();
        console.log(`  - RenderProxy @ ${pRenderProxy}`);
        console.log(`  - Returning Material @ ${pMaterial} from offset 0x168`);
    }
});

hookFunction(0x1415A68A0 - 0x1415A68A0, 'GetSomeHandle_188', {
    onEnter(args) {
        const pRenderProxy = args[0];
        const pHandle = pRenderProxy.add(0x188).readPointer();
        console.log(`  - RenderProxy @ ${pRenderProxy}`);
        console.log(`  - Getting Handle @ ${pHandle} from offset 0x188`);
    }
});

hookFunction(0x141990B10 - 0x140000000, 'GetSlotsLock', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
    },
    onLeave(retval) {
        console.log(`  - Returned pointer to m_SlotsLock: ${retval}`);
    }
});

hookFunction(0x142204920 - 0x140000000, 'GetGlowIntensity', {
    onEnter(args) {
        const pRenderProxy = args[0];
        const intensity = pRenderProxy.add(0x1E8).readFloat();
        console.log(`  - RenderProxy @ ${pRenderProxy}`);
        console.log(`  - Getting intensity: ${intensity} from offset 0x1E8`);
    }
});

hookFunction(0x14230A5D0 - 0x140000000, 'GetRenderNode', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
    },
    onLeave(retval) {
        console.log(`  - Returned pointer to IRenderNode interface: ${retval}`);
    }
});

hookFunction(0x146A496E0 - 0x140000000, 'CreateSomeEvent_9', {
    onEnter(args) {
        console.log(`  - Arg1 (this): ${args[0]}`);
        console.log(`  - Arg2 (pEvent): ${args[1]}`);
    }
});

// --- Core RenderProxy VTable Functions ---

hookFunction(0x146A71C10 - 0x140000000, 'RenderProxy_Constructor', {
    onEnter(args) {
        console.log(`  - Constructing RenderProxy @ ${args[0]}`);
    }
});

hookFunction(0x146A752D0 - 0x140000000, 'RenderProxy_Destructor', {
    onEnter(args) {
        console.log(`  - Destructing RenderProxy @ ${args[0]}`);
    }
});

hookFunction(0x146A79200 - 0x140000000, 'RenderProxy_Delete', {
    onEnter(args) {
        console.log(`  - Deleting RenderProxy @ ${args[0]}`);
    }
});

hookFunction(0x146A793D0 - 0x140000000, 'IsVisible', {
    onEnter(args) {
        const pRenderProxy = args[0];
        const flags = pRenderProxy.add(0x80).readU32();
        console.log(`  - RenderProxy @ ${pRenderProxy} with flags 0x${flags.toString(16)}`);
    },
    onLeave(retval) {
        console.log(`  - IsVisible: ${!retval.isNull()}`);
    }
});

hookFunction(0x146A80F20 - 0x140000000, 'ApplyChunksHideMask', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - Slot Index: ${args[1].toInt32()}`);
        console.log(`  - Hide Mask: ${args[2]}`);
    }
});

hookFunction(0x146A8FD60 - 0x140000000, 'ClearHUDSubObjectSilhouettesParams', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
    }
});

hookFunction(0x146A8FEC0 - 0x140000000, 'Thunk_sub_146AB1DF0', {});

hookFunction(0x146AA8AB0 - 0x140000000, 'SyncWithEntity', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
    }
});

hookFunction(0x146AA9030 - 0x140000000, 'UpdateAllRenderNodesTransform', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
    }
});

hookFunction(0x146AB1CC0 - 0x140000000, 'ForceVisualStateOnRenderNode', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - Slot Index: ${args[1].toInt32()}`);
        console.log(`  - Visual State: @ ${args[2]}`);
    }
});

hookFunction(0x146AB27F0 - 0x140000000, 'GetClassData', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
    }
});

hookFunction(0x146AB3260 - 0x140000000, 'GetCharacter', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - Slot Index: ${args[1].toInt32()}`);
    },
    onLeave(retval) {
        console.log(`  - Returned ICharacterInstance*: ${retval}`);
    }
});

hookFunction(0x146AB5EE0 - 0x140000000, 'GetTypeId', {
    onLeave(retval) {
        console.log(`  - Returned Type ID: 0x${retval.toString(16)}`);
    }
});

hookFunction(0x146AB67C0 - 0x140000000, 'GetGlowColor', {
    onEnter(args) {
        const pRenderProxy = args[0];
        const r = pRenderProxy.add(0x1E4).readU8();
        const g = pRenderProxy.add(0x1E5).readU8();
        const b = pRenderProxy.add(0x1E6).readU8();
        const a = pRenderProxy.add(0x1E7).readU8();
        console.log(`  - RenderProxy @ ${pRenderProxy}`);
        console.log(`  - Getting Glow Color (RGBA): ${r}, ${g}, ${b}, ${a}`);
    }
});

hookFunction(0x146AB6950 - 0x140000000, 'GetOrCreateSharedRenderData', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
    }
});

hookFunction(0x146AB6E80 - 0x140000000, 'Thunk_sub_146AB6DD0', {});

hookFunction(0x146AB76F0 - 0x140000000, 'GetLocalBounds', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - pAABB output @ ${args[1]}`);
    }
});

hookFunction(0x146AB77A0 - 0x140000000, 'GetLocalBounds_IncludeChildren', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - pAABB output @ ${args[1]}`);
        console.log(`  - bIncludeChildren: ${args[2].toInt32()}`);
        console.log(`  - nWhyFlags: ${args[3].toInt32()}`);
    }
});

hookFunction(0x146AB9650 - 0x140000000, 'GetSilhouettesParams', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - pParams output @ ${args[1]}`);
    }
});

hookFunction(0x146AB9670 - 0x140000000, 'GetOnlyCharacter', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
    },
    onLeave(retval) {
        console.log(`  - Returned ICharacterInstance*: ${retval}`);
    }
});

hookFunction(0x146AB9730 - 0x140000000, 'GetOpacity', {
    onEnter(args) {
        const opacityByte = args[0].add(0x19C).readU8();
        console.log(`  - RenderProxy @ ${args[0]}, opacity byte: ${opacityByte}`);
    },
    onLeave(retval) {
        console.log(`  - Returned opacity float: ${retval.toFloat()}`);
    }
});

hookFunction(0x146AB9750 - 0x140000000, 'GetParamByIndex', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - pOutput @ ${args[1]}`);
        console.log(`  - Index: ${args[2].toInt32()}`);
    }
});

// --- Profiler String ID Getters ---
hookFunction(0x146ABB790 - 0x140000000, 'GetProfilerId_Done', {});
hookFunction(0x146ABBE50 - 0x140000000, 'GetProfilerId_Initialize', {});
hookFunction(0x146ABC510 - 0x140000000, 'GetProfilerId_PostInitialize', {});
hookFunction(0x146ABCBD0 - 0x140000000, 'GetProfilerId_RegisterWithExternalSystems', {});
hookFunction(0x146ABD290 - 0x140000000, 'GetProfilerId_SpawnBatchComplete', {});
hookFunction(0x146ABD950 - 0x140000000, 'GetProfilerId_UnregisterFromExternalSystems', {});
hookFunction(0x146ABE010 - 0x140000000, 'GetProfilerId_Unregister', {});

// --- More RenderProxy VTable Functions ---

hookFunction(0x146ABE890 - 0x140000000, 'GetRenderMaterial', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - ppMaterial output @ ${args[1]}`);
        console.log(`  - Slot Index: ${args[2].toInt32()}`);
    }
});

hookFunction(0x146ABEC30 - 0x140000000, 'GetDrawNearZ', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
    },
    onLeave(retval) {
        console.log(`  - Returned DrawNearZ: ${retval.toFloat()}`);
    }
});

hookFunction(0x146ABEC70 - 0x140000000, 'IsHidden', {
    onEnter(args) {
        const flags = args[0].add(0x194).readU32();
        console.log(`  - RenderProxy @ ${args[0]}, flags: 0x${flags.toString(16)}`);
    },
    onLeave(retval) {
        console.log(`  - IsHidden: ${!retval.isNull()}`);
    }
});

hookFunction(0x146ABED70 - 0x140000000, 'GetSkin', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - ppSkin output @ ${args[1]}`);
        console.log(`  - Slot Index: ${args[2].toInt32()}`);
    }
});

hookFunction(0x146ABEFA0 - 0x140000000, 'GetSlotCount', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
    },
    onLeave(retval) {
        console.log(`  - Slot Count: ${retval.toInt32()}`);
    }
});

hookFunction(0x146AC12B0 - 0x140000000, 'GetSlotMaterial', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - ppMaterial output @ ${args[1]}`);
        console.log(`  - Slot Index: ${args[2].toInt32()}`);
    }
});

hookFunction(0x146AC1450 - 0x140000000, 'GetSlotScale', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - pScale output @ ${args[1]}`);
        console.log(`  - Slot Index: ${args[2].toInt32()}`);
    }
});

hookFunction(0x146AC1530 - 0x140000000, 'GetSlotTintPalette', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - Slot Index: ${args[1].toInt32()}`);
    },
    onLeave(retval) {
        console.log(`  - Returned Tint Palette: ${retval}`);
    }
});

hookFunction(0x146AC8750 - 0x140000000, 'GetStreamingAndUpdateRadius', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
    },
    onLeave(retval) {
        console.log(`  - Returned Radius: ${retval.toFloat()}`);
    }
});

hookFunction(0x146AC87F0 - 0x140000000, 'GetSubObjHideMask', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - pHideMask output @ ${args[1]}`);
        console.log(`  - Slot Index: ${args[2].toInt32()}`);
    }
});

hookFunction(0x146AC9A90 - 0x140000000, 'GetVisualState', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - Slot Index: ${args[1].toInt32()}`);
    },
    onLeave(retval) {
        console.log(`  - Returned Visual State*: ${retval}`);
    }
});

hookFunction(0x146AC9C00 - 0x140000000, 'GetWorldBounds', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - pAABB output @ ${args[1]}`);
        console.log(`  - nWhyFlags: ${args[2].toInt32()}`);
    }
});

hookFunction(0x146AD01D0 - 0x140000000, 'HasGeometry', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - Slot Index: ${args[1].toInt32()}`);
    },
    onLeave(retval) {
        console.log(`  - Has Geometry: ${!retval.isNull()}`);
    }
});

hookFunction(0x146AD08A0 - 0x140000000, 'AcquireGlowIdsForSlots', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
    }
});

hookFunction(0x146AD0C50 - 0x140000000, 'InitializeRenderNode', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
    }
});

hookFunction(0x146AD1FF0 - 0x140000000, 'Thunk_UpdateAABB', {});

hookFunction(0x146AD2DC0 - 0x140000000, 'IsA', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - pTypeID @ ${args[1]}`);
    }
});

hookFunction(0x146AD36E0 - 0x140000000, 'IsHolographic', {
    onEnter(args) {
        const flags = args[0].add(0x194).readU32();
        console.log(`  - RenderProxy @ ${args[0]}, flags: 0x${flags.toString(16)}`);
    },
    onLeave(retval) {
        console.log(`  - IsHolographic: ${!retval.isNull()}`);
    }
});

hookFunction(0x146AD3960 - 0x140000000, 'IsRecentlyRendered', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
    },
    onLeave(retval) {
        console.log(`  - IsRecentlyRendered: ${!retval.isNull()}`);
    }
});

hookFunction(0x146AD9F60 - 0x140000000, 'MoveParticleEmitter', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - ppEmitter output @ ${args[1]}`);
        console.log(`  - Slot Index: ${args[2].toInt32()}`);
    }
});

hookFunction(0x146ADA970 - 0x140000000, 'MoveToZone', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - VisArea: ${args[1]}`);
        console.log(`  - pMatrix: ${args[2]}`);
        console.log(`  - a4: ${args[3].toInt32()}`);
        console.log(`  - a5: ${args[4]}`);
    }
});

hookFunction(0x146AE8B90 - 0x140000000, 'OnEntityPropertyChange', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
    }
});

hookFunction(0x146AE9CE0 - 0x140000000, 'ProcessEvent', {
    onEnter(args) {
        const pEvent = args[1];
        const eventId = pEvent.readU32();
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - Event ID: ${eventId}`);
    }
});

hookFunction(0x146AEF060 - 0x140000000, 'RegisterWithExternalSystems', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
    }
});

hookFunction(0x146AF7910 - 0x140000000, 'SetAllowBakedRenderingFlag', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - bEnable: ${args[1].toInt32()}`);
    }
});

hookFunction(0x146AF7AB0 - 0x140000000, 'SetAsHolographicObject', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - bEnable: ${args[1].toInt32()}`);
    }
});

hookFunction(0x146AF7BD0 - 0x140000000, 'SetIgnoreGI', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - bIgnore: ${args[1].toInt32()}`);
    }
});

hookFunction(0x146AF8B70 - 0x140000000, 'SetGlow', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - pColor: ${args[1]}`);
        console.log(`  - intensity: ${args[2].toFloat()}`);
    }
});

hookFunction(0x146AF8D00 - 0x140000000, 'SetSilhouettesParams', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - pColor: ${args[1]}`);
        console.log(`  - a3: ${args[2].toFloat()}`);
        console.log(`  - a4: ${args[3].toInt32()}`);
        console.log(`  - a5: ${args[4].toInt32()}`);
        console.log(`  - a6: ${args[5].toInt32()}`);
        console.log(`  - a7: ${args[6].toInt32()}`);
    }
});

hookFunction(0x146AF8F60 - 0x140000000, 'SetHUDSubObjectSilhouettesParams', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - pColor: ${args[1]}`);
        console.log(`  - a3: ${args[2].toFloat()}`);
        console.log(`  - pSubObjectIds: ${args[3]}`);
    }
});

hookFunction(0x146AF9410 - 0x140000000, 'SetLayerEffect', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - pLayerEffect: ${args[1].readPointer()}`);
    }
});

hookFunction(0x146AF94B0 - 0x140000000, 'SetMotionBlurAmount', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - Amount: ${args[1].toInt32()}`);
    }
});

hookFunction(0x146AF9690 - 0x140000000, 'SetLocalBounds', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - pAABB: ${args[1]}`);
        console.log(`  - bDoNotRecalculate: ${args[2].toInt32()}`);
    }
});

hookFunction(0x146AF9A10 - 0x140000000, 'SetLodRatio', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - lodRatio: ${args[1].toInt32()}`);
    }
});

hookFunction(0x146AFA190 - 0x140000000, 'SetSilhouettesParams_2', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - pParams: ${args[1]}`);
    }
});

hookFunction(0x146AFA1A0 - 0x140000000, 'SetOpacity', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - Opacity: ${args[1].toFloat()}`);
    }
});

hookFunction(0x146AFA1F0 - 0x140000000, 'SetParam', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - Index: ${args[1].toInt32()}`);
        console.log(`  - pValue: ${args[2]}`);
    }
});

hookFunction(0x146AFBB00 - 0x140000000, 'SetHidden', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - bHide: ${args[1].toInt32()}`);
    }
});

hookFunction(0x146AFC190 - 0x140000000, 'SetSlotGeometry', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - Slot Index: ${args[1].toInt32()}`);
        console.log(`  - pStatObj: ${args[2].readPointer()}`);
        console.log(`  - bCompound: ${args[3].toInt32()}`);
    }
});

hookFunction(0x146AFC5A0 - 0x140000000, 'SetSlotMaterial', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - Slot Index: ${args[1].toInt32()}`);
        console.log(`  - pMaterial: ${args[2].readPointer()}`);
    }
});

hookFunction(0x146AFC730 - 0x140000000, 'SetSlotScale', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - Slot Index: ${args[1].toInt32()}`);
        console.log(`  - pScaleVec: ${args[2]}`);
    }
});

hookFunction(0x146AFC850 - 0x140000000, 'SetSlotTintPalette', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - Slot Index: ${args[1].toInt32()}`);
        console.log(`  - pPalette: ${args[2]}`);
    }
});

hookFunction(0x146AFD060 - 0x140000000, 'SetSubObjHideMask', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - Slot Index: ${args[1].toInt32()}`);
        console.log(`  - Hide Mask: ${args[2].readU64()}`);
    }
});

hookFunction(0x146AFD180 - 0x140000000, 'SetSunShadowModeFlags', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - Flags: ${args[1].toInt32()}`);
    }
});

hookFunction(0x146AFD990 - 0x140000000, 'SetTintPalette', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - pPalette: ${args[1]}`);
    }
});

hookFunction(0x146AFDBD0 - 0x140000000, 'SetTintPaletteOverride', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - Palette Name: ${args[1].readUtf8String()}`);
    }
});

hookFunction(0x146AFDC90 - 0x140000000, 'SetViewDistRatio', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - Ratio: ${args[1].toInt32()}`);
    }
});

hookFunction(0x146B082D0 - 0x140000000, 'UnregisterFromExternalSystems', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
    }
});

hookFunction(0x146B0DDD0 - 0x140000000, 'UpdateSlotLocalTransform', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - Slot Index: ${args[1].toInt32()}`);
        console.log(`  - pMatrix: ${args[2]}`);
    }
});

hookFunction(0x146B0E6D0 - 0x140000000, 'UpdateRenderNodeFlags', {
    onEnter(args) {
        console.log(`  - RenderProxy @ ${args[0]}`);
        console.log(`  - Flags: ${args[1].toInt32()}`);
    }
});

hookFunction(0x146B0F950 - 0x140000000, 'CreateOnAnimEvent', {
    onEnter(args) {
        console.log(`  - Arg1 (this): ${args[0]}`);
        console.log(`  - Arg2 (pEvent): ${args[1]}`);
    }
});

hookFunction(0x146B0FEF0 - 0x140000000, 'CreateSomeEvent_2', {
    onEnter(args) {
        console.log(`  - Arg1 (this): ${args[0]}`);
        console.log(`  - Arg2 (pEvent): ${args[1]}`);
    }
});

hookFunction(0x146B0FFE0 - 0x140000000, 'CreateSomeEvent_9_with_3C', {
    onEnter(args) {
        console.log(`  - Arg1 (this): ${args[0]}`);
        console.log(`  - Arg2 (pEvent): ${args[1]}`);
    }
});
