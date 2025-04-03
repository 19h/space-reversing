#include <winsock2.h>
#include <winsock.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <dbghelp.h>
#include <psapi.h>
#include <ws2tcpip.h>
#include <math.h>
#include <intrin.h>  /* For __int64, etc. on MSVC */
#include "hook.c"    /* MinHook header */
#include <direct.h>  /* For _mkdir, etc. */

/*
; =============== S U B R O U T I N E =======================================
;
; Sets the ammo count for an ammo container component, clamps the value, updates
; internal state, triggers related component updates, and optionally notifies
; listeners.
;
; Logic:
; 1. Reads the current ammo count (`oldAmmoCount`) from
;    `pAmmoContainerComponent + 244`.
; 2. Reads the ammo capacity using `GetAmmoCapacityFromComponent` (offset +240).
; 3. Clamps the input `newAmmoCountRaw` to the range [0, capacity], storing in
;    `newAmmoCountClamped`.
; 4. If the count changed (`oldAmmoCount != newAmmoCountClamped`):
;    a. Updates the stored count (`pAmmoContainerComponent + 244`).
;    b. Checks an entity flag via vtable +1808 on the entity handle
;       (`pAmmoContainerComponent + 8`). If set, recalculates total count
;       (`CalculateTotalAmmoCount`) and updates state flags/values at offsets
;       +208 and +216 using `UpdateValidationStateFlag`.
;    c. Checks a string field on a related component (`GetObjectFieldOffset64` ->
;       field +96). If the string is valid AND the ammo count crossed the zero
;       threshold (`!oldAmmoCount || !newAmmoCountClamped`):
;       i. Retrieves the 'IEntityGeometryResource' interface for the entity.
;       ii. If valid, calls vtable +1400 (if ammo > 0) or +1392 (if ammo == 0)
;           on the interface, passing a custom string allocated from the related
;           component's string field.
;    d. If a float state object exists (`pAmmoContainerComponent + 312`):
;       i. Calculates the ammo ratio (current / capacity).
;       ii. Calls `UpdateFloatStateAndCompare_SSE` on the float state object
;           with the ratio and another float from the related component (`field_90`).
;    e. If another related component field (+176) is non-NULL:
;       i. Retrieves the 'IEntityGeometryResource' interface for the entity.
;       ii. Navigates through intermediate objects via vtable calls (+1536, +72).
;       iii. Iterates through a list associated with the related component (+152).
;       iv. For each list item, gets a target component (vtable +104), determines
;           a boolean state based on whether `newAmmoCountClamped` is below a
;           threshold in the list item, and calls vtable +96 on the target
;           component with the boolean state.
; 5. If `notificationFlag` is 2 (always) or 1 (on change) AND the count changed:
;    a. Calls `NotifyListenersLocked` with the listener set at
;       `pAmmoContainerComponent + 264`, passing relevant arguments including
;       old/new counts and capacity.
; 6. Returns the clamped ammo count (`newAmmoCountClamped`) if no notification
;    was sent, otherwise returns the result of `NotifyListenersLocked`.
;
; Parameters:
;   pAmmoContainerComponent: Pointer to the ammo container component structure.
;   newAmmoCountRaw: The desired new ammo count (signed int).
;   notificationFlag: Flag controlling listener notification (0=never, 1=on change, 2=always).
;
; Return Value:
;   Returns the final clamped ammo count or the result of `NotifyListenersLocked`.

                              ; __int64 __fastcall SetAmmoCountAndUpdateState(__int64, int, char)
                              SetAmmoCountAndUpdateState proc near    ; CODE XREF: sub_143B25240+24B↑p
                                                                      ; sub_1457E3840+FC↑p ...

                              var_1B8         = qword ptr -1B8h
                              var_1B0         = qword ptr -1B0h
                              var_1A8         = qword ptr -1A8h
                              var_198         = dword ptr -198h
                              var_194         = byte ptr -194h
                              var_190         = dword ptr -190h
                              var_188         = qword ptr -188h
                              var_180         = dword ptr -180h
                              var_178         = dword ptr -178h
                              var_174         = dword ptr -174h
                              var_170         = dword ptr -170h
                              var_16C         = dword ptr -16Ch
                              var_168         = dword ptr -168h
                              var_164         = dword ptr -164h
                              var_160         = dword ptr -160h
                              var_158         = qword ptr -158h
                              var_150         = qword ptr -150h
                              var_148         = dword ptr -148h
                              var_144         = dword ptr -144h
                              var_140         = dword ptr -140h
                              var_13C         = dword ptr -13Ch
                              var_138         = dword ptr -138h
                              var_134         = dword ptr -134h
                              var_130         = qword ptr -130h
                              var_128         = qword ptr -128h
                              var_120         = qword ptr -120h
                              var_118         = qword ptr -118h
                              var_110         = qword ptr -110h
                              var_108         = qword ptr -108h
                              var_100         = qword ptr -100h
                              var_F8          = qword ptr -0F8h
                              var_F0          = qword ptr -0F0h
                              var_E8          = qword ptr -0E8h
                              var_E0          = qword ptr -0E0h
                              var_D8          = qword ptr -0D8h
                              var_D0          = qword ptr -0D0h
                              var_C8          = qword ptr -0C8h
                              var_C0          = qword ptr -0C0h
                              var_B8          = qword ptr -0B8h
                              var_B0          = qword ptr -0B0h
                              var_A8          = qword ptr -0A8h
                              var_A0          = qword ptr -0A0h
                              var_98          = qword ptr -98h
                              var_90          = qword ptr -90h
                              var_88          = qword ptr -88h
                              var_80          = qword ptr -80h
                              var_78          = qword ptr -78h
                              var_70          = qword ptr -70h
                              var_68          = qword ptr -68h
                              var_60          = qword ptr -60h
                              var_58          = qword ptr -58h
                              var_50          = qword ptr -50h
                              var_48          = qword ptr -48h
                              var_40          = qword ptr -40h
                              var_38          = qword ptr -38h
                              var_30          = qword ptr -30h
                              var_28          = qword ptr -28h
                              var_20          = qword ptr -20h
                              var_18          = qword ptr -18h
                              arg_0           = qword ptr  8
                              arg_8           = dword ptr  10h
                              arg_10          = byte ptr  18h

44 88 44 24 18                                mov     [rsp+arg_10], r8b
89 54 24 10                                   mov     [rsp+arg_8], edx
48 89 4C 24 08                                mov     [rsp+arg_0], rcx
48 81 EC D8 01 00 00                          sub     rsp, 1D8h
48 8B 84 24 E0 01 00 00                       mov     rax, [rsp+1D8h+arg_0]
8B 80 F4 00 00 00                             mov     eax, [rax+0F4h]
89 44 24 48                                   mov     [rsp+1D8h+var_190], eax
48 8B 8C 24 E0 01 00 00                       mov     rcx, [rsp+1D8h+arg_0]
E8 8C 6D FE FF                                call    GetAmmoCapacityFromComponent
89 44 24 58                                   mov     [rsp+1D8h+var_180], eax
83 BC 24 E8 01 00 00 00                       cmp     [rsp+1D8h+arg_8], 0
7D 0A                                         jge     short loc_145811B1C
C7 44 24 64 00 00 00 00                       mov     [rsp+1D8h+var_174], 0
EB 2A                                         jmp     short loc_145811B46
                              ; ---------------------------------------------------------------------------

                              loc_145811B1C:                          ; CODE XREF: SetAmmoCountAndUpdateState+40↑j
8B 44 24 58                                   mov     eax, [rsp+1D8h+var_180]
39 84 24 E8 01 00 00                          cmp     [rsp+1D8h+arg_8], eax
7D 0D                                         jge     short loc_145811B36
8B 84 24 E8 01 00 00                          mov     eax, [rsp+1D8h+arg_8]
89 44 24 60                                   mov     [rsp+1D8h+var_178], eax
EB 08                                         jmp     short loc_145811B3E
                              ; ---------------------------------------------------------------------------

                              loc_145811B36:                          ; CODE XREF: SetAmmoCountAndUpdateState+57↑j
8B 44 24 58                                   mov     eax, [rsp+1D8h+var_180]
89 44 24 60                                   mov     [rsp+1D8h+var_178], eax

                              loc_145811B3E:                          ; CODE XREF: SetAmmoCountAndUpdateState+64↑j
8B 44 24 60                                   mov     eax, [rsp+1D8h+var_178]
89 44 24 64                                   mov     [rsp+1D8h+var_174], eax

                              loc_145811B46:                          ; CODE XREF: SetAmmoCountAndUpdateState+4A↑j
8B 44 24 64                                   mov     eax, [rsp+1D8h+var_174]
89 44 24 40                                   mov     [rsp+1D8h+var_198], eax
8B 44 24 40                                   mov     eax, [rsp+1D8h+var_198]
39 44 24 48                                   cmp     [rsp+1D8h+var_190], eax
0F 84 3E 06 00 00                             jz      loc_14581219A
48 8B 84 24 E0 01 00 00                       mov     rax, [rsp+1D8h+arg_0]
8B 4C 24 40                                   mov     ecx, [rsp+1D8h+var_198]
89 88 F4 00 00 00                             mov     [rax+0F4h], ecx
48 8B 84 24 E0 01 00 00                       mov     rax, [rsp+1D8h+arg_0]
48 8B 40 08                                   mov     rax, [rax+8]
48 89 84 24 10 01 00 00                       mov     [rsp+1D8h+var_C8], rax
48 8D 8C 24 10 01 00 00                       lea     rcx, [rsp+1D8h+var_C8]
E8 91 AE AF FA                                call    GetLower48Bits
48 89 84 24 C8 00 00 00                       mov     [rsp+1D8h+var_110], rax
48 8B 84 24 C8 00 00 00                       mov     rax, [rsp+1D8h+var_110]
48 8B 00                                      mov     rax, [rax]
48 8B 8C 24 C8 00 00 00                       mov     rcx, [rsp+1D8h+var_110]
FF 90 10 07 00 00                             call    qword ptr [rax+710h]
0F B6 C0                                      movzx   eax, al
85 C0                                         test    eax, eax
74 49                                         jz      short loc_145811C00
48 8B 8C 24 E0 01 00 00                       mov     rcx, [rsp+1D8h+arg_0]
E8 4C 77 FD FF                                call    CalculateTotalAmmoCount
89 84 24 90 00 00 00                          mov     [rsp+1D8h+var_148], eax
48 8B 84 24 E0 01 00 00                       mov     rax, [rsp+1D8h+arg_0]
48 05 D0 00 00 00                             add     rax, 0D0h
48 89 84 24 D0 00 00 00                       mov     [rsp+1D8h+var_108], rax
48 8B 8C 24 D0 00 00 00                       mov     rcx, [rsp+1D8h+var_108]
E8 02 DD BA FA                                call    UpdateValidationStateFlag
48 8B 84 24 D0 00 00 00                       mov     rax, [rsp+1D8h+var_108]
8B 8C 24 90 00 00 00                          mov     ecx, [rsp+1D8h+var_148]
89 48 08                                      mov     [rax+8], ecx

                              loc_145811C00:                          ; CODE XREF: SetAmmoCountAndUpdateState+E5↑j
48 8B 8C 24 E0 01 00 00                       mov     rcx, [rsp+1D8h+arg_0]
E8 33 F0 B1 FA                                call    GetObjectFieldOffset64
48 89 84 24 18 01 00 00                       mov     [rsp+1D8h+var_C0], rax
48 8B 84 24 18 01 00 00                       mov     rax, [rsp+1D8h+var_C0]
48 83 C0 60                                   add     rax, 60h ; '`'
48 8B C8                                      mov     rcx, rax
E8 67 ED BC FA                                call    IsNullOrPointsToNullByte
0F B6 C0                                      movzx   eax, al
85 C0                                         test    eax, eax
0F 85 D1 01 00 00                             jnz     loc_145811E05
83 7C 24 48 00                                cmp     [rsp+1D8h+var_190], 0
74 0B                                         jz      short loc_145811C46
83 7C 24 40 00                                cmp     [rsp+1D8h+var_198], 0
0F 85 BF 01 00 00                             jnz     loc_145811E05

                              loc_145811C46:                          ; CODE XREF: SetAmmoCountAndUpdateState+169↑j
48 8D 15 87 F4 B6 FA                          lea     rdx, sub_1403810D4
33 C9                                         xor     ecx, ecx        ; Parameter
E8 5C FA A8 FA                                call    __StarEngineModule__
48 8B 84 24 E0 01 00 00                       mov     rax, [rsp+1D8h+arg_0]
48 8B 40 08                                   mov     rax, [rax+8]
48 89 84 24 20 01 00 00                       mov     [rsp+1D8h+var_B8], rax
48 8B 94 24 20 01 00 00                       mov     rdx, [rsp+1D8h+var_B8]
48 8D 8C 24 28 01 00 00                       lea     rcx, [rsp+1D8h+var_B0]
E8 53 5F 58 FC                                call    GetEntityGeometryResourceInterfaceFromHandle
48 8B 84 24 28 01 00 00                       mov     rax, [rsp+1D8h+var_B0]
48 89 84 24 30 01 00 00                       mov     [rsp+1D8h+var_A8], rax
48 8B 84 24 30 01 00 00                       mov     rax, [rsp+1D8h+var_A8]
48 89 84 24 D8 00 00 00                       mov     [rsp+1D8h+var_100], rax
48 8D 8C 24 D8 00 00 00                       lea     rcx, [rsp+1D8h+var_100]
E8 F6 AB AF FA                                call    ValidateHandleType2OrDispatch
0F B6 C0                                      movzx   eax, al
85 C0                                         test    eax, eax
75 0B                                         jnz     short loc_145811CBC
48 C7 44 24 50 00 00 00 00                    mov     [rsp+1D8h+var_188], 0
EB 1D                                         jmp     short loc_145811CD9
                              ; ---------------------------------------------------------------------------

                              loc_145811CBC:                          ; CODE XREF: SetAmmoCountAndUpdateState+1DF↑j
48 B8 FF FF FF FF FF FF 00 00                 mov     rax, 0FFFFFFFFFFFFh
48 8B 8C 24 D8 00 00 00                       mov     rcx, [rsp+1D8h+var_100]
48 23 C8                                      and     rcx, rax
48 8B C1                                      mov     rax, rcx
48 89 44 24 50                                mov     [rsp+1D8h+var_188], rax

                              loc_145811CD9:                          ; CODE XREF: SetAmmoCountAndUpdateState+1EA↑j
48 83 7C 24 50 00                             cmp     [rsp+1D8h+var_188], 0
0F 84 20 01 00 00                             jz      loc_145811E05
83 7C 24 40 00                                cmp     [rsp+1D8h+var_198], 0
0F 85 8D 00 00 00                             jnz     loc_145811D7D
48 8B 44 24 50                                mov     rax, [rsp+1D8h+var_188]
48 8B 00                                      mov     rax, [rax]
48 8B 80 70 05 00 00                          mov     rax, [rax+570h]
48 89 84 24 48 01 00 00                       mov     [rsp+1D8h+var_90], rax
48 8B 05 2A 86 F1 03                          mov     rax, cs:off_14972A338 ; "Weapon"
48 89 84 24 40 01 00 00                       mov     [rsp+1D8h+var_98], rax
48 8B 8C 24 E0 01 00 00                       mov     rcx, [rsp+1D8h+arg_0]
E8 1D EF B1 FA                                call    GetObjectFieldOffset64
48 89 84 24 38 01 00 00                       mov     [rsp+1D8h+var_A0], rax
48 8B 84 24 38 01 00 00                       mov     rax, [rsp+1D8h+var_A0]
48 83 C0 60                                   add     rax, 60h ; '`'
48 8B C8                                      mov     rcx, rax
E8 81 A5 B6 FA                                call    GetPointerOrDefaultSource
48 8B D0                                      mov     rdx, rax
48 8D 8C 24 E0 00 00 00                       lea     rcx, [rsp+1D8h+var_F8]
E8 C1 5B B4 FA                                call    AllocateAndAssignCustomString
4C 8B 84 24 40 01 00 00                       mov     r8, [rsp+1D8h+var_98]
48 8D 94 24 E0 00 00 00                       lea     rdx, [rsp+1D8h+var_F8]
48 8B 4C 24 50                                mov     rcx, [rsp+1D8h+var_188]
FF 94 24 48 01 00 00                          call    [rsp+1D8h+var_90]
48 8D 8C 24 E0 00 00 00                       lea     rcx, [rsp+1D8h+var_F8] ; void *
E8 E8 B4 B5 FA                                call    ReleaseCustomStringObject
E9 88 00 00 00                                jmp     loc_145811E05
                              ; ---------------------------------------------------------------------------

                              loc_145811D7D:                          ; CODE XREF: SetAmmoCountAndUpdateState+21A↑j
48 8B 44 24 50                                mov     rax, [rsp+1D8h+var_188]
48 8B 00                                      mov     rax, [rax]
48 8B 80 78 05 00 00                          mov     rax, [rax+578h]
48 89 84 24 60 01 00 00                       mov     [rsp+1D8h+var_78], rax
48 8B 05 9D 85 F1 03                          mov     rax, cs:off_14972A338 ; "Weapon"
48 89 84 24 58 01 00 00                       mov     [rsp+1D8h+var_80], rax
48 8B 8C 24 E0 01 00 00                       mov     rcx, [rsp+1D8h+arg_0]
E8 90 EE B1 FA                                call    GetObjectFieldOffset64
48 89 84 24 50 01 00 00                       mov     [rsp+1D8h+var_88], rax
48 8B 84 24 50 01 00 00                       mov     rax, [rsp+1D8h+var_88]
48 83 C0 60                                   add     rax, 60h ; '`'
48 8B C8                                      mov     rcx, rax
E8 F4 A4 B6 FA                                call    GetPointerOrDefaultSource
48 8B D0                                      mov     rdx, rax
48 8D 8C 24 E8 00 00 00                       lea     rcx, [rsp+1D8h+var_F0]
E8 34 5B B4 FA                                call    AllocateAndAssignCustomString
4C 8B 84 24 58 01 00 00                       mov     r8, [rsp+1D8h+var_80]
48 8D 94 24 E8 00 00 00                       lea     rdx, [rsp+1D8h+var_F0]
48 8B 4C 24 50                                mov     rcx, [rsp+1D8h+var_188]
FF 94 24 60 01 00 00                          call    [rsp+1D8h+var_78]
48 8D 8C 24 E8 00 00 00                       lea     rcx, [rsp+1D8h+var_F0] ; void *
E8 5B B4 B5 FA                                call    ReleaseCustomStringObject

                              loc_145811E05:                          ; CODE XREF: SetAmmoCountAndUpdateState+15E↑j
                                                                      ; SetAmmoCountAndUpdateState+170↑j ...
48 8B 84 24 E0 01 00 00                       mov     rax, [rsp+1D8h+arg_0]
48 8B 80 38 01 00 00                          mov     rax, [rax+138h]
48 89 84 24 68 01 00 00                       mov     [rsp+1D8h+var_70], rax
48 83 BC 24 68 01 00 00 00                    cmp     [rsp+1D8h+var_70], 0
0F 84 C3 00 00 00                             jz      loc_145811EEE
48 8B 8C 24 E0 01 00 00                       mov     rcx, [rsp+1D8h+arg_0]
E8 58 6A FE FF                                call    GetAmmoCapacityFromComponent
85 C0                                         test    eax, eax
7E 35                                         jle     short loc_145811E71
C5 FA 2A 44 24 40                             vcvtsi2ss xmm0, xmm0, [rsp+1D8h+var_198]
C5 FA 11 84 24 94 00 00 00                    vmovss  [rsp+1D8h+var_144], xmm0
48 8B 8C 24 E0 01 00 00                       mov     rcx, [rsp+1D8h+arg_0]
E8 38 6A FE FF                                call    GetAmmoCapacityFromComponent
C5 FA 2A C0                                   vcvtsi2ss xmm0, xmm0, eax
C5 FA 10 8C 24 94 00 00 00                    vmovss  xmm1, [rsp+1D8h+var_144]
C5 F2 5E C0                                   vdivss  xmm0, xmm1, xmm0
C5 FA 11 44 24 68                             vmovss  [rsp+1D8h+var_170], xmm0
EB 0A                                         jmp     short loc_145811E7B
                              ; ---------------------------------------------------------------------------

                              loc_145811E71:                          ; CODE XREF: SetAmmoCountAndUpdateState+36A↑j
C5 F8 57 C0                                   vxorps  xmm0, xmm0, xmm0
C5 FA 11 44 24 68                             vmovss  [rsp+1D8h+var_170], xmm0

                              loc_145811E7B:                          ; CODE XREF: SetAmmoCountAndUpdateState+39F↑j
C5 FA 10 44 24 68                             vmovss  xmm0, [rsp+1D8h+var_170]
C5 FA 11 84 24 9C 00 00 00                    vmovss  [rsp+1D8h+var_13C], xmm0
48 8B 84 24 C0 01 00 00                       mov     rax, [rsp+1D8h+var_18]
48 89 84 24 F0 00 00 00                       mov     [rsp+1D8h+var_E8], rax
48 8B 84 24 E0 01 00 00                       mov     rax, [rsp+1D8h+arg_0]
48 8B 80 38 01 00 00                          mov     rax, [rax+138h]
48 89 84 24 F0 00 00 00                       mov     [rsp+1D8h+var_E8], rax
48 8B 8C 24 E0 01 00 00                       mov     rcx, [rsp+1D8h+arg_0]
E8 82 ED B1 FA                                call    GetObjectFieldOffset64
C5 FA 10 80 90 00 00 00                       vmovss  xmm0, dword ptr [rax+90h]
C5 FA 11 84 24 98 00 00 00                    vmovss  [rsp+1D8h+var_140], xmm0
C5 FA 10 94 24 98 00 00 00                    vmovss  xmm2, [rsp+1D8h+var_140]
C5 FA 10 8C 24 9C 00 00 00                    vmovss  xmm1, [rsp+1D8h+var_13C]
48 8B 8C 24 F0 00 00 00                       mov     rcx, [rsp+1D8h+var_E8]
E8 32 2E 64 FD                                call    UpdateFloatStateAndCompare_SSE

                              loc_145811EEE:                          ; CODE XREF: SetAmmoCountAndUpdateState+355↑j
48 8B 8C 24 E0 01 00 00                       mov     rcx, [rsp+1D8h+arg_0]
E8 45 ED B1 FA                                call    GetObjectFieldOffset64
48 05 98 00 00 00                             add     rax, 98h
48 89 84 24 08 01 00 00                       mov     [rsp+1D8h+var_D0], rax
48 8B 84 24 08 01 00 00                       mov     rax, [rsp+1D8h+var_D0]
48 83 78 18 00                                cmp     qword ptr [rax+18h], 0
75 0A                                         jnz     short loc_145811F22
C7 44 24 6C 01 00 00 00                       mov     [rsp+1D8h+var_16C], 1
EB 08                                         jmp     short loc_145811F2A
                              ; ---------------------------------------------------------------------------

                              loc_145811F22:                          ; CODE XREF: SetAmmoCountAndUpdateState+446↑j
C7 44 24 6C 00 00 00 00                       mov     [rsp+1D8h+var_16C], 0

                              loc_145811F2A:                          ; CODE XREF: SetAmmoCountAndUpdateState+450↑j
0F B6 44 24 6C                                movzx   eax, byte ptr [rsp+1D8h+var_16C]
85 C0                                         test    eax, eax
0F 85 63 02 00 00                             jnz     loc_14581219A
48 8D 15 96 F1 B6 FA                          lea     rdx, sub_1403810D4
33 C9                                         xor     ecx, ecx        ; Parameter
E8 6B F7 A8 FA                                call    __StarEngineModule__
48 8B 84 24 E0 01 00 00                       mov     rax, [rsp+1D8h+arg_0]
48 8B 40 08                                   mov     rax, [rax+8]
48 89 84 24 70 01 00 00                       mov     [rsp+1D8h+var_68], rax
48 8B 94 24 70 01 00 00                       mov     rdx, [rsp+1D8h+var_68]
48 8D 8C 24 78 01 00 00                       lea     rcx, [rsp+1D8h+var_60]
E8 62 5C 58 FC                                call    GetEntityGeometryResourceInterfaceFromHandle
48 8B 84 24 78 01 00 00                       mov     rax, [rsp+1D8h+var_60]
48 89 84 24 80 01 00 00                       mov     [rsp+1D8h+var_58], rax
48 8B 84 24 80 01 00 00                       mov     rax, [rsp+1D8h+var_58]
48 89 84 24 F8 00 00 00                       mov     [rsp+1D8h+var_E0], rax
48 8D 8C 24 F8 00 00 00                       lea     rcx, [rsp+1D8h+var_E0]
E8 05 A9 AF FA                                call    ValidateHandleType2OrDispatch
0F B6 C0                                      movzx   eax, al
85 C0                                         test    eax, eax
0F 84 F4 01 00 00                             jz      loc_14581219A
48 B8 FF FF FF FF FF FF 00 00                 mov     rax, 0FFFFFFFFFFFFh
48 8B 8C 24 F8 00 00 00                       mov     rcx, [rsp+1D8h+var_E0]
48 23 C8                                      and     rcx, rax
48 8B C1                                      mov     rax, rcx
48 89 84 24 00 01 00 00                       mov     [rsp+1D8h+var_D8], rax
48 8B 84 24 00 01 00 00                       mov     rax, [rsp+1D8h+var_D8]
48 8B 00                                      mov     rax, [rax]
48 8B 8C 24 00 01 00 00                       mov     rcx, [rsp+1D8h+var_D8]
FF 90 00 06 00 00                             call    qword ptr [rax+600h]
48 89 84 24 A8 00 00 00                       mov     [rsp+1D8h+var_130], rax
48 83 BC 24 A8 00 00 00 00                    cmp     [rsp+1D8h+var_130], 0
0F 84 A4 01 00 00                             jz      loc_14581219A
48 8B 84 24 A8 00 00 00                       mov     rax, [rsp+1D8h+var_130]
48 8B 00                                      mov     rax, [rax]
48 8B 8C 24 A8 00 00 00                       mov     rcx, [rsp+1D8h+var_130]
FF 50 48                                      call    qword ptr [rax+48h]
48 89 84 24 B8 00 00 00                       mov     [rsp+1D8h+var_120], rax
48 83 BC 24 B8 00 00 00 00                    cmp     [rsp+1D8h+var_120], 0
0F 84 77 01 00 00                             jz      loc_14581219A
48 8B 84 24 08 01 00 00                       mov     rax, [rsp+1D8h+var_D0]
48 89 84 24 B0 00 00 00                       mov     [rsp+1D8h+var_128], rax
48 8B 84 24 B0 00 00 00                       mov     rax, [rsp+1D8h+var_128]
48 8B 40 10                                   mov     rax, [rax+10h]
48 89 84 24 80 00 00 00                       mov     [rsp+1D8h+var_158], rax
48 8B 84 24 B0 00 00 00                       mov     rax, [rsp+1D8h+var_128]
48 6B 40 18 28                                imul    rax, [rax+18h], 28h ; '('
48 8B 8C 24 B0 00 00 00                       mov     rcx, [rsp+1D8h+var_128]
48 03 41 10                                   add     rax, [rcx+10h]
48 89 84 24 88 01 00 00                       mov     [rsp+1D8h+var_50], rax
EB 14                                         jmp     short loc_14581207E
                              ; ---------------------------------------------------------------------------

                              loc_14581206A:                          ; CODE XREF: SetAmmoCountAndUpdateState:loc_145812195↓j
48 8B 84 24 80 00 00 00                       mov     rax, [rsp+1D8h+var_158]
48 83 C0 28                                   add     rax, 28h ; '('
48 89 84 24 80 00 00 00                       mov     [rsp+1D8h+var_158], rax

                              loc_14581207E:                          ; CODE XREF: SetAmmoCountAndUpdateState+598↑j
48 8B 84 24 88 01 00 00                       mov     rax, [rsp+1D8h+var_50]
48 39 84 24 80 00 00 00                       cmp     [rsp+1D8h+var_158], rax
0F 84 06 01 00 00                             jz      loc_14581219A
48 8B 84 24 80 00 00 00                       mov     rax, [rsp+1D8h+var_158]
48 89 84 24 88 00 00 00                       mov     [rsp+1D8h+var_150], rax
48 8B 84 24 B8 00 00 00                       mov     rax, [rsp+1D8h+var_120]
48 8B 00                                      mov     rax, [rax]
48 8B 40 68                                   mov     rax, [rax+68h]
48 89 84 24 90 01 00 00                       mov     [rsp+1D8h+var_48], rax
48 8B 84 24 88 00 00 00                       mov     rax, [rsp+1D8h+var_150]
8B 50 20                                      mov     edx, [rax+20h]
48 8B 8C 24 B8 00 00 00                       mov     rcx, [rsp+1D8h+var_120]
FF 94 24 90 01 00 00                          call    [rsp+1D8h+var_48]
48 89 84 24 C0 00 00 00                       mov     [rsp+1D8h+var_118], rax
48 83 BC 24 C0 00 00 00 00                    cmp     [rsp+1D8h+var_118], 0
0F 84 A9 00 00 00                             jz      loc_145812195
48 8B 84 24 88 00 00 00                       mov     rax, [rsp+1D8h+var_150]
8B 40 18                                      mov     eax, [rax+18h]
39 44 24 40                                   cmp     [rsp+1D8h+var_198], eax
7C 12                                         jl      short loc_14581210F
48 8B 84 24 88 00 00 00                       mov     rax, [rsp+1D8h+var_150]
0F B6 40 1C                                   movzx   eax, byte ptr [rax+1Ch]
89 44 24 74                                   mov     [rsp+1D8h+var_164], eax
EB 2A                                         jmp     short loc_145812139
                              ; ---------------------------------------------------------------------------

                              loc_14581210F:                          ; CODE XREF: SetAmmoCountAndUpdateState+62B↑j
48 8B 84 24 88 00 00 00                       mov     rax, [rsp+1D8h+var_150]
0F B6 40 1C                                   movzx   eax, byte ptr [rax+1Ch]
85 C0                                         test    eax, eax
75 0A                                         jnz     short loc_145812129
C7 44 24 70 01 00 00 00                       mov     [rsp+1D8h+var_168], 1
EB 08                                         jmp     short loc_145812131
                              ; ---------------------------------------------------------------------------

                              loc_145812129:                          ; CODE XREF: SetAmmoCountAndUpdateState+64D↑j
C7 44 24 70 00 00 00 00                       mov     [rsp+1D8h+var_168], 0

                              loc_145812131:                          ; CODE XREF: SetAmmoCountAndUpdateState+657↑j
8B 44 24 70                                   mov     eax, [rsp+1D8h+var_168]
89 44 24 74                                   mov     [rsp+1D8h+var_164], eax

                              loc_145812139:                          ; CODE XREF: SetAmmoCountAndUpdateState+63D↑j
0F B6 44 24 74                                movzx   eax, byte ptr [rsp+1D8h+var_164]
88 44 24 44                                   mov     [rsp+1D8h+var_194], al
0F B6 44 24 44                                movzx   eax, [rsp+1D8h+var_194]
85 C0                                         test    eax, eax
74 0A                                         jz      short loc_145812155
C7 44 24 78 00 00 00 00                       mov     [rsp+1D8h+var_160], 0
EB 08                                         jmp     short loc_14581215D
                              ; ---------------------------------------------------------------------------

                              loc_145812155:                          ; CODE XREF: SetAmmoCountAndUpdateState+679↑j
C7 44 24 78 01 00 00 00                       mov     [rsp+1D8h+var_160], 1

                              loc_14581215D:                          ; CODE XREF: SetAmmoCountAndUpdateState+683↑j
8B 44 24 78                                   mov     eax, [rsp+1D8h+var_160]
89 84 24 A0 00 00 00                          mov     [rsp+1D8h+var_138], eax
48 8B 84 24 C0 00 00 00                       mov     rax, [rsp+1D8h+var_118]
48 8B 00                                      mov     rax, [rax]
48 8B 40 60                                   mov     rax, [rax+60h]
48 89 84 24 98 01 00 00                       mov     [rsp+1D8h+var_40], rax
8B 94 24 A0 00 00 00                          mov     edx, [rsp+1D8h+var_138]
48 8B 8C 24 C0 00 00 00                       mov     rcx, [rsp+1D8h+var_118]
FF 94 24 98 01 00 00                          call    [rsp+1D8h+var_40]

                              loc_145812195:                          ; CODE XREF: SetAmmoCountAndUpdateState+616↑j
E9 D0 FE FF FF                                jmp     loc_14581206A
                              ; ---------------------------------------------------------------------------

                              loc_14581219A:                          ; CODE XREF: SetAmmoCountAndUpdateState+86↑j
                                                                      ; SetAmmoCountAndUpdateState+461↑j ...
80 BC 24 F0 01 00 00 02                       cmp     [rsp+1D8h+arg_10], 2
74 1C                                         jz      short loc_1458121C0
80 BC 24 F0 01 00 00 01                       cmp     [rsp+1D8h+arg_10], 1
0F 85 BA 00 00 00                             jnz     loc_14581226C
8B 44 24 40                                   mov     eax, [rsp+1D8h+var_198]
39 44 24 48                                   cmp     [rsp+1D8h+var_190], eax
0F 84 AC 00 00 00                             jz      loc_14581226C

                              loc_1458121C0:                          ; CODE XREF: SetAmmoCountAndUpdateState+6D2↑j
48 8B 84 24 E0 01 00 00                       mov     rax, [rsp+1D8h+arg_0]
48 05 08 01 00 00                             add     rax, 108h
48 89 84 24 B8 01 00 00                       mov     [rsp+1D8h+var_20], rax
48 8B 8C 24 E0 01 00 00                       mov     rcx, [rsp+1D8h+arg_0]
E8 AD 66 FE FF                                call    GetAmmoCapacityFromComponent
89 84 24 A4 00 00 00                          mov     [rsp+1D8h+var_134], eax
48 8B 8C 24 E0 01 00 00                       mov     rcx, [rsp+1D8h+arg_0]
E8 49 EA B1 FA                                call    GetObjectFieldOffset64
48 83 C0 58                                   add     rax, 58h ; 'X'
48 89 84 24 A8 01 00 00                       mov     [rsp+1D8h+var_30], rax
48 8B 84 24 E0 01 00 00                       mov     rax, [rsp+1D8h+arg_0]
48 8B 40 08                                   mov     rax, [rax+8]
48 89 84 24 A0 01 00 00                       mov     [rsp+1D8h+var_38], rax
48 8D 84 24 A0 01 00 00                       lea     rax, [rsp+1D8h+var_38]
48 89 84 24 B0 01 00 00                       mov     [rsp+1D8h+var_28], rax
48 8D 84 24 A4 00 00 00                       lea     rax, [rsp+1D8h+var_134]
48 89 44 24 30                                mov     [rsp+1D8h+var_1A8], rax
48 8D 44 24 40                                lea     rax, [rsp+1D8h+var_198]
48 89 44 24 28                                mov     [rsp+1D8h+var_1B0], rax
48 8D 44 24 48                                lea     rax, [rsp+1D8h+var_190]
48 89 44 24 20                                mov     [rsp+1D8h+var_1B8], rax
4C 8B 8C 24 A8 01 00 00                       mov     r9, [rsp+1D8h+var_30]
4C 8B 84 24 B0 01 00 00                       mov     r8, [rsp+1D8h+var_28]
48 8D 15 75 EE B6 FA                          lea     rdx, sub_1403810D4
48 8B 8C 24 B8 01 00 00                       mov     rcx, [rsp+1D8h+var_20]
E8 D4 D5 FB FF                                call    NotifyListenersLocked

                              loc_14581226C:                          ; CODE XREF: SetAmmoCountAndUpdateState+6DC↑j
                                                                      ; SetAmmoCountAndUpdateState+6EA↑j
48 81 C4 D8 01 00 00                          add     rsp, 1D8h
C3                                            retn
                              SetAmmoCountAndUpdateState endp

                              ; ---------------------------------------------------------------------------
                              algn_145812274:                         ; DATA XREF: .pdata:0000000151824A38↓o
CC CC CC CC CC CC CC CC CC CC…                align 20h
*/

/*
 * C-style reimplementation of the SetAmmoCountAndUpdateState function based on
 * the assembly analysis and provided description.
 * NOTE: This requires definitions for external functions, types (_QWORD, etc.),
 *       and global variables (e.g., off_14972A338) to compile.
 */

// Assumed external function declarations (replace with actual definitions/headers)
/* extern int GetAmmoCapacityFromComponent(__int64 pAmmoContainerComponent);
extern unsigned int CalculateTotalAmmoCount(__int64 pAmmoContainerComponent);
extern void UpdateValidationStateFlag(__int64 pStateObject); // Assuming takes pointer to offset +208
extern __int64 GetObjectFieldOffset64(__int64 pComponent);
extern unsigned char IsNullOrPointsToNullByte(const void* ptr);
extern void _StarEngineModule__(__int64 unknown); // Placeholder for the stub call
extern void GetEntityGeometryResourceInterfaceFromHandle(_QWORD* pOutHandleHolder, unsigned __int64 entityHandle);
extern unsigned char ValidateHandleType2OrDispatch_Vcall(__int64* pHandle); // Assuming specific version for vcall context
extern unsigned char ValidateHandleType2OrDispatch(__int64* pHandle); // Assuming general version
extern const unsigned long long* GetPointerOrDefaultSource(__int64 address); // Assuming function signature
extern void AllocateAndAssignCustomString(void** ppOutString, const char* source); // Assuming function signature
extern void ReleaseCustomStringObject(_QWORD* pStringObj); // Assuming function signature
extern void UpdateFloatStateAndCompare_SSE(__int64 pFloatStateObject, double val1, double val2);
extern __int64 NotifyListenersLocked(_QWORD* pListenerSet, void* callback, void* arg1, void* arg2, void* arg3, void* arg4, void* arg5); // Simplified signature
extern __int64 GetLower48Bits(unsigned __int64* pHandle); // Assuming function signature
extern void sub_1403810D4(); // Placeholder for the callback address
extern char* off_14972A338[]; // Placeholder for the global offset data

__int64 __fastcall SetAmmoCountAndUpdateState(
    __int64 pAmmoContainerComponent,
    int newAmmoCountRaw,
    char notificationFlag)
{
    // 1. Read old ammo count
    unsigned int oldAmmoCount = *(unsigned int*)(pAmmoContainerComponent + 244); // Offset 0xF4

    // 2. Read capacity
    int capacity = GetAmmoCapacityFromComponent(pAmmoContainerComponent); // Uses offset +240 (0xF0) internally

    // 3. Clamp new ammo count
    unsigned int clampedAmmoCount;
    if (newAmmoCountRaw < 0)
    {
        clampedAmmoCount = 0;
    }
    else if (capacity >= 0 && newAmmoCountRaw >= capacity) // Check capacity >= 0 for safety, use >= based on decompilation logic
    {
        clampedAmmoCount = (unsigned int)capacity;
    }
    else
    {
        clampedAmmoCount = (unsigned int)newAmmoCountRaw;
    }

    // Initialize potential return value
    __int64 returnValue = (__int64)clampedAmmoCount;
    bool countChanged = (oldAmmoCount != clampedAmmoCount);

    // 4. If the count changed:
    if (countChanged)
    {
        // 4a. Update stored count
        *(unsigned int*)(pAmmoContainerComponent + 244) = clampedAmmoCount; // Offset 0xF4

        // 4b. Entity flag check and state update
        unsigned __int64 entityHandle = *(_QWORD*)(pAmmoContainerComponent + 8); // Offset 0x8
        __int64 entityBaseAddress = GetLower48Bits(&entityHandle); // Assuming this gets the base address or relevant part
        // Assuming entityBaseAddress is valid if GetLower48Bits returns non-zero or handle was valid
        // Also assuming the vtable call returns a byte/bool indicating the flag status
        if (entityBaseAddress != 0 && (*(unsigned __int8(__fastcall**)(__int64))(*(_QWORD*)entityBaseAddress + 1808LL))(entityBaseAddress)) // Vtable offset 0x710 = 1808
        {
            unsigned int totalAmmo = CalculateTotalAmmoCount(pAmmoContainerComponent);
            UpdateValidationStateFlag((__int64)(pAmmoContainerComponent + 208)); // Offset 0xD0, pass address
            *(unsigned int*)(pAmmoContainerComponent + 216) = totalAmmo; // Offset 0xD8
        }

        // 4c. String field check and geometry resource interaction
        __int64 pRelatedComponent = GetObjectFieldOffset64(pAmmoContainerComponent); // Uses offset +64 (0x40) internally
        _QWORD* pStringFieldPtr = (_QWORD*)(pRelatedComponent + 96); // Offset 0x60
        if (!IsNullOrPointsToNullByte(pStringFieldPtr) && (!oldAmmoCount || !clampedAmmoCount)) // Check if crossed zero threshold
        {
            _StarEngineModule__(0LL); // Call stub

            unsigned __int64 entityHandleForGeom = *(_QWORD*)(pAmmoContainerComponent + 8); // Offset 0x8
            _QWORD geometryResourceInterfacePtrHolder[2] = {0}; // Placeholder like in decomp
            GetEntityGeometryResourceInterfaceFromHandle(geometryResourceInterfacePtrHolder, entityHandleForGeom);

            __int64 geometryResourceInterface = 0;
            __int64 handleToValidate = geometryResourceInterfacePtrHolder[0];
            // Use ValidateHandleType2OrDispatch_Vcall as seen in decompilation for this specific check
            if (ValidateHandleType2OrDispatch_Vcall(&handleToValidate))
            {
                // Assuming validation success means the lower 48 bits are the interface pointer
                geometryResourceInterface = handleToValidate & 0xFFFFFFFFFFFFLL;
            }

            if (geometryResourceInterface)
            {
                // Decompilation showed redundant calls, replicating that structure:
                if (clampedAmmoCount > 0)
                {
                    void* customStringPtr1 = NULL;
                    // Redundant GetObjectFieldOffset64 and GetPointerOrDefaultSource
                    __int64 relatedCompForString1 = GetObjectFieldOffset64(pAmmoContainerComponent);
                    const unsigned long long* sourceStringPtr1 = GetPointerOrDefaultSource(relatedCompForString1 + 96); // Offset 0x60
                    AllocateAndAssignCustomString(&customStringPtr1, (const char*)sourceStringPtr1);

                    // Call vtable + 1400 (0x578)
                    (*(void(__fastcall**)(__int64, void**, char*))(*(_QWORD*)geometryResourceInterface + 1400LL))(
                        geometryResourceInterface,
                        &customStringPtr1,
                        off_14972A338[0] // Global offset seen in decompilation
                    );
                    ReleaseCustomStringObject((_QWORD*)&customStringPtr1); // Pass address of the pointer
                }
                else // clampedAmmoCount == 0
                {
                    void* customStringPtr2 = NULL;
                    // Redundant GetObjectFieldOffset64 and GetPointerOrDefaultSource
                    __int64 relatedCompForString2 = GetObjectFieldOffset64(pAmmoContainerComponent);
                    const unsigned long long* sourceStringPtr2 = GetPointerOrDefaultSource(relatedCompForString2 + 96); // Offset 0x60
                    AllocateAndAssignCustomString(&customStringPtr2, (const char*)sourceStringPtr2);

                    // Call vtable + 1392 (0x570)
                    (*(void(__fastcall**)(__int64, void**, char*))(*(_QWORD*)geometryResourceInterface + 1392LL))(
                        geometryResourceInterface,
                        &customStringPtr2,
                        off_14972A338[0] // Global offset seen in decompilation
                    );
                    ReleaseCustomStringObject((_QWORD*)&customStringPtr2); // Pass address of the pointer
                }
            }
        }

        // 4d. Float state update
        __int64 pFloatStateObject = *(_QWORD*)(pAmmoContainerComponent + 312); // Offset 0x138
        if (pFloatStateObject)
        {
            float ammoRatio = 0.0f;
            int capacityForRatio = GetAmmoCapacityFromComponent(pAmmoContainerComponent); // Get capacity again
            if (capacityForRatio > 0)
            {
                ammoRatio = (float)clampedAmmoCount / (float)capacityForRatio;
            }

            __int64 pRelatedComponentForFloat = GetObjectFieldOffset64(pAmmoContainerComponent); // Get related component again
            float relatedFloat = *(float*)(pRelatedComponentForFloat + 90); // Offset 0x5A = 90 decimal

            // Call UpdateFloatStateAndCompare_SSE, passing floats cast to double as per description/signature
            UpdateFloatStateAndCompare_SSE(pFloatStateObject, (double)ammoRatio, (double)relatedFloat);
        }

        // 4e. Related component list iteration
        __int64 pRelatedComponentForList = GetObjectFieldOffset64(pAmmoContainerComponent); // Get related component again
        __int64 pListInfo = pRelatedComponentForList + 152; // Offset 0x98 = 152
        if (*(_QWORD*)(pRelatedComponentForList + 176) != 0LL) // Check field +176 (0xB0)
        {
            _StarEngineModule__(0LL); // Call stub

            unsigned __int64 entityHandleForListGeom = *(_QWORD*)(pAmmoContainerComponent + 8); // Offset 0x8
            _QWORD geomInterfaceHolderForList[2] = {0};
            GetEntityGeometryResourceInterfaceFromHandle(geomInterfaceHolderForList, entityHandleForListGeom); // Get interface again

            __int64 geomInterfaceForList = 0;
            __int64 handleToValidateList = geomInterfaceHolderForList[0];
            // Use ValidateHandleType2OrDispatch as seen in decompilation for this specific check
            if (ValidateHandleType2OrDispatch(&handleToValidateList))
            {
                geomInterfaceForList = handleToValidateList & 0xFFFFFFFFFFFFLL;
            }

            if (geomInterfaceForList)
            {
                // Vtable call +1536 (0x600)
                __int64 pIntermediateObject1 = (*(__int64(__fastcall**)(__int64))(*(_QWORD*)geomInterfaceForList + 1536LL))(geomInterfaceForList);
                if (pIntermediateObject1)
                {
                    // Vtable call +72 (0x48)
                    __int64 pIntermediateObject2 = (*(__int64(__fastcall**)(__int64))(*(_QWORD*)pIntermediateObject1 + 72LL))(pIntermediateObject1);
                    if (pIntermediateObject2)
                    {
                        // Iterate list at pListInfo (+152)
                        // Assuming structure: QWORD start @ +16 (0x10), QWORD count @ +24 (0x18), element size 40 (0x28)
                        __int64 pCurrentListItem = *(_QWORD*)(pListInfo + 16);
                        __int64 listCount = *(_QWORD*)(pListInfo + 24);
                        __int64 pListEnd = pCurrentListItem + 40LL * listCount;

                        while (pCurrentListItem != pListEnd)
                        {
                            // Vtable call +104 (0x68) on pIntermediateObject2 to get target component
                            __int64(__fastcall * pfnGetTargetComponent)(__int64, unsigned int) =
                                *(__int64(__fastcall**)(__int64, unsigned int))(*(_QWORD*)pIntermediateObject2 + 104LL);

                            unsigned int targetComponentId = *(unsigned int*)(pCurrentListItem + 32); // Offset 0x20 within list item
                            __int64 pTargetComponent = pfnGetTargetComponent(pIntermediateObject2, targetComponentId);

                            if (pTargetComponent)
                            {
                                // Determine boolean state based on threshold check and flag byte
                                int threshold = *(int*)(pCurrentListItem + 24); // Offset 0x18 within list item
                                unsigned char flagByte = *(unsigned char*)(pCurrentListItem + 28); // Offset 0x1C within list item

                                // Logic derived directly from decompilation analysis:
                                // state = (clamped < threshold) ? (flag == 0) : (flag != 0)
                                // finalState = !state
                                bool state;
                                if ((int)clampedAmmoCount < threshold) {
                                    state = (flagByte == 0);
                                } else {
                                    state = (flagByte != 0);
                                }
                                bool finalState = !state; // Invert the state for the final call

                                // Vtable call +96 (0x60) on pTargetComponent
                                (*(void(__fastcall**)(__int64, bool))(*(_QWORD*)pTargetComponent + 96LL))(pTargetComponent, finalState);
                            }
                            pCurrentListItem += 40LL; // Move to next 40-byte item
                        }
                    }
                }
            }
        }
        // Note: Intermediate assignments to 'returnValue' seen in the decompilation's list handling loop are omitted
        // as they contradict the function's described return value logic (return clamped count or notification result).
    } // End of if(countChanged)

    // 5. Notification
    if (notificationFlag == 2 || (notificationFlag == 1 && countChanged))
    {
        _QWORD* pListenerSet = (_QWORD*)(pAmmoContainerComponent + 264); // Offset 0x108
        int capacityForNotification = GetAmmoCapacityFromComponent(pAmmoContainerComponent); // Get capacity again
        __int64 pRelatedCompForNotify = GetObjectFieldOffset64(pAmmoContainerComponent);
        unsigned int* pRelatedComponentField88 = (unsigned int*)(pRelatedCompForNotify + 88); // Offset 0x58
        unsigned __int64 entityHandleForNotification = *(_QWORD*)(pAmmoContainerComponent + 8); // Get handle again

        // Prepare arguments for NotifyListenersLocked (passing pointers to the values)
        // Stack layout from assembly:
        // RSP+20h: &oldAmmoCount
        // RSP+28h: &newAmmoCountClamped
        // RSP+30h: &capacity
        // RCX: pListenerSet (pAmmoContainerComponent + 0x108)
        // RDX: callback function (sub_1403810D4)
        // R8:  &entityHandle
        // R9:  pRelatedComponentField88 (pointer to uint at offset +88)
        unsigned int notificationArg3_OldAmmoCount = oldAmmoCount;
        unsigned int notificationArg4_NewAmmoCount = clampedAmmoCount;
        int notificationArg5_Capacity = capacityForNotification;


        // Call NotifyListenersLocked and return its result directly
        // Note: The exact signature and argument passing for NotifyListenersLocked might vary.
        // This matches the register/stack usage seen in the assembly dump.
        return NotifyListenersLocked(
            pListenerSet,
            (void*)sub_1403810D4,          // RDX: Callback function pointer
            &entityHandleForNotification,  // R8: Pointer to handle
            pRelatedComponentField88,      // R9: Pointer to field (already points to the uint)
            &notificationArg3_OldAmmoCount,// Stack + 0x20: Pointer to old count
            &notificationArg4_NewAmmoCount,// Stack + 0x28: Pointer to new count
            &notificationArg5_Capacity     // Stack + 0x30: Pointer to capacity
        );
    }

    // 6. Return Value (if notification was not sent)
    return returnValue; // Return the clamped ammo count cast to __int64
} */


// Define the target function address
#define TARGET_ADDRESS 0x145811AD0

// Define the type of the original function
// __fastcall on x64 uses RCX, RDX, R8, R9 for first four args
// Our function has 3 args: RCX, RDX, R8
typedef __int64(__fastcall* SetAmmoCountAndUpdateState_t)(
    __int64 pAmmoContainerComponent, // RCX
    int newAmmoCountRaw,             // RDX
    char notificationFlag            // R8B
);

// Pointer to the original function
SetAmmoCountAndUpdateState_t fpOriginalSetAmmoCountAndUpdateState = NULL;

// Simple Hexdump Function
void HexDump(const char* description, const void* addr, const int len) {
    if (!addr || len <= 0) {
        printf("%s: Invalid address or length\n", description);
        return;
    }
    printf("--- Hexdump: %s (Address: %p, Length: %d bytes) ---\n", description, addr, len);
    int i;
    unsigned char buff[17];
    const unsigned char* pc = (const unsigned char*)addr;

    for (i = 0; i < len; i++) {
        if ((i % 16) == 0) {
            if (i != 0) printf("  %s\n", buff);
            printf("  %04x ", i);
        }
        printf(" %02x", pc[i]);
        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) {
            buff[i % 16] = '.';
        } else {
            buff[i % 16] = pc[i];
        }
        buff[(i % 16) + 1] = '\0';
    }
    while ((i % 16) != 0) {
        printf("   ");
        i++;
    }
    printf("  %s\n", buff);
    printf("--- End Hexdump: %s ---\n", description);
    fflush(stdout);
}

// Our hook function
__int64 __fastcall hkSetAmmoCountAndUpdateState(
    __int64 pAmmoContainerComponent, // RCX
    int newAmmoCountRaw,             // RDX
    char notificationFlag            // R8B
) {
    printf("\n=====================================================\n");
    printf("hkSetAmmoCountAndUpdateState(0x%llX) CALLED\n", (unsigned long long)TARGET_ADDRESS);
    printf("  pAmmoContainerComponent: %p\n", (void*)pAmmoContainerComponent);
    printf("  newAmmoCountRaw:         %d\n", newAmmoCountRaw);
    printf("  notificationFlag:        %d (0=Never, 1=OnChange, 2=Always)\n", (int)notificationFlag);
    fflush(stdout);

    // 1) Hexdump pAmmoContainerComponent (dumping a reasonable size, e.g., 512 bytes)
    const int DUMP_SIZE = 512;
    if (pAmmoContainerComponent) {
        HexDump("pAmmoContainerComponent", (void*)pAmmoContainerComponent, DUMP_SIZE);
    } else {
        printf("  pAmmoContainerComponent is NULL, cannot dump or infer data.\n");
        fflush(stdout);
        // Call original even if pointer is null, as the original function might handle it
        return fpOriginalSetAmmoCountAndUpdateState(pAmmoContainerComponent, newAmmoCountRaw, notificationFlag);
    }

    // 2) Print inferred information
    printf("\n--- Inferred Data from pAmmoContainerComponent (%p) ---\n", (void*)pAmmoContainerComponent);
    // Use uintptr_t for pointer arithmetic robustness
    uintptr_t base = (uintptr_t)pAmmoContainerComponent;

    // Access fields carefully, checking base pointer is not null (already done above)
    printf("  +0x008 (Entity Handle):        0x%llX\n", *(uint64_t*)(base + 0x8));
    printf("  +0x0F0 (Ammo Capacity):        %u\n", *(unsigned int*)(base + 0xF0));
    printf("  +0x0F4 (Current Ammo Count):   %u\n", *(unsigned int*)(base + 0xF4));
    printf("  +0x0D8 (Total Ammo Storage?):  %u\n", *(unsigned int*)(base + 0xD8)); // Set after CalculateTotalAmmoCount
    printf("  +0x108 (Listener Set Ptr?):    %p\n", *(void**)(base + 0x108));
    printf("  +0x138 (Float State Obj Ptr?): %p\n", *(void**)(base + 0x138));
    printf("  +0x140 (Fallback List Start?): %p\n", *(void**)(base + 0x140));
    printf("  +0x148 (Fallback List End?):   %p\n", *(void**)(base + 0x148)); // List ranges are usually 16 bytes (start/end)
    printf("  +0x158 (Primary List Start?):  %p\n", *(void**)(base + 0x158));
    printf("  +0x160 (Primary List End?):    %p\n", *(void**)(base + 0x160));
    printf("  +0x170 (Lock Structure Ptr?):  %p\n", (void*)(base + 0x170)); // Address of the potential lock struct start

    // Access related component data via the pointer at +0x40
    __int64 pRelatedComponent = *(__int64*)(base + 0x40);
    printf("  +0x040 (Related Component Ptr): %p\n", (void*)pRelatedComponent);
    if (pRelatedComponent) {
        uintptr_t relatedBase = (uintptr_t)pRelatedComponent;
        printf("    Related +0x58 (Field 88 for Notify?): %u\n", *(unsigned int*)(relatedBase + 0x58)); // 88
        printf("    Related +0x5A (Float for SSE?):       %f\n", *(float*)(relatedBase + 0x5A));       // 90
        printf("    Related +0x60 (String Ptr for Geom?): %p -> \"%s\"\n", *(char**)(relatedBase + 0x60), *(char**)(relatedBase + 0x60) ? *(char**)(relatedBase + 0x60) : "NULL"); // 96
        printf("    Related +0x98 (List Info Ptr?):       %p\n", (void*)(relatedBase + 0x98)); // 152
        printf("    Related +0xB0 (Field 176 Ptr?):       %p\n", *(void**)(relatedBase + 0xB0)); // 176
        printf("    Related +0xE0 (Field 224 Ptr?):       %p\n", *(void**)(relatedBase + 0xE0)); // 224
    } else {
        printf("    Related Component Pointer is NULL.\n");
    }

    printf("--- End Inferred Data ---\n");
    printf("=====================================================\n\n");
    fflush(stdout);

    // Call the original function with the original arguments
    return fpOriginalSetAmmoCountAndUpdateState(pAmmoContainerComponent, newAmmoCountRaw, notificationFlag);
}

// DllMain function
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            // Allocate a console for output
            AllocConsole();
            FILE* fDummy;
            freopen_s(&fDummy, "CONOUT$", "w", stdout);
            freopen_s(&fDummy, "CONOUT$", "w", stderr);
            printf("DLL Attached!\n");

            // Initialize MinHook
            if (MH_Initialize() != MH_OK) {
                printf("MinHook initialization failed!\n");
                return FALSE;
            }
            printf("MinHook initialized.\n");

            // Create the hook
            // IMPORTANT: Adjust TARGET_ADDRESS if ASLR is enabled!
            if (MH_CreateHook((LPVOID)TARGET_ADDRESS, &hkSetAmmoCountAndUpdateState, (LPVOID*)&fpOriginalSetAmmoCountAndUpdateState) != MH_OK) {
                printf("Failed to create hook for SetAmmoCountAndUpdateState (0x%llX)\n", (unsigned long long)TARGET_ADDRESS);
                MH_Uninitialize();
                return FALSE;
            }
            printf("Hook created for SetAmmoCountAndUpdateState (0x%llX)\n", (unsigned long long)TARGET_ADDRESS);

            // Enable the hook
            if (MH_EnableHook((LPVOID)TARGET_ADDRESS) != MH_OK) {
                printf("Failed to enable hook.\n");
                MH_RemoveHook((LPVOID)TARGET_ADDRESS); // Clean up created hook
                MH_Uninitialize();
                return FALSE;
            }
            printf("Hook enabled successfully!\n");
            fflush(stdout);
            break;

        case DLL_PROCESS_DETACH:
            printf("DLL Detaching...\n");
            fflush(stdout);

            // Disable the hook
            MH_DisableHook((LPVOID)TARGET_ADDRESS);
            printf("Hook disabled.\n");

            // Remove the hook (optional but good practice)
            MH_RemoveHook((LPVOID)TARGET_ADDRESS);
             printf("Hook removed.\n");

            // Uninitialize MinHook
            MH_Uninitialize();
            printf("MinHook uninitialized.\n");
            fflush(stdout);

            // Free the console
            // Optional: Keep console open for a bit if needed for debugging detachment issues
            // Sleep(5000);
            FreeConsole();
            break;

        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}