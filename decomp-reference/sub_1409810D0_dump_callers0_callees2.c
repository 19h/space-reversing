// Decompiled code dump generated by Code Dumper (Callers/Callees/Refs)
// Start Function: 0x1409810D0 (sub_1409810D0)
// Caller Depth: 0
// Callee/Ref Depth: 2
// Total Functions Found: 4
// ------------------------------------------------------------

// --- Function: GetCurrentThreadId (0x1405699D0) ---
// attributes: thunk
DWORD __stdcall GetCurrentThreadId()
{
  return __imp_GetCurrentThreadId();
}

// --- End Function: GetCurrentThreadId (0x1405699D0) ---

// --- Function: sub_14093D290 (0x14093D290) ---
void __fastcall sub_14093D290(float *a1, __int64 a2, __int64 a3)
{
  __int128 v5; // xmm5
  __int128 v13; // xmm7
  __int128 v15; // xmm8
  __int128 v26; // kr00_16
  float v27; // xmm10_4
  float v28; // xmm9_4
  float v31; // xmm5_4
  float v32; // xmm4_4

  _XMM3 = *((unsigned __int64 *)a1 + 2);
  _XMM0 = *(unsigned __int64 *)a1;
  v5 = *((unsigned __int64 *)a1 + 1);
  _XMM4 = *((unsigned __int64 *)a1 + 6);
  _XMM1 = *((unsigned __int64 *)a1 + 4);
  _XMM2 = *((unsigned __int64 *)a1 + 8);
  __asm { vcvtpd2ps xmm0, xmm0 }
  _XMM6 = *((unsigned __int64 *)a1 + 0xA);
  __asm { vcvtpd2ps xmm1, xmm1 }
  v13 = *((unsigned __int64 *)a1 + 5);
  v15 = *((unsigned __int64 *)a1 + 9);
  *(float *)a3 = *(float *)&_XMM0;
  *(float *)(a3 + 0x10) = *(float *)&_XMM1;
  __asm { vcvtsd2ss xmm0, xmm3, xmm3 }
  *(float *)(a3 + 4) = *(float *)&_XMM0;
  __asm { vcvtpd2ps xmm2, xmm2 }
  *(float *)(a3 + 0x20) = *(float *)&_XMM2;
  _XMM1 = v5 ^ 0x8000000000000000uLL;
  __asm { vcvtsd2ss xmm0, xmm1, xmm1 }
  *(float *)(a3 + 8) = *(float *)&_XMM0;
  _XMM0 = v13 ^ 0x8000000000000000uLL;
  __asm { vcvtsd2ss xmm1, xmm0, xmm0 }
  *(float *)(a3 + 0x18) = *(float *)&_XMM1;
  __asm { vcvtsd2ss xmm2, xmm4, xmm4 }
  *(float *)(a3 + 0x14) = *(float *)&_XMM2;
  _XMM0 = v15 ^ 0x8000000000000000uLL;
  __asm { vcvtsd2ss xmm1, xmm0, xmm0 }
  *(float *)(a3 + 0x28) = *(float *)&_XMM1;
  *(_DWORD *)(a3 + 0xC) = 0;
  *(_DWORD *)(a3 + 0x1C) = 0;
  *(_QWORD *)(a3 + 0x2C) = 0;
  *(_DWORD *)(a3 + 0x3C) = 0x3F800000;
  *(_DWORD *)(a3 + 0x34) = 0x80000000;
  *(_DWORD *)(a3 + 0x38) = 0;
  __asm { vcvtsd2ss xmm2, xmm6, xmm6 }
  *(float *)(a3 + 0x24) = *(float *)&_XMM2;
  v26 = *((unsigned int *)a1 + 0x3C);
  v27 = a1[0x42];
  *(double *)&_XMM0 = tan((float)(a1[0x3C] * 0.5));
  v28 = a1[0x48];
  *(double *)&v26 = *(double *)&_XMM0 * v27;
  _XMM0 = v26;
  __asm { vcvtsd2ss xmm2, xmm0, xmm0 }
  *(float *)&_XMM1 = *(float *)&_XMM2 * a1[0x3F];
  v31 = *(float *)&_XMM1 + a1[0x4B];
  *(float *)&v15 = *(float *)&_XMM2 + a1[0x4D];
  *(float *)&v13 = a1[0x4C] - *(float *)&_XMM2;
  v32 = a1[0x4A] - *(float *)&_XMM1;
  *(float *)&_XMM1 = 1.0 / (float)(v31 - v32);
  *(float *)a2 = *(float *)&_XMM1 * (float)(v27 + v27);
  *(_QWORD *)(a2 + 4) = 0;
  *(_QWORD *)(a2 + 0xC) = 0;
  *(float *)&v26 = 1.0 / (float)(*(float *)&v15 - *(float *)&v13);
  *(float *)(a2 + 0x14) = *(float *)&v26 * (float)(v27 + v27);
  *(_QWORD *)(a2 + 0x18) = 0;
  *(float *)(a2 + 0x20) = (float)(v31 + v32) * *(float *)&_XMM1;
  *(float *)(a2 + 0x24) = (float)(*(float *)&v15 + *(float *)&v13) * *(float *)&v26;
  *(float *)&_XMM2 = 1.0 / (float)(v28 - v27);
  *(float *)(a2 + 0x28) = v27 * *(float *)&_XMM2;
  *(_DWORD *)(a2 + 0x2C) = 0xBF800000;
  *(_QWORD *)(a2 + 0x30) = 0;
  *(float *)(a2 + 0x38) = (float)(v27 * v28) * *(float *)&_XMM2;
  *(_DWORD *)(a2 + 0x3C) = 0;
}

// --- End Function: sub_14093D290 (0x14093D290) ---

// --- Function: sub_1409810D0 (0x1409810D0) ---
// local variable allocation has failed, the output may be wrong!
char __fastcall sub_1409810D0(
        _QWORD *a1,
        double a2,
        double a3,
        double a4,
        float *a5,
        float *a6,
        float *a7,
        char a8,
        __int64 a9)
{
  __int128 v9; // xmm6
  __int128 v10; // xmm7
  __int128 v11; // xmm8
  __int128 v12; // xmm9
  __int128 v13; // xmm10
  _DWORD *v14; // rdi
  __int128 v16; // xmm10
  int v17; // eax
  DWORD CurrentThreadId; // eax
  __int64 v19; // rcx
  __int64 v20; // rdx
  _QWORD *v21; // rax
  int v22; // edi
  __int64 v23; // r8
  int v24; // esi
  double v26; // xmm7_8
  __int128 v30; // kr00_16
  float v36; // xmm1_4
  float v37; // xmm9_4
  float v38; // xmm8_4
  float v39; // xmm6_4
  float v40; // xmm7_4
  float v41; // kr00_4
  __m256 v43; // [rsp+28h] [rbp-E0h] BYREF
  __m256 v44; // [rsp+48h] [rbp-C0h]
  float v45; // [rsp+68h] [rbp-A0h]
  __m256 v46; // [rsp+78h] [rbp-90h] BYREF
  __m256 v47; // [rsp+98h] [rbp-70h]
  __int128 v48; // [rsp+128h] [rbp+20h]
  __int128 v49; // [rsp+138h] [rbp+30h]
  __int128 v50; // [rsp+148h] [rbp+40h]
  __int128 v51; // [rsp+158h] [rbp+50h]
  __int128 v52; // [rsp+168h] [rbp+60h]

  v14 = (_DWORD *)a1[0x4C];
  v52 = v9;
  v51 = v10;
  v50 = v11;
  v49 = v12;
  v48 = v13;
  v43 = ymmword_1481D7B60;
  v44 = ymmword_1481D7C60;
  v46 = ymmword_1481D7B60;
  v16 = *(_OWORD *)&a3;
  v47 = ymmword_1481D7C60;
  __asm { vzeroupper }
  if ( GetCurrentThreadId() == v14[0xF] )
  {
    v17 = v14[0xB] % 2;
  }
  else
  {
    CurrentThreadId = GetCurrentThreadId();
    if ( CurrentThreadId == v14[0xF] || CurrentThreadId == v14[0xE] )
      v17 = v14[0xC];
    else
      v17 = v14[0xD];
  }
  v19 = 0x888LL * v17;
  if ( a9 )
  {
    v24 = *(_DWORD *)(a9 + 0xF4);
    v22 = *(_DWORD *)(a9 + 0xF8);
    v26 = *(double *)(a9 + 0x58);
    *(_QWORD *)&_XMM6 = *(_QWORD *)(a9 + 0x18);
    *(_QWORD *)&_XMM8 = *(_QWORD *)(a9 + 0x38);
    if ( *(double *)&_XMM6 == 0.0 && *(double *)(a9 + 0x38) == 0.0 && v26 == 0.0 )
    {
      _XMM2 = *(_OWORD *)&a1[v19 + 0x41D1];
      v26 = *(double *)&a1[v19 + 0x41D3];
      __asm { vunpckhpd xmm8, xmm2, xmm2 }
      *(_QWORD *)&_XMM6 = _XMM2;
    }
    sub_14093D290((float *)a9, (__int64)&v46, (__int64)&v43);
    goto LABEL_22;
  }
  v20 = a1[v19 + 0x41E8];
  v21 = a1 + 0x41E9;
  v22 = 0;
  if ( v20 )
  {
    v23 = a1[v19 + 0x41E8];
  }
  else
  {
    v23 = v21[v19];
    if ( !v23 )
    {
      v24 = 0;
      goto LABEL_14;
    }
  }
  v24 = *(unsigned __int16 *)(v23 + 0x88);
  if ( v20 )
    goto LABEL_15;
LABEL_14:
  v20 = v21[v19];
  if ( v20 )
LABEL_15:
    v22 = *(unsigned __int16 *)(v20 + 0x8A);
  _XMM6 = *(_OWORD *)&a1[v19 + 0x41D1];
  v26 = *(double *)&a1[v19 + 0x41D3];
  (*(void (__fastcall **)(_QWORD *, _QWORD *, __m256 *, __m256 *))(*a1 + 0x110LL))(a1, &a1[v19 + 0x41FC], &v46, &v43);
  __asm { vunpckhpd xmm8, xmm6, xmm6 }
LABEL_22:
  *((double *)&v30 + 1) = *(&a2 + 1);
  *(double *)&v30 = a2 - *(double *)&_XMM6;
  _XMM0 = v30;
  __asm { vcvtsd2ss xmm5, xmm0, xmm0 }
  *((double *)&v30 + 1) = *(&a4 + 1);
  *(double *)&v30 = a4 - v26;
  _XMM0 = v30;
  __asm { vcvtsd2ss xmm3, xmm0, xmm0 }
  *((_QWORD *)&v30 + 1) = *((_QWORD *)&v16 + 1);
  *(double *)&v30 = *(double *)&v16 - *(double *)&_XMM8;
  _XMM1 = v30;
  __asm { vcvtsd2ss xmm10, xmm1, xmm1 }
  v45 = (float)((float)((float)((float)((float)((float)(v47.m256_f32[5] * v44.m256_f32[3])
                                              + (float)(v47.m256_f32[1] * v44.m256_f32[2]))
                                      + (float)((float)(v46.m256_f32[5] * v44.m256_f32[1])
                                              + (float)(v46.m256_f32[1] * v44.m256_f32[0])))
                              * *(float *)&_XMM3)
                      + (float)((float)((float)((float)(v47.m256_f32[5] * v43.m256_f32[3])
                                              + (float)(v47.m256_f32[1] * v43.m256_f32[2]))
                                      + (float)((float)(v46.m256_f32[5] * v43.m256_f32[1])
                                              + (float)(v46.m256_f32[1] * v43.m256_f32[0])))
                              * *(float *)&_XMM5))
              + (float)((float)((float)((float)(v47.m256_f32[5] * v43.m256_f32[7])
                                      + (float)(v47.m256_f32[1] * v43.m256_f32[6]))
                              + (float)((float)(v46.m256_f32[5] * v43.m256_f32[5])
                                      + (float)(v46.m256_f32[1] * v43.m256_f32[4])))
                      * *(float *)&_XMM10))
      + (float)((float)((float)(v47.m256_f32[5] * v44.m256_f32[7]) + (float)(v47.m256_f32[1] * v44.m256_f32[6]))
              + (float)((float)(v46.m256_f32[5] * v44.m256_f32[5]) + (float)(v46.m256_f32[1] * v44.m256_f32[4])));
  v36 = (float)((float)((float)((float)((float)((float)(v47.m256_f32[7] * v44.m256_f32[3])
                                              + (float)(v47.m256_f32[3] * v44.m256_f32[2]))
                                      + (float)((float)(v46.m256_f32[7] * v44.m256_f32[1])
                                              + (float)(v46.m256_f32[3] * v44.m256_f32[0])))
                              * *(float *)&_XMM3)
                      + (float)((float)((float)((float)(v47.m256_f32[7] * v43.m256_f32[3])
                                              + (float)(v47.m256_f32[3] * v43.m256_f32[2]))
                                      + (float)((float)(v46.m256_f32[7] * v43.m256_f32[1])
                                              + (float)(v46.m256_f32[3] * v43.m256_f32[0])))
                              * *(float *)&_XMM5))
              + (float)((float)((float)((float)(v47.m256_f32[7] * v43.m256_f32[7])
                                      + (float)(v47.m256_f32[3] * v43.m256_f32[6]))
                              + (float)((float)(v46.m256_f32[7] * v43.m256_f32[5])
                                      + (float)(v46.m256_f32[3] * v43.m256_f32[4])))
                      * *(float *)&_XMM10))
      + (float)((float)((float)(v47.m256_f32[7] * v44.m256_f32[7]) + (float)(v47.m256_f32[3] * v44.m256_f32[6]))
              + (float)((float)(v46.m256_f32[7] * v44.m256_f32[5]) + (float)(v46.m256_f32[3] * v44.m256_f32[4])));
  if ( v36 == 0.0 )
    return 0;
  v37 = (float)(1.0 / v36)
      * (float)((float)((float)((float)((float)((float)((float)(v47.m256_f32[6] * v44.m256_f32[3])
                                                      + (float)(v47.m256_f32[2] * v44.m256_f32[2]))
                                              + (float)((float)(v46.m256_f32[6] * v44.m256_f32[1])
                                                      + (float)(v46.m256_f32[2] * v44.m256_f32[0])))
                                      * *(float *)&_XMM3)
                              + (float)((float)((float)((float)(v47.m256_f32[6] * v43.m256_f32[3])
                                                      + (float)(v47.m256_f32[2] * v43.m256_f32[2]))
                                              + (float)((float)(v46.m256_f32[6] * v43.m256_f32[1])
                                                      + (float)(v46.m256_f32[2] * v43.m256_f32[0])))
                                      * *(float *)&_XMM5))
                      + (float)((float)((float)((float)(v47.m256_f32[6] * v43.m256_f32[7])
                                              + (float)(v47.m256_f32[2] * v43.m256_f32[6]))
                                      + (float)((float)(v46.m256_f32[6] * v43.m256_f32[5])
                                              + (float)(v46.m256_f32[2] * v43.m256_f32[4])))
                              * *(float *)&_XMM10))
              + (float)((float)((float)(v47.m256_f32[6] * v44.m256_f32[7]) + (float)(v47.m256_f32[2] * v44.m256_f32[6]))
                      + (float)((float)(v46.m256_f32[6] * v44.m256_f32[5]) + (float)(v46.m256_f32[2] * v44.m256_f32[4]))));
  v38 = (float)v24;
  v39 = (float)((float)((float)((float)((float)((float)((float)((float)((float)((float)(v47.m256_f32[4] * v44.m256_f32[3])
                                                                              + (float)(v47.m256_f32[0] * v44.m256_f32[2]))
                                                                      + (float)((float)(v46.m256_f32[4] * v44.m256_f32[1])
                                                                              + (float)(v46.m256_f32[0] * v44.m256_f32[0])))
                                                              * *(float *)&_XMM3)
                                                      + (float)((float)((float)((float)(v47.m256_f32[4] * v43.m256_f32[3])
                                                                              + (float)(v47.m256_f32[0] * v43.m256_f32[2]))
                                                                      + (float)((float)(v46.m256_f32[4] * v43.m256_f32[1])
                                                                              + (float)(v46.m256_f32[0] * v43.m256_f32[0])))
                                                              * *(float *)&_XMM5))
                                              + (float)((float)((float)((float)(v47.m256_f32[4] * v43.m256_f32[7])
                                                                      + (float)(v47.m256_f32[0] * v43.m256_f32[6]))
                                                              + (float)((float)(v46.m256_f32[4] * v43.m256_f32[5])
                                                                      + (float)(v46.m256_f32[0] * v43.m256_f32[4])))
                                                      * *(float *)&_XMM10))
                                      + (float)((float)((float)(v47.m256_f32[4] * v44.m256_f32[7])
                                                      + (float)(v47.m256_f32[0] * v44.m256_f32[6]))
                                              + (float)((float)(v46.m256_f32[4] * v44.m256_f32[5])
                                                      + (float)(v46.m256_f32[0] * v44.m256_f32[4]))))
                              / v36)
                      + 1.0)
              * (float)v24)
      * 0.5;
  v40 = (float)v22;
  v41 = (float)((float)(1.0 - (float)((float)(1.0 / v36) * v45)) * (float)v22) * 0.5;
  if ( !a8 )
  {
    *a5 = (float)(v39 * 100.0) / v38;
    *a6 = (float)(v41 * 100.0) / v40;
    *a7 = v37;
    return 1;
  }
  if ( v39 < 0.0 || v39 > v38 || v41 < 0.0 || v41 > v40 )
    return 0;
  *a5 = (float)(v39 * 100.0) / v38;
  *a6 = (float)(v41 * 100.0) / v40;
  *a7 = v37;
  return 1;
}

// --- End Function: sub_1409810D0 (0x1409810D0) ---

// --- Function: tan (0x14808226F) ---
// attributes: thunk
double __cdecl tan(double X)
{
  return __imp_tan(X);
}

// --- End Function: tan (0x14808226F) ---

