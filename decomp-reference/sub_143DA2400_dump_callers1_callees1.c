// Decompiled code dump generated by Code Dumper (Callers/Callees/Refs)
// Start Function: 0x143DA2400 (sub_143DA2400)
// Caller Depth: 1
// Callee/Ref Depth: 1
// Total Functions Found: 25
// ------------------------------------------------------------

// --- Function: sub_1402A24F0 (0x1402A24F0) ---
__int64 __fastcall sub_1402A24F0(__int64 a1)
{
  return a1;
}

// --- End Function: sub_1402A24F0 (0x1402A24F0) ---

// --- Function: sub_1402B1490 (0x1402B1490) ---
// local variable allocation has failed, the output may be wrong!
_QWORD *__fastcall sub_1402B1490(_QWORD *a1, double a2)
{
  __int128 v3; // kr00_16

  *((double *)&v3 + 1) = *(&a2 + 1);
  *(double *)&v3 = a2 * 10000000.0;
  _XMM0 = v3;
  __asm { vcvttsd2si rax, xmm0 }
  *a1 = _RAX;
  return a1;
}

// --- End Function: sub_1402B1490 (0x1402B1490) ---

// --- Function: sub_1402B15B0 (0x1402B15B0) ---
_QWORD *__fastcall sub_1402B15B0(_QWORD *a1)
{
  *a1 = 0;
  a1[1] = 0;
  a1[2] = 0;
  a1[3] = 0;
  a1[4] = 0;
  a1[5] = 0;
  return a1;
}

// --- End Function: sub_1402B15B0 (0x1402B15B0) ---

// --- Function: sub_1402FBEB0 (0x1402FBEB0) ---
_QWORD *__fastcall sub_1402FBEB0(_QWORD *a1, _QWORD *a2)
{
  *a1 += *a2;
  return a1;
}

// --- End Function: sub_1402FBEB0 (0x1402FBEB0) ---

// --- Function: sub_1403E6750 (0x1403E6750) ---
unsigned __int64 __fastcall sub_1403E6750(unsigned __int64 *a1)
{
  if ( sub_14030EC00(a1) )
    return *a1 & 0xFFFFFFFFFFFFLL;
  else
    return 0;
}

// --- End Function: sub_1403E6750 (0x1403E6750) ---

// --- Function: j_powf (0x1403E7F40) ---
// attributes: thunk
float __cdecl j_powf(float X, float Y)
{
  return powf(X, Y);
}

// --- End Function: j_powf (0x1403E7F40) ---

// --- Function: sub_1415FF190 (0x1415FF190) ---
// local variable allocation has failed, the output may be wrong!
__m128 __fastcall sub_1415FF190(double a1, __int64 a2)
{
  __int128 v3; // kr00_16

  v3 = *(_OWORD *)&a1;
  *(float *)&v3 = *(float *)&a1 * *(float *)(a2 + 8);
  return (__m128)v3;
}

// --- End Function: sub_1415FF190 (0x1415FF190) ---

// --- Function: sub_141D17630 (0x141D17630) ---
// attributes: thunk
__int64 __fastcall sub_141D17630(__int64 a1)
{
  return sub_1403335B0(a1);
}

// --- End Function: sub_141D17630 (0x141D17630) ---

// --- Function: sub_142C0F480 (0x142C0F480) ---
__m128 __fastcall sub_142C0F480(__int64 a1, float a2)
{
  __int128 v3; // kr00_16

  v3 = *(unsigned int *)(a1 + 8);
  *(float *)&v3 = *(float *)(a1 + 8) - a2;
  return (__m128)v3;
}

// --- End Function: sub_142C0F480 (0x142C0F480) ---

// --- Function: sub_142D8A720 (0x142D8A720) ---
// local variable allocation has failed, the output may be wrong!
__m128 __fastcall sub_142D8A720(double a1, __int64 a2)
{
  __int128 v3; // kr00_16

  v3 = *(_OWORD *)&a1;
  *(float *)&v3 = *(float *)&a1 + *(float *)(a2 + 8);
  return (__m128)v3;
}

// --- End Function: sub_142D8A720 (0x142D8A720) ---

// --- Function: sub_143CBFB70 (0x143CBFB70) ---
__int64 __fastcall sub_143CBFB70(__int64 a1)
{
  __int64 result; // rax
  bool v2; // [rsp+20h] [rbp-58h]
  bool v3; // [rsp+2Ch] [rbp-4Ch]
  bool v4; // [rsp+30h] [rbp-48h]
  unsigned __int64 v5; // [rsp+38h] [rbp-40h]

  v2 = 0;
  v5 = sub_1403E6750((unsigned __int64 *)(a1 + 8));
  if ( (*(unsigned __int8 (__fastcall **)(unsigned __int64))(*(_QWORD *)v5 + 0x720LL))(v5) )
  {
    v3 = *(float *)(a1 + 0x6B0) > 0.0
      || *(float *)(a1 + 0x6D0) > 0.0 && *(float *)(*(_QWORD *)(sub_141D17630(a1) + 0x28) + 0x2CLL) > 0.0
      || *(float *)(a1 + 0x6F0) > 0.0 && *(float *)(*(_QWORD *)(sub_141D17630(a1) + 0x28) + 0x38LL) > 0.0
      || *(_QWORD *)(a1 + 0x2B8)
      || *(_QWORD *)(a1 + 0x3B0);
    v2 = v3;
  }
  if ( *(_BYTE *)(sub_1402A24F0((__int64)&qword_149B4FBE0) + 0x5F5) && !v2 )
  {
    v4 = *(float *)(a1 + 0x6B0) > 0.0 || sub_143CEF7E0(a1 + 0x400) > 0.000099999997;
    v2 = v4;
  }
  result = v2;
  if ( !v2 )
    return sub_143CE5D60(a1, 0, 0);
  return result;
}

// --- End Function: sub_143CBFB70 (0x143CBFB70) ---

// --- Function: sub_143CC0690 (0x143CC0690) ---
__int64 __fastcall sub_143CC0690(__int64 a1, __int64 a2, unsigned __int8 a3)
{
  __int64 result; // rax
  ULONG_PTR Parameter_; // [rsp+28h] [rbp-80h] BYREF
  BOOL v6; // [rsp+30h] [rbp-78h]
  BOOL v7; // [rsp+34h] [rbp-74h]
  __int64 v8; // [rsp+38h] [rbp-70h]
  ULONG_PTR Parameter; // [rsp+40h] [rbp-68h] BYREF
  __int64 v11; // [rsp+50h] [rbp-58h]
  __int64 v12; // [rsp+58h] [rbp-50h]
  Parameter *Parameter_1; // [rsp+60h] [rbp-48h]
  ULONG_PTR v14; // [rsp+68h] [rbp-40h]
  __int64 v15; // [rsp+70h] [rbp-38h]
  ULONG_PTR v16; // [rsp+78h] [rbp-30h]
  __int64 v17; // [rsp+80h] [rbp-28h]
  __int64 v18; // [rsp+88h] [rbp-20h]
  _BYTE Parameter__1[24]; // [rsp+90h] [rbp-18h] BYREF

  if ( *(_QWORD *)(a1 + 0x2B8) )
  {
    v11 = a1 + 0x2B0;
    sub_14277D040((_QWORD **)(a1 + 0x2B0), (Parameter *)&Parameter_);
    while ( 1 )
    {
      v12 = a1 + 0x2B0;
      v8 = a1 + 0x2B0;
      Parameter_1 = *(_QWORD *)(a1 + 0x2B0);
      Parameter = Parameter_1;
      _StarEngineModule__((ULONG_PTR)&Parameter);
      v6 = Parameter_ == Parameter;
      if ( Parameter_ == Parameter )
        break;
      v14 = Parameter_ + 0x20;
      v15 = *(_QWORD *)(Parameter_ + 0x28);
      v7 = v15 < 0;
      if ( v15 >= 0
        && (v17 = a2 + 8, v16 = Parameter_ + 0x20, sub_140597660((_QWORD *)(a2 + 8), (_QWORD *)(Parameter_ + 0x28))) )
      {
        v18 = a1 + 0x2B0;
        Parameter_ = *sub_143C1EC60(a1 + 0x2B0, (Parameter *)Parameter__1, Parameter_);
        a3 = 1;
      }
      else
      {
        sub_142BB3820((__int64)&Parameter_);
      }
    }
  }
  else
  {
    a3 = 1;
  }
  result = a3;
  if ( a3 )
    return sub_143DAE9B0(a1);
  return result;
}

// --- End Function: sub_143CC0690 (0x143CC0690) ---

// --- Function: sub_143CD8500 (0x143CD8500) ---
_BOOL8 __fastcall sub_143CD8500(__int64 a1, __int64 a2)
{
  _BOOL8 result; // rax
  char *Parameter_; // [rsp+20h] [rbp-68h] BYREF
  BOOL v6; // [rsp+28h] [rbp-60h]
  __int64 v7; // [rsp+30h] [rbp-58h]
  ULONG_PTR Parameter[3]; // [rsp+38h] [rbp-50h] BYREF
  ULONG_PTR v9; // [rsp+50h] [rbp-38h]
  char *v10; // [rsp+58h] [rbp-30h]
  char *v11; // [rsp+60h] [rbp-28h]
  _QWORD v12[2]; // [rsp+68h] [rbp-20h] BYREF
  _BYTE Parameter__1[16]; // [rsp+78h] [rbp-10h] BYREF
  __int64 v15; // [rsp+98h] [rbp+10h] BYREF

  v15 = a2;
  Parameter[1] = a1 + 0x3A8;
  sub_14277D040((_QWORD **)(a1 + 0x3A8), (Parameter *)&Parameter_);
  while ( 1 )
  {
    Parameter[2] = a1 + 0x3A8;
    v7 = a1 + 0x3A8;
    v9 = *(_QWORD *)(a1 + 0x3A8);
    Parameter[0] = v9;
    _StarEngineModule__((ULONG_PTR)Parameter);
    v6 = Parameter_ == (char *)Parameter[0];
    result = v6;
    if ( Parameter_ == (char *)Parameter[0] )
      return result;
    v10 = Parameter_ + 0x20;
    sub_1405975C0(&v15, v12, (_QWORD *)Parameter_ + 5);
    v11 = Parameter_ + 0x20;
    if ( !sub_14030EC00((unsigned __int64 *)Parameter_ + 4) )
      goto LABEL_5;
    _XMM0 = sub_140597760();
    __asm { vcvtsd2ss xmm0, xmm0, xmm0 }
    if ( *(float *)&_XMM0 <= 1.0 )
    {
      sub_142BB3820((__int64)&Parameter_);
    }
    else
    {
LABEL_5:
      v12[1] = a1 + 0x3A8;
      Parameter_ = *sub_142CCB140((_QWORD *)(a1 + 0x3A8), (Parameter *)Parameter__1, (ULONG_PTR)Parameter_);
    }
  }
}

// --- End Function: sub_143CD8500 (0x143CD8500) ---

// --- Function: sub_143CFB4D0 (0x143CFB4D0) ---
__m128 __fastcall sub_143CFB4D0(__int64 a1)
{
  __int128 v2; // kr00_16

  v2 = *(unsigned int *)(a1 + 0x2F4);
  *(float *)&v2 = *(float *)(a1 + 0x2F4) * *(float *)(a1 + 0xE8);
  return (__m128)v2;
}

// --- End Function: sub_143CFB4D0 (0x143CFB4D0) ---

// --- Function: sub_143CFB4F0 (0x143CFB4F0) ---
__m128 __fastcall sub_143CFB4F0(__int64 a1)
{
  __int128 v2; // kr00_16

  v2 = *(unsigned int *)(a1 + 0x2F0);
  *(float *)&v2 = *(float *)(a1 + 0x2F0) * *(float *)(a1 + 0xC8);
  return (__m128)v2;
}

// --- End Function: sub_143CFB4F0 (0x143CFB4F0) ---

// --- Function: sub_143D01CD0 (0x143D01CD0) ---
float __fastcall sub_143D01CD0(__int64 a1)
{
  float v2; // [rsp+24h] [rbp-34h]

  if ( !*(_QWORD *)(sub_141D17630(a1) + 0x28) )
    return 1.0;
  v2 = sub_143CA00E0((__crt_win32_buffer_debug_info *)(a1 + 0x660), (float *)(a1 + 0x2EC), a1 + 0x3D0).m128_f32[0];
  if ( v2 <= 0.0 )
    return 1.0;
  else
    return v2;
}

// --- End Function: sub_143D01CD0 (0x143D01CD0) ---

// --- Function: sub_143D1DDF0 (0x143D1DDF0) ---
double __fastcall sub_143D1DDF0(__int64 a1, __int64 a2)
{
  return sub_143DA2400(a1, a2);
}

// --- End Function: sub_143D1DDF0 (0x143D1DDF0) ---

// --- Function: sub_143D7DF60 (0x143D7DF60) ---
unsigned __int64 __fastcall sub_143D7DF60(__int64 a1, float a2)
{
  unsigned __int64 result; // rax
  unsigned __int8 v3; // [rsp+20h] [rbp-28h]
  float v4; // [rsp+24h] [rbp-24h]
  float v5; // [rsp+28h] [rbp-20h]

  if ( a2 >= 0.0 )
  {
    if ( a2 >= 1.0 )
      v4 = 1.0;
    else
      v4 = a2;
    v5 = v4;
  }
  else
  {
    v5 = 0.0;
  }
  *(float *)(a1 + 0x6D0) = v5;
  sub_1403C3BF0(a1 + 0x6C8);
  result = *(unsigned __int8 *)(sub_1402A24F0((__int64)&qword_149B4FBE0) + 0x2A0);
  if ( (_DWORD)result )
  {
    v3 = *(_BYTE *)(sub_1402A24F0((__int64)&qword_149B4FBE0) + 0x5F5);
    result = v3;
    if ( v3 )
      return sub_143D2F760(a1);
  }
  return result;
}

// --- End Function: sub_143D7DF60 (0x143D7DF60) ---

// --- Function: sub_143D7EC10 (0x143D7EC10) ---
unsigned __int64 __fastcall sub_143D7EC10(__int64 a1, float a2)
{
  unsigned __int64 result; // rax
  unsigned __int8 v3; // [rsp+20h] [rbp-28h]
  float v4; // [rsp+24h] [rbp-24h]
  float v5; // [rsp+28h] [rbp-20h]

  if ( a2 >= 0.0 )
  {
    if ( a2 >= 1.0 )
      v4 = 1.0;
    else
      v4 = a2;
    v5 = v4;
  }
  else
  {
    v5 = 0.0;
  }
  *(float *)(a1 + 0x6F0) = v5;
  sub_1403C3BF0(a1 + 0x6E8);
  result = *(unsigned __int8 *)(sub_1402A24F0((__int64)&qword_149B4FBE0) + 0x2A0);
  if ( (_DWORD)result )
  {
    v3 = *(_BYTE *)(sub_1402A24F0((__int64)&qword_149B4FBE0) + 0x5F5);
    result = v3;
    if ( v3 )
      return sub_143D2F7C0(a1);
  }
  return result;
}

// --- End Function: sub_143D7EC10 (0x143D7EC10) ---

// --- Function: sub_143D915F0 (0x143D915F0) ---
__int64 __fastcall sub_143D915F0(__int64 a1, unsigned int n2)
{
  __int64 v2; // rax
  __int64 *v3; // rax
  __int64 result; // rax
  char v5; // [rsp+22h] [rbp-106h]
  char buf_; // [rsp+23h] [rbp-105h] BYREF
  _BYTE v7[4]; // [rsp+24h] [rbp-104h] BYREF
  BOOL v8; // [rsp+28h] [rbp-100h]
  ULONG_PTR Parameter; // [rsp+30h] [rbp-F8h] BYREF
  __int64 v10; // [rsp+38h] [rbp-F0h] BYREF
  __int64 v11; // [rsp+40h] [rbp-E8h]
  unsigned __int64 v12; // [rsp+48h] [rbp-E0h]
  unsigned __int64 v13; // [rsp+50h] [rbp-D8h]
  __int64 v14; // [rsp+58h] [rbp-D0h]
  __int64 v15; // [rsp+60h] [rbp-C8h]
  __int64 v16; // [rsp+68h] [rbp-C0h]
  _QWORD *v17; // [rsp+70h] [rbp-B8h]
  __int64 v18; // [rsp+78h] [rbp-B0h] BYREF
  unsigned __int8 (__fastcall *v19)(unsigned __int64, __int64); // [rsp+80h] [rbp-A8h]
  __int64 (__fastcall *v20)(__int64, _QWORD); // [rsp+88h] [rbp-A0h]
  __int64 v21; // [rsp+90h] [rbp-98h]
  __int64 v22; // [rsp+98h] [rbp-90h] BYREF
  _QWORD *v23; // [rsp+A0h] [rbp-88h]
  __int64 *v24; // [rsp+A8h] [rbp-80h]
  __int64 (__fastcall *v25)(__int64, _QWORD); // [rsp+B0h] [rbp-78h]
  __int64 v26; // [rsp+B8h] [rbp-70h]
  Parameter *Parameter_1; // [rsp+C0h] [rbp-68h]
  __int64 v28; // [rsp+C8h] [rbp-60h]
  __int64 *v29; // [rsp+D0h] [rbp-58h]
  __int64 v30; // [rsp+D8h] [rbp-50h]
  __int64 v31; // [rsp+E0h] [rbp-48h]
  __int64 v32; // [rsp+E8h] [rbp-40h]
  _QWORD v33[2]; // [rsp+F0h] [rbp-38h] BYREF
  _BYTE v34[40]; // [rsp+100h] [rbp-28h] BYREF

  v12 = sub_1403E6750((unsigned __int64 *)(a1 + 8));
  v19 = *(unsigned __int8 (__fastcall **)(unsigned __int64, __int64))(*(_QWORD *)v12 + 0x40LL);
  if ( v19(v12, 1) )
    return sub_1405C0E00(
             0xAu,
             0,
             "![Mineable] %s cannot destroy editor-unremovable entities.",
             "CEntityComponentMineable::SvTryDestroy");
  v13 = sub_1403E6750((unsigned __int64 *)(a1 + 8));
  if ( !(*(unsigned __int8 (__fastcall **)(unsigned __int64))(*(_QWORD *)v13 + 0x720LL))(v13) )
    return sub_1405C0E00(
             0xAu,
             0,
             "![Mineable] %s should only be called by the authoritative process!",
             "CEntityComponentMineable::SvTryDestroy");
  v14 = a1 + 0x300;
  *(_BYTE *)(a1 + 0x308) = 1;
  sub_1403C3BF0(v14);
  sub_143CE5D60(a1, 0, 0);
  if ( n2 != 1 || *(_BYTE *)(a1 + 0x320) || sub_143D1EBA0(a1) )
  {
    sub_143D8F980(a1, n2);
  }
  else
  {
    if ( !sub_143D1E160(a1) )
    {
      v5 = *(float *)(a1 + 0x6F0) < 0.5;
      v15 = *(_QWORD *)(sub_1402A24F0((__int64)&qword_149B4FBE0) + 0x60);
      v20 = *(__int64 (__fastcall **)(__int64, _QWORD))(*(_QWORD *)v15 + 0x38LL);
      v23 = (_QWORD *)v20(v15, 0);
      v21 = a1 + 8;
      sub_1403B0A70((unsigned __int64 *)(a1 + 8), &v22);
      v24 = &v22;
      v2 = sub_143C3FBD0((__int64)v34, &v22, v23, v5);
      sub_143B89AB0(a1, v2);
    }
    sub_143D791D0(a1);
    sub_143D8B830(a1);
  }
  v16 = *(_QWORD *)(sub_1402A24F0((__int64)&qword_149B4FBE0) + 0x60);
  v25 = *(__int64 (__fastcall **)(__int64, _QWORD))(*(_QWORD *)v16 + 0x38LL);
  v3 = (__int64 *)v25(v16, 0);
  sub_143CD8500(a1, *v3);
  v26 = a1 + 0x3A8;
  Parameter_1 = **(_QWORD **)(a1 + 0x3A8);
  Parameter = Parameter_1;
  _StarEngineModule__((ULONG_PTR)&Parameter);
  memset(&buf_, 0, sizeof(buf_));
  while ( 1 )
  {
    v8 = *(_BYTE *)(Parameter + 0x19) != 0;
    result = v8;
    if ( v8 )
      break;
    v17 = (_QWORD *)(Parameter + 0x20);
    if ( sub_14030EC00((unsigned __int64 *)(Parameter + 0x20)) )
    {
      v28 = sub_14030ECF0(v17);
      v29 = sub_143193C30(v28, v33);
      v30 = *v29;
      v18 = v30;
      if ( Handle::IsValid(&v18) )
      {
        v31 = v18 & 0xFFFFFFFFFFFFLL;
        sub_1434CFCA0(v18 & 0xFFFFFFFFFFFFLL, &v10);
        if ( is_valid_handle_typeA(&v10) )
        {
          v32 = *(_QWORD *)(sub_1402A24F0((__int64)&qword_149B4FBE0) + 0xA0);
          v11 = v33[1];
          if ( is_valid_handle_typeA(&v10) )
            v11 = v10 & 0xFFFFFFFFFFFFLL;
          else
            v11 = 0;
          sub_143B7F9B0(v32, v11, (__int64)v7);
        }
      }
    }
    sub_142BB3820((__int64)&Parameter);
  }
  return result;
}

// --- End Function: sub_143D915F0 (0x143D915F0) ---

// --- Function: sub_143DA2400 (0x143DA2400) ---
double __fastcall sub_143DA2400(__int64 a1, __int64 a2)
{
  _QWORD *v3; // rax
  double v4; // kr00_8
  double v5; // xmm0_8
  __int128 v7; // kr00_16
  __int64 v9; // rax
  __int64 v10; // rax
  double v11; // kr00_8
  double v12; // xmm0_8
  __int64 v13; // rax
  __int64 v14; // rax
  __int64 v15; // rax
  __int64 v16; // rax
  double v17; // kr00_8
  float v18; // xmm0_4
  double v19; // kr00_8
  __int128 v21; // kr00_16
  __int64 v23; // rax
  __int64 v24; // rax
  bool v25; // [rsp+31h] [rbp-217h]
  float v26; // [rsp+34h] [rbp-214h]
  float v27; // [rsp+40h] [rbp-208h]
  float v28; // [rsp+48h] [rbp-200h]
  float v29; // [rsp+50h] [rbp-1F8h]
  int v30; // [rsp+58h] [rbp-1F0h]
  float v31; // [rsp+5Ch] [rbp-1ECh]
  unsigned int v32; // [rsp+68h] [rbp-1E0h]
  __int64 v33; // [rsp+70h] [rbp-1D8h]
  __int64 v34; // [rsp+78h] [rbp-1D0h]
  __int64 v35; // [rsp+E0h] [rbp-168h]
  _QWORD v36[2]; // [rsp+F0h] [rbp-158h] BYREF
  __int64 v37; // [rsp+100h] [rbp-148h]
  __int64 v38; // [rsp+108h] [rbp-140h]
  __int64 v39; // [rsp+110h] [rbp-138h]
  __int64 v40; // [rsp+118h] [rbp-130h]
  __int64 v41; // [rsp+120h] [rbp-128h]
  __int64 v42; // [rsp+128h] [rbp-120h]
  __int64 v43; // [rsp+130h] [rbp-118h]
  __int64 v44; // [rsp+138h] [rbp-110h]
  __int64 v45; // [rsp+140h] [rbp-108h]
  __int64 v46; // [rsp+148h] [rbp-100h]
  __int64 v47; // [rsp+150h] [rbp-F8h]
  __int64 v48; // [rsp+158h] [rbp-F0h]
  __int64 v49; // [rsp+160h] [rbp-E8h]
  __int64 v50; // [rsp+168h] [rbp-E0h]
  _QWORD v51[2]; // [rsp+170h] [rbp-D8h] BYREF
  __int64 v52; // [rsp+180h] [rbp-C8h]
  __int64 v53; // [rsp+188h] [rbp-C0h]
  __int64 v54; // [rsp+190h] [rbp-B8h]
  __int64 v55; // [rsp+198h] [rbp-B0h]
  __int64 v56; // [rsp+1A0h] [rbp-A8h]
  double (__fastcall *v57)(_QWORD); // [rsp+1A8h] [rbp-A0h]
  _QWORD dst_[10]; // [rsp+1B0h] [rbp-98h] BYREF
  _QWORD buf_[9]; // [rsp+200h] [rbp-48h] BYREF

  sub_1402B15B0(dst_);
  memset(buf_, 0, 0x30u);
  qmemcpy(dst_, sub_1402B15B0(buf_), 0x30u);
  dst_[2] = __rdtsc();
  HIDWORD(dst_[0]) = 1;
  BYTE4(dst_[1]) = 0;
  LOWORD(dst_[0]) = 0x2C00;
  qword_149B4B870(
    dst_,
    &word_149E353A0,
    "CEntityComponentMineable::Update",
    "W:\\p4-src\\CryEngine\\Code\\GameSDK\\GameDll\\EntityComponentMineable.cpp",
    0x51F);
  WORD1(dst_[0]) = word_149E353A0;
  v33 = sub_1403E6750((unsigned __int64 *)(a1 + 8));
  if ( (*(unsigned __int8 (__fastcall **)(__int64))(*(_QWORD *)v33 + 0x720LL))(v33) )
  {
    if ( !*(_QWORD *)(sub_141D17630(a1) + 0x28) )
    {
      dst_[3] = __rdtsc();
      return qword_149B4B878(dst_);
    }
    v30 = *(_QWORD *)(a1 + 0x3B0);
    v34 = *(_QWORD *)(sub_1402A24F0((__int64)&qword_149B4FBE0) + 0x60);
    v3 = (_QWORD *)(*(__int64 (__fastcall **)(__int64, _QWORD))(*(_QWORD *)v34 + 0x38LL))(v34, 0);
    sub_143CD8500(a1, *v3);
    v25 = v30 != *(_QWORD *)(a1 + 0x3B0);
    if ( v30 != *(_QWORD *)(a1 + 0x3B0) )
      sub_143DACFD0(a1);
    sub_143CC0690(a1, a2, v25);
    sub_143DB0BB0(a1);
    if ( *(float *)(*(_QWORD *)(sub_141D17630(a1) + 0x28) + 0x230LL) <= 0.0 )
      v27 = 100.0;
    else
      v27 = *(float *)(*(_QWORD *)(sub_141D17630(a1) + 0x28) + 0x230LL);
    v26 = (float)((float)(v27 - sub_143D01CD0(a1)) / v27) + 1.0;
    if ( v26 >= 0.1 )
      v28 = v26;
    else
      v28 = 0.1;
    if ( sub_143CFB4F0(a1).m128_f32[0] > *(float *)(a1 + 0x6B0)
      || sub_143CFB4D0(a1).m128_f32[0] < *(float *)(a1 + 0x6B0) )
    {
      if ( sub_143CFB4D0(a1).m128_f32[0] > *(float *)(a1 + 0x6B0)
        || (v9 = sub_141D17630(a1), v36[1] = v9 + 0x18, v37 = *(_QWORD *)(v9 + 0x28), *(float *)(v37 + 0x28) <= 0.0) )
      {
        v13 = sub_141D17630(a1);
        v41 = v13 + 0x18;
        v42 = *(_QWORD *)(v13 + 0x28);
        if ( sub_142C0F480(a1 + 0x6C8, (float)(*(float *)(a2 + 0x10) * *(float *)(v42 + 0x2C)) * v28).m128_f32[0] > 0.0 )
        {
          v14 = sub_141D17630(a1);
          v43 = v14 + 0x18;
          v44 = *(_QWORD *)(v14 + 0x28);
          sub_142C0F480(a1 + 0x6C8, (float)(*(float *)(a2 + 0x10) * *(float *)(v44 + 0x2C)) * v28);
        }
        sub_143D7DF60(a1);
      }
      else
      {
        v10 = sub_141D17630(a1);
        v38 = v10 + 0x18;
        v39 = *(_QWORD *)(v10 + 0x28);
        v40 = a1 + 0x220;
        *(_QWORD *)&v11 = *(unsigned int *)(v39 + 0x28);
        *(float *)&v11 = *(float *)(v39 + 0x28) * v28;
        *(_QWORD *)&v12 = sub_1415FF190(v11, a1 + 0x200).m128_u64[0];
        sub_142D8A720(v12, a1 + 0x220);
        sub_143D7DF60(a1);
      }
    }
    else
    {
      v35 = *(_QWORD *)(sub_141D17630(a1) + 0x28);
      *(_QWORD *)&v4 = *(unsigned int *)(v35 + 0x24);
      *(float *)&v4 = *(float *)(v35 + 0x24) * v28;
      *(_QWORD *)&v5 = sub_1415FF190(v4, a1 + 0x1C0).m128_u64[0];
      sub_142D8A720(v5, a1 + 0x1E0);
      *((_QWORD *)&v7 + 1) = sub_143D7DF60(a1).m128_u64[1];
      *(double *)&v7 = *(float *)(a2 + 0x10);
      _XMM0 = v7;
      __asm { vmovupd xmm1, xmm0 }
      sub_1402B1490(v36, *(double *)&_XMM1);
      sub_1402FBEB0((_QWORD *)(a1 + 0x7E8), v36);
    }
    if ( sub_143CFB4D0(a1).m128_f32[0] >= *(float *)(a1 + 0x6B0) )
    {
      v23 = sub_141D17630(a1);
      v51[1] = v23 + 0x18;
      v52 = *(_QWORD *)(v23 + 0x28);
      if ( sub_142C0F480(a1 + 0x6E8, (float)(*(float *)(a2 + 0x10) * *(float *)(v52 + 0x38)) * v28).m128_f32[0] > 0.0 )
      {
        v24 = sub_141D17630(a1);
        v53 = v24 + 0x18;
        v54 = *(_QWORD *)(v24 + 0x28);
        sub_142C0F480(a1 + 0x6E8, (float)(*(float *)(a2 + 0x10) * *(float *)(v54 + 0x38)) * v28);
      }
      sub_143D7EC10(a1);
    }
    else
    {
      if ( sub_143CFB4D0(a1).m128_f32[0] >= 1.0 )
      {
        v29 = 0.0;
      }
      else
      {
        v31 = *(float *)(a1 + 0x6B0) - sub_143CFB4D0(a1).m128_f32[0];
        v29 = v31 / (float)(1.0 - sub_143CFB4D0(a1).m128_f32[0]);
      }
      v15 = sub_141D17630(a1);
      v45 = v15 + 0x18;
      v47 = *(_QWORD *)(v15 + 0x28);
      v16 = sub_141D17630(a1);
      v46 = v16 + 0x18;
      v48 = *(_QWORD *)(v16 + 0x28);
      v50 = a1 + 0x220;
      v49 = a1 + 0x200;
      *(float *)&v32 = *(float *)(a2 + 0x10) * *(float *)(v47 + 0x30);
      *(_QWORD *)&v17 = v32;
      *(float *)&v17 = (float)(*(float *)&v32 * j_powf(v29 + 1.0, *(float *)(v48 + 0x34))) * v28;
      v18 = sub_1415FF190(v17, v49).m128_f32[0];
      *(_QWORD *)&v19 = *(unsigned int *)(a1 + 0x6F0);
      *(float *)&v19 = *(float *)(a1 + 0x6F0) + v18;
      sub_142D8A720(v19, v50);
      *((_QWORD *)&v21 + 1) = sub_143D7EC10(a1).m128_u64[1];
      *(double *)&v21 = *(float *)(a2 + 0x10);
      _XMM0 = v21;
      __asm { vmovupd xmm1, xmm0 }
      sub_1402B1490(v51, *(double *)&_XMM1);
      sub_1402FBEB0((_QWORD *)(a1 + 0x7F0), v51);
    }
    if ( *(float *)(a1 + 0x6D0) >= 1.0 || *(float *)(a1 + 0x6F0) >= 1.0 )
      sub_143D915F0(a1, 1);
  }
  v55 = sub_1402A24F0((__int64)&qword_149B4FBE0);
  if ( *(_BYTE *)(v55 + 0x5F5) )
  {
    v56 = a1 + 0x400;
    sub_143DAA120(a1 + 0x400);
    sub_143DA5D80(a1);
  }
  sub_143CBFB70(a1);
  dst_[3] = __rdtsc();
  v57 = qword_149B4B878;
  return qword_149B4B878(dst_);
}

// --- End Function: sub_143DA2400 (0x143DA2400) ---

// --- Function: sub_143DA5D80 (0x143DA5D80) ---
__int64 __fastcall sub_143DA5D80(__int64 a1, float a2)
{
  __int64 v2; // rax
  __int64 result; // rax
  __int64 v4; // rax
  __int64 v5; // rax
  __int64 v6; // r8
  __int64 v7; // rax
  __int64 v8; // r8
  __int64 v9; // rax
  __int64 v10; // r8
  __int64 v11; // rax
  __int64 v12; // r8
  __int64 v13; // rax
  __int64 v14; // r8
  __int64 v15; // rax
  __int64 v16; // r8
  __int64 v17; // rax
  __int64 v18; // rax
  __int64 v19; // r8
  __int64 v20; // [rsp+20h] [rbp-178h] BYREF
  float v21; // [rsp+28h] [rbp-170h]
  float v22; // [rsp+30h] [rbp-168h]
  float v23; // [rsp+34h] [rbp-164h]
  unsigned int v24; // [rsp+38h] [rbp-160h]
  int v25; // [rsp+3Ch] [rbp-15Ch]
  unsigned int v26; // [rsp+40h] [rbp-158h]
  int v27; // [rsp+44h] [rbp-154h]
  unsigned int v28; // [rsp+48h] [rbp-150h]
  int v29; // [rsp+4Ch] [rbp-14Ch]
  unsigned int v30; // [rsp+50h] [rbp-148h]
  unsigned __int32 v31; // [rsp+54h] [rbp-144h]
  unsigned int v32; // [rsp+58h] [rbp-140h]
  float v33; // [rsp+5Ch] [rbp-13Ch]
  unsigned int v34; // [rsp+60h] [rbp-138h]
  unsigned int v35; // [rsp+64h] [rbp-134h]
  int v36; // [rsp+68h] [rbp-130h]
  unsigned int v37; // [rsp+6Ch] [rbp-12Ch]
  __int64 v38; // [rsp+70h] [rbp-128h]
  __int64 v39; // [rsp+78h] [rbp-120h]
  __int64 v40; // [rsp+80h] [rbp-118h]
  __int64 v41; // [rsp+88h] [rbp-110h]
  __int64 v42; // [rsp+90h] [rbp-108h]
  __int64 v43; // [rsp+98h] [rbp-100h]
  __int64 v44; // [rsp+A0h] [rbp-F8h]
  __int64 v45; // [rsp+A8h] [rbp-F0h]
  __int64 v46; // [rsp+B0h] [rbp-E8h]
  __int64 v47; // [rsp+B8h] [rbp-E0h]
  __int64 v48; // [rsp+C0h] [rbp-D8h]
  __int64 v49; // [rsp+C8h] [rbp-D0h]
  void (__fastcall *v50)(__int64, _QWORD); // [rsp+D0h] [rbp-C8h]
  __int64 v51; // [rsp+D8h] [rbp-C0h]
  __int64 v52; // [rsp+E0h] [rbp-B8h]
  void (__fastcall *v53)(__int64, _QWORD, __int64, _QWORD); // [rsp+E8h] [rbp-B0h]
  __int64 v54; // [rsp+F0h] [rbp-A8h]
  __int64 v55; // [rsp+F8h] [rbp-A0h]
  void (__fastcall *v56)(__int64, _QWORD, __int64, _QWORD); // [rsp+100h] [rbp-98h]
  __int64 v57; // [rsp+108h] [rbp-90h]
  __int64 v58; // [rsp+110h] [rbp-88h]
  void (__fastcall *v59)(__int64, _QWORD, __int64, _QWORD); // [rsp+118h] [rbp-80h]
  __int64 v60; // [rsp+120h] [rbp-78h]
  __int64 v61; // [rsp+128h] [rbp-70h]
  void (__fastcall *v62)(__int64, _QWORD, __int64, _QWORD); // [rsp+130h] [rbp-68h]
  __int64 v63; // [rsp+138h] [rbp-60h]
  __int64 v64; // [rsp+140h] [rbp-58h]
  void (__fastcall *v65)(__int64, _QWORD, __int64, _QWORD); // [rsp+148h] [rbp-50h]
  __int64 v66; // [rsp+150h] [rbp-48h]
  __int64 v67; // [rsp+158h] [rbp-40h]
  void (__fastcall *v68)(__int64, _QWORD, __int64, _QWORD); // [rsp+160h] [rbp-38h]
  __int64 v69; // [rsp+168h] [rbp-30h]
  __int64 v70; // [rsp+170h] [rbp-28h]
  __int64 v71; // [rsp+178h] [rbp-20h]
  __int64 v72; // [rsp+180h] [rbp-18h]
  void (__fastcall *v73)(__int64, _QWORD, __int64, _QWORD); // [rsp+188h] [rbp-10h]

  v2 = sub_141D17630(a1);
  v46 = v2 + 0x30;
  result = *(_QWORD *)(v2 + 0x40);
  v47 = result;
  if ( result )
  {
    v20 = *(_QWORD *)(a1 + 0x7A8);
    if ( is_valid_handle_typeA(&v20) )
    {
      if ( !*(_BYTE *)(a1 + 0x7B9) && *(float *)(a1 + 0x6B0) > 0.025 && *(_BYTE *)(a1 + 0x7BA) )
      {
        v38 = (v20 & 0xFFFFFFFFFFFFLL) + 0x70;
        v50 = *(void (__fastcall **)(__int64, _QWORD))(*(_QWORD *)((v20 & 0xFFFFFFFFFFFFLL) + 0x70) + 8LL);
        v4 = sub_141D17630(a1);
        v48 = v4 + 0x30;
        v49 = *(_QWORD *)(v4 + 0x40);
        v24 = *(_DWORD *)(v49 + 0x108);
        v50(v38, v24);
        *(_BYTE *)(a1 + 0x7B9) = 1;
      }
      v39 = (v20 & 0xFFFFFFFFFFFFLL) + 0x70;
      v53 = *(void (__fastcall **)(__int64, _QWORD, __int64, _QWORD))(*(_QWORD *)((v20 & 0xFFFFFFFFFFFFLL) + 0x70)
                                                                    + 0x30LL);
      v25 = *(_DWORD *)(a1 + 0x6B0);
      v5 = sub_141D17630(a1);
      v51 = v5 + 0x30;
      v52 = *(_QWORD *)(v5 + 0x40);
      v26 = AK::WriteBytesMem::Count((AK::WriteBytesMem *)(v52 + 8));
      v53(v39, v26, v6, 0);
      v40 = (v20 & 0xFFFFFFFFFFFFLL) + 0x70;
      v56 = *(void (__fastcall **)(__int64, _QWORD, __int64, _QWORD))(*(_QWORD *)((v20 & 0xFFFFFFFFFFFFLL) + 0x70)
                                                                    + 0x30LL);
      v27 = *(_DWORD *)(a1 + 0x6F0);
      v7 = sub_141D17630(a1);
      v54 = v7 + 0x30;
      v55 = *(_QWORD *)(v7 + 0x40);
      v28 = AK::WriteBytesMem::Count((AK::WriteBytesMem *)(v55 + 0x28));
      v56(v40, v28, v8, 0);
      v41 = (v20 & 0xFFFFFFFFFFFFLL) + 0x70;
      v59 = *(void (__fastcall **)(__int64, _QWORD, __int64, _QWORD))(*(_QWORD *)((v20 & 0xFFFFFFFFFFFFLL) + 0x70)
                                                                    + 0x30LL);
      v29 = *(_DWORD *)(a1 + 0x6D0);
      v9 = sub_141D17630(a1);
      v57 = v9 + 0x30;
      v58 = *(_QWORD *)(v9 + 0x40);
      v30 = AK::WriteBytesMem::Count((AK::WriteBytesMem *)(v58 + 0x48));
      v59(v41, v30, v10, 0);
      v42 = (v20 & 0xFFFFFFFFFFFFLL) + 0x70;
      v62 = *(void (__fastcall **)(__int64, _QWORD, __int64, _QWORD))(*(_QWORD *)((v20 & 0xFFFFFFFFFFFFLL) + 0x70)
                                                                    + 0x30LL);
      v31 = sub_143CEF7E0(a1 + 0x400).m128_u32[0];
      v11 = sub_141D17630(a1);
      v60 = v11 + 0x30;
      v61 = *(_QWORD *)(v11 + 0x40);
      v32 = AK::WriteBytesMem::Count((AK::WriteBytesMem *)(v61 + 0xA8));
      v62(v42, v32, v12, 0);
      v43 = (v20 & 0xFFFFFFFFFFFFLL) + 0x70;
      v65 = *(void (__fastcall **)(__int64, _QWORD, __int64, _QWORD))(*(_QWORD *)((v20 & 0xFFFFFFFFFFFFLL) + 0x70)
                                                                    + 0x30LL);
      v33 = (float)(int)sub_143CEBD60(a1);
      v13 = sub_141D17630(a1);
      v63 = v13 + 0x30;
      v64 = *(_QWORD *)(v13 + 0x40);
      v34 = AK::WriteBytesMem::Count((AK::WriteBytesMem *)(v64 + 0xC8));
      v65(v43, v34, v14, 0);
      if ( *(float *)(a1 + 0x7B4) < *(float *)(a1 + 0x6B0) || *(float *)(a1 + 0x6B0) == 1.0 )
      {
        *(float *)(a1 + 0x7B0) = 0x3F800000;
        v44 = (v20 & 0xFFFFFFFFFFFFLL) + 0x70;
        v68 = *(void (__fastcall **)(__int64, _QWORD, __int64, _QWORD))(*(_QWORD *)((v20 & 0xFFFFFFFFFFFFLL) + 0x70)
                                                                      + 0x30LL);
        v15 = sub_141D17630(a1);
        v66 = v15 + 0x30;
        v67 = *(_QWORD *)(v15 + 0x40);
        v35 = AK::WriteBytesMem::Count((AK::WriteBytesMem *)(v67 + 0x88));
        v68(v44, v35, v16, 0);
      }
      else if ( *(float *)(a1 + 0x7B0) > 0.0 && !*(_BYTE *)(a1 + 0x7B8) )
      {
        v17 = sub_141D17630(a1);
        v69 = v17 + 0x30;
        v70 = *(_QWORD *)(v17 + 0x40);
        v21 = *(float *)(a1 + 0x7B0) - (float)(*(float *)(v70 + 0xE8) * a2);
        if ( v21 >= 0.0 )
        {
          if ( v21 >= 1.0 )
            v22 = 1.0;
          else
            v22 = v21;
          v23 = v22;
        }
        else
        {
          v23 = 0.0;
        }
        *(float *)(a1 + 0x7B0) = v23;
        v45 = (v20 & 0xFFFFFFFFFFFFLL) + 0x70;
        v73 = *(void (__fastcall **)(__int64, _QWORD, __int64, _QWORD))(*(_QWORD *)((v20 & 0xFFFFFFFFFFFFLL) + 0x70)
                                                                      + 0x30LL);
        v36 = *(_DWORD *)(a1 + 0x7B0);
        v18 = sub_141D17630(a1);
        v71 = v18 + 0x30;
        v72 = *(_QWORD *)(v18 + 0x40);
        v37 = AK::WriteBytesMem::Count((AK::WriteBytesMem *)(v72 + 0x88));
        v73(v45, v37, v19, 0);
      }
      *(float *)(a1 + 0x7B4) = *(float *)(a1 + 0x6B0);
    }
    result = a1;
    *(_BYTE *)(a1 + 0x7B8) = 0;
  }
  return result;
}

// --- End Function: sub_143DA5D80 (0x143DA5D80) ---

// --- Function: sub_143DAA120 (0x143DAA120) ---
__int64 __fastcall sub_143DAA120(__int64 a1, float a2)
{
  __int64 result; // rax
  float v3; // [rsp+20h] [rbp-118h]
  float v4; // [rsp+28h] [rbp-110h]
  __int64 v5; // [rsp+30h] [rbp-108h]
  float v6; // [rsp+38h] [rbp-100h]
  float v7; // [rsp+3Ch] [rbp-FCh]
  float v8; // [rsp+40h] [rbp-F8h]
  float v9; // [rsp+44h] [rbp-F4h]
  float X_1; // [rsp+4Ch] [rbp-ECh]
  float X; // [rsp+50h] [rbp-E8h]
  float v12; // [rsp+58h] [rbp-E0h]
  float v13; // [rsp+60h] [rbp-D8h]
  float v14; // [rsp+6Ch] [rbp-CCh]
  float v15; // [rsp+88h] [rbp-B0h]
  float v16; // [rsp+8Ch] [rbp-ACh]
  float v17; // [rsp+90h] [rbp-A8h] BYREF
  float v18; // [rsp+94h] [rbp-A4h] BYREF
  float v19; // [rsp+98h] [rbp-A0h]
  float Y; // [rsp+9Ch] [rbp-9Ch]
  __int64 v21; // [rsp+A0h] [rbp-98h]
  __int64 v22; // [rsp+A8h] [rbp-90h]
  __int64 v23; // [rsp+B0h] [rbp-88h]
  void (__fastcall ***v24)(_QWORD); // [rsp+B8h] [rbp-80h]
  __int64 v25; // [rsp+C0h] [rbp-78h]
  __int64 v26; // [rsp+C8h] [rbp-70h] BYREF
  __int64 (__fastcall *v27)(__int64, _BYTE *); // [rsp+D0h] [rbp-68h]
  _QWORD *v28; // [rsp+D8h] [rbp-60h]
  _QWORD *v29; // [rsp+E0h] [rbp-58h]
  void (__fastcall *v30)(__int64, __int64, _QWORD *); // [rsp+E8h] [rbp-50h]
  void (__fastcall ***v31[2])(_QWORD); // [rsp+F0h] [rbp-48h] BYREF
  __int64 v32; // [rsp+100h] [rbp-38h]
  _BYTE v33[8]; // [rsp+108h] [rbp-30h] BYREF
  __int64 v34; // [rsp+110h] [rbp-28h]
  _QWORD v35[4]; // [rsp+118h] [rbp-20h] BYREF

  v5 = sub_141D17630(*(_QWORD *)a1);
  v4 = sub_143CF19F0(*(_QWORD *)a1);
  Y = *(float *)(v5 + 0x78);
  if ( *(_DWORD *)(v5 + 0x68) == 1 )
  {
    LODWORD(v7) = sub_143CFB4F0(*(_QWORD *)a1).m128_u32[0];
  }
  else
  {
    if ( *(_DWORD *)(v5 + 0x68) == 2 )
      LODWORD(v6) = sub_143CFB4D0(*(_QWORD *)a1).m128_u32[0];
    else
      v6 = 0.0;
    v7 = v6;
  }
  if ( *(_DWORD *)(v5 + 0x6C) )
  {
    if ( *(_DWORD *)(v5 + 0x6C) == 1 )
      LODWORD(v8) = sub_143CFB4D0(*(_QWORD *)a1).m128_u32[0];
    else
      v8 = 1.0;
    v9 = v8;
  }
  else
  {
    LODWORD(v9) = sub_143CFB4F0(*(_QWORD *)a1).m128_u32[0];
  }
  v3 = (float)((float)((float)(v4 - v7) * (float)(1.0 - 0.0)) / (float)(v9 - v7)) + 0.0;
  if ( v3 >= 0.0 )
  {
    if ( v3 >= 1.0 )
      X_1 = 1.0;
    else
      X_1 = (float)((float)((float)(v4 - v7) * (float)(1.0 - 0.0)) / (float)(v9 - v7)) + 0.0;
    X = X_1;
  }
  else
  {
    X = 0.0;
  }
  v19 = (float)((float)(1.0 - 0.0) * j_powf(X, Y)) + 0.0;
  v16 = sub_1404F8CC0(a1 + 0x210).m128_f32[0];
  v15 = a2 * *(float *)(v5 + 0x7C);
  v17 = v16 + (float)(v15 * (float)(v19 - sub_1404F8CC0(a1 + 0x210).m128_f32[0]));
  sub_140468C30(a1 + 0x210, &v17);
  v12 = sub_1404F8CC0(a1 + 0x1D0).m128_f32[0];
  if ( (float)(v4 * 2.0) >= v12 )
    v13 = v4 * 2.0;
  else
    v13 = v12;
  if ( v13 <= 1.0 )
    v14 = v13;
  else
    v14 = 1.0;
  v18 = v14;
  sub_140468C30(a1 + 0x1D0, &v18);
  *(float *)(a1 + 0x80) = sub_143C9FE10((__int64 *)a1, 0.5, v4);
  result = *(_QWORD *)(a1 + 0x10);
  v23 = result;
  if ( result )
  {
    v24 = *(void (__fastcall ****)(_QWORD))(a1 + 0x1C8);
    sub_143C34690(v31, v24);
    v25 = *(_QWORD *)a1;
    v26 = *(_QWORD *)(v25 + 8);
    v22 = sub_14030ECF0(&v26);
    v27 = *(__int64 (__fastcall **)(__int64, _BYTE *))(*(_QWORD *)v22 + 0x3B8LL);
    v32 = *(_QWORD *)v27(v22, v33);
    v21 = v34;
    v21 = *(_QWORD *)(a1 + 0x10);
    v30 = *(void (__fastcall **)(__int64, __int64, _QWORD *))(*(_QWORD *)v21 + 0x248LL);
    v28 = v35;
    sub_14035C440(v35, v31);
    v35[1] = v31[1];
    v35[2] = v32;
    v29 = v35;
    v30(v21, a1 + 0x20, v35);
    return sub_140371650((__int64 *)v31);
  }
  return result;
}

// --- End Function: sub_143DAA120 (0x143DAA120) ---

// --- Function: sub_143DACFD0 (0x143DACFD0) ---
__int64 __fastcall sub_143DACFD0(__int64 a1)
{
  float v1; // xmm0_4
  float v2; // kr00_4
  _BYTE buf_[2]; // [rsp+20h] [rbp-F8h] BYREF
  float v5; // [rsp+24h] [rbp-F4h]
  float v8; // [rsp+30h] [rbp-E8h]
  float v9; // [rsp+34h] [rbp-E4h]
  ULONG_PTR Parameter; // [rsp+38h] [rbp-E0h] BYREF
  ULONG_PTR Parameter__2; // [rsp+40h] [rbp-D8h] BYREF
  _QWORD *v12; // [rsp+48h] [rbp-D0h]
  __int64 v13; // [rsp+50h] [rbp-C8h]
  __int64 v14[2]; // [rsp+58h] [rbp-C0h] BYREF
  __int64 v15; // [rsp+68h] [rbp-B0h]
  _DWORD *v16; // [rsp+70h] [rbp-A8h]
  __int64 *Parameter_; // [rsp+78h] [rbp-A0h] BYREF
  __int64 v18; // [rsp+80h] [rbp-98h]
  __int64 v19; // [rsp+88h] [rbp-90h]
  Parameter *Parameter_1; // [rsp+90h] [rbp-88h]
  __int64 v21; // [rsp+98h] [rbp-80h]
  __int64 *v22; // [rsp+A0h] [rbp-78h]
  __int64 v23; // [rsp+A8h] [rbp-70h]
  __int64 (__fastcall *v24)(__int64, _QWORD); // [rsp+B0h] [rbp-68h]
  __int64 v25; // [rsp+B8h] [rbp-60h]
  _QWORD v26[3]; // [rsp+C0h] [rbp-58h] BYREF
  ULONG_PTR Parameter__3; // [rsp+D8h] [rbp-40h]
  ULONG_PTR v28; // [rsp+E0h] [rbp-38h]
  __int64 v29; // [rsp+E8h] [rbp-30h]
  __int64 v30; // [rsp+F0h] [rbp-28h] BYREF
  _BYTE Parameter__1[8]; // [rsp+F8h] [rbp-20h] BYREF
  __int64 v32[3]; // [rsp+100h] [rbp-18h] BYREF

  sub_143C2C160((Parameter *)&Parameter_);
  v29 = a1 + 0x3A8;
  sub_14277D040((_QWORD **)(a1 + 0x3A8), (Parameter *)Parameter__1);
  v19 = a1 + 0x3A8;
  Parameter_1 = **(_QWORD **)(a1 + 0x3A8);
  Parameter = Parameter_1;
  _StarEngineModule__((ULONG_PTR)&Parameter);
  memset(buf_, 0, 1u);
  while ( *(_BYTE *)(Parameter + 0x19) == 0 )
  {
    v12 = (_QWORD *)(Parameter + 0x20);
    if ( sub_14030EC00((unsigned __int64 *)(Parameter + 0x20)) )
    {
      v13 = sub_14030ECF0(v12);
      if ( !(*(unsigned __int8 (__fastcall **)(__int64))(*(_QWORD *)v13 + 0x58LL))(v13) )
      {
        v21 = sub_14030ECF0(v12);
        v22 = sub_14033AB40(v21, &v30);
        v23 = *v22;
        v14[0] = v23;
        if ( AssetMeta::HasActorSubresource(v14) )
        {
          v14[1] = v14[0] & 0xFFFFFFFFFFFFLL;
          v24 = *(__int64 (__fastcall **)(__int64, _QWORD))(*(_QWORD *)(v14[0] & 0xFFFFFFFFFFFFLL) + 0x5C8LL);
          v15 = v24(v14[0] & 0xFFFFFFFFFFFFLL, 0);
          if ( v15 )
          {
            v25 = v15 + 8;
            sub_1403B0A70((unsigned __int64 *)(v15 + 8), v26);
            v16 = (_DWORD *)(*(_QWORD *)sub_143BEABD0(&Parameter_, (__int64)v32, (const struct __crt_stdio_stream *)v26)
                           + 0x28LL);
            ++*v16;
          }
        }
      }
    }
    sub_142BB3820((__int64)&Parameter);
  }
  v26[1] = v18;
  if ( v18 < 0 )
  {
    v2 = (float)(v18 & 1 | ((unsigned __int64)v18 >> 1));
    v1 = v2 + v2;
  }
  else
  {
    v1 = (float)v18;
  }
  v8 = v1;
  v5 = 1.0;
  v26[2] = &Parameter_;
  Parameter__3 = *Parameter_;
  Parameter__2 = Parameter__3;
  _StarEngineModule__((ULONG_PTR)&Parameter__2);
  memset(&buf_[1], 0, sizeof(_BYTE));
  while ( *(_BYTE *)(Parameter__2 + 0x19) == 0 )
  {
    v28 = Parameter__2 + 0x20;
    v5 = v5 * (float)*(int *)(Parameter__2 + 0x28);
    std::_Tree_unchecked_const_iterator<std::_Tree_val<std::_Tree_simple_types<std::pair<std::string const,AK::WwiseAuthoringAPI::AkJsonBase<AK::WwiseAuthoringAPI::AkVariant,std::string,std::less<std::string>>>>>,std::_Iterator_base0>::operator++((std::_Tree_unchecked_const_iterator<std::_Tree_val<std::_Tree_simple_types<std::pair<std::string const ,AK::WwiseAuthoringAPI::AkJsonBase<AK::WwiseAuthoringAPI::AkVariant,std::string,std::less<std::string > > > > >,std::_Iterator_base0> *)&Parameter__2);
  }
  if ( v8 <= 0.0 )
    v9 = 1.0;
  else
    v9 = v8 / v5;
  *(float *)(a1 + 0x2C4) = v9;
  return sub_143C4CBC0((Parameter *)&Parameter_);
}

// --- End Function: sub_143DACFD0 (0x143DACFD0) ---

// --- Function: sub_143DB0BB0 (0x143DB0BB0) ---
__int64 __fastcall sub_143DB0BB0(__int64 a1, float a2)
{
  __int64 v2; // rax
  float v3; // xmm0_4
  float v4; // kr00_4
  __int64 result; // rax
  float v6; // [rsp+20h] [rbp-68h]
  float v7; // [rsp+20h] [rbp-68h]
  float v8; // [rsp+24h] [rbp-64h]
  float v9; // [rsp+28h] [rbp-60h]
  float v10; // [rsp+34h] [rbp-54h]
  float *i; // [rsp+40h] [rbp-48h]
  float v12; // [rsp+48h] [rbp-40h]
  float v13; // [rsp+4Ch] [rbp-3Ch]

  sub_143CC0230(a1);
  sub_143D4EB30(a1, a2);
  v12 = a2 * *(float *)(*(_QWORD *)(sub_141D17630(a1) + 0x28) + 0xCLL);
  v13 = v12 * sub_143D01CD0(a1);
  *(float *)(a1 + 0x370) = *(float *)(a1 + 0x370) - (float)(v13 / sub_143CF8B30(a1));
  if ( *(float *)(a1 + 0x370) > 0.0 )
  {
    v6 = 1.0;
    if ( *(_QWORD *)(a1 + 0x378) != *(_QWORD *)(a1 + 0x380) )
    {
      v7 = 0.0;
      for ( i = *(float **)(a1 + 0x378); i != *(float **)(a1 + 0x380); ++i )
        v7 = v7 + *i;
      v2 = sub_1403EABD0((_QWORD *)(a1 + 0x378));
      if ( v2 < 0 )
      {
        v4 = (float)(v2 & 1 | ((unsigned __int64)v2 >> 1));
        v3 = v4 + v4;
      }
      else
      {
        v3 = (float)v2;
      }
      v6 = v7 / v3;
      sub_1403E42C0((__int64 *)(a1 + 0x378));
    }
    v8 = (float)(sub_143CFF960(a1, 1) * *(float *)(a1 + 0x360)) * v6;
    if ( v8 < 0.0 )
      *(float *)(a1 + 0x370) = *(float *)(a1 + 0x370) / (float)(1.0 - v8);
    else
      *(float *)(a1 + 0x370) = *(float *)(a1 + 0x370) * (float)(v8 + 1.0);
  }
  v9 = *(float *)(a1 + 0x6B0) + *(float *)(a1 + 0x370);
  if ( v9 >= 0.0 )
  {
    if ( v9 >= 1.0 )
      v10 = 1.0;
    else
      v10 = *(float *)(a1 + 0x6B0) + *(float *)(a1 + 0x370);
    sub_143D82890(a1, v10);
  }
  else
  {
    sub_143D82890(a1, 0.0);
  }
  result = a1;
  *(float *)(a1 + 0x370) = 0;
  return result;
}

// --- End Function: sub_143DB0BB0 (0x143DB0BB0) ---

