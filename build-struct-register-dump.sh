#!/bin/bash

x86_64-w64-mingw32-gcc -shared -o struct-register-dump.dll struct-register-dump.c -lws2_32 -ldbghelp -lpsapi -lgdi32 -Wl,--out-implib,libstruct-register-dump.a
