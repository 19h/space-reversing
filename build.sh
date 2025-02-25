#!/bin/bash
x86_64-w64-mingw32-gcc -shared -o dump.dll dump1.c -lws2_32 -ldbghelp -lpsapi -lgdi32 -Wl,--out-implib,libfoo.a
