#!/bin/bash

killall StarCitizen.exe

x86_64-w64-mingw32-gcc -shared -o struct-register-dump.dll struct-register-dump.c \
    -lws2_32 -ldbghelp -lpsapi -lgdi32 -lmsvcrt \
    -Wl,--out-implib,libstruct-register-dump.a \
    -Wl,--kill-at

WINEPREFIX=/home/null/Games/foo /home/null/Games/foo/runners/wine-tkg-ntsync-git-10.3.r171.ge66405a5040-327-x86_64/bin/wine64 injector.exe -l struct-register-dump.dll -- /media/null/ares/Games/foo/drive_c/Program\ Files/Roberts\ Space\ Industries/StarCitizen/LIVE/Bin64/StarCitizen.exe  -no_login_dialog -envtag PUB --client-login-show-dialog 0 --services-config-enabled 1 --system-trace-service-enabled 1 --system-trace-env-id pub-sc-alpha-410-9650658 --grpc-client-endpoint-override https://pub-sc-alpha-410-9650658.test1.cloudimperiumgames.com:443
