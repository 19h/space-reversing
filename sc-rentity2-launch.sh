#!/bin/bash

#cp loginData.json /home/null/Games/star-citizen/drive_c/Program\ Files/Roberts\ Space\ Industries/StarCitizen/LIVE/loginData.json
killall StarCitizen.exe StarCitizen_Launcher.exe
WINEPREFIX="/home/null/Games/star-citizen" /usr/bin/wine injector.exe -l rentity2.dll -- "C:\Program Files\Roberts Space Industries\StarCitizen\LIVE\Bin64/StarCitizen.exe" -no_login_dialog -envtag PUB --client-login-show-dialog 0 --services-config-enabled 1 --system-trace-service-enabled 1 --system-trace-env-id pub-sc-alpha-401-9497712 --grpc-client-endpoint-override https://pub-sc-alpha-401-9497712.test1.cloudimperiumgames.com:443
