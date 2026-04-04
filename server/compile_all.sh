#!/bin/bash

i686-w64-mingw32-gcc -shared -O2 -s -o ServerGracefulShutdown.dll cw-server-graceful-shutdown.c
i686-w64-mingw32-gcc -shared -O2 -s -static-libgcc -o ServerConfig.dll cw-server-config.c -lws2_32

i686-w64-mingw32-gcc -DVERBOSE -shared -O2 -s -o ServerGracefulShutdownDebug.dll cw-server-graceful-shutdown.c
i686-w64-mingw32-gcc -DVERBOSE -shared -O2 -s -static-libgcc -o ServerConfigDebug.dll cw-server-config.c -lws2_32
