# Cube World Alpha Server Mods

DLL mods for the Cube World Alpha dedicated server.

Requires the [Cube World Server Mod Launcher](https://github.com/coremaze/Cube-World-Server-Mod-Launcher)  
Download it here: [prerelease2](https://github.com/coremaze/Cube-World-Server-Mod-Launcher/releases/tag/prerelease2)


## Mods

- **Config.dll**
  - uses `seed.cfg` instead of `server.cfg`
  - adds `port.cfg` to configure the listening port and falls back to port `12345` if `port.cfg` is missing or invalid

- **GracefulShutdown.dll**
  - keeps the normal manual shutdown with `q`
  - also allows clean shutdown by creating a `shutdown.request` file


## Runtime files

- `seed.cfg` — world seed
- `port.cfg` — optional port override
- `shutdown.request` — one-shot clean shutdown trigger


## Use

Place the DLLs in the `Server_Mods` folder used by the mod loader.

```text
Server_Mods/
  Config.dll
  GracefulShutdown.dll
````


## Build

Build as 32-bit Windows DLLs with MinGW-w64.

### Config.dll

```bash
i686-w64-mingw32-gcc -shared -O2 -static-libgcc -o Config.dll cw-config.c -lws2_32
```

### GracefulShutdown.dll

```bash
i686-w64-mingw32-gcc -shared -O2 -s -o GracefulShutdown.dll cw-graceful-shutdown.c
```
