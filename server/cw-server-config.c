#define WIN32_LEAN_AND_MEAN
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <winnt.h>
#include <winsock2.h>

/*
 * ============================================================================
 * Cube World Alpha - Server Config Mod
 * ============================================================================
 *
 * The goal of this mod is to make the Cube World Alpha server more
 * configurable.
 *
 *
 * What problem does this solve?
 * -----------------------------
 * The file named "server.cfg" is actually used for the world seed. That is
 * confusing.
 *
 * Also, the server does not provide a way to change the port it listens on.
 *
 * This mod makes two improvements:
 *   - Rename the seed file from server.cfg to seed.cfg
 *   - Add a port configuration file: port.cfg
 *
 * If port.cfg exists and contains a valid number, the server will bind to that
 * port instead of the default 12345. If port.cfg is missing or invalid, the
 * mod keeps the default 12345.
 *
 * Changing the port on the server will require the same change on the client.
 * The Client Config Mod exists for this reason.
 *
 *
 * How does the mod work?
 * ----------------------
 * It uses two different techniques:
 *
 *   - String patch:
 *      It patches the filename string inside the executable from "server.cfg"
 *      to "seed.cfg".
 *
 *   - bind() hook:
 *      When the server asks Windows to bind its listening socket, it intercepts
 *      that call and replace the port in the sockaddr_in structure.
 *
 * ============================================================================
 */

/*
 * Set this to TRUE for debugging. It will create a file called "ServerConfig.log"
 * where logs are appended. This behavior comes from the logf_line function below.
 */
#ifndef VERBOSE
#   define VERBOSE FALSE
#endif


/*
 * These values came from Ghidra.
 *
 * IMAGE_BASE (documentation only):
 *   The base address where the executable expects to be loaded.
 *
 * SERVER_CFG_STRING_RVA:
 *   RVA (Relative Virtual Address) of the location of the "server.cfg"
 *   string inside the executable image, computed using IMAGE_BASE.
 */
#define IMAGE_BASE               0x00400000u
#define SERVER_CFG_STRING_RVA    0x00173D0Cu


/* Names of the configuration files used by the mod */
static const char *g_port_cfg_filename = "port.cfg";
static const char *g_seed_cfg_replacement = "seed.cfg";


/* Function pointer type matching the real bind() */
typedef int (WSAAPI *BindFn)(SOCKET, const struct sockaddr *, int);
/* Global pointer to the original bind() */
static BindFn g_real_bind = NULL;


/* This simply prints messages to a log file if the VERBOSE macro is set to TRUE. */
static void logf_line(const char *fmt, ...) {
    if (!VERBOSE) {
        return;
    }

    char buf[1024];
    va_list ap;

    va_start(ap, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if (len < 0) {
        return;
    }
    if ((size_t)len >= sizeof(buf)) {
        len = (int)(sizeof(buf) - 1);
    }

    HANDLE h = CreateFileA(
        "ServerConfig.log",
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (h == INVALID_HANDLE_VALUE) {
        return;
    }

    DWORD written;
    WriteFile(h, buf, (DWORD)len, &written, NULL);
    WriteFile(h, "\r\n", 2, &written, NULL);
    CloseHandle(h);
}


/* Case-insensitive ASCII string compare. */
static int streqi_ascii(const char *a, const char *b) {
    for (;;) {
        char ca = *a++;
        char cb = *b++;

        if (ca >= 'A' && ca <= 'Z')
            ca = (char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z')
            cb = (char)(cb - 'A' + 'a');

        if (ca != cb)
            return 0;
        if (ca == '\0')
            return 1;
    }
}


/*
 * Network protocols store port numbers in "network byte order" (big-endian).
 *
 * Normal x86 CPUs use little-endian, so a value like 12345 must be byte-swapped
 * before being placed into sockaddr_in.sin_port.
 *
 * This function does the same job as htons(), but manually.
 */
static unsigned short to_network_u16(unsigned short value) {
    return (unsigned short)(((value & 0x00FFu) << 8) |
                            ((value & 0xFF00u) >> 8));
}


/* Reads the desired port from "port.cfg". */
static unsigned short read_port_cfg(void) {
    unsigned long value = 12345;

    FILE *file = fopen(g_port_cfg_filename, "rb");
    if (file == NULL) {
        logf_line("[cw-server-config] port.cfg not found, using default 12345");
        return 12345;
    }

    if (fscanf(file, "%lu", &value) != 1) {
        fclose(file);
        logf_line("[cw-server-config] could not parse port.cfg, using default 12345");
        return 12345;
    }

    fclose(file);

    if (value == 0 || value > 65535) {
        logf_line("[cw-server-config] port.cfg out of range, using default 12345");
        return 12345;
    }

    return (unsigned short)value;
}


/*
 * We patch the string "server.cfg" string in memory so the game uses "seed.cfg" instead.
 *
 * We use VirtualProtect because the memory page containing the executable's data
 * is usually not writable. We temporarily make it writable, overwrite the string,
 * then restore the old protection.
 */
static int patch_seed_cfg_string(void) {
    /* Base address of the main executable */
    BYTE *base = (BYTE *)GetModuleHandleA(NULL);
    if (base == NULL) {
        logf_line("[cw-server-config] GetModuleHandleA(NULL) failed in string patch");
        return 0;
    }

    /* Address of the original filename string in memory */
    char *target = (char *)(base + SERVER_CFG_STRING_RVA);

    /*
     * Build the replacement buffer: "seed.cfg\0" followed by zero padding
     * to match the length of "server.cfg\0"
     */
    unsigned char replacement_buf[11]; /* space for "server.cfg\0" */
    memset(replacement_buf, 0, sizeof(replacement_buf));
    memcpy(replacement_buf, g_seed_cfg_replacement, strlen(g_seed_cfg_replacement));

    logf_line("[cw-server-config] seed string target = %p", target);
    logf_line("[cw-server-config] old seed filename string = \"%s\"", target);
    fflush(stdout);

    /* Make the memory writable so we can modify the function pointer */
    DWORD old_protect = 0;
    if (!VirtualProtect(target, sizeof(replacement_buf), PAGE_READWRITE, &old_protect)) {
        logf_line("[cw-server-config] VirtualProtect failed for seed string");
        return 0;
    }

    /* Overwrite "server.cfg" with "seed.cfg" */
    memcpy(target, replacement_buf, sizeof(replacement_buf));

    /* Restore the previous memory protection */
    VirtualProtect(target, sizeof(replacement_buf), old_protect, &old_protect);

    /* Flush instruction cache after patching process memory */
    FlushInstructionCache(GetCurrentProcess(), target, sizeof(replacement_buf));

    logf_line("[cw-server-config] new seed filename string = \"%s\"", target);
    fflush(stdout);

    return 1;
}


/* This function replaces the server's original bind(). */
static int WSAAPI hooked_bind(SOCKET socket, const struct sockaddr *name, int namelen) {
    if (g_real_bind == NULL) {
        logf_line("[cw-server-config] g_real_bind is NULL");
        return SOCKET_ERROR;
    }

    /* Only patch IPv4 socket addresses. */
    if (
        name != NULL &&
        namelen >= (int)sizeof(struct sockaddr_in) &&
        name->sa_family == AF_INET
    ) {
        /* Make a writable copy of the address structure */
        struct sockaddr_in patched = *(const struct sockaddr_in *)name;

        /*
         * Use read_port_cfg and to_network_u16 to get and write the
         * desired port to the address structure
         */
        unsigned short port = read_port_cfg();
        patched.sin_port = to_network_u16(port);

        logf_line("[cw-server-config] using port %u", (unsigned)port);

        /* Call the real bind() with the modified address */
        return g_real_bind(socket, (const struct sockaddr *)&patched, namelen);
    }

    /* For non-IPv4 addresses, do nothing special */
    return g_real_bind(socket, name, namelen);
}


/*
 * This patches the main executable's Import Address Table (IAT) entry for bind().
 *
 * When an executable imports a function from a DLL, Windows stores the resolved
 * function pointer in a table.
 *
 * For example, Cube World's Server.exe imports bind() from WS2_32.dll.
 *
 * If we replace the IAT entry for bind(), then when the server thinks it is
 * calling bind(), it actually calls our hooked_bind() first.
 *
 * Here are the steps performed here:
 *   1. Get base of the main executable
 *   2. Load WS2_32.dll if needed
 *   3. Resolve the real bind() address
 *   4. Parse the PE headers of the main executable
 *   5. Walk the import table looking for WS2_32.dll / wsock32.dll
 *   6. Find the IAT slot that contains the real bind() pointer
 *   7. Replace that slot with hooked_bind()
 */
static int patch_main_exe_iat_bind(void) {
    /* Get the base address of the main executable */
    HMODULE main_module = GetModuleHandleA(NULL);
    if (!main_module) {
        logf_line("[cw-server-config] GetModuleHandleA(NULL) failed in IAT patch");
        return 0;
    }

    /*
     * Get a handle to the Winsock DLL that provides bind(),
     * and if it is not already loaded, load it.
     */
    HMODULE ws2_module = GetModuleHandleA("WS2_32.dll");
    if (!ws2_module) {
        ws2_module = LoadLibraryA("WS2_32.dll");
    }
    if (!ws2_module) {
        logf_line("[cw-server-config] could not load WS2_32.dll");
        return 0;
    }

    /* Get the address of the real bind() */
    FARPROC bind_addr = GetProcAddress(ws2_module, "bind");
    if (!bind_addr) {
        logf_line("[cw-server-config] GetProcAddress(bind) failed");
        return 0;
    }

    /*
     * Parse the PE headers of the main executable.
     * (PE = Portable Executable, the Windows executable format)**
     *
     * The first header is the DOS Header and the second one is the NT Header.
     */
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)main_module;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        logf_line("[cw-server-config] DOS signature check failed");
        return 0;
    }

    /* e_lfanew tells us where the NT header starts relative to the image base */
    IMAGE_NT_HEADERS32 *nt = (IMAGE_NT_HEADERS32 *)((BYTE *)main_module + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        logf_line("[cw-server-config] NT signature check failed");
        return 0;
    }

    /*
     * Locate the import directory inside the PE headers.
     * This is the metadata that describes imported DLLs and functions.
     */
    IMAGE_DATA_DIRECTORY import_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.VirtualAddress == 0 || import_dir.Size == 0) {
        logf_line("[cw-server-config] no import directory");
        return 0;
    }

    /* Walk through the imported DLL descriptors */
    for (
        IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR *)((BYTE *)main_module + import_dir.VirtualAddress);
        imp->Name != 0;
        ++imp
    ) {
        const char *dll_name = (const char *)((BYTE *)main_module + imp->Name);

        /*
         * Only consider Winsock-related DLLs.
         * Depending on the binary, imports may be listed as WS2_32.dll or wsock32.dll,
         * so we just accept both.
         */
        if (!streqi_ascii(dll_name, "WS2_32.dll") && !streqi_ascii(dll_name, "wsock32.dll")) {
            continue;
        }

        /*
         * FirstThunk points to the resolved function pointers, which is the
         * actual Import Address Table used by the executable at runtime.
         */
        for (
            IMAGE_THUNK_DATA32 *iat_thunk = (IMAGE_THUNK_DATA32 *)((BYTE *)main_module + imp->FirstThunk);
            iat_thunk->u1.Function != 0;
            ++iat_thunk
        ) {
            void **slot = (void **)&iat_thunk->u1.Function;

            /*
             * We identify the bind() IAT slot by comparing the resolved
             * function pointer stored in the slot against the real bind()
             * address we got from GetProcAddress().
             */
            if ((FARPROC)(uintptr_t)iat_thunk->u1.Function != bind_addr) {
                continue;
            }

            /* We patch the slot, similarly as what we did with the string overwrite earlier */

            g_real_bind = (BindFn)bind_addr;

            logf_line("[cw-server-config] bind IAT slot = %p", slot);
            logf_line("[cw-server-config] original bind = %p", bind_addr);

            DWORD old_protect = 0;
            if (!VirtualProtect(slot, sizeof(*slot), PAGE_READWRITE, &old_protect)) {
                logf_line("[cw-server-config] VirtualProtect failed for bind IAT slot");
                return 0;
            }

            *slot = (void *)&hooked_bind;

            VirtualProtect(slot, sizeof(*slot), old_protect, &old_protect);

            FlushInstructionCache(GetCurrentProcess(), slot, sizeof(*slot));

            logf_line("[cw-server-config] patched bind = %p", *slot);
            logf_line("[cw-server-config] bind IAT patched");

            return 1;
        }
    }

    logf_line("[cw-server-config] could not find bind in main executable IAT");
    return 0;
}


/*
 * DllMain is a delicate place to run code.
 * Windows recommends doing as little as possible there.
 *
 * So in DllMain we only create a thread, and that thread does the real work.
 */
static DWORD WINAPI init_thread(LPVOID unused) {
    (void)unused;
    logf_line("[cw-server-config] init thread started");
    patch_seed_cfg_string();
    patch_main_exe_iat_bind();
    return 0;
}


/*
 * The modloader calls this automatically when the DLL is loaded.
 *
 * We disable useless thread attach/detach notifications and start our
 * init thread.
 */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    HANDLE thread;

    (void)lpReserved;

    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);

        thread = CreateThread(NULL, 0, init_thread, NULL, 0, NULL);
        if (thread != NULL) {
            CloseHandle(thread);
        }
    }

    return TRUE;
}
