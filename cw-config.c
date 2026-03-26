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
 * Cube World Alpha - Config Mod
 * ============================================================================
 *
 * What problem does this solve?
 * -----------------------------
 * In Cube World Alpha, the file named "server.cfg" is actually used for the
 * world seed.
 *
 * That is confusing.
 *
 * This mod makes two improvements:
 *   - Rename the seed file from server.cfg to seed.cfg
 *   - Add a real port configuration file: port.cfg
 *
 * If port.cfg exists and contains a valid number, the server will bind to that
 * port instead of the default 12345.
 *
 * If port.cfg is missing or invalid, the mod keeps the default 12345.
 *
 *
 * How does the mod work?
 * ----------------------
 * It uses two different techniques:
 *   - String patch:
 *      It patches the filename string inside the executable from "server.cfg"
 *      to "seed.cfg".
 *   - bind() hook:
 *      When the server asks Windows to bind its listening socket, we intercept
 *      that call and replace the port in the sockaddr_in structure.
 *
 * ============================================================================
 */

/*
 * Set this to TRUE for debugging. It will create a file called "Config.log"
 * where logs are appended. This behavior comes from the logf_line function below.
 */
#define VERBOSE FALSE


/* ---------------------------------------------------------------------------
 * Reverse-engineered constants
 * ---------------------------------------------------------------------------
 *
 * These values came from Ghidra.
 *
 * IMAGE_BASE:
 *   The base address where the executable expects to be loaded.
 *
 * SERVER_CFG_STRING_RVA
 *   RVA (Relative Virtual Address) of the location of the "server.cfg"
 *   string inside the executable image.
 *
 * Reverse-engineered addresses were taken relative to the original image base.
 * At runtime we use module_base + RVA.
 */
/* Original image base used when deriving the RVAs below (documentation only). */
#define IMAGE_BASE               0x00400000u

/* The IMAGE_BASE address was used to compute the following address offset */
#define SERVER_CFG_STRING_RVA    0x00173D0Cu


/* Names of the configuration files used by the mod */
static const char *g_port_cfg_filename = "port.cfg";
static const char *g_seed_cfg_replacement = "seed.cfg";


/* ---------------------------------------------------------------------------
 * bind hook
 * ---------------------------------------------------------------------------
 *
 * We hook the Winsock bind() function.
 *
 * bind() is the Windows networking function that attaches a socket to a local
 * address/port.
 *
 * The server eventually calls bind() with something like:
 *   address family = AF_INET
 *   port           = 12345
 *
 * We intercept that call and replace the port with the value from port.cfg.
 */

/* Function pointer type matching the real bind() */
typedef int (WSAAPI *BindFn)(SOCKET, const struct sockaddr *, int);

/* Global pointer to the original bind() */
static BindFn g_real_bind = NULL;


/* ---------------------------------------------------------------------------
 * Logging helper
 * ---------------------------------------------------------------------------
 *
 * This simply prints messages to a log file if the VERBOSE macro is set to TRUE.
 */
static void logf_line(const char *fmt, ...) {
    if (!VERBOSE) {
        return;
    }

    char buf[1024];
    DWORD written;
    HANDLE h;
    va_list ap;
    int len;

    va_start(ap, fmt);
    len = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if (len < 0) {
        return;
    }
    if ((size_t)len >= sizeof(buf)) {
        len = (int)(sizeof(buf) - 1);
    }

    h = CreateFileA(
        "Config.log",
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

    WriteFile(h, buf, (DWORD)len, &written, NULL);
    WriteFile(h, "\r\n", 2, &written, NULL);
    CloseHandle(h);
}


/* ---------------------------------------------------------------------------
 * streqi_ascii
 * ---------------------------------------------------------------------------
 *
 * Tiny case-insensitive ASCII string compare.
 *
 * We use this to compare imported DLL names like "WS2_32.dll" and "ws2_32.dll".
 */
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


/* ---------------------------------------------------------------------------
 * to_network_u16
 * ---------------------------------------------------------------------------
 *
 * Network protocols store port numbers in "network byte order" (big-endian).
 *
 * Normal x86 CPUs use little-endian, so a value like 12345 must be byte-swapped
 * before being placed into sockaddr_in.sin_port.
 *
 * This function does the same job as htons(), but manually.
 */
static unsigned short to_network_u16(unsigned short v) {
    return (unsigned short)(((v & 0x00FFu) << 8) |
                            ((v & 0xFF00u) >> 8));
}


/* ---------------------------------------------------------------------------
 * read_port_cfg
 * ---------------------------------------------------------------------------
 *
 * Reads the desired port from "port.cfg".
 *
 * If the file:
 *   - does not exist
 *   - cannot be parsed
 *   - is outside the valid range [1 ; 65535]
 * then the function falls back to the default port 12345.
 */
static unsigned short read_port_cfg(void) {
    FILE *f;
    unsigned long value = 12345;

    f = fopen(g_port_cfg_filename, "rb");
    if (f == NULL) {
        logf_line("[cw-config] port.cfg not found, using default 12345");
        return 12345;
    }

    if (fscanf(f, "%lu", &value) != 1) {
        fclose(f);
        logf_line("[cw-config] could not parse port.cfg, using default 12345");
        return 12345;
    }

    fclose(f);

    if (value == 0 || value > 65535) {
        logf_line("[cw-config] port.cfg out of range, using default 12345");
        return 12345;
    }

    return (unsigned short)value;
}


/* ---------------------------------------------------------------------------
 * patch_seed_cfg_string
 * ---------------------------------------------------------------------------
 *
 * The original executable uses the string "server.cfg" for the world seed file.
 * We patch that string in memory so the game instead uses "seed.cfg".
 *
 * Why VirtualProtect?
 * -------------------
 * Because the memory page containing the executable's data is usually not
 * writable. We temporarily make it writable, overwrite the string, then
 * restore the old protection.
 */
static int patch_seed_cfg_string(void) {
    BYTE *base;
    char *target;
    DWORD old_protect = 0;
    unsigned char replacement_buf[11]; /* space for "server.cfg\0" */

    /* Base address of the main executable */
    base = (BYTE *)GetModuleHandleA(NULL);
    if (base == NULL) {
        logf_line("[cw-config] GetModuleHandleA(NULL) failed in string patch");
        return 0;
    }

    /* Address of the original filename string in memory */
    target = (char *)(base + SERVER_CFG_STRING_RVA);

    /*
     * Build the replacement buffer: "seed.cfg\0" followed by zero padding
     * to match the length of "server.cfg\0".
     */
    memset(replacement_buf, 0, sizeof(replacement_buf));
    memcpy(replacement_buf, g_seed_cfg_replacement,
           strlen(g_seed_cfg_replacement));

    logf_line("[cw-config] seed string target = %p", target);
    logf_line("[cw-config] old seed filename string = \"%s\"", target);
    fflush(stdout);

    /*
     * Make the memory writable so we can modify the function pointer.
     */
    if (!VirtualProtect(target, sizeof(replacement_buf), PAGE_READWRITE, &old_protect)) {
        logf_line("[cw-config] VirtualProtect failed for seed string");
        return 0;
    }

    /* Overwrite "server.cfg" with "seed.cfg" */
    memcpy(target, replacement_buf, sizeof(replacement_buf));

    /* Restore the previous memory protection */
    VirtualProtect(target, sizeof(replacement_buf), old_protect, &old_protect);

    /*
     * Flush instruction cache as a harmless belt-and-suspenders step after patching
     * process memory.
     */
    FlushInstructionCache(GetCurrentProcess(), target, sizeof(replacement_buf));

    logf_line("[cw-config] new seed filename string = \"%s\"", target);
    fflush(stdout);

    return 1;
}


/* ---------------------------------------------------------------------------
 * hooked_bind
 * ---------------------------------------------------------------------------
 *
 * This function replaces the server's imported bind().
 *
 * The modified behavior:
 *   - if the address is IPv4 (AF_INET), make a copy of the sockaddr_in
 *   - read the desired port from port.cfg
 *   - replace sin_port in the copy
 *   - call the real bind() with the modified address
 */
static int WSAAPI hooked_bind(SOCKET s, const struct sockaddr *name, int namelen) {
    unsigned short port;
    struct sockaddr_in patched;

    if (g_real_bind == NULL) {
        logf_line("[cw-config] g_real_bind is NULL");
        return SOCKET_ERROR;
    }

    /*
     * Only patch IPv4 socket addresses.
     */
    if (name != NULL &&
        namelen >= (int)sizeof(struct sockaddr_in) &&
        name->sa_family == AF_INET) {

        /* Make a writable copy of the address structure */
        patched = *(const struct sockaddr_in *)name;

        /* Load desired port from port.cfg (or default 12345) */
        port = read_port_cfg();

        /* Replace the port field with the chosen port, in network byte order */
        patched.sin_port = to_network_u16(port);

        logf_line("[cw-config] using port %u", (unsigned)port);

        /* Call the real bind() with our modified address */
        return g_real_bind(s, (const struct sockaddr *)&patched, namelen);
    }

    /* For non-IPv4 addresses, do nothing special */
    return g_real_bind(s, name, namelen);
}


/* ---------------------------------------------------------------------------
 * patch_main_exe_iat_bind
 * ---------------------------------------------------------------------------
 *
 * This patches the main executable's Import Address Table (IAT) entry for bind.
 *
 * What is the Import Address Table (IAT)?
 * ---------------------------------------
 * When an executable imports a function from a DLL, Windows stores the resolved
 * function pointer in a table.
 *
 * For example, Cube World's Server.exe imports bind from WS2_32.dll.
 *
 * If we replace the IAT entry for bind, then when the server thinks it is
 * calling bind(), it actually calls our hooked_bind() first.
 *
 * Here are the steps performed here:
 *   1. Get base of the main executable
 *   2. Load WS2_32.dll if needed
 *   3. Resolve the real bind() address
 *   4. Parse the PE headers of the main executable
 *   5. Walk the import table looking for WS2_32.dll / wsock32.dll
 *   6. Find the IAT slot that contains the real bind() pointer
 *   7. Replace that slot with hooked_bind
 */
static int patch_main_exe_iat_bind(void) {
    HMODULE main_module;
    HMODULE ws2_module;
    FARPROC bind_addr;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS32 *nt;
    IMAGE_DATA_DIRECTORY import_dir;
    IMAGE_IMPORT_DESCRIPTOR *imp;

    /* Get the base address of the main executable (Server.exe) */
    main_module = GetModuleHandleA(NULL);
    if (!main_module) {
        logf_line("[cw-config] GetModuleHandleA(NULL) failed in IAT patch");
        return 0;
    }

    /*
     * Get a handle to the Winsock DLL that provides bind().
     */
    ws2_module = GetModuleHandleA("WS2_32.dll");
    if (!ws2_module) {
        ws2_module = LoadLibraryA("WS2_32.dll");
    }
    if (!ws2_module) {
        logf_line("[cw-config] could not load WS2_32.dll");
        return 0;
    }

    /* Get the address of the real bind() */
    bind_addr = GetProcAddress(ws2_module, "bind");
    if (!bind_addr) {
        logf_line("[cw-config] GetProcAddress(bind) failed");
        return 0;
    }

    /*
     * Parse the PE headers of the main executable.
     *
     * PE = Portable Executable, the Windows executable format.
     */
    dos = (IMAGE_DOS_HEADER *)main_module;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        logf_line("[cw-config] DOS signature check failed");
        return 0;
    }

    nt = (IMAGE_NT_HEADERS32 *)((BYTE *)main_module + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        logf_line("[cw-config] NT signature check failed");
        return 0;
    }

    /* Locate the import directory */
    import_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.VirtualAddress == 0 || import_dir.Size == 0) {
        logf_line("[cw-config] no import directory");
        return 0;
    }

    /* Walk imported DLLs */
    imp = (IMAGE_IMPORT_DESCRIPTOR *)((BYTE *)main_module + import_dir.VirtualAddress);

    for (; imp->Name != 0; ++imp) {
        const char *dll_name = (const char *)((BYTE *)main_module + imp->Name);
        IMAGE_THUNK_DATA32 *iat_thunk;

        /*
         * Accept either WS2_32.dll or wsock32.dll naming.
         */
        if (!streqi_ascii(dll_name, "WS2_32.dll") &&
            !streqi_ascii(dll_name, "wsock32.dll")) {
            continue;
        }

        /*
         * FirstThunk points to the resolved function pointers (the actual IAT).
         */
        iat_thunk = (IMAGE_THUNK_DATA32 *)((BYTE *)main_module + imp->FirstThunk);

        for (; iat_thunk->u1.Function != 0; ++iat_thunk) {
            void **slot = (void **)&iat_thunk->u1.Function;

            /*
             * If this IAT slot points to the real bind(), we patch it
             * similarly as what we did with the string overwrite earlier.
             */
            if ((FARPROC)(uintptr_t)iat_thunk->u1.Function == bind_addr) {
                DWORD old_protect = 0;

                g_real_bind = (BindFn)bind_addr;

                logf_line("[cw-config] bind IAT slot = %p", slot);
                logf_line("[cw-config] original bind = %p", bind_addr);

                if (!VirtualProtect(slot, sizeof(*slot), PAGE_READWRITE, &old_protect)) {
                    logf_line("[cw-config] VirtualProtect failed for bind IAT slot");
                    return 0;
                }

                /* Replace the IAT entry with the hook */
                *slot = (void *)&hooked_bind;

                VirtualProtect(slot, sizeof(*slot), old_protect, &old_protect);

                FlushInstructionCache(GetCurrentProcess(), slot, sizeof(*slot));

                logf_line("[cw-config] patched bind = %p", *slot);
                logf_line("[cw-config] bind IAT patched");

                return 1;
            }
        }
    }

    logf_line("[cw-config] could not find bind in main executable IAT");
    return 0;
}


/* ---------------------------------------------------------------------------
 * init_thread
 * ---------------------------------------------------------------------------
 *
 * Why use a separate init thread?
 * -------------------------------
 * DllMain is a delicate place to run code.
 * Windows recommends doing as little as possible there.
 *
 * So in DllMain we only create a thread, and that thread does the real work.
 */
static DWORD WINAPI init_thread(LPVOID unused) {
    (void)unused;
    logf_line("[cw-config] init thread started");
    patch_seed_cfg_string();
    patch_main_exe_iat_bind();
    return 0;
}


/* ---------------------------------------------------------------------------
 * DllMain - the DLL entry point
 * ---------------------------------------------------------------------------
 *
 * Windows calls this automatically when the DLL is loaded.
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
