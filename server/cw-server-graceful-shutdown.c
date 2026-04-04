#define WIN32_LEAN_AND_MEAN
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <windows.h>

/*
 * ============================================================================
 * Cube World Alpha - Server Graceful Shutdown Mod
 * ============================================================================
 *
 * The goal of this mod is to provide a way to shutdown the Cube World Alpha
 * server without a keyboard interactive action.
 *
 *
 * What problem does this solve?
 * -----------------------------
 * The server normally expects someone to type the lowercase 'q' in its console
 * to shut down cleanly.
 *
 * That is inconvenient for services / automation / scripting.
 *
 * This mod adds a second clean shutdown method:
 *   - Original behavior still works: type 'q' in the server console
 *   - New behavior added by this mod: create a file named "shutdown.request"
 *
 * In both cases, the server follows its normal shutdown path, which is
 * important because the server appears to write final state to its database
 * files when shutting down cleanly.
 *
 *
 * How does the mod work?
 * ----------------------
 * Through reverse engineering, I found that the server starts a special
 * "quit watcher" thread whose job is roughly:
 *   - wait for the user to type 'q'
 *   - when that happens, set an internal "shutdown flag" to 0
 *
 * The main loop checks that flag, and when it becomes 0, the server performs
 * its cleanup/shutdown routine.
 *
 * Instead of replacing the whole shutdown system, this mod patches one vtable
 * slot so that:
 *   1. the mod starts its own helper thread that watches for the file "shutdown.request"
 *   2. it then calls the original quit-watcher function so that manual 'q' still works
 *
 * ============================================================================
 */

/*
 * Set this to TRUE for debugging. It will create a file called "ServerGracefulShutdown.log"
 * where logs are appended. This behavior comes from the logf_line function below.
 */
#ifndef VERBOSE
#   define VERBOSE FALSE
#endif


/*
 * On 32-bit Windows, some functions use "__fastcall", which means the first
 * arguments are passed in CPU registers instead of only on the stack.
 *
 * Ghidra identified the original quit function as __fastcall, so we match that.
 *
 * We define FASTCALL in a compiler-friendly way:
 *   - MSVC uses __fastcall
 *   - GCC (MinGW) uses __attribute__((fastcall))
 */
#ifndef FASTCALL
#  if defined(_MSC_VER)
#    define FASTCALL __fastcall
#  else
#    define FASTCALL __attribute__((fastcall))
#  endif
#endif


/*
 * These values came from Ghidra.
 *
 * IMAGE_BASE (documentation only):
 *   The base address where the executable expects to be loaded.
 *
 * QUIT_VTABLE_SLOT_RVA:
 *   RVA (Relative Virtual Address) of the vtable slot that points to the
 *   server's original quit-watcher function, computed using IMAGE_BASE.
 *
 * QUIT_FUNCTION_RVA:
 *   RVA of the original quit-watcher function itself, computed using
 *   IMAGE_BASE.
 */
#define IMAGE_BASE              0x00400000u
#define QUIT_VTABLE_SLOT_RVA    0x00173D6Cu
#define QUIT_FUNCTION_RVA       0x00149B50u


/* This is the function pointer for the original quit-watcher callable. */
typedef void (FASTCALL *QuitOperatorFn)(void *self);
static QuitOperatorFn g_original_quit_operator = NULL;


/* Name of the shutdown file used by the mod */
static const char *g_shutdown_flag_file = "shutdown.request";


/*
 * Through reverse engineering, I found that the object used by the original
 * quit watcher looks like this:
 *   +0 : pointer to vtable
 *   +4 : pointer to the shutdown flag byte
 *
 * We only need those two fields.
 */
typedef struct QuitWatcherObject {
    void **vtable;                /* offset +0 */
    volatile unsigned char *flag; /* offset +4 */
} QuitWatcherObject;


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
        "ServerGracefulShutdown.log",
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


/* Returns non-zero if the file "shutdown.request" exists and is not a directory. */
static int shutdown_requested(void) {
    DWORD attr = GetFileAttributesA(g_shutdown_flag_file);
    return attr != INVALID_FILE_ATTRIBUTES &&
           !(attr & FILE_ATTRIBUTE_DIRECTORY);
}


/*
 * This is the new helper thread added by the mod.
 *
 * Here is what it does:
 *   - repeatedly checks if the server is already shutting down
 *   - repeatedly checks if "shutdown.request" exists
 *   - if the file exists, delete it and set the shutdown flag to 0,
 *     which tells the server to leave its main loop and run cleanup.
 *
 * We use a separate thread because we want to preserve the original quit
 * behavior too. The original quit logic is blocking: it waits for console
 * input. So we run our file-based watcher in parallel.
 */
static DWORD WINAPI file_watcher_thread(LPVOID param) {
    volatile unsigned char *flag = (volatile unsigned char *)param;

    logf_line("[cw-server-graceful-shutdown] file watcher thread started");

    if (flag == NULL) {
        logf_line("[cw-server-graceful-shutdown] file watcher: NULL flag pointer");
        return 0;
    }

    for (;;) {
        /* If the server is already shutting down, there is nothing left to do. */
        if (*flag == 0) {
            logf_line("[cw-server-graceful-shutdown] file watcher: flag already zero, exiting");
            return 0;
        }

        /* If our trigger file exists, request clean shutdown. */
        if (shutdown_requested()) {
            logf_line("[cw-server-graceful-shutdown] shutdown.request detected");

            /*
             * Delete the file so the trigger is one-shot.
             * That way, future runs do not immediately shut down by accident.
             */
            DeleteFileA(g_shutdown_flag_file);

            /* Tell the server to shut down cleanly. */
            *flag = 0;

            logf_line("[cw-server-graceful-shutdown] shutdown flag set to 0");
            return 0;
        }

        /* Sleep a bit so we do not burn CPU in a busy loop. */
        Sleep(250);
    }
}


/* This function replaces the original quit-watcher callable in the vtable. */
static void FASTCALL my_quit_operator(void *self_void) {
    QuitWatcherObject *self = (QuitWatcherObject *)self_void;

    logf_line("[cw-server-graceful-shutdown] my_quit_operator entered");
    logf_line("[cw-server-graceful-shutdown] self = %p", self);

    if (self != NULL) {
        logf_line("[cw-server-graceful-shutdown] self->flag = %p", (const void *)self->flag);
    }

    /* Start the helper thread only if the object and flag pointer look valid. */
    if (self != NULL && self->flag != NULL) {
        HANDLE thread = CreateThread(
            NULL,                 /* default security */
            0,                    /* default stack size */
            file_watcher_thread,  /* thread entry point */
            (LPVOID)self->flag,   /* argument passed to the thread */
            0,                    /* start immediately */
            NULL                  /* thread id not needed */
        );

        if (thread != NULL) {
            /*
             * We do not need the thread handle after creation, so close it.
             * Closing the handle does not kill the thread.
             */
            CloseHandle(thread);
            logf_line("[cw-server-graceful-shutdown] file watcher thread launched");
        } else {
            logf_line("[cw-server-graceful-shutdown] failed to launch file watcher thread");
        }
    } else {
        logf_line("[cw-server-graceful-shutdown] invalid self/flag, not launching file watcher");
    }

    /* Call the original quit operator so the old manual console behavior remains. */
    if (g_original_quit_operator != NULL) {
        logf_line("[cw-server-graceful-shutdown] calling original quit operator");
        g_original_quit_operator(self_void);
        logf_line("[cw-server-graceful-shutdown] original quit operator returned");
    } else {
        logf_line("[cw-server-graceful-shutdown] original quit operator is NULL");
    }
}


/*
 * This function patches the vtable slot with our quit-watcher function.
 *
 * In C++ objects, a vtable is a table of function pointers used for virtual
 * methods / callable objects.
 *
 * We use VirtualProtect because the memory page containing the vtable is
 * usually not writable. We temporarily make it writable, patch the function pointer,
 * then restore the old protection.
 */
static int patch_quit_vtable_slot(void) {
    /* Get the base address of the main executable */
    BYTE *base = (BYTE *)GetModuleHandleA(NULL);
    if (base == NULL) {
        logf_line("[cw-server-graceful-shutdown] GetModuleHandleA(NULL) failed");
        return 0;
    }

    /* Compute the address of the vtable slot we want to patch */
    void **slot = (void **)(base + QUIT_VTABLE_SLOT_RVA);

    /* This is where we expect the original function to live */
    void *expected_original = (void *)(base + QUIT_FUNCTION_RVA);

    logf_line("[cw-server-graceful-shutdown] module base = %p", base);
    logf_line("[cw-server-graceful-shutdown] vtable slot = %p", slot);
    logf_line("[cw-server-graceful-shutdown] current slot value = %p", *slot);
    logf_line("[cw-server-graceful-shutdown] expected original = %p", expected_original);

    /* Store the slot value */
    g_original_quit_operator = (QuitOperatorFn)(*slot);

    /* Make the memory writable so we can modify the function pointer */
    DWORD old_protect = 0;
    if (!VirtualProtect(slot, sizeof(*slot), PAGE_EXECUTE_READWRITE, &old_protect)) {
        logf_line("[cw-server-graceful-shutdown] VirtualProtect failed");
        return 0;
    }

    /* Replace the original function pointer */
    *slot = (void *)&my_quit_operator;

    /* Restore the previous memory protection */
    VirtualProtect(slot, sizeof(*slot), old_protect, &old_protect);

    /* Flush instruction cache after patching process memory */
    FlushInstructionCache(GetCurrentProcess(), slot, sizeof(*slot));

    logf_line("[cw-server-graceful-shutdown] patched slot value = %p", *slot);
    logf_line("[cw-server-graceful-shutdown] quit vtable slot patched");

    return 1;
}


/*
 * DllMain is a delicate place to run code.
 * Windows recommends doing as little as possible there.
 *
 * So in DllMain we only create a thread, and that thread does the real work.
 */
static DWORD WINAPI init_thread(LPVOID unused) {
    (void)unused;
    logf_line("[cw-server-graceful-shutdown] init thread started");
    patch_quit_vtable_slot();
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
