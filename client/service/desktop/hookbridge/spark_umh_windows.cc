#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "spark_umh.h"

extern "C" {

static BOOL CALLBACK SparkEnumWindowsProc(HWND hwnd, LPARAM lParam) {
    (void)lParam;
    if (IsWindow(hwnd)) {
        SetWindowDisplayAffinity(hwnd, WDA_NONE);
    }
    return TRUE;
}

int spark_umh_init(void) {
    return 0;
}

int spark_umh_apply(const char *connection_id, int force_input, int force_capture) {
    (void)connection_id;
    EnumWindows(SparkEnumWindowsProc, 0);
    if (force_input) {
        BlockInput(FALSE);
    }
    if (force_capture) {
        // Placeholder for future capture enforcement (e.g., DXGI hooks)
    }
    return 0;
}

int spark_umh_release(const char *connection_id) {
    (void)connection_id;
    return 0;
}

void spark_umh_shutdown(void) {}

}  // extern "C"

#endif
