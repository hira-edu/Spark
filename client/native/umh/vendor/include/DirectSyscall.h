#pragma once

#include <Windows.h>
#include <winternl.h>

#include <string>

namespace injection {

using StructuredLogFn = void(*)(const std::string& event,
                                const std::string& func,
                                const std::string& details);

bool EnsureDirectSyscallInitialized();

NTSTATUS DirectNtOpenProcess(PHANDLE ProcessHandle,
                             ACCESS_MASK DesiredAccess,
                             POBJECT_ATTRIBUTES ObjectAttributes,
                             CLIENT_ID* ClientId);

NTSTATUS DirectNtAllocateVirtualMemory(HANDLE ProcessHandle,
                                       PVOID* BaseAddress,
                                       ULONG_PTR ZeroBits,
                                       PSIZE_T RegionSize,
                                       ULONG AllocationType,
                                       ULONG Protect);

NTSTATUS DirectNtWriteVirtualMemory(HANDLE ProcessHandle,
                                    PVOID BaseAddress,
                                    PVOID Buffer,
                                    SIZE_T BufferSize,
                                    PSIZE_T NumberOfBytesWritten);

NTSTATUS DirectNtCreateThreadEx(PHANDLE ThreadHandle,
                                ACCESS_MASK DesiredAccess,
                                POBJECT_ATTRIBUTES ObjectAttributes,
                                HANDLE ProcessHandle,
                                LPTHREAD_START_ROUTINE StartRoutine,
                                LPVOID Argument,
                                ULONG CreateFlags,
                                ULONG_PTR ZeroBits,
                                SIZE_T StackSize,
                                SIZE_T MaximumStackSize,
                                LPVOID AttributeList);

bool InjectDllViaDirectSyscall(DWORD processId, const std::wstring& dllPath);

void SetDirectSyscallStructuredLogger(StructuredLogFn logger);

} // namespace injection
