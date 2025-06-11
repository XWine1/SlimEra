#ifndef _XBOX_ERA_
#define _XBOX_ERA_

#include <Windows.h>

#define MEM_GRAPHICS 0x10000000
#define MEM_TITLE    0x40000000

typedef enum _CONSOLE_TYPE
{
    CONSOLE_TYPE_UNKNOWN,
    CONSOLE_TYPE_XBOX_ONE,
    CONSOLE_TYPE_XBOX_ONE_S,
    CONSOLE_TYPE_XBOX_ONE_X,
    CONSOLE_TYPE_XBOX_ONE_X_DEVKIT,
} CONSOLE_TYPE, *PCONSOLE_TYPE, *LPCONSOLE_TYPE;

EXTERN_C CONSOLE_TYPE WINAPI GetConsoleType();

typedef struct _SYSTEMOSVERSIONINFO
{
    BYTE MajorVersion;
    BYTE MinorVersion;
    WORD BuildNumber;
    WORD Revision;
} SYSTEMOSVERSIONINFO, *PSYSTEMOSVERSIONINFO, *LPSYSTEMOSVERSIONINFO;

EXTERN_C VOID WINAPI GetSystemOSVersion(
    _Out_ LPSYSTEMOSVERSIONINFO lpVersionInformation);

typedef struct _PROCESSOR_SCHEDULING_STATISTICS
{
    ULONGLONG RunningTime;
    ULONGLONG IdleTime;
    ULONGLONG GlobalTime;
} PROCESSOR_SCHEDULING_STATISTICS, *PPROCESSOR_SCHEDULING_STATISTICS, *LPPROCESSOR_SCHEDULING_STATISTICS;

EXTERN_C VOID WINAPI QueryProcessorSchedulingStatistics(
    _Out_ PPROCESSOR_SCHEDULING_STATISTICS lpStatistics);

EXTERN_C BOOL WINAPI SetThreadpoolAffinityMask(
    _Inout_ PTP_POOL Pool,
    _In_ DWORD_PTR dwThreadAffinityMask);

EXTERN_C BOOL WINAPI SetThreadName(
    _In_ HANDLE hThread,
    _In_ PCWSTR lpThreadName);

EXTERN_C BOOL WINAPI GetThreadName(
    _In_ HANDLE hThread,
    _Out_ PWSTR lpThreadName,
    _In_ SIZE_T dwBufferLength,
    _Out_ PSIZE_T pdwReturnLength);

typedef struct _TITLEMEMORYSTATUS
{
    DWORD dwLength;
    DWORD dwReserved;
    ULONGLONG ullTotalMem;
    ULONGLONG ullAvailMem;
    ULONGLONG ullLegacyUsed;
    ULONGLONG ullLegacyPeak;
    ULONGLONG ullLegacyAvail;
    ULONGLONG ullTitleUsed;
    ULONGLONG ullTitleAvail;
    ULONGLONG ullLegacyPageTableUsed;
    ULONGLONG ullTitlePageTableUsed;
} TITLEMEMORYSTATUS, *PTITLEMEMORYSTATUS, *LPTITLEMEMORYSTATUS;

EXTERN_C BOOL WINAPI TitleMemoryStatus(
    _Inout_ LPTITLEMEMORYSTATUS lpBuffer);

EXTERN_C BOOL WINAPI JobTitleMemoryStatus(
    _Inout_ LPTITLEMEMORYSTATUS lpBuffer);

typedef struct _TOOLINGMEMORYSTATUS
{
    DWORD dwLength;
    DWORD dwReserved;
    ULONGLONG ullTotalMem;
    ULONGLONG ullAvailMem;
    ULONGLONG ulPeakUsage;
    ULONGLONG ullPageTableUsage;
} TOOLINGMEMORYSTATUS, *PTOOLINGMEMORYSTATUS, *LPTOOLINGMEMORYSTATUS;

EXTERN_C BOOL WINAPI ToolingMemoryStatus(
    _Inout_ LPTOOLINGMEMORYSTATUS lpBuffer);

EXTERN_C BOOL WINAPI AllocateTitlePhysicalPages(
    _In_ HANDLE hProcess,
    _In_ DWORD flAllocationType,
    _Inout_ PULONG_PTR NumberOfPages,
    _Out_ PULONG_PTR PageArray);

EXTERN_C BOOL WINAPI FreeTitlePhysicalPages(
    _In_ HANDLE hProcess,
    _In_ ULONG_PTR NumberOfPages,
    _In_ PULONG_PTR PageArray);

EXTERN_C PVOID WINAPI MapTitlePhysicalPages(
    _In_opt_ PVOID VirtualAddress,
    _In_ ULONG_PTR NumberOfPages,
    _In_ DWORD flAllocationType,
    _In_ DWORD flProtect,
    _In_ PULONG_PTR PageArray);

// This is not a standard ERA function, it is provided for convenience
// to aid in the implementation of the Direct3D D3DMapEsramMemory API.
EXTERN_C HRESULT WINAPI MapTitleEsramPages(
    _In_ PVOID VirtualAddress,
    _In_ UINT NumberOfPages,
    _In_ DWORD flAllocationType,
    _In_opt_ UINT const *PageArray);

typedef union _XALLOC_ATTRIBUTES
{
    ULONGLONG dwAttributes;

    struct
    {
        ULONGLONG dwObjectType : 14;
        ULONGLONG dwPageSize : 2;
        ULONGLONG dwAllocatorId : 8;
        ULONGLONG dwAlignment : 5;
        ULONGLONG dwMemoryType : 4;
        ULONGLONG reserved : 31;
    } s;
} XALLOC_ATTRIBUTES, *PXALLOC_ATTRIBUTES, *LPXALLOC_ATTRIBUTES;

#define XALLOC_IS_GRAPHICS(Attributes) ((BOOL)(((Attributes) & 0x1E0000000ULL) != 0))

EXTERN_C PVOID WINAPI XMemAllocDefault(
    _In_ SIZE_T dwSize,
    _In_ ULONGLONG dwAttributes);

EXTERN_C void WINAPI XMemFreeDefault(
    _In_ PVOID lpAddress,
    _In_ ULONGLONG dwAttributes);

EXTERN_C PVOID WINAPI XMemAlloc(
    _In_ SIZE_T dwSize,
    _In_ ULONGLONG dwAttributes);

EXTERN_C void WINAPI XMemFree(
    _In_ PVOID lpAddress,
    _In_ ULONGLONG dwAttributes);

typedef PVOID WINAPI XMEMALLOC_ROUTINE(
    _In_ SIZE_T dwSize,
    _In_ ULONGLONG dwAttributes);

typedef XMEMALLOC_ROUTINE *PXMEMALLOC_ROUTINE, *LPXMEMALLOC_ROUTINE;

typedef void WINAPI XMEMFREE_ROUTINE(
    _In_ PVOID lpAddress,
    _In_ ULONGLONG dwAttributes);

typedef XMEMFREE_ROUTINE *PXMEMFREE_ROUTINE, *LPXMEMFREE_ROUTINE;

EXTERN_C void WINAPI XMemSetAllocationHooks(
    _In_opt_ PXMEMALLOC_ROUTINE pAllocRoutine,
    _In_opt_ PXMEMFREE_ROUTINE pFreeRoutine);

EXTERN_C void WINAPI XMemCheckDefaultHeaps();

// XMemSetAllocationHysteresis

// XMemGetAllocationHysteresis

// XMemPreallocateFreeSpace

// XMemGetAllocationStatistics

// XMemGetAuxiliaryTitleMemory

// XMemReleaseAuxiliaryTitleMemory

#endif /* _XBOX_ERA_ */
