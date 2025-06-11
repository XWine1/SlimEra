#include <Windows.h>
#include <evntprov.h>

typedef struct _ETX_FIELD_DESCRIPTOR
{
    UINT8 Type : 5;
    UINT8 IsLengthField : 1;
} ETX_FIELD_DESCRIPTOR, *PETX_FIELD_DESCRIPTOR, *LPETX_FIELD_DESCRIPTOR;

typedef struct _ETX_EVENT_DESCRIPTOR
{
    EVENT_DESCRIPTOR EtwDescriptor;
    LPCSTR Name;
    LPCSTR SchemaVersion;
    ETX_FIELD_DESCRIPTOR const *FieldDescriptors;
    UINT8 NumFields;
    UINT8 UploadEnabled;
    UINT8 CurrentUploadEnabledState;
    UINT8 DefaultUploadEnabledState;
    INT8 CurrentPopulationSample;
    INT8 DefaultPopulationSample;
    UINT8 CurrentLatency;
    UINT8 DefaultLatency;
    UINT8 CurrentPriority;
    UINT8 DefaultPriority;
} ETX_EVENT_DESCRIPTOR, *PETX_EVENT_DESCRIPTOR, *LPETX_EVENT_DESCRIPTOR;

typedef struct _ETX_PROVIDER_DESCRIPTOR
{
    LPCSTR Name;
    GUID Guid;
    ULONG NumEvents;
    PETX_EVENT_DESCRIPTOR EventDescriptors;
    UINT8 UploadEnabled;
    UINT8 CurrentUploadEnabledState;
    UINT8 DefaultUploadEnabledState;
    INT8 CurrentPopulationSample;
    INT8 DefaultPopulationSample;
    UINT8 CurrentLatency;
    UINT8 DefaultLatency;
    UINT8 CurrentPriority;
    UINT8 DefaultPriority;
} ETX_PROVIDER_DESCRIPTOR, *PETX_PROVIDER_DESCRIPTOR, *LPETX_PROVIDER_DESCRIPTOR;

EXTERN_C ULONG WINAPI EtxEventWrite(
    _In_ PETX_EVENT_DESCRIPTOR EventDescriptor,
    _In_ PETX_PROVIDER_DESCRIPTOR ProviderDescriptor,
    _In_ REGHANDLE RegHandle,
    _In_ ULONG UserDataCount,
    _In_opt_ PEVENT_DATA_DESCRIPTOR UserData)
{
    UNREFERENCED_PARAMETER(EventDescriptor);
    UNREFERENCED_PARAMETER(ProviderDescriptor);
    UNREFERENCED_PARAMETER(RegHandle);
    UNREFERENCED_PARAMETER(UserDataCount);
    UNREFERENCED_PARAMETER(UserData);
    return ERROR_SUCCESS;
}

EXTERN_C void WINAPI EtxFillCommonFields_v7(
    _Out_ PEVENT_DATA_DESCRIPTOR EventData,
    _Out_ PUINT8 Scratch,
    _In_ SIZE_T ScratchSize)
{
    UNREFERENCED_PARAMETER(EventData);
    UNREFERENCED_PARAMETER(Scratch);
    UNREFERENCED_PARAMETER(ScratchSize);
    ZeroMemory(EventData, sizeof(*EventData));
}

EXTERN_C ULONG WINAPI EtxRegister(
    _In_ PETX_PROVIDER_DESCRIPTOR ProviderDescriptor,
    _Out_ PREGHANDLE RegHandle)
{
    UNREFERENCED_PARAMETER(ProviderDescriptor);
    *RegHandle = 0;
    return ERROR_SUCCESS;
}

EXTERN_C void WINAPI EtxResumeUploading()
{
}

EXTERN_C void WINAPI EtxSuspendUploading()
{
}

EXTERN_C ULONG WINAPI EtxUnregister(
    _In_ PETX_PROVIDER_DESCRIPTOR ProviderDescriptor,
    _In_ PREGHANDLE RegHandle)
{
    UNREFERENCED_PARAMETER(ProviderDescriptor);
    UNREFERENCED_PARAMETER(RegHandle);
    return ERROR_SUCCESS;
}

//
// Exports
//
#pragma comment(linker, "/export:EtxEventWrite")
#pragma comment(linker, "/export:EtxFillCommonFields_v7")
#pragma comment(linker, "/export:EtxRegister")
#pragma comment(linker, "/export:EtxResumeUploading")
#pragma comment(linker, "/export:EtxSuspendUploading")
#pragma comment(linker, "/export:EtxUnregister")
