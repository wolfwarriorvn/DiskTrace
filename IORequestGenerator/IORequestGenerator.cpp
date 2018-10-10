/*

DISKSPD

Copyright(c) Microsoft Corporation
All rights reserved.

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

//FUTURE EXTENSION: make it compile with /W4

// Windows 7
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include "common.h"
#include "IORequestGenerator.h"

#include <stdio.h>
#include <stdlib.h>
#include <Winioctl.h>   //DISK_GEOMETRY
#include <windows.h>
#include <stddef.h>

#include <Wmistr.h>     //WNODE_HEADER

#include <chrono>
#include <thread>
#include <vector>

#include "etw.h"
#include <assert.h>
#include "ThroughputMeter.h"
#include "OverlappedQueue.h"

// Flags for RtlFlushNonVolatileMemory
#ifndef FLUSH_NV_MEMORY_IN_FLAG_NO_DRAIN
#define FLUSH_NV_MEMORY_IN_FLAG_NO_DRAIN    (0x00000001)
#endif

/*****************************************************************************/
// gets size of a dynamic volume, return zero on failure
//
UINT64 GetDynamicPartitionSize(HANDLE hFile)
{
    assert(NULL != hFile && INVALID_HANDLE_VALUE != hFile);

    UINT64 size = 0;
    VOLUME_DISK_EXTENTS diskExt = {0};
    PVOLUME_DISK_EXTENTS pDiskExt = &diskExt;
    DWORD bytesReturned;

    DWORD status = ERROR_SUCCESS;
    BOOL rslt;

    OVERLAPPED ovlp = {0};
    ovlp.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (ovlp.hEvent == nullptr)
    {
        PrintError("ERROR: Failed to create event (error code: %u)\n", GetLastError());
        return 0;
    }

    rslt = DeviceIoControl(hFile,
                            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                            NULL,
                            0,
                            pDiskExt,
                            sizeof(VOLUME_DISK_EXTENTS),
                            &bytesReturned,
                            &ovlp);
    if (!rslt) {
        status = GetLastError();
        if (status == ERROR_MORE_DATA) {
            status = ERROR_SUCCESS;

            bytesReturned = sizeof(VOLUME_DISK_EXTENTS) + ((pDiskExt->NumberOfDiskExtents - 1) * sizeof(DISK_EXTENT));
            pDiskExt = (PVOLUME_DISK_EXTENTS)LocalAlloc(LPTR, bytesReturned);

            if (pDiskExt)
            {
                rslt = DeviceIoControl(hFile,
                                    IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                                    NULL,
                                    0,
                                    pDiskExt,
                                    bytesReturned,
                                    &bytesReturned,
                                    &ovlp);
                if (!rslt)
                {
                    status = GetLastError();
                    if (status == ERROR_IO_PENDING)
                    {
                        if (WAIT_OBJECT_0 != WaitForSingleObject(ovlp.hEvent, INFINITE))
                        {
                            status = GetLastError();
                            PrintError("ERROR: Failed while waiting for event to be signaled (error code: %u)\n", status);
                        }
                        else
                        {
                            status = ERROR_SUCCESS;
                            assert(pDiskExt->NumberOfDiskExtents <= 1);
                        }
                    }
                    else
                    {
                        PrintError("ERROR: Could not obtain dynamic volume extents (error code: %u)\n", status);
                    }
                }
            }
            else
            {
                status = GetLastError();
                PrintError("ERROR: Could not allocate memory (error code: %u)\n", status);
            }
        }
        else if (status == ERROR_IO_PENDING)
        {
            if (WAIT_OBJECT_0 != WaitForSingleObject(ovlp.hEvent, INFINITE))
            {
                status = GetLastError();
                PrintError("ERROR: Failed while waiting for event to be signaled (error code: %u)\n", status);
            }
            else
            {
                status = ERROR_SUCCESS;
                assert(pDiskExt->NumberOfDiskExtents <= 1);
            }
        }
        else
        {
            PrintError("ERROR: Could not obtain dynamic volume extents (error code: %u)\n", status);
        }
    }
    else
    {
        assert(pDiskExt->NumberOfDiskExtents <= 1);
    }

    if (status == ERROR_SUCCESS)
    {
        for (DWORD n = 0; n < pDiskExt->NumberOfDiskExtents; n++) {
            size += pDiskExt->Extents[n].ExtentLength.QuadPart;
        }
    }

    if (pDiskExt && (pDiskExt != &diskExt)) {
        LocalFree(pDiskExt);
    }
    CloseHandle(ovlp.hEvent);

    return size;
}

/*****************************************************************************/
// gets partition size, return zero on failure
//
UINT64 GetPartitionSize(HANDLE hFile)
{
    assert(NULL != hFile && INVALID_HANDLE_VALUE != hFile);

    PARTITION_INFORMATION_EX pinf;
    OVERLAPPED ovlp = {};

    ovlp.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (ovlp.hEvent == nullptr)
    {
        PrintError("ERROR: Failed to create event (error code: %u)\n", GetLastError());
        return 0;
    }

    DWORD rbcnt = 0;
    DWORD status = ERROR_SUCCESS;
    UINT64 size = 0;

    if (!DeviceIoControl(hFile,
                        IOCTL_DISK_GET_PARTITION_INFO_EX,
                        NULL,
                        0,
                        &pinf,
                        sizeof(pinf),
                        &rbcnt,
                        &ovlp)
        )
    {
        status = GetLastError();
        if (status == ERROR_IO_PENDING)
        {
            if (WAIT_OBJECT_0 != WaitForSingleObject(ovlp.hEvent, INFINITE))
            {
                PrintError("ERROR: Failed while waiting for event to be signaled (error code: %u)\n", GetLastError());
            }
            else
            {
                size = pinf.PartitionLength.QuadPart;
            }
        }
        else
        {
            size = GetDynamicPartitionSize(hFile);
        }
    }
    else
    {
        size = pinf.PartitionLength.QuadPart;
    }

    CloseHandle(ovlp.hEvent);

    return size;
}

/*****************************************************************************/
// gets physical drive size, return zero on failure
//
UINT64 GetPhysicalDriveSize(HANDLE hFile)
{
    assert(NULL != hFile && INVALID_HANDLE_VALUE != hFile);

    DISK_GEOMETRY_EX geom;
    OVERLAPPED ovlp = {};

    ovlp.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (ovlp.hEvent == nullptr)
    {
        PrintError("ERROR: Failed to create event (error code: %u)\n", GetLastError());
        return 0;
    }

    DWORD rbcnt = 0;
    DWORD status = ERROR_SUCCESS;
    BOOL rslt;

    rslt = DeviceIoControl(hFile,
        IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
        NULL,
        0,
        &geom,
        sizeof(geom),
        &rbcnt,
        &ovlp);

    if (!rslt)
    {
        status = GetLastError();
        if (status == ERROR_IO_PENDING)
        {
            if (WAIT_OBJECT_0 != WaitForSingleObject(ovlp.hEvent, INFINITE))
            {
                PrintError("ERROR: Failed while waiting for event to be signaled (error code: %u)\n", GetLastError());
            }
            else
            {
                rslt = TRUE;
            }
        }
        else
        {
            PrintError("ERROR: Could not obtain drive geometry (error code: %u)\n", status);
        }
    }

    CloseHandle(ovlp.hEvent);

    if (!rslt)
    {
        return 0;
    }

    return (UINT64)geom.DiskSize.QuadPart;
}

/*****************************************************************************/
// activates specified privilege in process token
//
bool SetPrivilege(LPCSTR pszPrivilege, LPCSTR pszErrorPrefix = "ERROR:")
{
    TOKEN_PRIVILEGES TokenPriv;
    HANDLE hToken = INVALID_HANDLE_VALUE;
    DWORD dwError;
    bool fOk = true;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
    {
        PrintError("%s Error opening process token (error code: %u)\n", pszErrorPrefix, GetLastError());
        fOk = false;
        goto cleanup;
    }

    TokenPriv.PrivilegeCount = 1;
    TokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValue(nullptr, pszPrivilege, &TokenPriv.Privileges[0].Luid))
    {
        PrintError("%s Error looking up privilege value %s (error code: %u)\n", pszErrorPrefix, pszPrivilege, GetLastError());
        fOk = false;
        goto cleanup;
    }

    if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPriv, 0, nullptr, nullptr))
    {
        PrintError("%s Error adjusting token privileges for %s (error code: %u)\n", pszErrorPrefix, pszPrivilege, GetLastError());
        fOk = false;
        goto cleanup;
    }

    if (ERROR_SUCCESS != (dwError = GetLastError()))
    {
        PrintError("%s Error adjusting token privileges for %s (error code: %u)\n", pszErrorPrefix, pszPrivilege, dwError);
        fOk = false;
        goto cleanup;
    }

cleanup:
    if (hToken != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hToken);
    }
    
    return fOk;
}

BOOL
DisableLocalCache(
    HANDLE h
)
/*++
Routine Description:

    Disables local caching of I/O to a file by SMB. All reads/writes will flow to the server.

Arguments:

    h - Handle to the file

Return Value:

    Returns ERROR_SUCCESS (0) on success, nonzero error code on failure.

--*/
{
    DWORD BytesReturned = 0;
    OVERLAPPED Overlapped = { 0 };
    DWORD Status = ERROR_SUCCESS;
    BOOL Success = false;

    Overlapped.hEvent = CreateEvent(nullptr, true, false, nullptr);
    if (!Overlapped.hEvent)
    {
        return GetLastError();
    }

#ifndef FSCTL_DISABLE_LOCAL_BUFFERING
#define FSCTL_DISABLE_LOCAL_BUFFERING   CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 174, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

    Success = DeviceIoControl(h,
        FSCTL_DISABLE_LOCAL_BUFFERING,
        nullptr,
        0,
        nullptr,
        0,
        nullptr,
        &Overlapped);

    if (!Success) {
        Status = GetLastError();
    }

    if (!Success && Status == ERROR_IO_PENDING)
    {
        if (!GetOverlappedResult(h, &Overlapped, &BytesReturned, true))
        {
            Status = GetLastError();
        }
        else
        {
            Status = (DWORD) Overlapped.Internal;
        }
    }

    if (Overlapped.hEvent)
    {
        CloseHandle(Overlapped.hEvent);
    }

    return Status;
}

/*****************************************************************************/
// structures and global variables
//
struct ETWEventCounters g_EtwEventCounters;

__declspec(align(4)) static LONG volatile g_lRunningThreadsCount = 0;   //must be aligned on a 32-bit boundary, otherwise InterlockedIncrement
                                                                        //and InterlockedDecrement will fail on 64-bit systems

static BOOL volatile g_bRun;                    //used for letting threads know that they should stop working

typedef NTSTATUS (__stdcall *NtQuerySysInfo)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
static NtQuerySysInfo g_pfnNtQuerySysInfo;

typedef VOID (__stdcall *RtlCopyMemNonTemporal)(VOID UNALIGNED *, VOID UNALIGNED *, SIZE_T);
static RtlCopyMemNonTemporal g_pfnRtlCopyMemoryNonTemporal;

typedef NTSTATUS (__stdcall *RtlFlushNvMemory)(PVOID, PVOID, SIZE_T, ULONG);
static RtlFlushNvMemory g_pfnRtlFlushNonVolatileMemory;

typedef NTSTATUS(__stdcall *RtlGetNvToken)(PVOID, SIZE_T, PVOID *);
static RtlGetNvToken g_pfnRtlGetNonVolatileToken;

typedef NTSTATUS(__stdcall *RtlFreeNvToken)(PVOID);
static RtlFreeNvToken g_pfnRtlFreeNonVolatileToken;

static PRINTF g_pfnPrintOut = nullptr;
static PRINTF g_pfnPrintError = nullptr;
static PRINTF g_pfnPrintVerbose = nullptr;

static BOOL volatile g_bThreadError = FALSE;    //true means that an error has occured in one of the threads
BOOL volatile g_bTracing = TRUE;                //true means that ETW is turned on

// TODO: is this still needed?
__declspec(align(4)) static LONG volatile g_lGeneratorRunning = 0;  //used to detect if GenerateRequests is already running

static BOOL volatile g_bError = FALSE;                              //true means there was fatal error during intialization and threads shouldn't perform their work

queue<sDiskioTypeGroup1> q_DiskIO;
queue<sDiskioTypeGroup1> q_WriteIO;
std::vector<sDiskioTypeGroup1> vReadIO;
std::vector<sDiskioTypeGroup1> vWriteIO;


VOID SetProcGroupMask(WORD wGroupNum, DWORD dwProcNum, PGROUP_AFFINITY pGroupAffinity)
{
    //must zero this structure first, otherwise it fails to set affinity
    memset(pGroupAffinity, 0, sizeof(GROUP_AFFINITY));

    pGroupAffinity->Group = wGroupNum;
    pGroupAffinity->Mask = (KAFFINITY)1<<dwProcNum;
}

/*****************************************************************************/
void IORequestGenerator::_CloseOpenFiles(vector<HANDLE>& vhFiles) const
{
    for (size_t x = 0; x < vhFiles.size(); ++x)
    {
        if ((INVALID_HANDLE_VALUE != vhFiles[x]) && (nullptr != vhFiles[x]))
        {
            if (!CloseHandle(vhFiles[x]))
            {
                PrintError("Warning: unable to close file handle (error code: %u)\n", GetLastError());
            }
            vhFiles[x] = nullptr;
        }
    }
}

/*****************************************************************************/
// wrapper for pfnPrintOut. printf cannot be used directly, because IORequestGenerator.dll
// may be consumed by gui app which doesn't have stdout
static void print(const char *format, ...)
{
    assert(NULL != format);

    if( NULL != g_pfnPrintOut )
    {
        va_list listArg;
        va_start(listArg, format);
        g_pfnPrintOut(format, listArg);
        va_end(listArg);
    }
}

/*****************************************************************************/
// wrapper for pfnPrintError. fprintf(stderr) cannot be used directly, because IORequestGenerator.dll
// may be consumed by gui app which doesn't have stdout
void PrintError(const char *format, ...)
{
    assert(NULL != format);

    if( NULL != g_pfnPrintError )
    {
        va_list listArg;

        va_start(listArg, format);
        g_pfnPrintError(format, listArg);
        va_end(listArg);
    }
}

/*****************************************************************************/
// prints the string only if verbose mode is set to true
//
static void printfv(bool fVerbose, const char *format, ...)
{
    assert(NULL != format);

    if( NULL != g_pfnPrintVerbose && fVerbose )
    {
        va_list argList;
        va_start(argList, format);
        g_pfnPrintVerbose(format, argList);
        va_end(argList);
    }
}

/*****************************************************************************/
// thread for gathering ETW data (etw functions are defined in etw.cpp)
//
DWORD WINAPI etwThreadFunc(LPVOID cookie)
{
    UNREFERENCED_PARAMETER(cookie);

    g_bTracing = TRUE;
    BOOL result = TraceEvents();
    g_bTracing = FALSE;

    return result ? 0 : 1;
}
/*****************************************************************************/
// thread for gathering ETW data (etw functions are defined in etw.cpp)
//
DWORD WINAPI etwDebug(LPVOID cookie)
{
	UNREFERENCED_PARAMETER(cookie);
	sDiskioTypeGroup1 DiskioTypeGroup1;
	while (1)
	{
		//Pop only when queue has at least 1 element 
		if (vReadIO.size() > 0) {
			// Get the data from the end of array
			DiskioTypeGroup1 = vReadIO[vReadIO.size() - 1];
			//printf("Read: %lu\n", DiskioTypeGroup1.TransferSize);
			printf("%5lu %10s %16lu %5lu\n",
				DiskioTypeGroup1.DiskNumber,
				"Read",
				(DiskioTypeGroup1.ByteOffset)/512,
				(DiskioTypeGroup1.TransferSize)/512);

			// Pop the consumed data from queue 
			vReadIO.pop_back();
		}
		if (vWriteIO.size() > 0) {
			// Get the data from the front of queue 
			DiskioTypeGroup1 = vWriteIO[vWriteIO.size() - 1];
			//printf("Write: %lu\n", DiskioTypeGroup1.TransferSize);
			printf("%5lu %10s %16lu %5lu\n",
				DiskioTypeGroup1.DiskNumber,
				"Write",
				(DiskioTypeGroup1.ByteOffset)/512,
				(DiskioTypeGroup1.TransferSize)/512);

			// Pop the consumed data from queue 
			vWriteIO.pop_back();
		}
	}

	return 0;
}

/*****************************************************************************/
// display file size in a user-friendly form using 'verbose' stream
//
void IORequestGenerator::_DisplayFileSizeVerbose(bool fVerbose, UINT64 fsize) const
{
    if( fsize > (UINT64)10*1024*1024*1024 )     // > 10GB
    {
        printfv(fVerbose, "%I64uGB", fsize >> 30);
    }
    else if( fsize > (UINT64)10*1024*1024 )     // > 10MB
    {
        printfv(fVerbose, "%I64uMB", fsize >> 20);
    }
    else if( fsize > 10*1024 )                  // > 10KB
    {
        printfv(fVerbose, "%I64uKB", fsize >> 10);
    }
    else
    {
        printfv(fVerbose, "%I64uB", fsize);
    }
}

/*****************************************************************************/
bool IORequestGenerator::_LoadDLLs()
{
    _hNTDLL = LoadLibraryExW(L"ntdll.dll", nullptr, 0);
    if( nullptr == _hNTDLL )
    {
        return false;
    }

    g_pfnNtQuerySysInfo = (NtQuerySysInfo)GetProcAddress(_hNTDLL, "NtQuerySystemInformation");
    if( nullptr == g_pfnNtQuerySysInfo )
    {
        return false;
    }

    g_pfnRtlCopyMemoryNonTemporal = (RtlCopyMemNonTemporal)GetProcAddress(_hNTDLL, "RtlCopyMemoryNonTemporal");
    g_pfnRtlFlushNonVolatileMemory = (RtlFlushNvMemory)GetProcAddress(_hNTDLL, "RtlFlushNonVolatileMemory");
    g_pfnRtlGetNonVolatileToken = (RtlGetNvToken)GetProcAddress(_hNTDLL, "RtlGetNonVolatileToken");
    g_pfnRtlFreeNonVolatileToken = (RtlFreeNvToken)GetProcAddress(_hNTDLL, "RtlFreeNonVolatileToken");

    return true;
}

/*****************************************************************************/
bool IORequestGenerator::_GetSystemPerfInfo(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION *pInfo, UINT32 uCpuCount) const
{
    NTSTATUS Status = NO_ERROR;
    UINT32 uCpuCtr;
    WORD wActiveGroupCtr;
    BYTE bActiveProc;
    HANDLE hThread = GetCurrentThread();
    GROUP_AFFINITY GroupAffinity;
    PROCESSOR_NUMBER procNumber;
    bool fOk = true;

    assert(NULL != pInfo);
    assert(uCpuCount > 0);

    for (uCpuCtr=0,wActiveGroupCtr=0; wActiveGroupCtr < g_SystemInformation.processorTopology._vProcessorGroupInformation.size(); wActiveGroupCtr++)
    {
        ProcessorGroupInformation *pGroup = &g_SystemInformation.processorTopology._vProcessorGroupInformation[wActiveGroupCtr];
        
        if (pGroup->_activeProcessorCount != 0) {
            
            //
            // Affinitize to the group we're querying counters from
            //
            
            GetCurrentProcessorNumberEx(&procNumber);
            
            if (procNumber.Group != wActiveGroupCtr)
            {
                for (bActiveProc = 0; bActiveProc < pGroup->_maximumProcessorCount; bActiveProc++)
                {
                    if (pGroup->IsProcessorActive(bActiveProc))
                    {
                        SetProcGroupMask(wActiveGroupCtr, bActiveProc, &GroupAffinity);
                        break;
                    }
                }

                if (bActiveProc == pGroup->_maximumProcessorCount ||
                    SetThreadGroupAffinity(hThread, &GroupAffinity, nullptr) == FALSE)
                {
                    fOk = false;
                    break;
                }
            }

            Status = g_pfnNtQuerySysInfo(SystemProcessorPerformanceInformation,
                                         (PVOID)(pInfo + uCpuCtr),
                                         (sizeof(*pInfo) * uCpuCount) - (uCpuCtr * sizeof(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION)),
                                         NULL);

            if (!NT_SUCCESS(Status))
            {
                fOk = false;
                break;
            }
        }
    
        uCpuCtr += pGroup->_maximumProcessorCount;
    }

    return fOk;
}

/*****************************************************************************/
// calculate the offset of the next I/O operation
//

__inline UINT64 IORequestGenerator::GetNextFileOffset(ThreadParameters& tp, size_t targetNum, UINT64 prevOffset)
{
    Target &target = tp.vTargets[targetNum];

    UINT64 blockAlignment = target.GetBlockAlignmentInBytes();
    UINT64 baseFileOffset = target.GetBaseFileOffsetInBytes();
    UINT64 baseThreadOffset = target.GetThreadBaseFileOffsetInBytes(tp.ulRelativeThreadNo);
    UINT64 blockSize = target.GetBlockSizeInBytes();
    UINT64 nextBlockOffset;

    // now apply bounds for IO offset
    // aligned target size is the closed interval of byte offsets at which it is legal to issue IO
    // ISSUE IMPROVEMENT: much of this should be precalculated. It belongs within Target, which will
    //      need discovery of target sizing moved from its current just-in-time at thread launch.
    UINT64 alignedTargetSize = tp.vullFileSizes[targetNum] - baseFileOffset - blockSize;

    if (target.GetUseRandomAccessPattern() ||
        target.GetUseInterlockedSequential())
    {
        // convert aligned target size to the open interval
        alignedTargetSize = ((alignedTargetSize / blockAlignment) + 1) * blockAlignment;

        // increment/produce - note, logically relative to base offset
        if (target.GetUseRandomAccessPattern())
        {
            nextBlockOffset = tp.pRand->Rand64();
            nextBlockOffset -= (nextBlockOffset % blockAlignment);
            nextBlockOffset %= alignedTargetSize;
        }
        else
        {
            nextBlockOffset = InterlockedAdd64((PLONGLONG) &tp.pullSharedSequentialOffsets[targetNum], blockAlignment) - blockAlignment;
            nextBlockOffset %= alignedTargetSize;
        }
    }
    else
    {
        if (prevOffset == FIRST_OFFSET)
        {
            nextBlockOffset = baseThreadOffset - baseFileOffset;
        }
        else 
        {
            if (target.GetUseParallelAsyncIO())
            {
                nextBlockOffset = prevOffset - baseFileOffset + blockAlignment;
            }
            else // normal sequential access pattern
            {
                nextBlockOffset = tp.vullPrivateSequentialOffsets[targetNum] + blockAlignment;
            }
        }

        // parasync and seq bases are potentially modified by threadstride and loop back to the
        // file base offset + increment which will return them to their initial base offset.
        if (nextBlockOffset > alignedTargetSize) {
            nextBlockOffset = (baseThreadOffset - baseFileOffset) % blockAlignment;

        }

        if (!target.GetUseParallelAsyncIO())
        {
            tp.vullPrivateSequentialOffsets[targetNum] = nextBlockOffset;
        }
    }

    // Convert into the next full offset
    nextBlockOffset += baseFileOffset;

#ifndef NDEBUG
    // Don't overrun the end of the file
    UINT64 fileSize = tp.vullFileSizes[targetNum];
    assert(nextBlockOffset + blockSize <= fileSize);
#endif

    return nextBlockOffset;
}

/*****************************************************************************/
// Decide the kind of IO to issue during a mix test
// Future Work: Add more types of distribution in addition to random
__inline static IOOperation DecideIo(Random *pRand, UINT32 ulWriteRatio)
{
    return ((pRand->Rand32() % 100 + 1) > ulWriteRatio) ? IOOperation::ReadIO : IOOperation::WriteIO;
}

VOID CALLBACK fileIOCompletionRoutine(DWORD dwErrorCode, DWORD dwBytesTransferred, LPOVERLAPPED pOverlapped);

static bool issueNextIO(ThreadParameters *p, IORequest *pIORequest, DWORD *pdwBytesTransferred, bool useCompletionRoutines)
{
    OVERLAPPED *pOverlapped = pIORequest->GetOverlapped();
    Target *pTarget = pIORequest->GetCurrentTarget();
    size_t iTarget = pTarget - &p->vTargets[0];
    UINT32 iRequest = pIORequest->GetRequestIndex();
    LARGE_INTEGER li;
    BOOL rslt = true;

    li.LowPart = pOverlapped->Offset;
    li.HighPart = pOverlapped->OffsetHigh;
    
    li.QuadPart = IORequestGenerator::GetNextFileOffset(*p, iTarget, li.QuadPart);
    
    pOverlapped->Offset = li.LowPart;
    pOverlapped->OffsetHigh = li.HighPart;
    
    IOOperation readOrWrite = DecideIo(p->pRand, pTarget->GetWriteRatio());
    pIORequest->SetIoType(readOrWrite);
    
    if (TraceLoggingProviderEnabled(g_hEtwProvider,
                                    TRACE_LEVEL_VERBOSE,
                                    DISKSPD_TRACE_IO))
    {
        GUID ActivityId = p->NextActivityId();
        pIORequest->SetActivityId(ActivityId);
        
        TraceLoggingWriteActivity(g_hEtwProvider,
                                  "DiskSpd IO",
                                  &ActivityId,
                                  NULL,
                                  TraceLoggingKeyword(DISKSPD_TRACE_IO),
                                  TraceLoggingOpcode(EVENT_TRACE_TYPE_START),
                                  TraceLoggingLevel(TRACE_LEVEL_VERBOSE),
                                  TraceLoggingUInt32(p->ulThreadNo, "Thread"),
                                  TraceLoggingString(readOrWrite == IOOperation::ReadIO ? "Read" : "Write", "IO Type"),
                                  TraceLoggingUInt64(iTarget, "Target"),
                                  TraceLoggingInt32(pTarget->GetBlockSizeInBytes(), "Block Size"),
                                  TraceLoggingInt64(li.QuadPart, "Offset"));
    }

    if (p->pTimeSpan->GetMeasureLatency())
    {
        pIORequest->SetStartTime(PerfTimer::GetTime());
    }
    
    if (readOrWrite == IOOperation::ReadIO)
    {
        if (pTarget->GetMemoryMappedIoMode() == MemoryMappedIoMode::On)
        {
            if (pTarget->GetWriteThroughMode() == WriteThroughMode::On )
            {
                g_pfnRtlCopyMemoryNonTemporal(p->GetReadBuffer(iTarget, iRequest), pTarget->GetMappedView() + li.QuadPart, pTarget->GetBlockSizeInBytes());
            }
            else
            {
                memcpy(p->GetReadBuffer(iTarget, iRequest), pTarget->GetMappedView() + li.QuadPart, pTarget->GetBlockSizeInBytes());
            }
            *pdwBytesTransferred = pTarget->GetBlockSizeInBytes();
        }
        else
        {
            if (useCompletionRoutines)
            {
                rslt = ReadFileEx(p->vhTargets[iTarget], p->GetReadBuffer(iTarget, iRequest), pTarget->GetBlockSizeInBytes(), pOverlapped, fileIOCompletionRoutine);
            }
            else
            {
                rslt = ReadFile(p->vhTargets[iTarget], p->GetReadBuffer(iTarget, iRequest), pTarget->GetBlockSizeInBytes(), pdwBytesTransferred, pOverlapped);
            }
        }
    }
    else
    {
        if (pTarget->GetMemoryMappedIoMode() == MemoryMappedIoMode::On)
        {
            if (pTarget->GetWriteThroughMode() == WriteThroughMode::On)
            {
                g_pfnRtlCopyMemoryNonTemporal(pTarget->GetMappedView() + li.QuadPart, p->GetWriteBuffer(iTarget, iRequest), pTarget->GetBlockSizeInBytes());
            }
            else
            {
                memcpy(pTarget->GetMappedView() + li.QuadPart, p->GetWriteBuffer(iTarget, iRequest), pTarget->GetBlockSizeInBytes());

                switch (pTarget->GetMemoryMappedIoFlushMode())
                {
                    case MemoryMappedIoFlushMode::ViewOfFile:
                        FlushViewOfFile(pTarget->GetMappedView() + li.QuadPart, pTarget->GetBlockSizeInBytes());
                        break;
                    case MemoryMappedIoFlushMode::NonVolatileMemory:
                        g_pfnRtlFlushNonVolatileMemory(pTarget->GetMemoryMappedIoNvToken(), pTarget->GetMappedView() + li.QuadPart, pTarget->GetBlockSizeInBytes(), 0);
                        break;
                    case MemoryMappedIoFlushMode::NonVolatileMemoryNoDrain:
                        g_pfnRtlFlushNonVolatileMemory(pTarget->GetMemoryMappedIoNvToken(), pTarget->GetMappedView() + li.QuadPart, pTarget->GetBlockSizeInBytes(), FLUSH_NV_MEMORY_IN_FLAG_NO_DRAIN);
                        break;
                }
            }
            *pdwBytesTransferred = pTarget->GetBlockSizeInBytes();
        }
        else
        {
            if (useCompletionRoutines)
            {
                rslt = WriteFileEx(p->vhTargets[iTarget], p->GetWriteBuffer(iTarget, iRequest), pTarget->GetBlockSizeInBytes(), pOverlapped, fileIOCompletionRoutine);
            }
            else
            {
                rslt = WriteFile(p->vhTargets[iTarget], p->GetWriteBuffer(iTarget, iRequest), pTarget->GetBlockSizeInBytes(), pdwBytesTransferred, pOverlapped);
            }
        }
    }

    if (p->vThroughputMeters.size() != 0 && p->vThroughputMeters[iTarget].IsRunning())
    {
        p->vThroughputMeters[iTarget].Adjust(pTarget->GetBlockSizeInBytes());
    }

    return (rslt) ? true : false;
}

static void completeIO(ThreadParameters *p, IORequest *pIORequest, DWORD dwBytesTransferred)
{
    Target *pTarget = pIORequest->GetCurrentTarget();
    size_t iTarget = pTarget - &p->vTargets[0];

    if (TraceLoggingProviderEnabled(g_hEtwProvider,
                                    TRACE_LEVEL_VERBOSE,
                                    DISKSPD_TRACE_IO))
    {
        GUID ActivityId = pIORequest->GetActivityId();

        TraceLoggingWriteActivity(g_hEtwProvider,
                                  "DiskSpd IO",
                                  &ActivityId,
                                  NULL,
                                  TraceLoggingKeyword(DISKSPD_TRACE_IO),
                                  TraceLoggingOpcode(EVENT_TRACE_TYPE_STOP),
                                  TraceLoggingLevel(TRACE_LEVEL_VERBOSE));
    }

    //check if I/O transferred all of the requested bytes
    if (dwBytesTransferred != pTarget->GetBlockSizeInBytes())
    {
        PrintError("Warning: thread %u transferred %u bytes instead of %u bytes\n",
            p->ulThreadNo,
            dwBytesTransferred,
            pTarget->GetBlockSizeInBytes());
    }

    if (*p->pfAccountingOn)
    {
        p->pResults->vTargetResults[iTarget].Add(dwBytesTransferred,
            pIORequest->GetIoType(),
            pIORequest->GetStartTime(),
            *(p->pullStartTime),
            p->pTimeSpan->GetMeasureLatency(),
            p->pTimeSpan->GetCalculateIopsStdDev());
    }

    // check if we should print a progress dot
    if (p->pProfile->GetProgress() != 0)
    {
        DWORD dwIOCnt = ++p->dwIOCnt;
        if (dwIOCnt % p->pProfile->GetProgress() == 0)
        {
            print(".");
        }
    }
}

/*****************************************************************************/
// function called from worker thread
// performs synch I/O
//
static bool doWorkUsingSynchronousIO(ThreadParameters *p)
{
    bool fOk = true;
    BOOL rslt = FALSE;
    DWORD dwBytesTransferred;
    size_t cIORequests = p->vIORequest.size();

    while(g_bRun && !g_bThreadError)
    {
        DWORD dwMinSleepTime = ~((DWORD)0);
        for (size_t i = 0; i < cIORequests; i++)
        {
            IORequest *pIORequest = &p->vIORequest[i];
            Target *pTarget = pIORequest->GetNextTarget();

            if (p->vThroughputMeters.size() != 0)
            {
                size_t iTarget = pTarget - &p->vTargets[0];
                ThroughputMeter *pThroughputMeter = &p->vThroughputMeters[iTarget];

                DWORD dwSleepTime = pThroughputMeter->GetSleepTime();
                dwMinSleepTime = min(dwMinSleepTime, dwSleepTime);
                if (pThroughputMeter->IsRunning() && dwSleepTime > 0)
                {
                    continue;
                }
            }

            rslt = issueNextIO(p, pIORequest, &dwBytesTransferred, false);

            if (!rslt)
            {
                PrintError("t[%u] error during %s error code: %u)\n", (UINT32)i, (pIORequest->GetIoType() == IOOperation::ReadIO ? "read" : "write"), GetLastError());
                fOk = false;
                goto cleanup;
            }

            completeIO(p, pIORequest, dwBytesTransferred);
        }

        // if no IOs were issued, wait for the next scheduling time
        if (dwMinSleepTime != ~((DWORD)0) && dwMinSleepTime != 0)
        {
            Sleep(dwMinSleepTime);
        }

        assert(!g_bError);  // at this point we shouldn't be seeing initialization error
    }

cleanup:
    return fOk;
}

/*****************************************************************************/
// function called from worker thread
// performs asynch I/O using IO Completion Ports
//
static bool doWorkUsingIOCompletionPorts(ThreadParameters *p, HANDLE hCompletionPort)
{
    assert(nullptr!= p);
    assert(nullptr != hCompletionPort);

    bool fOk = true;
    BOOL rslt = FALSE;
    OVERLAPPED * pCompletedOvrp;
    ULONG_PTR ulCompletionKey;
    DWORD dwBytesTransferred;
    OverlappedQueue overlappedQueue;
    size_t cIORequests = p->vIORequest.size();

    //start IO operations
    for (size_t i = 0; i < cIORequests; i++)
    {
        overlappedQueue.Add(p->vIORequest[i].GetOverlapped());
    }

    //
    // perform work
    //
    while(g_bRun && !g_bThreadError)
    {
        DWORD dwMinSleepTime = ~((DWORD)0);
        for (size_t i = 0; i < overlappedQueue.GetCount(); i++)
        {
            OVERLAPPED *pReadyOverlapped = overlappedQueue.Remove();
            IORequest *pIORequest = IORequest::OverlappedToIORequest(pReadyOverlapped);
            Target *pTarget = pIORequest->GetNextTarget();

            if (p->vThroughputMeters.size() != 0)
            {
                size_t iTarget = pTarget - &p->vTargets[0];
                ThroughputMeter *pThroughputMeter = &p->vThroughputMeters[iTarget];

                DWORD dwSleepTime = pThroughputMeter->GetSleepTime();
                if (pThroughputMeter->IsRunning() && dwSleepTime > 0)
                {
                    dwMinSleepTime = min(dwMinSleepTime, dwSleepTime);
                    overlappedQueue.Add(pReadyOverlapped);
                    continue;
                }
            }

            rslt = issueNextIO(p, pIORequest, &dwBytesTransferred, false);

            if (!rslt && GetLastError() != ERROR_IO_PENDING)
            {
                UINT32 iIORequest = (UINT32)(pIORequest - &p->vIORequest[0]);
                PrintError("t[%u] error during %s error code: %u)\n", iIORequest, (pIORequest->GetIoType()== IOOperation::ReadIO ? "read" : "write"), GetLastError());
                fOk = false;
                goto cleanup;
            }

            if (rslt && pTarget->GetMemoryMappedIoMode() == MemoryMappedIoMode::On)
            {
                completeIO(p, pIORequest, dwBytesTransferred);
                overlappedQueue.Add(pReadyOverlapped);
            }
        }

        // if no IOs are in flight, wait for the next scheduling time
        if ((overlappedQueue.GetCount() == p->vIORequest.size()) && dwMinSleepTime != ~((DWORD)0))
        {
            Sleep(dwMinSleepTime);
        }

        // wait till one of the IO operations finishes
        if (GetQueuedCompletionStatus(hCompletionPort, &dwBytesTransferred, &ulCompletionKey, &pCompletedOvrp, 1) != 0)
        {
            //find which I/O operation it was (so we know to which buffer should we use)
            IORequest *pIORequest = IORequest::OverlappedToIORequest(pCompletedOvrp);
            completeIO(p, pIORequest, dwBytesTransferred);
            overlappedQueue.Add(pCompletedOvrp);
        }
        else
        {
            DWORD err = GetLastError();
            if (err != WAIT_TIMEOUT)
            {
                PrintError("error during overlapped IO operation (error code: %u)\n", err);
                fOk = false;
                goto cleanup;
            }
        }
    } // end work loop

cleanup:
    return fOk;
}

/*****************************************************************************/
// I/O completion routine. used by ReadFileEx and WriteFileEx
//

VOID CALLBACK fileIOCompletionRoutine(DWORD dwErrorCode, DWORD dwBytesTransferred, LPOVERLAPPED pOverlapped)
{
    assert(NULL != pOverlapped);

    BOOL rslt = FALSE;

    ThreadParameters *p = (ThreadParameters *)pOverlapped->hEvent;

    assert(NULL != p);

    //check error code
    if (0 != dwErrorCode)
    {
        PrintError("Thread %u failed executing an I/O operation (error code: %u)\n", p->ulThreadNo, dwErrorCode);
        goto cleanup;
    }

    IORequest *pIORequest = IORequest::OverlappedToIORequest(pOverlapped);

    completeIO(p, pIORequest, dwBytesTransferred);

    // start a new IO operation
    if (g_bRun && !g_bThreadError)
    {
        Target *pTarget = pIORequest->GetNextTarget();
        size_t iTarget = pTarget - &p->vTargets[0];

        rslt = issueNextIO(p, pIORequest, NULL, true);

        if (!rslt)
        {
            PrintError("t[%u:%u] error during %s error code: %u)\n", p->ulThreadNo, iTarget, (pIORequest->GetIoType() == IOOperation::ReadIO ? "read" : "write"), GetLastError());
            goto cleanup;
        }
    }

cleanup:
    return;
}

/*****************************************************************************/
// function called from worker thread
// performs asynch I/O using IO Completion Routines (ReadFileEx, WriteFileEx)
//
static bool doWorkUsingCompletionRoutines(ThreadParameters *p)
{
    assert(NULL != p);
    bool fOk = true;
    BOOL rslt = FALSE;
    
    //start IO operations
    UINT32 cIORequests = (UINT32)p->vIORequest.size();

    for (size_t iIORequest = 0; iIORequest < cIORequests; iIORequest++) {
        IORequest *pIORequest = &p->vIORequest[iIORequest];
        Target *pTarget = pIORequest->GetNextTarget();
        size_t iTarget = pTarget - &p->vTargets[0];

        rslt = issueNextIO(p, pIORequest, NULL, true);

        if (!rslt)
        {
            PrintError("t[%u:%u] error during %s error code: %u)\n", p->ulThreadNo, iTarget, (pIORequest->GetIoType() == IOOperation::ReadIO ? "read" : "write"), GetLastError());
            fOk = false;
            goto cleanup;
        }
    }

    DWORD dwWaitResult = 0;
    while( g_bRun && !g_bThreadError )
    {
        dwWaitResult = WaitForSingleObjectEx(p->hEndEvent, INFINITE, TRUE);

        assert(WAIT_IO_COMPLETION == dwWaitResult || (WAIT_OBJECT_0 == dwWaitResult && (!g_bRun || g_bThreadError)));

        //check WaitForSingleObjectEx status
        if( WAIT_IO_COMPLETION != dwWaitResult && WAIT_OBJECT_0 != dwWaitResult )
        {
            PrintError("Error in thread %u during WaitForSingleObjectEx (in completion routines)\n", p->ulThreadNo);
            fOk = false;
            goto cleanup;
        }
    }
cleanup:
    return fOk;
}

struct UniqueTarget {
    string path;
    TargetCacheMode caching;
    PRIORITY_HINT priority;
    DWORD dwDesiredAccess;
    DWORD dwFlags;

    bool operator < (const struct UniqueTarget &ut) const {
        if (path < ut.path) {
            return true;
        }
        else if (ut.path < path) {
            return false;
        }

        if (caching < ut.caching) {
            return true;
        }
        else if (ut.caching < caching) {
            return false;
        }

        if (priority < ut.priority) {
            return true;
        }
        else if (ut.priority < priority) {
            return false;
        }

        if (dwDesiredAccess < ut.dwDesiredAccess) {
            return true;
        }
        else if (ut.dwDesiredAccess < dwDesiredAccess) {
            return false;
        }

        if (dwFlags < ut.dwFlags) {
            return true;
        }

        return false;
    }
};

/*****************************************************************************/
// worker thread function
//
DWORD WINAPI threadFunc(LPVOID cookie)
{
    bool fOk = true;
    bool fAnyMappedIo = false;
    bool fAllMappedIo = true;
    ThreadParameters *p = reinterpret_cast<ThreadParameters *>(cookie);
    HANDLE hCompletionPort = nullptr;

    //
    // A single file can be specified in multiple targets, so only open one
    // handle for each unique file.
    //
    
    vector<HANDLE> vhUniqueHandles;
    map< UniqueTarget, UINT32 > mHandleMap;

    bool fCalculateIopsStdDev = p->pTimeSpan->GetCalculateIopsStdDev();
    UINT64 ioBucketDuration = 0;
    UINT32 expectedNumberOfBuckets = 0;
    if(fCalculateIopsStdDev)
    {
        UINT32 ioBucketDurationInMilliseconds = p->pTimeSpan->GetIoBucketDurationInMilliseconds();
        ioBucketDuration = PerfTimer::MillisecondsToPerfTime(ioBucketDurationInMilliseconds);
        expectedNumberOfBuckets = Util::QuotientCeiling(p->pTimeSpan->GetDuration() * 1000, ioBucketDurationInMilliseconds);
    }

    // apply affinity. The specific assignment is provided in the thread profile up front.
    if (!p->pTimeSpan->GetDisableAffinity())
    {
        GROUP_AFFINITY GroupAffinity;

        printfv(p->pProfile->GetVerbose(), "affinitizing thread %u to Group %u / CPU %u\n", p->ulThreadNo, p->wGroupNum, p->bProcNum);
        SetProcGroupMask(p->wGroupNum, p->bProcNum, &GroupAffinity);

        HANDLE hThread = GetCurrentThread();
        if (SetThreadGroupAffinity(hThread, &GroupAffinity, nullptr) == FALSE)
        {
            PrintError("Error setting affinity mask in thread %u\n", p->ulThreadNo);
            fOk = false;
            goto cleanup;
        }
    }

    // adjust thread token if large pages are needed
    for (auto pTarget = p->vTargets.begin(); pTarget != p->vTargets.end(); pTarget++)
    {
        if (pTarget->GetUseLargePages())
        {
            if (!SetPrivilege(SE_LOCK_MEMORY_NAME))
            {
                fOk = false;
                goto cleanup;
            }
            break;
        }
    }

    UINT32 cIORequests = p->GetTotalRequestCount();

    // TODO: open files
    size_t iTarget = 0;
    for (auto pTarget = p->vTargets.begin(); pTarget != p->vTargets.end(); pTarget++)
    {
        bool fPhysical = false;
        bool fPartition = false;

        string sPath(pTarget->GetPath());
        const char *filename = sPath.c_str();

        const char *fname = nullptr;    //filename (can point to physFN)
        char physFN[32];                //disk/partition name

        if (NULL == filename || NULL == *(filename))
        {
            PrintError("FATAL ERROR: invalid filename\n");
            fOk = false;
            goto cleanup;
        }

        //check if it is a physical drive
        if ('#' == *filename && NULL != *(filename + 1))
        {
            if (pTarget->GetMemoryMappedIoMode() == MemoryMappedIoMode::On)
            {
                PrintError("Memory mapped I/O is not supported on physical drives\n");
                fOk = false;
                goto cleanup;
            }
            UINT32 nDriveNo = (UINT32)atoi(filename + 1);
            fPhysical = true;
            sprintf_s(physFN, 32, "\\\\.\\PhysicalDrive%u", nDriveNo);
            fname = physFN;
        }

        //check if it is a partition
        if (!fPhysical && NULL != *(filename + 1) && NULL == *(filename + 2) && isalpha((unsigned char)filename[0]) && ':' == filename[1])
        {
            if (pTarget->GetMemoryMappedIoMode() == MemoryMappedIoMode::On)
            {
                PrintError("Memory mapped I/O is not supported on partitions\n");
                fOk = false;
                goto cleanup;
            }
            fPartition = true;

            sprintf_s(physFN, 32, "\\\\.\\%c:", filename[0]);
            fname = physFN;
        }

        //check if it is a regular file
        if (!fPhysical && !fPartition)
        {
            fname = sPath.c_str();
        }

        // get/set file flags
        DWORD dwFlags = pTarget->GetCreateFlags(cIORequests > 1);
        DWORD dwDesiredAccess = 0;
        if (pTarget->GetWriteRatio() == 0)
        {
            dwDesiredAccess = GENERIC_READ;
        }
        else if (pTarget->GetWriteRatio() == 100)
        {
            dwDesiredAccess = GENERIC_WRITE;
        }
        else
        {
            dwDesiredAccess = GENERIC_READ | GENERIC_WRITE;
        }

        if (pTarget->GetMemoryMappedIoMode() == MemoryMappedIoMode::On)
        {
            dwDesiredAccess = GENERIC_READ | GENERIC_WRITE;
            fAnyMappedIo = true;
        }
        else
        {
            fAllMappedIo = false;
        }

        HANDLE hFile;
        UniqueTarget ut;
        ut.path = sPath;
        ut.priority = pTarget->GetIOPriorityHint();
        ut.caching = pTarget->GetCacheMode();
        ut.dwDesiredAccess = dwDesiredAccess;
        ut.dwFlags = dwFlags;

        if (mHandleMap.find(ut) == mHandleMap.end()) {
            hFile = CreateFile(fname,
                dwDesiredAccess,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr,        //security
                OPEN_EXISTING,
                dwFlags,        //flags
                nullptr);       //template file
            if (INVALID_HANDLE_VALUE == hFile)
            {
                // TODO: error out
                PrintError("Error opening file: %s [%u]\n", sPath.c_str(), GetLastError());
                fOk = false;
                goto cleanup;
            }

            if (pTarget->GetCacheMode() == TargetCacheMode::DisableLocalCache)
            {
                DWORD Status = DisableLocalCache(hFile);
                if (Status != ERROR_SUCCESS)
                {
                    PrintError("Failed to disable local caching (error %u). NOTE: only supported on remote filesystems with Windows 8 or newer.\n", Status);
                    fOk = false;
                    goto cleanup;
                }
            }

            //set IO priority
            if (pTarget->GetIOPriorityHint() != IoPriorityHintNormal)
            {
                _declspec(align(8)) FILE_IO_PRIORITY_HINT_INFO hintInfo;
                hintInfo.PriorityHint = pTarget->GetIOPriorityHint();
                if (!SetFileInformationByHandle(hFile, FileIoPriorityHintInfo, &hintInfo, sizeof(hintInfo)))
                {
                    PrintError("Error setting IO priority for file: %s [%u]\n", sPath.c_str(), GetLastError());
                    fOk = false;
                    goto cleanup;
                }
            }
            
            mHandleMap[ut] = (UINT32)vhUniqueHandles.size();
            vhUniqueHandles.push_back(hFile);
        }
        else {
            hFile = vhUniqueHandles[mHandleMap[ut]];
        }

        p->vhTargets.push_back(hFile);

        // obtain file/disk/partition size
        {
            UINT64 fsize = 0;   //file size

            //check if it is a disk
            if (fPhysical)
            {
                fsize = GetPhysicalDriveSize(hFile);
            }
            // check if it is a partition
            else if (fPartition)
            {
                fsize = GetPartitionSize(hFile);
            }
            // it has to be a regular file
            else
            {
                ULARGE_INTEGER ulsize;

                ulsize.LowPart = GetFileSize(hFile, &ulsize.HighPart);
                if (INVALID_FILE_SIZE == ulsize.LowPart && GetLastError() != NO_ERROR)
                {
                    PrintError("Error getting file size\n");
                    fOk = false;
                    goto cleanup;
                }
                else
                {
                    fsize = ulsize.QuadPart;
                }
            }

            // check if file size is valid (if it's == 0, it won't be useful)
            if (0 == fsize)
            {
                // TODO: error out
                PrintError("The file is too small or there has been an error during getting file size\n");
                fOk = false;
                goto cleanup;
            }

            if (fsize < pTarget->GetMaxFileSize())
            {
                PrintError("Warning - file size is less than MaxFileSize\n");
            }

            if (pTarget->GetMaxFileSize() > 0)
            {
                // user wants to use only a part of the target
                // if smaller, of course use the entire content
                p->vullFileSizes.push_back(pTarget->GetMaxFileSize() > fsize ? fsize : pTarget->GetMaxFileSize());
            }
            else
            {
                // the whole file will be used
                p->vullFileSizes.push_back(fsize);
            }

            UINT64 startingFileOffset = pTarget->GetThreadBaseFileOffsetInBytes(p->ulRelativeThreadNo);

            // test whether the file is large enough for this thread to do work
            if (startingFileOffset + pTarget->GetBlockSizeInBytes() >= p->vullFileSizes[iTarget])
            {
                PrintError("The file is too small. File: '%s' relative thread %u size: %I64u, base offset: %I64u block size: %u\n",
                    pTarget->GetPath().c_str(),
                    p->ulRelativeThreadNo,
                    fsize,
                    pTarget->GetBaseFileOffsetInBytes(),
                    pTarget->GetBlockSizeInBytes());
                fOk = false;
                goto cleanup;
            }

            if (pTarget->GetUseRandomAccessPattern())
            {
                printfv(p->pProfile->GetVerbose(), "thread %u starting: file '%s' relative thread %u random pattern\n",
                    p->ulThreadNo,
                    pTarget->GetPath().c_str(),
                    p->ulRelativeThreadNo);
            }
            else
            {
                printfv(p->pProfile->GetVerbose(), "thread %u starting: file '%s' relative thread %u file offset: %I64u (starting in block: %I64u)\n",
                    p->ulThreadNo,
                    pTarget->GetPath().c_str(),
                    p->ulRelativeThreadNo,
                    startingFileOffset,
                    startingFileOffset / pTarget->GetBlockSizeInBytes());
            }
        }

        // allocate memory for a data buffer
        if (!p->AllocateAndFillBufferForTarget(*pTarget))
        {
            PrintError("ERROR: Could not allocate a buffer for target '%s'. Error code: 0x%x\n", pTarget->GetPath().c_str(), GetLastError());
            fOk = false;
            goto cleanup;
        }

        // initialize memory mapped views of files
        if (pTarget->GetMemoryMappedIoMode() == MemoryMappedIoMode::On)
        {
            NTSTATUS status;
            PVOID nvToken;

            pTarget->SetMappedViewFileHandle(hFile);
            if (!p->InitializeMappedViewForTarget(*pTarget, dwDesiredAccess))
            {
                PrintError("ERROR: Could not map view for target '%s'. Error code: 0x%x\n", pTarget->GetPath().c_str(), GetLastError());
                fOk = false;
                goto cleanup;
            }

            if (pTarget->GetWriteThroughMode() == WriteThroughMode::On && nullptr == g_pfnRtlCopyMemoryNonTemporal)
            {
                PrintError("ERROR: Windows runtime environment does not support the non-temporal memory copy API for target '%s'.\n", pTarget->GetPath().c_str());
                fOk = false;
                goto cleanup;
            }

            if ((pTarget->GetMemoryMappedIoFlushMode() == MemoryMappedIoFlushMode::NonVolatileMemory) || (pTarget->GetMemoryMappedIoFlushMode() == MemoryMappedIoFlushMode::NonVolatileMemoryNoDrain))
            {
                // RtlGetNonVolatileToken() works only on DAX enabled PMEM devices.
                if (g_pfnRtlGetNonVolatileToken != nullptr && g_pfnRtlFreeNonVolatileToken != nullptr)
                {
                    status = g_pfnRtlGetNonVolatileToken(pTarget->GetMappedView(), (SIZE_T) pTarget->GetFileSize(), &nvToken);
                    if (!NT_SUCCESS(status))
                    {
                        PrintError("ERROR: Could not get non-volatile token for target '%s'. Error code: 0x%x\n", pTarget->GetPath().c_str(), GetLastError());
                        fOk = false;
                        goto cleanup;
                    }
                    pTarget->SetMemoryMappedIoNvToken(nvToken);
                }
                else
                {
                    PrintError("ERROR: Windows runtime environment does not support the non-volatile memory flushing APIs for target '%s'.\n", pTarget->GetPath().c_str());
                    fOk = false;
                    goto cleanup;
                }
            }
        }

        iTarget++;
    }
 
    // TODO: copy parameters for better memory locality?    
    // TODO: tell the main thread we're ready
    // TODO: wait for a signal to start

    printfv(p->pProfile->GetVerbose(), "thread %u started (random seed: %u)\n", p->ulThreadNo, p->ulRandSeed);
    
    p->vullPrivateSequentialOffsets.clear();
    p->vullPrivateSequentialOffsets.resize(p->vTargets.size());
    p->pResults->vTargetResults.clear();
    p->pResults->vTargetResults.resize(p->vTargets.size());
    for (size_t i = 0; i < p->vullFileSizes.size(); i++)
    {
        p->pResults->vTargetResults[i].sPath = p->vTargets[i].GetPath();
        p->pResults->vTargetResults[i].ullFileSize = p->vullFileSizes[i];
        if(fCalculateIopsStdDev) 
        {
            p->pResults->vTargetResults[i].readBucketizer.Initialize(ioBucketDuration, expectedNumberOfBuckets);
            p->pResults->vTargetResults[i].writeBucketizer.Initialize(ioBucketDuration, expectedNumberOfBuckets);
        }
    }

    //
    // fill the IORequest structures
    //
    
    p->vIORequest.clear();
    
    if (p->pTimeSpan->GetThreadCount() != 0 &&
        p->pTimeSpan->GetRequestCount() != 0)
    {
        p->vIORequest.resize(cIORequests, IORequest(p->pRand));

        for (UINT32 iIORequest = 0; iIORequest < cIORequests; iIORequest++)
        {
            p->vIORequest[iIORequest].SetRequestIndex(iIORequest);

            for (unsigned int iFile = 0; iFile < p->vTargets.size(); iFile++)
            {
                Target *pTarget = &p->vTargets[iFile];
                const vector<ThreadTarget> vThreadTargets = pTarget->GetThreadTargets();
                UINT32 ulWeight = pTarget->GetWeight();

                for (UINT32 iThreadTarget = 0; iThreadTarget < vThreadTargets.size(); iThreadTarget++)
                {
                    if (vThreadTargets[iThreadTarget].GetThread() == p->ulRelativeThreadNo)
                    {
                        if (vThreadTargets[iThreadTarget].GetWeight() != 0)
                        {
                            ulWeight = vThreadTargets[iThreadTarget].GetWeight();
                        }
                        break;
                    }
                }

                p->vIORequest[iIORequest].AddTarget(pTarget, ulWeight);
            }
        }
    }
    else
    {
        for (unsigned int iFile = 0; iFile < p->vTargets.size(); iFile++)
        {
            Target *pTarget = &p->vTargets[iFile];
    
            for (DWORD iRequest = 0; iRequest < pTarget->GetRequestCount(); ++iRequest)
            {
                IORequest ioRequest(p->pRand);
                ioRequest.AddTarget(pTarget, 1);
                ioRequest.SetRequestIndex(iRequest);
                p->vIORequest.push_back(ioRequest);
            }
        }
    }

    //
    // fill the throughput meter structures
    //
    size_t cTargets = p->vTargets.size();
    bool fUseThrougputMeter = false;
    for (size_t i = 0; i < cTargets; i++)
    {
        ThroughputMeter throughputMeter;
        Target *pTarget = &p->vTargets[i];
        DWORD dwBurstSize = pTarget->GetBurstSize();
        if (p->pTimeSpan->GetThreadCount() > 0)
        {
            if (pTarget->GetThreadTargets().size() == 0)
            {
                dwBurstSize /= p->pTimeSpan->GetThreadCount();
            }
            else
            {
                dwBurstSize /= (DWORD)pTarget->GetThreadTargets().size();
            }
        }
        else
        {
            dwBurstSize /= pTarget->GetThreadsPerFile();
        }

        if (pTarget->GetThroughputInBytesPerMillisecond() > 0 || pTarget->GetThinkTime() > 0)
        {
            fUseThrougputMeter = true;
            throughputMeter.Start(pTarget->GetThroughputInBytesPerMillisecond(), pTarget->GetBlockSizeInBytes(), pTarget->GetThinkTime(), dwBurstSize);
        }

        p->vThroughputMeters.push_back(throughputMeter);
    }

    if (!fUseThrougputMeter)
    {
        p->vThroughputMeters.clear();
    }
    
    //FUTURE EXTENSION: enable asynchronous I/O even if only 1 outstanding I/O per file (requires another parameter)
    if (cIORequests == 1 || fAllMappedIo)
    {
        //synchronous IO - no setup needed
    }
    else if (p->pTimeSpan->GetCompletionRoutines() && !fAnyMappedIo)
    {
        //in case of completion routines hEvent field is not used,
        //so we can use it to pass a pointer to the thread parameters
        for (UINT32 iIORequest = 0; iIORequest < cIORequests; iIORequest++) {
            OVERLAPPED *pOverlapped;

            pOverlapped = p->vIORequest[iIORequest].GetOverlapped();
            pOverlapped->hEvent = (HANDLE)p;
        }
    }
    else
    {
        //
        // create IO completion port if not doing completion routines or synchronous IO
        //
        for (unsigned int i = 0; i < vhUniqueHandles.size(); i++)
        {
            hCompletionPort = CreateIoCompletionPort(vhUniqueHandles[i], hCompletionPort, 0, 1);
            if (nullptr == hCompletionPort)
            {
                PrintError("unable to create IO completion port (error code: %u)\n", GetLastError());
                fOk = false;
                goto cleanup;
            }
        }
    }

    //
    // wait for a signal to start
    //
    printfv(p->pProfile->GetVerbose(), "thread %u: waiting for a signal to start\n", p->ulThreadNo);
    if( WAIT_FAILED == WaitForSingleObject(p->hStartEvent, INFINITE) )
    {
        PrintError("Waiting for a signal to start failed (error code: %u)\n", GetLastError());
        fOk = false;
        goto cleanup;
    }
    printfv(p->pProfile->GetVerbose(), "thread %u: received signal to start\n", p->ulThreadNo);

    //check if everything is ok
    if (g_bError)
    {
        fOk = false;
        goto cleanup;
    }

    //error handling and memory freeing is done in doWorkUsingIOCompletionPorts and doWorkUsingCompletionRoutines
    if (cIORequests == 1 || fAllMappedIo)
    {
        // use synchronous IO (it will also clse the event)
        if (!doWorkUsingSynchronousIO(p))
        {
            fOk = false;
            goto cleanup;
        }
    }
    else if (!p->pTimeSpan->GetCompletionRoutines() || fAnyMappedIo)
    {
        // use IO Completion Ports (it will also close the I/O completion port)
        if (!doWorkUsingIOCompletionPorts(p, hCompletionPort))
        {
            fOk = false;
            goto cleanup;
        }
    }
    else
    {
        //use completion routines
        if (!doWorkUsingCompletionRoutines(p))
        {
            fOk = false;
            goto cleanup;
        }
    }

    assert(!g_bError);  // at this point we shouldn't be seeing initialization error

    // save results

cleanup:
    if (!fOk)
    {
        g_bThreadError = TRUE;
    }

    // free memory allocated with VirtualAlloc
    for (auto i = p->vpDataBuffers.begin(); i != p->vpDataBuffers.end(); i++)
    {
        if (nullptr != *i)
        {
#pragma prefast(suppress:6001, "Prefast does not understand this vector will only contain validly allocated buffer pointers")
            VirtualFree(*i, 0, MEM_RELEASE);
        }
    }

    // free NV tokens
    for (auto i = p->vTargets.begin(); i != p->vTargets.end(); i++)
    {
        if (i->GetMemoryMappedIoNvToken() != nullptr && g_pfnRtlFreeNonVolatileToken != nullptr)
        {
            g_pfnRtlFreeNonVolatileToken(i->GetMemoryMappedIoNvToken());
            i->SetMemoryMappedIoNvToken(nullptr);
        }
    }

    // close files
    for (auto i = vhUniqueHandles.begin(); i != vhUniqueHandles.end(); i++)
    {
        CloseHandle(*i);
    }

    // close completion ports
    if (hCompletionPort != nullptr)
    {
        CloseHandle(hCompletionPort);
    }

    delete p->pRand;
    delete p;

    // notify master thread that we've finished
    InterlockedDecrement(&g_lRunningThreadsCount);

    return fOk ? 1 : 0;
}

/*****************************************************************************/
struct ETWSessionInfo IORequestGenerator::_GetResultETWSession(const EVENT_TRACE_PROPERTIES *pTraceProperties) const
{
    struct ETWSessionInfo session = {};
    if (nullptr != pTraceProperties)
    {
        session.lAgeLimit = pTraceProperties->AgeLimit;
        session.ulBufferSize = pTraceProperties->BufferSize;
        session.ulBuffersWritten = pTraceProperties->BuffersWritten;
        session.ulEventsLost = pTraceProperties->EventsLost;
        session.ulFlushTimer = pTraceProperties->FlushTimer;
        session.ulFreeBuffers = pTraceProperties->FreeBuffers;
        session.ulLogBuffersLost = pTraceProperties->LogBuffersLost;
        session.ulMaximumBuffers = pTraceProperties->MaximumBuffers;
        session.ulMinimumBuffers = pTraceProperties->MinimumBuffers;
        session.ulNumberOfBuffers = pTraceProperties->NumberOfBuffers;
        session.ulRealTimeBuffersLost = pTraceProperties->RealTimeBuffersLost;
    }
    return session;
}

DWORD IORequestGenerator::_CreateDirectoryPath(const char *pszPath) const
{
    char *c = nullptr;          //variable used to browse the path
    char dirPath[MAX_PATH];  //copy of the path (it will be altered)

    //only support absolute paths that specify the drive letter
    if (pszPath[0] == '\0' || pszPath[1] != ':')
    {
        return ERROR_NOT_SUPPORTED;
    }
    
    if (strcpy_s(dirPath, _countof(dirPath), pszPath) != 0)
    {
        return ERROR_BUFFER_OVERFLOW;
    }
    
    c = dirPath;
    while('\0' != *c)
    {
        if ('\\' == *c)
        {
            //skip the first one as it will be the drive name
            if (c-dirPath >= 3)
            {
                *c = '\0';
                //create directory if it doesn't exist
                if (GetFileAttributes(dirPath) == INVALID_FILE_ATTRIBUTES)
                {
                    if (CreateDirectory(dirPath, NULL) == FALSE)
                    {
                        return GetLastError();
                    }
                }
                *c = L'\\';
            }
        }
        
        c++;
    }

    return ERROR_SUCCESS;
}

/*****************************************************************************/
// create a file of the given size
//
bool IORequestGenerator::_CreateFile(UINT64 ullFileSize, const char *pszFilename, bool fZeroBuffers, bool fVerbose) const
{
    bool fSlowWrites = false;
    printfv(fVerbose, "Creating file '%s' of size %I64u.\n", pszFilename, ullFileSize);

    //enable SE_MANAGE_VOLUME_NAME privilege, required to set valid size of a file
    if (!SetPrivilege(SE_MANAGE_VOLUME_NAME, "WARNING:"))
    {
        PrintError("WARNING: Could not set privileges for setting valid file size; will use a slower method of preparing the file\n", GetLastError());
        fSlowWrites = true;
    }

    // there are various forms of paths we do not support creating subdir hierarchies
    // for - relative and unc paths specifically. this is fine, and not neccesary to
    // warn about. we can add support in the future.
    DWORD dwError = _CreateDirectoryPath(pszFilename);
    if (dwError != ERROR_SUCCESS && dwError != ERROR_NOT_SUPPORTED)
    {
        PrintError("WARNING: Could not create intermediate directory (error code: %u)\n", dwError);
    }

    // create handle to the file
    HANDLE hFile = CreateFile(pszFilename,
                              GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr,
                              CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL,
                              nullptr);
    if (INVALID_HANDLE_VALUE == hFile)
    {
        PrintError("Could not create the file (error code: %u)\n", GetLastError());
        return false;
    }

    if (ullFileSize > 0)
    {
        LARGE_INTEGER li;
        li.QuadPart = ullFileSize;

        LARGE_INTEGER liNewFilePointer;

        if (!SetFilePointerEx(hFile, li, &liNewFilePointer, FILE_BEGIN))
        {
            PrintError("Could not set file pointer during file creation when extending file (error code: %u)\n", GetLastError());
            CloseHandle(hFile);
            return false;
        }
        if (liNewFilePointer.QuadPart != li.QuadPart)
        {
            PrintError("File pointer improperly moved during file creation when extending file\n");
            CloseHandle(hFile);
            return false;
        }

        //extends file (warning! this is a kind of "reservation" of space; valid size of the file is still 0!)
        if (!SetEndOfFile(hFile))
        {
            PrintError("Error setting end of file (error code: %u)\n", GetLastError());
            CloseHandle(hFile);
            return false;
        }
        //try setting valid size of the file (privileges for that are enabled before CreateFile)
        if (!fSlowWrites && !SetFileValidData(hFile, ullFileSize))
        {
            PrintError("WARNING: Could not set valid file size (error code: %u); trying a slower method of filling the file"
                       " (this does not affect performance, just makes the test preparation longer)\n",
                       GetLastError());
            fSlowWrites = true;
        }

        //if setting valid size couldn't be performed, fill in the file by simply writing to it (slower)
        if (fSlowWrites)
        {
            li.QuadPart = 0;
            if (!SetFilePointerEx(hFile, li, &liNewFilePointer, FILE_BEGIN))
            {
                PrintError("Could not set file pointer during file creation (error code: %u)\n", GetLastError());
                CloseHandle(hFile);
                return false;
            }
            if (liNewFilePointer.QuadPart != li.QuadPart)
            {
                PrintError("File pointer improperly moved during file creation\n");
                CloseHandle(hFile);
                return false;
            }

            UINT32 ulBufSize;
            UINT64 ullRemainSize;

            ulBufSize = 1024*1024;
            if (ullFileSize < (UINT64)ulBufSize)
            {
                ulBufSize = (UINT32)ullFileSize;
            }

            vector<BYTE> vBuf(ulBufSize);
            for (UINT32 i=0; i<ulBufSize; ++i)
            {
                vBuf[i] = fZeroBuffers ? 0 : (BYTE)(i&0xFF);
            }

            ullRemainSize = ullFileSize;
            while (ullRemainSize > 0)
            {
                DWORD dwBytesWritten;
                if ((UINT64)ulBufSize > ullRemainSize)
                {
                    ulBufSize = (UINT32)ullRemainSize;
                }

                if (!WriteFile(hFile, &vBuf[0], ulBufSize, &dwBytesWritten, NULL))
                {
                    PrintError("Error while writng during file creation (error code: %u)\n", GetLastError());
                    CloseHandle(hFile);
                    return false;
                }

                if (dwBytesWritten != ulBufSize)
                {
                    PrintError("Improperly written data during file creation\n");
                    CloseHandle(hFile);
                    return false;
                }

                ullRemainSize -= ulBufSize;
            }
        }
    }

    //if compiled with debug support, check file size
#ifndef NDEBUG
    LARGE_INTEGER li;
    if( GetFileSizeEx(hFile, &li) )
    {
        assert(li.QuadPart == (LONGLONG)ullFileSize);
    }
#endif

    CloseHandle(hFile);

    return true;
}

/*****************************************************************************/
void IORequestGenerator::_TerminateWorkerThreads(vector<HANDLE>& vhThreads) const
{
    for (UINT32 x = 0; x < vhThreads.size(); ++x)
    {
        assert(NULL != vhThreads[x]);
#pragma warning( push )
#pragma warning( disable : 6258 )
        if (!TerminateThread(vhThreads[x], 0))
        {
            PrintError("Warning: unable to terminate worker thread %u\n", x);
        }
#pragma warning( pop )
    }
}
/*****************************************************************************/
void IORequestGenerator::_AbortWorkerThreads(HANDLE hStartEvent, vector<HANDLE>& vhThreads) const
{
    assert(NULL != hStartEvent);

    if (NULL == hStartEvent)
    {
        return;
    }

    g_bError = TRUE;
    if (!SetEvent(hStartEvent))
    {
        PrintError("Error signaling start event\n");
        _TerminateWorkerThreads(vhThreads);
    }
    else
    {
        //FUTURE EXTENSION: maximal timeout may be added here (and below)
        while (g_lRunningThreadsCount > 0)
        {
            Sleep(100);
        }
    }
}

/*****************************************************************************/
bool IORequestGenerator::_StopETW(bool fUseETW, TRACEHANDLE hTraceSession) const
{
    bool fOk = true;
    if (fUseETW)
    {
        PEVENT_TRACE_PROPERTIES pETWSession = StopETWSession(hTraceSession);
        if (nullptr == pETWSession)
        {
            PrintError("Error stopping ETW session\n");
            fOk = false;
        }
        else
        {
            free(pETWSession);
        }
    }
    return fOk;
}

/*****************************************************************************/
// initializes all global parameters
//
void IORequestGenerator::_InitializeGlobalParameters()
{
    g_lRunningThreadsCount = 0;     //number of currently running worker threads
    g_bRun = TRUE;                  //used for letting threads know that they should stop working

    g_bThreadError = FALSE;         //true means that an error has occured in one of the threads
    g_bTracing = FALSE;             //true means that ETW is turned on

    _hNTDLL = nullptr;              //handle to ntdll.dll
    g_bError = FALSE;               //true means there was fatal error during intialization and threads shouldn't perform their work
}

bool IORequestGenerator::_PrecreateFiles(Profile& profile) const
{
    bool fOk = true;

    if (profile.GetPrecreateFiles() != PrecreateFiles::None)
    {
        vector<CreateFileParameters> vFilesToCreate = _GetFilesToPrecreate(profile);
        vector<string> vCreatedFiles;
        for (auto file : vFilesToCreate)
        {
            fOk = _CreateFile(file.ullFileSize, file.sPath.c_str(), file.fZeroWriteBuffers, profile.GetVerbose());
            if (!fOk)
            {
                break;
            }
            vCreatedFiles.push_back(file.sPath);
        }

        if (fOk)
        {
            profile.MarkFilesAsPrecreated(vCreatedFiles);
        }
    }

    return fOk;
}

bool IORequestGenerator::GenerateRequests(Profile& profile, IResultParser& resultParser, PRINTF pPrintOut, PRINTF pPrintError, PRINTF pPrintVerbose, struct Synchronization *pSynch)
{
    g_pfnPrintOut = pPrintOut;
    g_pfnPrintError = pPrintError;
    g_pfnPrintVerbose = pPrintVerbose;

    bool fOk = _PrecreateFiles(profile);
    if (fOk)
    {
        const vector<TimeSpan>& vTimeSpans = profile.GetTimeSpans();
        vector<Results> vResults(vTimeSpans.size());
        for (size_t i = 0; fOk && (i < vTimeSpans.size()); i++)
        {
            printfv(profile.GetVerbose(), "Generating requests for timespan %u.\n", i + 1);
            fOk = _GenerateRequestsForTimeSpan(profile, vTimeSpans[i], vResults[i], pSynch);
        }

        // TODO: show results only for timespans that succeeded
        //SystemInformation system;
        //EtwResultParser::ParseResults(vResults);
        //string sResults = resultParser.ParseResults(profile, system, vResults);
        //print("%s", sResults.c_str());
    }

    return fOk;
}

bool IORequestGenerator::_GenerateRequestsForTimeSpan(const Profile& profile, const TimeSpan& timeSpan, Results& results, struct Synchronization *pSynch)
{
	HANDLE hEtwThread, hDebug;
	memset(&g_EtwEventCounters, 0, sizeof(struct ETWEventCounters));  // reset all etw event counters
	bool fUseETW = profile.GetEtwEnabled();            //true if user wants ETW
	printfv(profile.GetVerbose(), "starting trace session\n");
	//
	// start etw session
	//
	printf("Disk  |  Request  |     Sector   | Length\n");
	TRACEHANDLE hTraceSession = NULL;

	hTraceSession = StartETWSession(profile);
	if (NULL == hTraceSession)
	{
		PrintError("Could not start ETW session\n");
		//_TerminateWorkerThreads(vhThreads);
		return false;
	}
	hEtwThread = CreateThread(NULL, 64 * 1024, etwThreadFunc, NULL, 0, NULL);
	if (NULL == hEtwThread)
	{
		PrintError("Warning: unable to create thread for ETW session\n");
		//_TerminateWorkerThreads(vhThreads);
		return false;
	}
	hDebug = CreateThread(NULL, 0, etwDebug, NULL, 0, NULL);
	if (NULL == hDebug)
	{
		PrintError("Warning: unable to create thread for ETW session\n");
		//_TerminateWorkerThreads(vhThreads);
		return false;
	}



	std::this_thread::sleep_for(5s);

	//Stop ETW session
	PEVENT_TRACE_PROPERTIES pETWSession = NULL;

	//printfv(profile.GetVerbose(), "stopping ETW session\n");
	pETWSession = StopETWSession(hTraceSession);
	if (NULL == pETWSession)
	{
		PrintError("Error stopping ETW session\n");
		return false;
	}


	WaitForSingleObject(hEtwThread, INFINITE);
	CloseHandle(hEtwThread);
	CloseHandle(hDebug);


	results.EtwEventCounters = g_EtwEventCounters;
	printfv(profile.GetVerbose(), "Read count %lu\n", g_EtwEventCounters.ullIORead);
	printfv(profile.GetVerbose(), "Write count %lu\n", g_EtwEventCounters.ullIOWrite);
	printfv(profile.GetVerbose(), "tracing events\n", g_EtwEventCounters);
	results.EtwSessionInfo = _GetResultETWSession(pETWSession);
	return true;
}

vector<struct IORequestGenerator::CreateFileParameters> IORequestGenerator::_GetFilesToPrecreate(const Profile& profile) const
{
    vector<struct CreateFileParameters> vFilesToCreate;
    const vector<TimeSpan>& vTimeSpans = profile.GetTimeSpans();
    map<string, vector<struct CreateFileParameters>> filesMap;
    for (const auto& timeSpan : vTimeSpans)
    {
        vector<Target> vTargets(timeSpan.GetTargets());
        for (const auto& target : vTargets)
        {
            struct CreateFileParameters createFileParameters;
            createFileParameters.sPath = target.GetPath();
            createFileParameters.ullFileSize = target.GetFileSize();
            createFileParameters.fZeroWriteBuffers = target.GetZeroWriteBuffers();

            filesMap[createFileParameters.sPath].push_back(createFileParameters);
        }
    }

    PrecreateFiles filter = profile.GetPrecreateFiles();
    for (auto fileMapEntry : filesMap)
    {
        if (fileMapEntry.second.size() > 0)
        {
            UINT64 ullLastNonZeroSize = fileMapEntry.second[0].ullFileSize;
            UINT64 ullMaxSize = fileMapEntry.second[0].ullFileSize;
            bool fLastZeroWriteBuffers = fileMapEntry.second[0].fZeroWriteBuffers;
            bool fHasZeroSizes = false;
            bool fConstantSize = true;
            bool fConstantZeroWriteBuffers = true;
            for (auto file : fileMapEntry.second)
            {
                ullMaxSize = max(ullMaxSize, file.ullFileSize);
                if (ullLastNonZeroSize == 0)
                {
                    ullLastNonZeroSize = file.ullFileSize;
                }
                if (file.ullFileSize == 0)
                {
                    fHasZeroSizes = true;
                }
                if ((file.ullFileSize != 0) && (file.ullFileSize != ullLastNonZeroSize))
                {
                    fConstantSize = false;
                }
                if (file.fZeroWriteBuffers != fLastZeroWriteBuffers)
                {
                    fConstantZeroWriteBuffers = false;
                }
                if (file.ullFileSize != 0)
                {
                    ullLastNonZeroSize = file.ullFileSize;
                }
                fLastZeroWriteBuffers = file.fZeroWriteBuffers;
            }

            if (fConstantZeroWriteBuffers && ullMaxSize > 0)
            {
                struct CreateFileParameters file = fileMapEntry.second[0];
                file.ullFileSize = ullMaxSize;
                if (filter == PrecreateFiles::UseMaxSize)
                {
                    vFilesToCreate.push_back(file);
                }
                else if ((filter == PrecreateFiles::OnlyFilesWithConstantSizes) && fConstantSize && !fHasZeroSizes)
                {
                    vFilesToCreate.push_back(file);
                }
                else if ((filter == PrecreateFiles::OnlyFilesWithConstantOrZeroSizes) && fConstantSize)
                {
                    vFilesToCreate.push_back(file);
                }
            }
        }
    }

    return vFilesToCreate;
}

