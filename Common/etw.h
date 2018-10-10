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

#pragma once


#include <windows.h>
#include <Wmistr.h>		///WNODE_HEADER
#define INITGUID		//Include this #define to use SystemTraceControlGuid in Evntrace.h.
#include <Evntrace.h>	//ETW
#include "Common.h"
#include <queue> 
struct sDiskioTypeGroup1
{
	UINT32 DiskNumber;
	UINT32 IrpFlags;
	UINT32 TransferSize;
	UINT32 Reserved;
	INT64 ByteOffset;
	UINT32 FileObject;
	UINT32 Irp;
	UINT64 HighResResponseTime;
	UINT32 IssuingThreadId;
};
struct sFileIOName
{
	UINT32 FileObject;
	string FileName;
};
BOOL TraceEvents();
TRACEHANDLE StartETWSession(const Profile& profile);
PEVENT_TRACE_PROPERTIES StopETWSession(TRACEHANDLE hTraceSession);