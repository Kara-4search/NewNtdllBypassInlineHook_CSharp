using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace NewNtdllBypassInlineHook
{
    class DelegatesFunctions
    {
		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate uint DFNtAllocateVirtualMemory(
			IntPtr ProcessHandle,
			ref IntPtr BaseAddress,
			IntPtr ZeroBits,
			ref UIntPtr RegionSize,
			ulong AllocationType,
			ulong Protect);

		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate uint DFNtCreateThreadEx(
			out IntPtr hThread,
			uint DesiredAccess,
			IntPtr ObjectAttributes,
			IntPtr ProcessHandle,
			IntPtr lpStartAddress,
			IntPtr lpParameter,
			bool CreateSuspended,
			uint StackZeroBits,
			uint SizeOfStackCommit,
			uint SizeOfStackReserve,
			IntPtr lpBytesBuffer
			);

		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate uint DFNtWaitForSingleObject(IntPtr Object, bool Alertable, uint Timeout);
	}
}
