using System;
using System.Runtime.InteropServices;

namespace ManagedSyscall
{
	public static unsafe class NtApi
	{
		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate uint NtAllocateVirtualMemoryDelegate(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, uint AllocationType, uint Protect);

		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate uint NtFreeVirtualMemoryDelegate(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, uint FreeType);

		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate uint NtProtectVirtualMemoryDelegate(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, uint NewProtect, out uint OldProtect);

		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate uint NtWriteVirtualMemoryDelegate(IntPtr ProcessHandle, IntPtr BaseAddress, IntPtr Buffer, uint NumberOfBytesToWrite, out uint NumberOfBytesWritten);

		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate uint NtCloseDelegate(IntPtr Handle);

		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate uint NtOpenProcessDelegate(out IntPtr processHandle, ProcessAccess desiredAccess, ref OBJECT_ATTRIBUTES objectAttributes, ref CLIENT_ID clientId);

		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate uint NtTerminateProcessDelegate(IntPtr processHandle, uint exitStatus);

		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate uint NtReadVirtualMemoryDelegate(IntPtr processHandle, IntPtr baseAddress, IntPtr buffer, uint numberOfBytesToRead, out uint numberOfBytesRead);

		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate uint NtCreateThreadExDelegate(out IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, uint flags, IntPtr stackZeroBits, IntPtr sizeOfStackCommit, IntPtr sizeOfStackReserve, IntPtr bytesBuffer);

		private static readonly Lazy<NtAllocateVirtualMemoryDelegate> _ntAllocateVirtualMemory = new Lazy<NtAllocateVirtualMemoryDelegate>(() => Syscall.GetDelegate<NtAllocateVirtualMemoryDelegate>("NtAllocateVirtualMemory"));
		private static readonly Lazy<NtFreeVirtualMemoryDelegate> _ntFreeVirtualMemory = new Lazy<NtFreeVirtualMemoryDelegate>(() => Syscall.GetDelegate<NtFreeVirtualMemoryDelegate>("NtFreeVirtualMemory"));
		private static readonly Lazy<NtProtectVirtualMemoryDelegate> _ntProtectVirtualMemory = new Lazy<NtProtectVirtualMemoryDelegate>(() => Syscall.GetDelegate<NtProtectVirtualMemoryDelegate>("NtProtectVirtualMemory"));
		private static readonly Lazy<NtWriteVirtualMemoryDelegate> _ntWriteVirtualMemory = new Lazy<NtWriteVirtualMemoryDelegate>(() => Syscall.GetDelegate<NtWriteVirtualMemoryDelegate>("NtWriteVirtualMemory"));
		private static readonly Lazy<NtCloseDelegate> _ntClose = new Lazy<NtCloseDelegate>(() => Syscall.GetDelegate<NtCloseDelegate>("NtClose"));
		private static readonly Lazy<NtOpenProcessDelegate> _ntOpenProcess = new Lazy<NtOpenProcessDelegate>(() => Syscall.GetDelegate<NtOpenProcessDelegate>("NtOpenProcess"));
		private static readonly Lazy<NtTerminateProcessDelegate> _ntTerminateProcess = new Lazy<NtTerminateProcessDelegate>(() => Syscall.GetDelegate<NtTerminateProcessDelegate>("NtTerminateProcess"));
		private static readonly Lazy<NtReadVirtualMemoryDelegate> _ntReadVirtualMemory = new Lazy<NtReadVirtualMemoryDelegate>(() => Syscall.GetDelegate<NtReadVirtualMemoryDelegate>("NtReadVirtualMemory"));
		private static readonly Lazy<NtCreateThreadExDelegate> _ntCreateThreadEx = new Lazy<NtCreateThreadExDelegate>(() => Syscall.GetDelegate<NtCreateThreadExDelegate>("NtCreateThreadEx"));

		public static uint NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, uint AllocationType, uint Protect) =>
			_ntAllocateVirtualMemory.Value(ProcessHandle, ref BaseAddress, ZeroBits, ref RegionSize, AllocationType, Protect);

		public static uint NtFreeVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, uint FreeType) =>
			_ntFreeVirtualMemory.Value(ProcessHandle, ref BaseAddress, ref RegionSize, FreeType);

		public static uint NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, uint NewProtect, out uint OldProtect) =>
			_ntProtectVirtualMemory.Value(ProcessHandle, ref BaseAddress, ref RegionSize, NewProtect, out OldProtect);

		public static uint NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, IntPtr Buffer, uint NumberOfBytesToWrite, out uint NumberOfBytesWritten) =>
			_ntWriteVirtualMemory.Value(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, out NumberOfBytesWritten);

		public static uint NtClose(IntPtr Handle) => _ntClose.Value(Handle);

		public static uint NtOpenProcess(out IntPtr processHandle, ProcessAccess desiredAccess, ref OBJECT_ATTRIBUTES objectAttributes, ref CLIENT_ID clientId) =>
			_ntOpenProcess.Value(out processHandle, desiredAccess, ref objectAttributes, ref clientId);

		public static uint NtTerminateProcess(IntPtr processHandle, uint exitStatus) => _ntTerminateProcess.Value(processHandle, exitStatus);

		public static uint NtReadVirtualMemory(IntPtr processHandle, IntPtr baseAddress, IntPtr buffer, uint numberOfBytesToRead, out uint numberOfBytesRead) =>
			_ntReadVirtualMemory.Value(processHandle, baseAddress, buffer, numberOfBytesToRead, out numberOfBytesRead);

		public static uint NtCreateThreadEx(out IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, uint flags, IntPtr stackZeroBits, IntPtr sizeOfStackCommit, IntPtr sizeOfStackReserve, IntPtr bytesBuffer) =>
			_ntCreateThreadEx.Value(out threadHandle, desiredAccess, objectAttributes, processHandle, startAddress, parameter, flags, stackZeroBits, sizeOfStackCommit, sizeOfStackReserve, bytesBuffer);
	}
}