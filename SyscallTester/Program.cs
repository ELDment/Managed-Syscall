using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using ManagedSyscall;

public unsafe class Program
{
	private const uint NT_SUCCESS = 0;

	public static void Main(string[] args)
	{
		TestMemoryApis();
		TestProcessApis();
		TestGetDelegateById();
		TestGetDelegateByName();
	}

	private static void TestMemoryApis()
	{
		Console.WriteLine("\n[1] Testing Memory APIs");

		IntPtr baseAddress = IntPtr.Zero;
		IntPtr regionSize = (IntPtr)4096;
		uint status;

		// Allocate Memory
		status = NtApi.NtAllocateVirtualMemory((IntPtr)(-1), ref baseAddress, IntPtr.Zero, ref regionSize, (uint)(AllocationType.Commit | AllocationType.Reserve), (uint)MemoryProtection.ReadWrite);
		if (status != NT_SUCCESS) throw new Exception($"NtAllocateVirtualMemory failed: {status:X}");
		Console.WriteLine($"  - Memory allocated at 0x{baseAddress:X}");

		// Write Memory
		byte[] dataToWrite = BitConverter.GetBytes(1337);
		GCHandle pinnedData = GCHandle.Alloc(dataToWrite, GCHandleType.Pinned);
		status = NtApi.NtWriteVirtualMemory((IntPtr)(-1), baseAddress, pinnedData.AddrOfPinnedObject(), (uint)dataToWrite.Length, out uint bytesWritten);
		pinnedData.Free();
		if (status != NT_SUCCESS) throw new Exception($"NtWriteVirtualMemory failed: {status:X}");
		Console.WriteLine("  - Wrote 1337 to memory.");

		// Memory Protection
		status = NtApi.NtProtectVirtualMemory((IntPtr)(-1), ref baseAddress, ref regionSize, (uint)MemoryProtection.ReadOnly, out uint oldProtect);
		if (status != NT_SUCCESS) throw new Exception($"NtProtectVirtualMemory failed: {status:X}");
		Console.WriteLine("  - Changed memory protection to ReadOnly.");

		// Read Memory
		byte[] readBuffer = new byte[4];
		GCHandle pinnedBuffer = GCHandle.Alloc(readBuffer, GCHandleType.Pinned);
		status = NtApi.NtReadVirtualMemory((IntPtr)(-1), baseAddress, pinnedBuffer.AddrOfPinnedObject(), (uint)readBuffer.Length, out uint bytesRead);
		int readValue = BitConverter.ToInt32(readBuffer, 0);
		pinnedBuffer.Free();
		if (status != NT_SUCCESS || readValue != 1337) throw new Exception($"NtReadVirtualMemory failed or read incorrect data. Status: {status:X}, Value: {readValue}");
		Console.WriteLine($"  - Read back value: {readValue}");

		// Memory Protection
		status = NtApi.NtProtectVirtualMemory((IntPtr)(-1), ref baseAddress, ref regionSize, (uint)MemoryProtection.ReadWrite, out oldProtect);
		if (status != NT_SUCCESS) throw new Exception($"NtProtectVirtualMemory failed on revert: {status:X}");

		// Free Memory
		status = NtApi.NtFreeVirtualMemory((IntPtr)(-1), ref baseAddress, ref regionSize, (uint)AllocationType.Release);
		if (status != NT_SUCCESS) throw new Exception($"NtFreeVirtualMemory failed: {status:X}");
		Console.WriteLine("  - Memory freed successfully.");
	}

	private static void TestProcessApis()
	{
		Console.WriteLine("\n[2] Testing Process APIs");
		Process? notepad = null;
		IntPtr processHandle = IntPtr.Zero;
		try
		{
			notepad = Process.Start("notepad.exe");
			if (notepad == null) throw new Exception("Failed to start notepad.exe");
			Console.WriteLine($"  - Started notepad.exe with PID: {notepad.Id}");

			// Open Process
			OBJECT_ATTRIBUTES objAttr = new OBJECT_ATTRIBUTES();
			CLIENT_ID clientId = new CLIENT_ID { UniqueProcess = (IntPtr)notepad.Id };
			uint status = NtApi.NtOpenProcess(out processHandle, ProcessAccess.All, ref objAttr, ref clientId);
			if (status != NT_SUCCESS || processHandle == IntPtr.Zero) throw new Exception($"NtOpenProcess failed: {status:X}");
			Console.WriteLine($"  - Successfully opened process handle: 0x{processHandle:X}");

			// Terminate Process
			status = NtApi.NtTerminateProcess(processHandle, 0);
			if (status != NT_SUCCESS) throw new Exception($"NtTerminateProcess failed: {status:X}");
			Console.WriteLine("  - Successfully terminated process.");
			notepad.WaitForExit();
			notepad = null;
		}
		finally
		{
			if (processHandle != IntPtr.Zero)
			{
				uint status = NtApi.NtClose(processHandle);
				if (status != NT_SUCCESS) throw new Exception($"NtClose failed: {status:X}");
				Console.WriteLine("  - Closed process handle.");
			}
			if (notepad != null)
			{
				notepad.Kill();
			}
		}
	}

	private static void TestGetDelegateById()
	{
		Console.WriteLine("\n[3] Testing GetDelegate by Syscall ID");
		const int ntCloseSyscallId = 0x0F; // NtClose

		var ntCloseById = Syscall.GetDelegate<NtApi.NtCloseDelegate>(ntCloseSyscallId);
		Console.WriteLine("  - Successfully got delegate for NtClose using ID.");

		Process? notepad = null;
		try
		{
			notepad = Process.Start("notepad.exe");
			if (notepad == null) throw new Exception("Failed to start notepad.exe for handle test.");

			OBJECT_ATTRIBUTES objAttr = new OBJECT_ATTRIBUTES();
			CLIENT_ID clientId = new CLIENT_ID { UniqueProcess = (IntPtr)notepad.Id };
			uint status = NtApi.NtOpenProcess(out IntPtr processHandle, ProcessAccess.All, ref objAttr, ref clientId);
			if (status != NT_SUCCESS || processHandle == IntPtr.Zero) throw new Exception($"NtOpenProcess failed for ID test: {status:X}");

			status = ntCloseById(processHandle);
			if (status != NT_SUCCESS) throw new Exception($"NtClose by ID failed: {status:X}");

			Console.WriteLine("  - Successfully closed handle using delegate from Syscall ID.");
		}
		finally
		{
			if (notepad != null && !notepad.HasExited)
			{
				notepad.Kill();
			}
		}
	}

	private static void TestGetDelegateByName()
	{
		Console.WriteLine("\n[4] Testing GetDelegate by Name");

		var ntClose = Syscall.GetDelegate<NtApi.NtCloseDelegate>("NtClose");
		if (ntClose == null) throw new Exception("Failed to get delegate for NtClose by name.");
		Console.WriteLine("  - Successfully got delegate for NtClose using name.");

		var process = Process.Start("notepad.exe");
		System.Threading.Thread.Sleep(500);

		try
		{
			var objectAttributes = new OBJECT_ATTRIBUTES();
			var clientId = new CLIENT_ID { UniqueProcess = (IntPtr)process.Id };
			uint status = NtApi.NtOpenProcess(out IntPtr handle, ProcessAccess.Terminate, ref objectAttributes, ref clientId);
			if (status != NT_SUCCESS) throw new Exception($"NtOpenProcess failed: {status:X}");

			status = ntClose(handle);
			if (status != NT_SUCCESS) throw new Exception($"NtClose failed using delegate from name: {status:X}");
			Console.WriteLine("  - Successfully closed handle using delegate from name.");
		}
		finally
		{
			if (process != null && !process.HasExited)
			{
				process.Kill();
			}
		}
	}
}