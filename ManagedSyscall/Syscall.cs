using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;

namespace ManagedSyscall
{
	public static unsafe class Syscall
	{
		private static readonly ConcurrentDictionary<string, Delegate> delegateCacheByName = new ConcurrentDictionary<string, Delegate>();
		private static readonly ConcurrentDictionary<int, Delegate> delegateCacheById = new ConcurrentDictionary<int, Delegate>();

		public static T GetDelegate<T>(string functionName) where T : Delegate
		{
			if (delegateCacheByName.TryGetValue(functionName, out Delegate? syscallDelegate))
			{
				return (T)syscallDelegate;
			}

			int syscallId = GetId(functionName);
			syscallDelegate = GetDelegate<T>(syscallId);

			delegateCacheByName.TryAdd(functionName, syscallDelegate);

			return (T)syscallDelegate;
		}

		public static T GetDelegate<T>(int syscallId) where T : Delegate
		{
			if (delegateCacheById.TryGetValue(syscallId, out Delegate? syscallDelegate))
			{
				return (T)syscallDelegate;
			}

			syscallDelegate = CreateDelegate(syscallId, typeof(T));
			delegateCacheById.TryAdd(syscallId, syscallDelegate);
			return (T)syscallDelegate;
		}

		private delegate uint NtAllocateVirtualMemoryDelegate(IntPtr processHandle, ref IntPtr baseAddress, IntPtr zeroBits, ref IntPtr regionSize, uint allocationType, uint protect);
		private delegate uint NtProtectVirtualMemoryDelegate(IntPtr processHandle, ref IntPtr baseAddress, ref IntPtr regionSize, uint newProtect, out uint oldProtect);

		private static readonly NtAllocateVirtualMemoryDelegate _ntAllocateVirtualMemory;
		private static readonly NtProtectVirtualMemoryDelegate _ntProtectVirtualMemory;

		static Syscall()
		{
			if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.ProcessArchitecture != Architecture.X64)
			{
				throw new PlatformNotSupportedException("ManagedSyscall is only supported on Windows x64.");
			}

			_ntAllocateVirtualMemory = CreateBootstrapDelegate<NtAllocateVirtualMemoryDelegate>("NtAllocateVirtualMemory");
			_ntProtectVirtualMemory = CreateBootstrapDelegate<NtProtectVirtualMemoryDelegate>("NtProtectVirtualMemory");
		}

		private static T CreateBootstrapDelegate<T>(string functionName) where T : Delegate
		{
			int syscallId = GetId(functionName);
			return (T)CreateDelegateInternal(syscallId, typeof(T), true);
		}

		private static Delegate CreateDelegate(int syscallId, Type delegateType)
		{
			return CreateDelegateInternal(syscallId, delegateType, false);
		}

		private static Delegate CreateDelegateInternal(int syscallId, Type delegateType, bool bootstrap)
		{
			byte[] syscallStub = {	
				0x4C, 0x8B, 0xD1,					// mov r10, rcx
				0xB8, 0x00, 0x00, 0x00, 0x00,		// mov eax, syscall_id
				0x0F, 0x05,							// syscall
				0xC3								// ret
			};

			byte[] idBytes = BitConverter.GetBytes(syscallId);
			Buffer.BlockCopy(idBytes, 0, syscallStub, 4, 4);

			IntPtr pCode;
			IntPtr regionSize = (IntPtr)syscallStub.Length;

			if (bootstrap)
			{
				pCode = BootstrapVirtualAlloc(IntPtr.Zero, (uint)syscallStub.Length, (uint)(AllocationType.Commit | AllocationType.Reserve), (uint)MemoryProtection.ReadWrite);
				if (pCode == IntPtr.Zero) throw new System.ComponentModel.Win32Exception("Bootstrap allocation failed.");
			}
			else
			{
				pCode = IntPtr.Zero;
				uint status = _ntAllocateVirtualMemory((IntPtr)(-1), ref pCode, IntPtr.Zero, ref regionSize, (uint)(AllocationType.Commit | AllocationType.Reserve), (uint)MemoryProtection.ReadWrite);
				if (status != 0) throw new Exception($"Failed to allocate memory for syscall stub: {status:X}");
			}

			Marshal.Copy(syscallStub, 0, pCode, syscallStub.Length);

			if (bootstrap)
			{
				if (!BootstrapVirtualProtect(pCode, (uint)syscallStub.Length, (uint)MemoryProtection.ExecuteRead, out _))
				{
					throw new System.ComponentModel.Win32Exception("Bootstrap protection failed.");
				}
			}
			else
			{
				uint status = _ntProtectVirtualMemory((IntPtr)(-1), ref pCode, ref regionSize, (uint)MemoryProtection.ExecuteRead, out _);
				if (status != 0) throw new Exception($"Failed to protect memory for syscall stub: {status:X}");
			}

			return Marshal.GetDelegateForFunctionPointer(pCode, delegateType);
		}

		public static int GetId(string functionName)
		{
			IntPtr functionAddress = GetFunctionAddress("ntdll.dll", functionName);
			byte[] functionBytes = new byte[8];
			Marshal.Copy(functionAddress, functionBytes, 0, 8);

			byte[] syscallSignature = { 0x4c, 0x8b, 0xd1, 0xb8 };
			if (functionBytes[0] == syscallSignature[0] &&
				functionBytes[1] == syscallSignature[1] &&
				functionBytes[2] == syscallSignature[2] &&
				functionBytes[3] == syscallSignature[3])
			{
				return BitConverter.ToInt32(functionBytes, 4);
			}

			throw new NotSupportedException("Syscall signature not found or function is hooked.");
		}

		private static IntPtr GetFunctionAddress(string moduleName, string functionName)
		{
			IntPtr moduleBase = GetModuleBaseAddress(moduleName);
			if (moduleBase == IntPtr.Zero)
			{
				throw new DllNotFoundException($"{moduleName} not found in current process.");
			}

			int peHeader = Marshal.ReadInt32(moduleBase + 0x3C);
			int exportTableRva = Marshal.ReadInt32(moduleBase + peHeader + 0x88);
			IntPtr exportTableAddr = moduleBase + exportTableRva;

			int nameTableRva = Marshal.ReadInt32(exportTableAddr + 0x20);
			int ordinalTableRva = Marshal.ReadInt32(exportTableAddr + 0x24);
			int functionTableRva = Marshal.ReadInt32(exportTableAddr + 0x1C);
			int numberOfNames = Marshal.ReadInt32(exportTableAddr + 0x18);

			IntPtr nameTableAddr = moduleBase + nameTableRva;
			IntPtr ordinalTableAddr = moduleBase + ordinalTableRva;
			IntPtr functionTableAddr = moduleBase + functionTableRva;

			for (int i = 0; i < numberOfNames; i++)
			{
				int functionNameRva = Marshal.ReadInt32(nameTableAddr + i * 4);
				string? currentFunctionName = Marshal.PtrToStringAnsi(moduleBase + functionNameRva);
				if (string.Equals(currentFunctionName, functionName, StringComparison.OrdinalIgnoreCase))
				{
					ushort ordinal = (ushort)Marshal.ReadInt16(ordinalTableAddr + i * 2);
					int functionRva = Marshal.ReadInt32(functionTableAddr + ordinal * 4);
					return moduleBase + functionRva;
				}
			}

			throw new EntryPointNotFoundException($"Function {functionName} not found in {moduleName}.");
		}

		private static IntPtr GetModuleBaseAddress(string moduleName)
		{
			foreach (ProcessModule? module in Process.GetCurrentProcess().Modules)
			{
				if (module != null && string.Equals(module.ModuleName, moduleName, StringComparison.OrdinalIgnoreCase))
				{
					return module.BaseAddress;
				}
			}
			return IntPtr.Zero;
		}

		[DllImport("kernel32.dll", SetLastError = true, EntryPoint = "VirtualAlloc")]
		private static extern IntPtr BootstrapVirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

		[DllImport("kernel32.dll", SetLastError = true, EntryPoint = "VirtualProtect")]
		private static extern bool BootstrapVirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
	}
}