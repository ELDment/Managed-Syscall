# ManagedSyscall

一个为 .NET 8 设计的类库，用于在 Windows x64 平台上直接、高效地执行原生 NT 系统调用 (Syscall)，旨在绕过传统 P/Invoke 的开销与钩子。

## 核心特性

- **🚀 直接调用**：通过 `syscall` 汇编指令执行系统调用，性能更高，且能有效规避 EDR/AV 对高层 API 的钩子。
- **⚙️ 动态解析**：运行时从 `ntdll.dll` 动态解析系统调用号，无需硬编码，保证跨 Windows 版本的兼容性。
- **⚡ 高效缓存**：内置线程安全的委托缓存，确保重复调用的性能开销降至最低。
- **📦 易用封装**：提供 `NtApi` 静态类，封装了常用的 NT 函数，开箱即用。

## 环境要求

- **操作系统**: Windows x64
- **框架**: .NET 8

本库在启动时会进行环境检查。
<br>
若在非 Windows x64 环境下使用，将抛出 `PlatformNotSupportedException`。

## 快速上手

使用 `NtApi` 静态类是与系统内核交互最简单的方式。

```csharp
using ManagedSyscall;
using System;

// 在当前进程中分配 4KB 的可读写内存
IntPtr baseAddress = IntPtr.Zero;
IntPtr regionSize = (IntPtr)4096;
uint status = NtApi.NtAllocateVirtualMemory(
    (IntPtr)(-1),
    ref baseAddress,
    IntPtr.Zero,
    ref regionSize,
    (uint)(AllocationType.Commit | AllocationType.Reserve),
    (uint)MemoryProtection.ReadWrite
);

if (status == 0) // NT_SUCCESS
{
    Console.WriteLine($"成功分配内存: 0x{baseAddress:X}");

    // ... 执行内存读写操作 ...

    // 释放内存
    NtApi.NtFreeVirtualMemory((IntPtr)(-1), ref baseAddress, ref regionSize, (uint)AllocationType.Release);
    Console.WriteLine("内存已释放。");
}
```

## 高级用法

当需要调用 `NtApi` 未封装的函数，可以通过 `Syscall.GetDelegate` 获取委托。

### 通过函数名获取

这是最常见的用法。库会自动解析函数名对应的系统调用ID并获取委托。

```csharp
using ManagedSyscall;
using System;
using System.Runtime.InteropServices;

// 1. 定义与NT函数签名完全一致的委托
[UnmanagedFunctionPointer(CallingConvention.StdCall)]
delegate uint NtQuerySystemInformationDelegate(
    uint SystemInformationClass,
    IntPtr SystemInformation,
    uint SystemInformationLength,
    out uint ReturnLength
);

// 2. 通过函数名获取委托实例
var ntQuery = Syscall.GetDelegate<NtQuerySystemInformationDelegate>("NtQuerySystemInformation");

// 3. 像调用普通方法一样调用它
// ...
```

### 通过系统调用ID获取

对于某些未导出的函数，且已知确切的系统调用ID时，可以直接通过ID获取委托。

```csharp
using ManagedSyscall;
using System;
using System.Runtime.InteropServices;

// 1. 定义 NtClose 的委托签名
[UnmanagedFunctionPointer(CallingConvention.StdCall)]
delegate uint NtCloseDelegate(IntPtr handle);

// 2. 假设我们已知 NtClose 在当前系统的ID是 0x0F
const int ntCloseSyscallId = 0x0F;

// 3. 直接通过ID获取委托实例
var ntClose = Syscall.GetDelegate<NtCloseDelegate>(ntCloseSyscallId);

// 4. 像调用普通方法一样调用它
// ...
```

## 构建与测试

项目内含一个 `SyscallTester` 控制台应用，用于演示库的功能。

进入 `SyscallTester` 目录并执行以下命令：

```powershell
dotnet run
```

如果成功，控制台将会出现类似输出：

```powershell
[1] Testing Memory APIs
  - Memory allocated at 0x2660000
  - Wrote 1337 to memory.
  - Changed memory protection to ReadOnly.
  - Read back value: 1337
  - Memory freed successfully.

[2] Testing Process APIs
  - Started notepad.exe with PID: 126296
  - Successfully opened process handle: 0x484
  - Successfully terminated process.
  - Closed process handle.

[3] Testing GetDelegate by Syscall ID
  - Successfully got delegate for NtClose using ID.
  - Successfully closed handle using delegate from Syscall ID.

[4] Testing GetDelegate by Name
  - Successfully got delegate for NtClose using name.
  - Successfully closed handle using delegate from name.
```
