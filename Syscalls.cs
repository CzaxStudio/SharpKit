using System.Runtime.InteropServices;

namespace SharpKit;

public enum SyscallResult : int
{
    Success = 0,
    AccessDenied = unchecked((int)0xC0000022),
    InvalidParameter = unchecked((int)0xC000000D),
    InsufficientResources = unchecked((int)0xC000009A),
    NotImplemented = unchecked((int)0xC0000002),
    ObjectNameNotFound = unchecked((int)0xC0000034),
    InvalidHandle = unchecked((int)0xC0000008),
    NoMemory = unchecked((int)0xC0000017),
    Timeout = unchecked((int)0x00000102),
}

public sealed class SyscallStub : IDisposable
{
    private IntPtr _executableMemory;
    private int _stubSize;
    private bool _disposed;

    private static readonly byte[] SyscallGadget =
    [
        0x0F, 0x05,
        0xC3
    ];

    private static readonly byte[] IndirectStubTemplate =
    [
        0x4C, 0x8B, 0xD1,
        0xB8, 0x00, 0x00, 0x00, 0x00,
        0x49, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x41, 0xFF, 0xE3
    ];

    public IntPtr StubAddress => _executableMemory;

    public SyscallStub(uint syscallNumber, IntPtr syscallGadgetAddress)
    {
        var stub = (byte[])IndirectStubTemplate.Clone();
        var ssnBytes = BitConverter.GetBytes(syscallNumber);
        stub[4] = ssnBytes[0];
        stub[5] = ssnBytes[1];
        stub[6] = ssnBytes[2];
        stub[7] = ssnBytes[3];

        var gadgetBytes = BitConverter.GetBytes(syscallGadgetAddress.ToInt64());
        Buffer.BlockCopy(gadgetBytes, 0, stub, 10, 8);

        _stubSize = stub.Length;
        _executableMemory = Win32.VirtualAlloc(IntPtr.Zero, (uint)stub.Length, Win32.MEM_COMMIT | Win32.MEM_RESERVE, Win32.PAGE_READWRITE);

        if (_executableMemory == IntPtr.Zero)
            throw new InvalidOperationException($"VirtualAlloc failed: {Marshal.GetLastWin32Error()}");

        Marshal.Copy(stub, 0, _executableMemory, stub.Length);
        Win32.VirtualProtect(_executableMemory, (uint)stub.Length, Win32.PAGE_EXECUTE_READ, out _);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_executableMemory != IntPtr.Zero)
        {
            Win32.VirtualFree(_executableMemory, 0, Win32.MEM_RELEASE);
            _executableMemory = IntPtr.Zero;
        }
    }
}

public static unsafe class Syscalls
{
    private static IntPtr _ntdllBase = IntPtr.Zero;
    private static IntPtr _syscallGadget = IntPtr.Zero;
    private static readonly Dictionary<string, uint> _ssnCache = new(StringComparer.OrdinalIgnoreCase);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    private static extern IntPtr GetModuleHandle(string moduleName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualQuery(IntPtr lpAddress, out Win32.MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    public static void Initialize()
    {
        _ntdllBase = GetModuleHandle("ntdll.dll");
        if (_ntdllBase == IntPtr.Zero)
            throw new InvalidOperationException("Failed to get ntdll.dll base address");

        _syscallGadget = FindSyscallGadget(_ntdllBase);
    }

    private static IntPtr FindSyscallGadget(IntPtr moduleBase)
    {
        if (moduleBase == IntPtr.Zero) return IntPtr.Zero;

        var dosHeader = (ushort*)moduleBase.ToPointer();
        if (*dosHeader != 0x5A4D) return IntPtr.Zero;

        var e_lfanew = *(int*)((byte*)moduleBase + 0x3C);
        var ntHeader = (byte*)moduleBase + e_lfanew;

        var optionalHeaderOffset = ntHeader + 4 + 20;
        var sizeOfImage = *(int*)(optionalHeaderOffset + 56);

        var ptr = (byte*)moduleBase;
        var end = ptr + sizeOfImage - 2;

        while (ptr < end)
        {
            if (ptr[0] == 0x0F && ptr[1] == 0x05 && ptr[2] == 0xC3)
                return (IntPtr)ptr;
            ptr++;
        }

        return IntPtr.Zero;
    }

    public static uint GetSyscallNumber(string functionName)
    {
        if (_ssnCache.TryGetValue(functionName, out var cached))
            return cached;

        if (_ntdllBase == IntPtr.Zero)
            Initialize();

        var funcAddr = GetProcAddress(_ntdllBase, functionName);
        if (funcAddr == IntPtr.Zero)
            throw new InvalidOperationException($"Function {functionName} not found in ntdll");

        var bytes = (byte*)funcAddr.ToPointer();

        if (bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 &&
            bytes[3] == 0xB8)
        {
            var ssn = *(uint*)(bytes + 4);
            _ssnCache[functionName] = ssn;
            return ssn;
        }

        if (bytes[0] == 0xE9)
        {
            var offset = *(int*)(bytes + 1);
            var hooked = bytes + 5 + offset;

            for (int i = 0; i < 32; i++)
            {
                if (hooked[i] == 0x4C && hooked[i + 1] == 0x8B && hooked[i + 2] == 0xD1 &&
                    hooked[i + 3] == 0xB8)
                {
                    var ssn = *(uint*)(hooked + i + 4);
                    _ssnCache[functionName] = ssn;
                    return ssn;
                }
            }
        }

        var neighborSsn = FindNeighborSsn(functionName);
        _ssnCache[functionName] = neighborSsn;
        return neighborSsn;
    }

    private static uint FindNeighborSsn(string targetFunction)
    {
        if (_ntdllBase == IntPtr.Zero) return 0;

        var dosHeader = (ushort*)_ntdllBase.ToPointer();
        if (*dosHeader != 0x5A4D) return 0;

        var e_lfanew = *(int*)((byte*)_ntdllBase + 0x3C);
        var ntHeaders = (byte*)_ntdllBase + e_lfanew;
        var optHeader = ntHeaders + 4 + 20;

        var exportDirRva = *(int*)(optHeader + 96);
        if (exportDirRva == 0) return 0;

        var exportDir = (byte*)_ntdllBase + exportDirRva;
        var numberOfNames = *(int*)(exportDir + 24);
        var addressOfFunctionsRva = *(int*)(exportDir + 28);
        var addressOfNamesRva = *(int*)(exportDir + 32);
        var addressOfNameOrdinalsRva = *(int*)(exportDir + 36);

        var functions = (int*)((byte*)_ntdllBase + addressOfFunctionsRva);
        var names = (int*)((byte*)_ntdllBase + addressOfNamesRva);
        var ordinals = (ushort*)((byte*)_ntdllBase + addressOfNameOrdinalsRva);

        var syscallFunctions = new SortedDictionary<uint, string>();

        for (int i = 0; i < numberOfNames; i++)
        {
            var name = Marshal.PtrToStringAnsi((IntPtr)((byte*)_ntdllBase + names[i]));
            if (name == null || !name.StartsWith("Nt", StringComparison.Ordinal)) continue;

            var funcAddr = (byte*)_ntdllBase + functions[ordinals[i]];
            if (funcAddr[0] == 0x4C && funcAddr[1] == 0x8B && funcAddr[2] == 0xD1 && funcAddr[3] == 0xB8)
            {
                var ssn = *(uint*)(funcAddr + 4);
                syscallFunctions[ssn] = name;
            }
        }

        var sortedNames = syscallFunctions.Values.ToList();
        var idx = sortedNames.IndexOf(targetFunction);
        if (idx < 0) return 0;

        for (int delta = 1; delta <= sortedNames.Count; delta++)
        {
            if (idx - delta >= 0)
            {
                var neighbor = sortedNames[idx - delta];
                var neighborAddr = GetProcAddress(_ntdllBase, neighbor);
                if (neighborAddr == IntPtr.Zero) continue;
                var nb = (byte*)neighborAddr.ToPointer();
                if (nb[0] == 0x4C && nb[3] == 0xB8)
                {
                    var neighborSsn = *(uint*)(nb + 4);
                    return neighborSsn + (uint)delta;
                }
            }
        }

        return 0;
    }

    public static IntPtr GetSyscallGadget()
    {
        if (_syscallGadget == IntPtr.Zero)
            Initialize();
        return _syscallGadget;
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtAllocateVirtualMemoryDelegate(
        IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits,
        ref IntPtr RegionSize, uint AllocationType, uint Protect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtFreeVirtualMemoryDelegate(
        IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, uint FreeType);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtProtectVirtualMemoryDelegate(
        IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr NumberOfBytesToProtect,
        uint NewAccessProtection, out uint OldAccessProtection);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtWriteVirtualMemoryDelegate(
        IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer,
        uint NumberOfBytesToWrite, out uint NumberOfBytesWritten);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtReadVirtualMemoryDelegate(
        IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer,
        uint NumberOfBytesToRead, out uint NumberOfBytesRead);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtOpenProcessDelegate(
        out IntPtr ProcessHandle, uint DesiredAccess,
        IntPtr ObjectAttributes, IntPtr ClientId);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtCreateThreadExDelegate(
        out IntPtr ThreadHandle, uint DesiredAccess, IntPtr ObjectAttributes,
        IntPtr ProcessHandle, IntPtr StartRoutine, IntPtr Argument,
        uint CreateFlags, IntPtr ZeroBits, IntPtr StackSize,
        IntPtr MaximumStackSize, IntPtr AttributeList);

    public static int NtAllocateVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref IntPtr regionSize, uint allocationType, uint protect)
    {
        using var stub = new SyscallStub(GetSyscallNumber("NtAllocateVirtualMemory"), GetSyscallGadget());
        var del = Marshal.GetDelegateForFunctionPointer<NtAllocateVirtualMemoryDelegate>(stub.StubAddress);
        return del(processHandle, ref baseAddress, IntPtr.Zero, ref regionSize, allocationType, protect);
    }

    public static int NtFreeVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref IntPtr regionSize, uint freeType)
    {
        using var stub = new SyscallStub(GetSyscallNumber("NtFreeVirtualMemory"), GetSyscallGadget());
        var del = Marshal.GetDelegateForFunctionPointer<NtFreeVirtualMemoryDelegate>(stub.StubAddress);
        return del(processHandle, ref baseAddress, ref regionSize, freeType);
    }

    public static int NtProtectVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref IntPtr numberOfBytes, uint newProtect, out uint oldProtect)
    {
        using var stub = new SyscallStub(GetSyscallNumber("NtProtectVirtualMemory"), GetSyscallGadget());
        var del = Marshal.GetDelegateForFunctionPointer<NtProtectVirtualMemoryDelegate>(stub.StubAddress);
        return del(processHandle, ref baseAddress, ref numberOfBytes, newProtect, out oldProtect);
    }

    public static int NtWriteVirtualMemory(IntPtr processHandle, IntPtr baseAddress, byte[] buffer, out uint bytesWritten)
    {
        using var stub = new SyscallStub(GetSyscallNumber("NtWriteVirtualMemory"), GetSyscallGadget());
        var del = Marshal.GetDelegateForFunctionPointer<NtWriteVirtualMemoryDelegate>(stub.StubAddress);
        return del(processHandle, baseAddress, buffer, (uint)buffer.Length, out bytesWritten);
    }

    public static int NtReadVirtualMemory(IntPtr processHandle, IntPtr baseAddress, byte[] buffer, out uint bytesRead)
    {
        using var stub = new SyscallStub(GetSyscallNumber("NtReadVirtualMemory"), GetSyscallGadget());
        var del = Marshal.GetDelegateForFunctionPointer<NtReadVirtualMemoryDelegate>(stub.StubAddress);
        return del(processHandle, baseAddress, buffer, (uint)buffer.Length, out bytesRead);
    }

    public static int NtOpenProcess(out IntPtr processHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr clientId)
    {
        using var stub = new SyscallStub(GetSyscallNumber("NtOpenProcess"), GetSyscallGadget());
        var del = Marshal.GetDelegateForFunctionPointer<NtOpenProcessDelegate>(stub.StubAddress);
        return del(out processHandle, desiredAccess, objectAttributes, clientId);
    }

    public static int NtCreateThreadEx(out IntPtr threadHandle, uint desiredAccess, IntPtr processHandle, IntPtr startRoutine, IntPtr argument, uint createFlags)
    {
        using var stub = new SyscallStub(GetSyscallNumber("NtCreateThreadEx"), GetSyscallGadget());
        var del = Marshal.GetDelegateForFunctionPointer<NtCreateThreadExDelegate>(stub.StubAddress);
        return del(out threadHandle, desiredAccess, IntPtr.Zero, processHandle, startRoutine, argument, createFlags, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
    }

    public static bool IsHooked(string functionName)
    {
        if (_ntdllBase == IntPtr.Zero) Initialize();
        var funcAddr = GetProcAddress(_ntdllBase, functionName);
        if (funcAddr == IntPtr.Zero) return false;

        var bytes = (byte*)funcAddr.ToPointer();
        return !(bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 && bytes[3] == 0xB8);
    }

    public static Dictionary<string, bool> AuditNtFunctions(IEnumerable<string> functionNames)
    {
        if (_ntdllBase == IntPtr.Zero) Initialize();
        var results = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in functionNames)
            results[name] = IsHooked(name);
        return results;
    }
}
