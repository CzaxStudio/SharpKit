using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace SharpKit;

public sealed class ProcessInfo
{
    public int Pid { get; init; }
    public int ParentPid { get; init; }
    public string Name { get; init; } = string.Empty;
    public string ImagePath { get; init; } = string.Empty;
    public string Owner { get; init; } = string.Empty;
    public string CommandLine { get; init; } = string.Empty;
    public int SessionId { get; init; }
    public int ThreadCount { get; init; }
    public long WorkingSetBytes { get; init; }
    public DateTime StartTime { get; init; }
    public bool Is64Bit { get; init; }
    public List<string> LoadedModules { get; init; } = [];
}

public sealed class NetworkConnectionInfo
{
    public string Protocol { get; init; } = string.Empty;
    public IPEndPoint LocalEndPoint { get; init; } = new(IPAddress.Any, 0);
    public IPEndPoint? RemoteEndPoint { get; init; }
    public string State { get; init; } = string.Empty;
    public int OwningPid { get; init; }
}

public sealed class PrivilegeInfo
{
    public string Name { get; init; } = string.Empty;
    public bool IsEnabled { get; init; }
    public bool IsPresent { get; init; }
}

public sealed class NamedPipeInfo
{
    public string Name { get; init; } = string.Empty;
    public string FullPath { get; init; } = string.Empty;
    public int Instances { get; init; }
    public int MaxInstances { get; init; }
}

public sealed class LocalUserInfo
{
    public string Username { get; init; } = string.Empty;
    public string FullName { get; init; } = string.Empty;
    public string Comment { get; init; } = string.Empty;
    public bool IsDisabled { get; init; }
    public bool PasswordNeverExpires { get; init; }
    public bool IsLockedOut { get; init; }
    public DateTime LastLogon { get; init; }
    public List<string> GroupMemberships { get; init; } = [];
}

public static class Recon
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr hProcess, uint dwFlags, StringBuilder lpExeName, ref uint lpdwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsWow64Process(IntPtr hProcess, out bool wow64Process);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr hProcess, int infoClass, IntPtr info, uint size, out uint returnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr hProcess, uint access, out IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr hToken, int tokenInfoClass, IntPtr tokenInfo, uint tokenInfoLength, out uint returnLength);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeName(string? lpSystemName, ref Win32.LUID lpLuid, StringBuilder lpName, ref uint cchName);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr hToken, uint tokenInfoClass, IntPtr tokenInfo, uint tokenInfoLength, out uint returnLength);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFile(string lpFileName, uint dwAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool GetNamedPipeInfo(IntPtr hPipe, out uint lpFlags, out uint lpOutBufferSize, out uint lpInBufferSize, out uint lpMaxInstances);

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES_BLOCK
    {
        public uint PrivilegeCount;
        public Win32.LUID_AND_ATTRIBUTES Privilege;
    }

    private const int TokenPrivileges = 3;
    private const int TokenUser = 1;
    private const uint SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;
    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint OPEN_EXISTING = 3;

    public static List<ProcessInfo> GetRunningProcesses(bool includeModules = false)
    {
        var results = new List<ProcessInfo>();
        var processes = Process.GetProcesses();

        foreach (var proc in processes)
        {
            try
            {
                var info = new ProcessInfo
                {
                    Pid = proc.Id,
                    ParentPid = GetParentPid(proc.Id),
                    Name = proc.ProcessName,
                    ImagePath = GetProcessImagePath(proc.Id),
                    Owner = GetProcessOwner(proc.Id),
                    SessionId = proc.SessionId,
                    ThreadCount = proc.Threads.Count,
                    WorkingSetBytes = proc.WorkingSet64,
                    StartTime = GetProcessStartTime(proc),
                    Is64Bit = IsProcess64Bit(proc.Id),
                    LoadedModules = includeModules ? GetLoadedModules(proc.Id) : []
                };
                results.Add(info);
            }
            catch
            {
                results.Add(new ProcessInfo
                {
                    Pid = proc.Id,
                    Name = proc.ProcessName
                });
            }
            finally
            {
                proc.Dispose();
            }
        }

        return results.OrderBy(p => p.Pid).ToList();
    }

    public static ProcessInfo? GetProcessById(int pid, bool includeModules = false)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            return new ProcessInfo
            {
                Pid = proc.Id,
                ParentPid = GetParentPid(proc.Id),
                Name = proc.ProcessName,
                ImagePath = GetProcessImagePath(proc.Id),
                Owner = GetProcessOwner(proc.Id),
                SessionId = proc.SessionId,
                ThreadCount = proc.Threads.Count,
                WorkingSetBytes = proc.WorkingSet64,
                StartTime = GetProcessStartTime(proc),
                Is64Bit = IsProcess64Bit(proc.Id),
                LoadedModules = includeModules ? GetLoadedModules(proc.Id) : []
            };
        }
        catch
        {
            return null;
        }
    }

    public static List<ProcessInfo> FindProcessesByName(string name, bool includeModules = false)
    {
        return GetRunningProcesses(includeModules)
            .Where(p => p.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
            .ToList();
    }

    public static int? FindProcessPid(string name)
    {
        return FindProcessesByName(name).FirstOrDefault()?.Pid;
    }

    private static int GetParentPid(int pid)
    {
        try
        {
            var hProc = Win32.OpenProcess(Win32.PROCESS_QUERY_INFORMATION, false, pid);
            if (hProc == IntPtr.Zero) return -1;
            try
            {
                var pbiSize = 48u;
                var buf = Marshal.AllocHGlobal((int)pbiSize);
                try
                {
                    NtQueryInformationProcess(hProc, 0, buf, pbiSize, out _);
                    return Marshal.ReadInt32(buf, IntPtr.Size * 5);
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
            finally { Win32.CloseHandle(hProc); }
        }
        catch { return -1; }
    }

    private static string GetProcessImagePath(int pid)
    {
        var hProc = Win32.OpenProcess(Win32.PROCESS_QUERY_INFORMATION | Win32.PROCESS_VM_READ, false, pid);
        if (hProc == IntPtr.Zero) return string.Empty;
        try
        {
            var sb = new StringBuilder(1024);
            var size = (uint)sb.Capacity;
            return QueryFullProcessImageName(hProc, 0, sb, ref size) ? sb.ToString() : string.Empty;
        }
        finally { Win32.CloseHandle(hProc); }
    }

    private static string GetProcessOwner(int pid)
    {
        var hProc = Win32.OpenProcess(Win32.PROCESS_QUERY_INFORMATION, false, pid);
        if (hProc == IntPtr.Zero) return string.Empty;
        try
        {
            if (!OpenProcessToken(hProc, Win32.TOKEN_QUERY, out var hToken)) return string.Empty;
            try
            {
                using var identity = new WindowsIdentity(hToken);
                return identity.Name;
            }
            finally { Win32.CloseHandle(hToken); }
        }
        catch { return string.Empty; }
        finally { Win32.CloseHandle(hProc); }
    }

    private static DateTime GetProcessStartTime(Process proc)
    {
        try { return proc.StartTime; }
        catch { return DateTime.MinValue; }
    }

    private static bool IsProcess64Bit(int pid)
    {
        var hProc = Win32.OpenProcess(Win32.PROCESS_QUERY_INFORMATION, false, pid);
        if (hProc == IntPtr.Zero) return false;
        try
        {
            IsWow64Process(hProc, out var isWow64);
            return !isWow64 && Environment.Is64BitOperatingSystem;
        }
        finally { Win32.CloseHandle(hProc); }
    }

    public static List<string> GetLoadedModules(int pid)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            return proc.Modules.Cast<ProcessModule>()
                .Select(m => m.FileName ?? string.Empty)
                .Where(f => !string.IsNullOrEmpty(f))
                .ToList();
        }
        catch { return []; }
    }

    public static List<PrivilegeInfo> GetCurrentPrivileges()
    {
        var results = new List<PrivilegeInfo>();

        if (!OpenProcessToken(Win32.GetCurrentProcess(), Win32.TOKEN_QUERY, out var hToken))
            return results;

        try
        {
            GetTokenInformation(hToken, TokenPrivileges, IntPtr.Zero, 0, out var size);
            var buf = Marshal.AllocHGlobal((int)size);
            try
            {
                if (!GetTokenInformation(hToken, TokenPrivileges, buf, size, out _))
                    return results;

                var count = Marshal.ReadInt32(buf);
                var offset = 4;

                for (int i = 0; i < count; i++)
                {
                    var luid = new Win32.LUID
                    {
                        LowPart = (uint)Marshal.ReadInt32(buf, offset),
                        HighPart = Marshal.ReadInt32(buf, offset + 4)
                    };
                    var attributes = (uint)Marshal.ReadInt32(buf, offset + 8);
                    offset += 12;

                    var nameSb = new StringBuilder(256);
                    var nameLen = (uint)nameSb.Capacity;
                    LookupPrivilegeName(null, ref luid, nameSb, ref nameLen);

                    results.Add(new PrivilegeInfo
                    {
                        Name = nameSb.ToString(),
                        IsPresent = true,
                        IsEnabled = (attributes & Win32.SE_PRIVILEGE_ENABLED) != 0
                            || (attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) != 0
                    });
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        finally { Win32.CloseHandle(hToken); }

        return results.OrderBy(p => p.Name).ToList();
    }

    public static bool HasPrivilege(string privilegeName)
    {
        return GetCurrentPrivileges()
            .Any(p => p.Name.Equals(privilegeName, StringComparison.OrdinalIgnoreCase) && p.IsPresent);
    }

    public static bool IsElevated()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    public static bool IsSystem()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return identity.IsSystem;
        }
        catch { return false; }
    }

    public static List<NetworkConnectionInfo> GetNetworkConnections()
    {
        var results = new List<NetworkConnectionInfo>();

        try
        {
            var ipGlobal = IPGlobalProperties.GetIPGlobalProperties();

            foreach (var conn in ipGlobal.GetActiveTcpConnections())
            {
                results.Add(new NetworkConnectionInfo
                {
                    Protocol = "TCP",
                    LocalEndPoint = conn.LocalEndPoint,
                    RemoteEndPoint = conn.RemoteEndPoint,
                    State = conn.State.ToString()
                });
            }

            foreach (var listener in ipGlobal.GetActiveTcpListeners())
            {
                results.Add(new NetworkConnectionInfo
                {
                    Protocol = "TCP",
                    LocalEndPoint = listener,
                    State = "Listen"
                });
            }

            foreach (var listener in ipGlobal.GetActiveUdpListeners())
            {
                results.Add(new NetworkConnectionInfo
                {
                    Protocol = "UDP",
                    LocalEndPoint = listener,
                    State = "Listen"
                });
            }
        }
        catch { }

        return results;
    }

    public static List<string> GetNetworkInterfaces()
    {
        var results = new List<string>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            var props = nic.GetIPProperties();
            var unicast = props.UnicastAddresses
                .Select(a => a.Address.ToString())
                .ToList();

            results.Add($"{nic.Name} [{nic.NetworkInterfaceType}] MAC={nic.GetPhysicalAddress()} IPs=[{string.Join(", ", unicast)}] Status={nic.OperationalStatus}");
        }
        return results;
    }

    public static List<NamedPipeInfo> GetNamedPipes()
    {
        var results = new List<NamedPipeInfo>();

        try
        {
            var pipePath = @"\\.\pipe\";
            if (!Directory.Exists(pipePath)) return results;

            foreach (var pipe in Directory.GetFiles(pipePath))
            {
                var name = Path.GetFileName(pipe);
                var info = new NamedPipeInfo
                {
                    Name = name,
                    FullPath = pipe
                };

                var hPipe = CreateFile(pipe, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);

                if (hPipe != IntPtr.Zero && hPipe != new IntPtr(-1))
                {
                    GetNamedPipeInfo(hPipe, out _, out _, out _, out var maxInst);
                    Win32.CloseHandle(hPipe);
                    results.Add(info with { MaxInstances = (int)maxInst });
                }
                else
                {
                    results.Add(info);
                }
            }
        }
        catch { }

        return results.OrderBy(p => p.Name).ToList();
    }

    public static List<LocalUserInfo> GetLocalUsers()
    {
        var results = new List<LocalUserInfo>();

        try
        {
            var usersDir = @"C:\Users";
            if (!Directory.Exists(usersDir)) return results;

            foreach (var dir in Directory.GetDirectories(usersDir))
            {
                var username = Path.GetFileName(dir);
                if (username is "Public" or "Default" or "Default User" or "All Users") continue;

                results.Add(new LocalUserInfo
                {
                    Username = username,
                    FullName = username
                });
            }
        }
        catch { }

        return results;
    }

    public static Dictionary<string, string> GetSystemInfo()
    {
        var info = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        info["Hostname"] = Environment.MachineName;
        info["Username"] = Environment.UserName;
        info["Domain"] = Environment.UserDomainName;
        info["OS"] = Environment.OSVersion.ToString();
        info["Architecture"] = Environment.Is64BitOperatingSystem ? "x64" : "x86";
        info["ProcessArchitecture"] = Environment.Is64BitProcess ? "x64" : "x86";
        info["CLR"] = Environment.Version.ToString();
        info["ProcessorCount"] = Environment.ProcessorCount.ToString();
        info["SystemDirectory"] = Environment.SystemDirectory;
        info["TempPath"] = Path.GetTempPath();
        info["Uptime"] = TimeSpan.FromMilliseconds(Environment.TickCount64).ToString(@"d\.hh\:mm\:ss");
        info["IsElevated"] = IsElevated().ToString();
        info["IsSystem"] = IsSystem().ToString();
        info["CurrentDirectory"] = Directory.GetCurrentDirectory();
        info["CurrentPid"] = Environment.ProcessId.ToString();

        try { info["DnsDomain"] = IPGlobalProperties.GetIPGlobalProperties().DomainName; }
        catch { info["DnsDomain"] = string.Empty; }

        return info;
    }

    public static List<string> GetEnvironmentVariables()
    {
        var results = new List<string>();
        foreach (System.Collections.DictionaryEntry entry in Environment.GetEnvironmentVariables())
            results.Add($"{entry.Key}={entry.Value}");
        return results.OrderBy(s => s).ToList();
    }

    public static List<string> FindWritableDirectories(string root, int maxDepth = 3)
    {
        var results = new List<string>();
        FindWritableDirectoriesRecursive(root, 0, maxDepth, results);
        return results;
    }

    private static void FindWritableDirectoriesRecursive(string path, int depth, int maxDepth, List<string> results)
    {
        if (depth > maxDepth) return;

        try
        {
            var testFile = Path.Combine(path, $".sk_{Guid.NewGuid():N}");
            File.WriteAllText(testFile, "test");
            File.Delete(testFile);
            results.Add(path);
        }
        catch { }

        if (depth < maxDepth)
        {
            try
            {
                foreach (var dir in Directory.GetDirectories(path))
                {
                    try { FindWritableDirectoriesRecursive(dir, depth + 1, maxDepth, results); }
                    catch { }
                }
            }
            catch { }
        }
    }

    public static List<string> SearchFiles(string root, string pattern, int maxDepth = 5)
    {
        var results = new List<string>();
        SearchFilesRecursive(root, pattern, 0, maxDepth, results);
        return results;
    }

    private static void SearchFilesRecursive(string path, string pattern, int depth, int maxDepth, List<string> results)
    {
        if (depth > maxDepth) return;
        try
        {
            results.AddRange(Directory.GetFiles(path, pattern));
            foreach (var dir in Directory.GetDirectories(path))
            {
                try { SearchFilesRecursive(dir, pattern, depth + 1, maxDepth, results); }
                catch { }
            }
        }
        catch { }
    }
}
