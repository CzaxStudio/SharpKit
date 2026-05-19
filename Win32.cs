using System.Runtime.InteropServices;
using System.Text;

namespace SharpKit;

public static class Win32
{
    // -------------------------------------------------------------------------
    // Process access rights
    // ---------------------------------------------------------------------
    public const uint PROCESS_ALL_ACCESS = 0x001FFFFF;
    public const uint PROCESS_VM_READ = 0x0010;
    public const uint PROCESS_VM_WRITE = 0x0020;
    public const uint PROCESS_VM_OPERATION = 0x0008;
    public const uint PROCESS_CREATE_THREAD = 0x0002;
    public const uint PROCESS_QUERY_INFORMATION = 0x0400;
    public const uint PROCESS_QUERY_LIMITED = 0x1000;
    public const uint PROCESS_DUP_HANDLE = 0x0040;
    public const uint PROCESS_SET_INFORMATION = 0x0200;
    public const uint PROCESS_SUSPEND_RESUME = 0x0800;
    public const uint PROCESS_TERMINATE = 0x0001;

    // ---------------------------------------------------------------
    // Thread access rights
    // -------------------------------------------------------------------------
    public const uint THREAD_ALL_ACCESS = 0x001FFFFF;
    public const uint THREAD_GET_CONTEXT = 0x0008;
    public const uint THREAD_SET_CONTEXT = 0x0010;
    public const uint THREAD_SUSPEND_RESUME = 0x0002;
    public const uint THREAD_QUERY_INFORMATION = 0x0040;
    public const uint THREAD_SET_INFORMATION = 0x0020;
    public const uint THREAD_SET_THREAD_TOKEN = 0x0080;
    public const uint THREAD_TERMINATE = 0x0001;

    // ----------------------------------------------------------------
    // Token access rights
    // -------------------------------------------------------------------------
    public const uint TOKEN_ALL_ACCESS = 0x000F01FF;
    public const uint TOKEN_QUERY = 0x0008;
    public const uint TOKEN_QUERY_SOURCE = 0x0010;
    public const uint TOKEN_IMPERSONATE = 0x0004;
    public const uint TOKEN_DUPLICATE = 0x0002;
    public const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
    public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    public const uint TOKEN_ADJUST_GROUPS = 0x0040;
    public const uint TOKEN_ADJUST_DEFAULT = 0x0080;
    public const uint TOKEN_ADJUST_SESSIONID = 0x0100;

    // ------------------------------------------------------------------
    // Memory flags
    // -------------------------------------------------------------------------
    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_RESERVE = 0x2000;
    public const uint MEM_DECOMMIT = 0x4000;
    public const uint MEM_RELEASE = 0x8000;
    public const uint MEM_RESET = 0x00080000;
    public const uint MEM_LARGE_PAGES = 0x20000000;
    public const uint MEM_MAPPED = 0x00040000;
    public const uint MEM_PRIVATE = 0x00020000;
    public const uint MEM_IMAGE = 0x01000000;

    // ----------------------------------------------------------------------------------------
    // Page protection
    // -------------------------------------------------------------------------
    public const uint PAGE_NOACCESS = 0x01;
    public const uint PAGE_READONLY = 0x02;
    public const uint PAGE_READWRITE = 0x04;
    public const uint PAGE_WRITECOPY = 0x08;
    public const uint PAGE_EXECUTE = 0x10;
    public const uint PAGE_EXECUTE_READ = 0x20;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint PAGE_EXECUTE_WRITECOPY = 0x80;
    public const uint PAGE_GUARD = 0x100;
    public const uint PAGE_NOCACHE = 0x200;
    public const uint PAGE_WRITECOMBINE = 0x400;

    // -------------------------------------------------------------------------
    // Process creation flags
    // -------------------------------------------------------------------------
    public const uint CREATE_SUSPENDED = 0x00000004;
    public const uint CREATE_NO_WINDOW = 0x08000000;
    public const uint CREATE_NEW_CONSOLE = 0x00000010;
    public const uint CREATE_NEW_PROCESS_GROUP = 0x00000200;
    public const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    public const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    public const uint DETACHED_PROCESS = 0x00000008;

    // -------------------------------------------------------------------------
    // File / named pipe / I/O
    // ------------------------------------------------------------------------------------------
    public const uint GENERIC_READ = 0x80000000;
    public const uint GENERIC_WRITE = 0x40000000;
    public const uint GENERIC_EXECUTE = 0x20000000;
    public const uint GENERIC_ALL = 0x10000000;
    public const uint FILE_SHARE_READ = 0x00000001;
    public const uint FILE_SHARE_WRITE = 0x00000002;
    public const uint FILE_SHARE_DELETE = 0x00000004;
    public const uint OPEN_EXISTING = 3;
    public const uint CREATE_ALWAYS = 2;
    public const uint CREATE_NEW = 1;
    public const uint OPEN_ALWAYS = 4;
    public const uint TRUNCATE_EXISTING = 5;
    public const uint FILE_ATTRIBUTE_NORMAL = 0x80;
    public const uint FILE_ATTRIBUTE_HIDDEN = 0x02;
    public const uint FILE_FLAG_OVERLAPPED = 0x40000000;
    public const uint FILE_FLAG_NO_BUFFERING = 0x20000000;
    public const uint FILE_FLAG_WRITE_THROUGH = 0x80000000;

    public const uint PIPE_ACCESS_DUPLEX = 0x00000003;
    public const uint PIPE_ACCESS_INBOUND = 0x00000001;
    public const uint PIPE_ACCESS_OUTBOUND = 0x00000002;
    public const uint PIPE_TYPE_BYTE = 0x00000000;
    public const uint PIPE_TYPE_MESSAGE = 0x00000004;
    public const uint PIPE_READMODE_BYTE = 0x00000000;
    public const uint PIPE_READMODE_MESSAGE = 0x00000002;
    public const uint PIPE_WAIT = 0x00000000;
    public const uint PIPE_NOWAIT = 0x00000001;
    public const uint PIPE_UNLIMITED_INSTANCES = 255;
    public const uint NMPWAIT_WAIT_FOREVER = 0xFFFFFFFF;
    public const uint NMPWAIT_NOWAIT = 0x00000001;

    // ---------------------------------------------------------------------------------
    // Service control manager
    // -------------------------------------------------------------------------
    public const uint SC_MANAGER_ALL_ACCESS = 0xF003F;
    public const uint SC_MANAGER_CONNECT = 0x0001;
    public const uint SC_MANAGER_CREATE_SERVICE = 0x0002;
    public const uint SC_MANAGER_ENUMERATE_SERVICE = 0x0004;
    public const uint SC_MANAGER_LOCK = 0x0008;
    public const uint SC_MANAGER_QUERY_LOCK_STATUS = 0x0010;
    public const uint SC_MANAGER_MODIFY_BOOT_CONFIG = 0x0020;
    public const uint SERVICE_ALL_ACCESS = 0xF01FF;
    public const uint SERVICE_QUERY_CONFIG = 0x0001;
    public const uint SERVICE_CHANGE_CONFIG = 0x0002;
    public const uint SERVICE_QUERY_STATUS = 0x0004;
    public const uint SERVICE_ENUMERATE_DEPENDENTS = 0x0008;
    public const uint SERVICE_START = 0x0010;
    public const uint SERVICE_STOP = 0x0020;
    public const uint SERVICE_PAUSE_CONTINUE = 0x0040;
    public const uint SERVICE_WIN32_OWN_PROCESS = 0x00000010;
    public const uint SERVICE_DEMAND_START = 0x00000003;
    public const uint SERVICE_AUTO_START = 0x00000002;
    public const uint SERVICE_ERROR_NORMAL = 0x00000001;
    public const uint SERVICE_CONTROL_STOP = 0x00000001;
    public const uint SERVICE_CONTROL_PAUSE = 0x00000002;
    public const uint SERVICE_CONTROL_CONTINUE = 0x00000003;
    public const uint SERVICE_RUNNING = 0x00000004;
    public const uint SERVICE_STOPPED = 0x00000001;

    // -----------------------------------------------------------------
    // Registry
    // -------------------------------------------------------------------------
    public const uint KEY_READ = 0x20019;
    public const uint KEY_WRITE = 0x20006;
    public const uint KEY_ALL_ACCESS = 0xF003F;
    public const uint KEY_QUERY_VALUE = 0x0001;
    public const uint KEY_SET_VALUE = 0x0002;
    public const uint KEY_CREATE_SUB_KEY = 0x0004;
    public const uint KEY_ENUMERATE_SUB_KEYS = 0x0008;
    public const uint KEY_WOW64_64KEY = 0x0100;
    public const uint KEY_WOW64_32KEY = 0x0200;
    public static readonly IntPtr HKEY_LOCAL_MACHINE = new(-2147483646);
    public static readonly IntPtr HKEY_CURRENT_USER = new(-2147483647);
    public static readonly IntPtr HKEY_CLASSES_ROOT = new(-2147483648);
    public static readonly IntPtr HKEY_USERS = new(-2147483645);
    public const uint REG_SZ = 1;
    public const uint REG_EXPAND_SZ = 2;
    public const uint REG_BINARY = 3;
    public const uint REG_DWORD = 4;
    public const uint REG_QWORD = 11;
    public const uint REG_MULTI_SZ = 7;

    // --------------------------------------------------------------
    // Synchronisation / handle flags
    // -------------------------------------------------------------------------
    public const uint INFINITE = 0xFFFFFFFF;
    public const uint WAIT_OBJECT_0 = 0x00000000;
    public const uint WAIT_TIMEOUT = 0x00000102;
    public const uint WAIT_ABANDONED = 0x00000080;
    public const uint WAIT_FAILED = 0xFFFFFFFF;
    public const int DUPLICATE_SAME_ACCESS = 0x2;
    public const int DUPLICATE_CLOSE_SOURCE = 0x1;
    public const int STARTF_USESTDHANDLES = 0x100;
    public const int STARTF_USESHOWWINDOW = 0x001;

    // --------------------------------------------------------------
    // Token / privilege misc
    // -------------------------------------------------------------------------
    public const uint SE_PRIVILEGE_ENABLED = 0x00000002;
    public const uint SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;
    public const uint SE_PRIVILEGE_REMOVED = 0x00000004;
    public const uint TOKEN_ELEVATION_TYPE = 18;
    public const int SecurityAnonymous = 0;
    public const int SecurityIdentification = 1;
    public const int SecurityImpersonation = 2;
    public const int SecurityDelegation = 3;
    public const int TokenPrimary = 1;
    public const int TokenImpersonation = 2;

    // ----------------------------------------------------
    // Structs
    // -------------------------------------------------------------------------

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public uint cb;
        public string? lpReserved;
        public string? lpDesktop;
        public string? lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public LUID_AND_ATTRIBUTES[] Privileges;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_INFO
    {
        public ushort wProcessorArchitecture;
        public ushort wReserved;
        public uint dwPageSize;
        public IntPtr lpMinimumApplicationAddress;
        public IntPtr lpMaximumApplicationAddress;
        public IntPtr dwActiveProcessorMask;
        public uint dwNumberOfProcessors;
        public uint dwProcessorType;
        public uint dwAllocationGranularity;
        public ushort wProcessorLevel;
        public ushort wProcessorRevision;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct OVERLAPPED
    {
        public IntPtr Internal;
        public IntPtr InternalHigh;
        public uint Offset;
        public uint OffsetHigh;
        public IntPtr hEvent;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SERVICE_STATUS
    {
        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_ATTRIBUTES
    {
        public uint Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CLIENT_ID
    {
        public IntPtr UniqueProcess;
        public IntPtr UniqueThread;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IO_STATUS_BLOCK
    {
        public IntPtr Status;
        public IntPtr Information;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_HANDLE_TABLE_ENTRY_INFO
    {
        public ushort UniqueProcessId;
        public ushort CreatorBackTraceIndex;
        public byte ObjectTypeIndex;
        public byte HandleAttributes;
        public ushort HandleValue;
        public IntPtr Object;
        public uint GrantedAccess;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORYSTATUSEX
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

    // -------------------------------------------------------------------------
    // kernel32 — process / thread
    // -------------------------------------------------------------------------

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    public static extern uint GetCurrentProcessId();

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentThread();

    [DllImport("kernel32.dll")]
    public static extern uint GetCurrentThreadId();

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SuspendThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetExitCodeThread(IntPtr hThread, out uint lpExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool TerminateThread(IntPtr hThread, uint dwExitCode);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcess(
        string? lpApplicationName,
        string lpCommandLine,
        ref SECURITY_ATTRIBUTES lpProcessAttributes,
        ref SECURITY_ATTRIBUTES lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string? lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateRemoteThread(
        IntPtr hProcess,
        IntPtr lpThreadAttributes,
        uint dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        uint dwCreationFlags,
        out uint lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DuplicateHandle(
        IntPtr hSourceProcessHandle,
        IntPtr hSourceHandle,
        IntPtr hTargetProcessHandle,
        out IntPtr lpTargetHandle,
        uint dwDesiredAccess,
        bool bInheritHandle,
        uint dwOptions);

    // -------------------------------------------------------------------------
    // kernel32 — memory
    // -------------------------------------------------------------------------

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint dwFreeType);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualFree(IntPtr lpAddress, int dwSize, uint dwFreeType);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [DllImport("kernel32.dll")]
    public static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

    // -------------------------------------------------------------------------
    // kernel32 — synchronisation
    // -------------------------------------------------------------------------

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForMultipleObjects(uint nCount, IntPtr[] lpHandles, bool bWaitAll, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr CreateEvent(IntPtr lpEventAttributes, bool bManualReset, bool bInitialState, string? lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetEvent(IntPtr hEvent);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ResetEvent(IntPtr hEvent);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr CreateMutex(IntPtr lpMutexAttributes, bool bInitialOwner, string? lpName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr OpenMutex(uint dwDesiredAccess, bool bInheritHandle, string lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReleaseMutex(IntPtr hMutex);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr CreateSemaphore(IntPtr lpSemaphoreAttributes, int lInitialCount, int lMaximumCount, string? lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReleaseSemaphore(IntPtr hSemaphore, int lReleaseCount, out int lpPreviousCount);

    // -------------------------------------------------------------------------
    // kernel32 — named pipes
    // -------------------------------------------------------------------------

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr CreateNamedPipe(
        string lpName,
        uint dwOpenMode,
        uint dwPipeMode,
        uint nMaxInstances,
        uint nOutBufferSize,
        uint nInBufferSize,
        uint nDefaultTimeOut,
        IntPtr lpSecurityAttributes);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ConnectNamedPipe(IntPtr hNamedPipe, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DisconnectNamedPipe(IntPtr hNamedPipe);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool WaitNamedPipe(string lpNamedPipeName, uint nTimeOut);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetNamedPipeInfo(
        IntPtr hNamedPipe,
        out uint lpFlags,
        out uint lpOutBufferSize,
        out uint lpInBufferSize,
        out uint lpMaxInstances);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetNamedPipeHandleState(
        IntPtr hNamedPipe,
        out uint lpState,
        out uint lpCurInstances,
        out uint lpMaxCollectionCount,
        out uint lpCollectDataTimeout,
        StringBuilder? lpUserName,
        uint nMaxUserNameSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool PeekNamedPipe(
        IntPtr hNamedPipe,
        byte[]? lpBuffer,
        uint nBufferSize,
        out uint lpBytesRead,
        out uint lpTotalBytesAvail,
        out uint lpBytesLeftThisMessage);

    // -------------------------------------------------------------------------
    // kernel32 — file I/O
    // -------------------------------------------------------------------------

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadFile(
        IntPtr hFile,
        byte[] lpBuffer,
        uint nNumberOfBytesToRead,
        out uint lpNumberOfBytesRead,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteFile(
        IntPtr hFile,
        byte[] lpBuffer,
        uint nNumberOfBytesToWrite,
        out uint lpNumberOfBytesWritten,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool FlushFileBuffers(IntPtr hFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetFilePointerEx(
        IntPtr hFile,
        long liDistanceToMove,
        out long lpNewFilePointer,
        uint dwMoveMethod);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetFileSizeEx(IntPtr hFile, out long lpFileSize);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, uint dwFlags);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool DeleteFile(string lpFileName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CopyFile(string lpExistingFileName, string lpNewFileName, bool bFailIfExists);

    // -------------------------------------------------------------------------
    // kernel32 — library loading
    // -------------------------------------------------------------------------

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hFile, uint dwFlags);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool FreeLibrary(IntPtr hModule);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr GetModuleHandle(string? moduleName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern uint GetModuleFileName(IntPtr hModule, StringBuilder lpFilename, uint nSize);

    // -------------------------------------------------------------------------
    // kernel32 — misc
    // -------------------------------------------------------------------------

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool IsWow64Process(IntPtr hProcess, out bool wow64Process);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool QueryFullProcessImageName(
        IntPtr hProcess,
        uint dwFlags,
        StringBuilder lpExeName,
        ref uint lpdwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool pbDebuggerPresent);

    [DllImport("kernel32.dll")]
    public static extern bool IsDebuggerPresent();

    [DllImport("kernel32.dll")]
    public static extern void OutputDebugString(string lpOutputString);

    // -------------------------------------------------------------------------
    // advapi32 — token
    // -------------------------------------------------------------------------

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenThreadToken(IntPtr ThreadHandle, uint DesiredAccess, bool OpenAsSelf, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool DuplicateTokenEx(
        IntPtr hExistingToken,
        uint dwDesiredAccess,
        IntPtr lpTokenAttributes,
        int ImpersonationLevel,
        int TokenType,
        out IntPtr phNewToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool GetTokenInformation(
        IntPtr hToken,
        uint TokenInformationClass,
        IntPtr TokenInformation,
        uint TokenInformationLength,
        out uint ReturnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool SetTokenInformation(
        IntPtr hToken,
        uint TokenInformationClass,
        IntPtr TokenInformation,
        uint TokenInformationLength);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LookupPrivilegeValue(string? lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LookupPrivilegeName(
        string? lpSystemName,
        ref LUID lpLuid,
        StringBuilder lpName,
        ref uint cchName);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(
        IntPtr TokenHandle,
        bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState,
        uint BufferLength,
        IntPtr PreviousState,
        IntPtr ReturnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool ImpersonateNamedPipeClient(IntPtr hNamedPipe);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool RevertToSelf();

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessWithTokenW(
        IntPtr hToken,
        uint dwLogonFlags,
        string? lpApplicationName,
        string lpCommandLine,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string? lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessAsUser(
        IntPtr hToken,
        string? lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string? lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LogonUser(
        string lpszUsername,
        string lpszDomain,
        string lpszPassword,
        int dwLogonType,
        int dwLogonProvider,
        out IntPtr phToken);

    // -------------------------------------------------------------------------
    // advapi32 — service control manager
    // -------------------------------------------------------------------------

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr OpenSCManager(string? lpMachineName, string? lpDatabaseName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr CreateService(
        IntPtr hSCManager,
        string lpServiceName,
        string lpDisplayName,
        uint dwDesiredAccess,
        uint dwServiceType,
        uint dwStartType,
        uint dwErrorControl,
        string lpBinaryPathName,
        string? lpLoadOrderGroup,
        IntPtr lpdwTagId,
        string? lpDependencies,
        string? lpServiceStartName,
        string? lpPassword);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool StartService(IntPtr hService, uint dwNumServiceArgs, string[]? lpServiceArgVectors);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool ControlService(IntPtr hService, uint dwControl, out SERVICE_STATUS lpServiceStatus);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool DeleteService(IntPtr hService);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool QueryServiceStatus(IntPtr hService, out SERVICE_STATUS lpServiceStatus);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool CloseServiceHandle(IntPtr hSCObject);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool ChangeServiceConfig(
        IntPtr hService,
        uint dwServiceType,
        uint dwStartType,
        uint dwErrorControl,
        string? lpBinaryPathName,
        string? lpLoadOrderGroup,
        IntPtr lpdwTagId,
        string? lpDependencies,
        string? lpServiceStartName,
        string? lpPassword,
        string? lpDisplayName);

    // -------------------------------------------------------------------------
    // advapi32 — registry
    // -------------------------------------------------------------------------

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int RegOpenKeyEx(IntPtr hKey, string subKey, uint options, uint samDesired, out IntPtr phkResult);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int RegCreateKeyEx(
        IntPtr hKey,
        string lpSubKey,
        uint Reserved,
        string? lpClass,
        uint dwOptions,
        uint samDesired,
        IntPtr lpSecurityAttributes,
        out IntPtr phkResult,
        out uint lpdwDisposition);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int RegQueryValueEx(
        IntPtr hKey,
        string lpValueName,
        IntPtr lpReserved,
        out uint lpType,
        byte[]? lpData,
        ref uint lpcbData);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int RegSetValueEx(
        IntPtr hKey,
        string lpValueName,
        uint Reserved,
        uint dwType,
        byte[] lpData,
        uint cbData);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int RegDeleteValue(IntPtr hKey, string lpValueName);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int RegDeleteKeyEx(IntPtr hKey, string lpSubKey, uint samDesired, uint Reserved);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int RegEnumKeyEx(
        IntPtr hKey,
        uint dwIndex,
        StringBuilder lpName,
        ref uint lpcchName,
        IntPtr lpReserved,
        StringBuilder? lpClass,
        IntPtr lpcchClass,
        out long lpftLastWriteTime);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int RegEnumValue(
        IntPtr hKey,
        uint dwIndex,
        StringBuilder lpValueName,
        ref uint lpcchValueName,
        IntPtr lpReserved,
        out uint lpType,
        byte[]? lpData,
        ref uint lpcbData);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern int RegCloseKey(IntPtr hKey);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int RegConnectRegistry(string? lpMachineName, IntPtr hKey, out IntPtr phkResult);

    // -------------------------------------------------------------------------
    // ntdll
    // -------------------------------------------------------------------------

    [DllImport("ntdll.dll", SetLastError = true)]
    public static extern int NtQueryInformationProcess(
        IntPtr ProcessHandle,
        int ProcessInformationClass,
        IntPtr ProcessInformation,
        uint ProcessInformationLength,
        out uint ReturnLength);

    [DllImport("ntdll.dll")]
    public static extern int NtSetInformationProcess(
        IntPtr ProcessHandle,
        int ProcessInformationClass,
        IntPtr ProcessInformation,
        uint ProcessInformationLength);

    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationThread(
        IntPtr ThreadHandle,
        int ThreadInformationClass,
        IntPtr ThreadInformation,
        uint ThreadInformationLength,
        out uint ReturnLength);

    [DllImport("ntdll.dll")]
    public static extern int NtSetInformationThread(
        IntPtr ThreadHandle,
        int ThreadInformationClass,
        IntPtr ThreadInformation,
        uint ThreadInformationLength);

    [DllImport("ntdll.dll")]
    public static extern int NtSuspendProcess(IntPtr ProcessHandle);

    [DllImport("ntdll.dll")]
    public static extern int NtResumeProcess(IntPtr ProcessHandle);

    [DllImport("ntdll.dll")]
    public static extern int NtTerminateProcess(IntPtr ProcessHandle, uint ExitStatus);

    [DllImport("ntdll.dll")]
    public static extern int NtQuerySystemInformation(
        int SystemInformationClass,
        IntPtr SystemInformation,
        uint SystemInformationLength,
        out uint ReturnLength);

    [DllImport("ntdll.dll")]
    public static extern int NtQueryObject(
        IntPtr ObjectHandle,
        int ObjectInformationClass,
        IntPtr ObjectInformation,
        uint ObjectInformationLength,
        out uint ReturnLength);

    [DllImport("ntdll.dll")]
    public static extern int NtDuplicateObject(
        IntPtr SourceProcessHandle,
        IntPtr SourceHandle,
        IntPtr TargetProcessHandle,
        out IntPtr TargetHandle,
        uint DesiredAccess,
        uint HandleAttributes,
        uint Options);

    [DllImport("ntdll.dll")]
    public static extern int NtClose(IntPtr Handle);

    [DllImport("ntdll.dll")]
    public static extern int NtOpenProcess(
        out IntPtr ProcessHandle,
        uint DesiredAccess,
        ref OBJECT_ATTRIBUTES ObjectAttributes,
        ref CLIENT_ID ClientId);

    [DllImport("ntdll.dll")]
    public static extern int NtOpenThread(
        out IntPtr ThreadHandle,
        uint DesiredAccess,
        ref OBJECT_ATTRIBUTES ObjectAttributes,
        ref CLIENT_ID ClientId);

    [DllImport("ntdll.dll")]
    public static extern int NtDelayExecution(bool Alertable, ref long DelayInterval);

    [DllImport("ntdll.dll")]
    public static extern int NtFlushInstructionCache(
        IntPtr ProcessHandle,
        IntPtr BaseAddress,
        uint NumberOfBytesToFlush);

    [DllImport("ntdll.dll")]
    public static extern int NtQueryVirtualMemory(
        IntPtr ProcessHandle,
        IntPtr BaseAddress,
        int MemoryInformationClass,
        out MEMORY_BASIC_INFORMATION MemoryInformation,
        uint MemoryInformationLength,
        out uint ReturnLength);

    // -------------------------------------------------------------------------
    // Managed helpers — privilege
    // -------------------------------------------------------------------------

    public static bool EnablePrivilege(IntPtr tokenHandle, string privilege)
    {
        if (!LookupPrivilegeValue(null, privilege, out var luid))
            return false;

        var tp = new TOKEN_PRIVILEGES
        {
            PrivilegeCount = 1,
            Privileges = [new LUID_AND_ATTRIBUTES { Luid = luid, Attributes = SE_PRIVILEGE_ENABLED }]
        };

        return AdjustTokenPrivileges(tokenHandle, false, ref tp, (uint)Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero);
    }

    public static bool EnableCurrentProcessPrivilege(string privilege)
    {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out var token))
            return false;

        try { return EnablePrivilege(token, privilege); }
        finally { CloseHandle(token); }
    }

    public static bool DisablePrivilege(IntPtr tokenHandle, string privilege)
    {
        if (!LookupPrivilegeValue(null, privilege, out var luid))
            return false;

        var tp = new TOKEN_PRIVILEGES
        {
            PrivilegeCount = 1,
            Privileges = [new LUID_AND_ATTRIBUTES { Luid = luid, Attributes = 0 }]
        };

        return AdjustTokenPrivileges(tokenHandle, false, ref tp, (uint)Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero);
    }

    public static string? LookupPrivilegeName(LUID luid)
    {
        var sb = new StringBuilder(256);
        var size = (uint)sb.Capacity;
        return LookupPrivilegeName(null, ref luid, sb, ref size) ? sb.ToString() : null;
    }

    // -------------------------------------------------------------------------
    // Managed helpers — memory
    // -------------------------------------------------------------------------

    public static byte[] ReadMemory(IntPtr hProcess, IntPtr address, int size)
    {
        var buffer = new byte[size];
        ReadProcessMemory(hProcess, address, buffer, size, out _);
        return buffer;
    }

    public static bool WriteMemory(IntPtr hProcess, IntPtr address, byte[] data)
        => WriteProcessMemory(hProcess, address, data, data.Length, out _);

    public static List<MEMORY_BASIC_INFORMATION> EnumerateMemoryRegions(IntPtr hProcess)
    {
        var regions = new List<MEMORY_BASIC_INFORMATION>();
        GetSystemInfo(out var sysInfo);

        var address = sysInfo.lpMinimumApplicationAddress;
        var maxAddress = sysInfo.lpMaximumApplicationAddress;
        var size = (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();

        while (address.ToInt64() < maxAddress.ToInt64())
        {
            if (VirtualQueryEx(hProcess, address, out var mbi, size) == 0) break;
            regions.Add(mbi);
            address = new IntPtr(address.ToInt64() + mbi.RegionSize.ToInt64());
        }

        return regions;
    }

    public static List<MEMORY_BASIC_INFORMATION> EnumerateMemoryRegions(
        IntPtr hProcess, uint stateFilter, uint protectFilter)
    {
        return EnumerateMemoryRegions(hProcess)
            .Where(r => (stateFilter == 0 || r.State == stateFilter)
                     && (protectFilter == 0 || (r.Protect & protectFilter) != 0))
            .ToList();
    }

    public static bool IsPeHeader(IntPtr hProcess, IntPtr address)
    {
        var h = ReadMemory(hProcess, address, 2);
        return h.Length == 2 && h[0] == 0x4D && h[1] == 0x5A;
    }

    public static ulong GetTotalPhysicalMemory()
    {
        var mem = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
        GlobalMemoryStatusEx(ref mem);
        return mem.ullTotalPhys;
    }

    public static ulong GetAvailablePhysicalMemory()
    {
        var mem = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
        GlobalMemoryStatusEx(ref mem);
        return mem.ullAvailPhys;
    }

    // -------------------------------------------------------------------------
    // Managed helpers — process
    // -------------------------------------------------------------------------

    public static string? GetProcessImagePath(int pid)
    {
        var hProc = OpenProcess(PROCESS_QUERY_LIMITED, false, pid);
        if (hProc == IntPtr.Zero)
            hProc = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
        if (hProc == IntPtr.Zero) return null;

        try
        {
            var sb = new StringBuilder(1024);
            var size = (uint)sb.Capacity;
            return QueryFullProcessImageName(hProc, 0, sb, ref size) ? sb.ToString() : null;
        }
        finally { CloseHandle(hProc); }
    }

    public static bool Is64BitProcess(IntPtr hProcess)
    {
        if (!IsWow64Process(hProcess, out var isWow64)) return false;
        return !isWow64 && Environment.Is64BitOperatingSystem;
    }

    // -------------------------------------------------------------------------
    // Managed helpers — named pipes
    // -------------------------------------------------------------------------

    public static IntPtr CreateServerPipe(string name,
        uint maxInstances = PIPE_UNLIMITED_INSTANCES, uint bufferSize = 65536)
    {
        var fullName = name.StartsWith(@"\\.\pipe\") ? name : $@"\\.\pipe\{name}";
        return CreateNamedPipe(fullName,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            maxInstances, bufferSize, bufferSize, 0, IntPtr.Zero);
    }

    public static IntPtr ConnectToPipe(string name, uint access = 0)
    {
        if (access == 0) access = GENERIC_READ | GENERIC_WRITE;
        var fullName = name.StartsWith(@"\\.\pipe\") ? name : $@"\\.\pipe\{name}";
        return CreateFile(fullName, access, 0, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
    }

    public static bool PipeWrite(IntPtr hPipe, byte[] data)
    {
        WriteFile(hPipe, data, (uint)data.Length, out var written, IntPtr.Zero);
        return written == data.Length;
    }

    public static byte[] PipeRead(IntPtr hPipe, uint maxBytes = 65536)
    {
        var buf = new byte[maxBytes];
        ReadFile(hPipe, buf, maxBytes, out var read, IntPtr.Zero);
        var result = new byte[read];
        Buffer.BlockCopy(buf, 0, result, 0, (int)read);
        return result;
    }

    public static uint PipeBytesAvailable(IntPtr hPipe)
    {
        PeekNamedPipe(hPipe, null, 0, out _, out var avail, out _);
        return avail;
    }

    // -------------------------------------------------------------------------
    // Managed helpers — registry
    // -------------------------------------------------------------------------

    public static string? RegReadString(IntPtr hKey, string valueName)
    {
        var size = 0u;
        RegQueryValueEx(hKey, valueName, IntPtr.Zero, out _, null, ref size);
        if (size == 0) return null;
        var data = new byte[size];
        if (RegQueryValueEx(hKey, valueName, IntPtr.Zero, out _, data, ref size) != 0) return null;
        return Encoding.Unicode.GetString(data).TrimEnd('\0');
    }

    public static bool RegWriteString(IntPtr hKey, string valueName, string value)
    {
        var data = Encoding.Unicode.GetBytes(value + '\0');
        return RegSetValueEx(hKey, valueName, 0, REG_SZ, data, (uint)data.Length) == 0;
    }

    public static uint? RegReadDword(IntPtr hKey, string valueName)
    {
        var size = 4u;
        var data = new byte[4];
        if (RegQueryValueEx(hKey, valueName, IntPtr.Zero, out _, data, ref size) != 0) return null;
        return BitConverter.ToUInt32(data, 0);
    }

    public static bool RegWriteDword(IntPtr hKey, string valueName, uint value)
    {
        var data = BitConverter.GetBytes(value);
        return RegSetValueEx(hKey, valueName, 0, REG_DWORD, data, 4) == 0;
    }

    public static byte[]? RegReadBinary(IntPtr hKey, string valueName)
    {
        var size = 0u;
        RegQueryValueEx(hKey, valueName, IntPtr.Zero, out _, null, ref size);
        if (size == 0) return null;
        var data = new byte[size];
        if (RegQueryValueEx(hKey, valueName, IntPtr.Zero, out _, data, ref size) != 0) return null;
        return data;
    }

    public static bool RegWriteBinary(IntPtr hKey, string valueName, byte[] value)
        => RegSetValueEx(hKey, valueName, 0, REG_BINARY, value, (uint)value.Length) == 0;

    public static List<string> RegEnumSubKeys(IntPtr hKey)
    {
        var results = new List<string>();
        var sb = new StringBuilder(256);
        var idx = 0u;
        while (true)
        {
            var len = (uint)sb.Capacity;
            if (RegEnumKeyEx(hKey, idx++, sb, ref len, IntPtr.Zero, null, IntPtr.Zero, out _) != 0)
                break;
            results.Add(sb.ToString());
        }
        return results;
    }

    public static List<string> RegEnumValueNames(IntPtr hKey)
    {
        var results = new List<string>();
        var sb = new StringBuilder(256);
        var idx = 0u;
        while (true)
        {
            var nameLen = (uint)sb.Capacity;
            var dataLen = 0u;
            if (RegEnumValue(hKey, idx++, sb, ref nameLen, IntPtr.Zero, out _, null, ref dataLen) != 0)
                break;
            results.Add(sb.ToString());
        }
        return results;
    }

    // -------------------------------------------------------------------------
    // Managed helpers — service control
    // -------------------------------------------------------------------------

    public static bool ServiceExists(string serviceName, string? machineName = null)
    {
        var hScm = OpenSCManager(machineName, null, SC_MANAGER_CONNECT);
        if (hScm == IntPtr.Zero) return false;
        try
        {
            var hSvc = OpenService(hScm, serviceName, SERVICE_QUERY_STATUS);
            if (hSvc == IntPtr.Zero) return false;
            CloseServiceHandle(hSvc);
            return true;
        }
        finally { CloseServiceHandle(hScm); }
    }

    public static uint GetServiceState(string serviceName, string? machineName = null)
    {
        var hScm = OpenSCManager(machineName, null, SC_MANAGER_CONNECT);
        if (hScm == IntPtr.Zero) return 0;
        try
        {
            var hSvc = OpenService(hScm, serviceName, SERVICE_QUERY_STATUS);
            if (hSvc == IntPtr.Zero) return 0;
            try
            {
                QueryServiceStatus(hSvc, out var status);
                return status.dwCurrentState;
            }
            finally { CloseServiceHandle(hSvc); }
        }
        finally { CloseServiceHandle(hScm); }
    }

    public static bool StartNamedService(string serviceName, string? machineName = null)
    {
        var hScm = OpenSCManager(machineName, null, SC_MANAGER_CONNECT);
        if (hScm == IntPtr.Zero) return false;
        try
        {
            var hSvc = OpenService(hScm, serviceName, SERVICE_START);
            if (hSvc == IntPtr.Zero) return false;
            try { return StartService(hSvc, 0, null); }
            finally { CloseServiceHandle(hSvc); }
        }
        finally { CloseServiceHandle(hScm); }
    }

    public static bool StopNamedService(string serviceName, string? machineName = null)
    {
        var hScm = OpenSCManager(machineName, null, SC_MANAGER_CONNECT);
        if (hScm == IntPtr.Zero) return false;
        try
        {
            var hSvc = OpenService(hScm, serviceName, SERVICE_STOP);
            if (hSvc == IntPtr.Zero) return false;
            try { return ControlService(hSvc, SERVICE_CONTROL_STOP, out _); }
            finally { CloseServiceHandle(hSvc); }
        }
        finally { CloseServiceHandle(hScm); }
    }

    // -------------------------------------------------------------------------
    // Managed helpers — synchronisation / misc
    // -------------------------------------------------------------------------

    public static void SleepNt(int milliseconds)
    {
        long delay = -10000L * milliseconds;
        NtDelayExecution(false, ref delay);
    }

    public static IntPtr WaitAny(IntPtr[] handles, uint timeoutMs = INFINITE)
    {
        var idx = WaitForMultipleObjects((uint)handles.Length, handles, false, timeoutMs);
        if (idx >= WAIT_OBJECT_0 && idx < WAIT_OBJECT_0 + handles.Length)
            return handles[idx - WAIT_OBJECT_0];
        return IntPtr.Zero;
    }

    public static bool WaitAll(IntPtr[] handles, uint timeoutMs = INFINITE)
        => WaitForMultipleObjects((uint)handles.Length, handles, true, timeoutMs) == WAIT_OBJECT_0;
}

// ================ Please contribute or star the Repo =========================
