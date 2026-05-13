using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using SharpKit;

internal static class Program
{
    private static async Task Main(string[] args)
    {
        Console.WriteLine("SharpKit Demo Runner");
        Console.WriteLine(new string('=', 60));

        await RunHttpAgentDemo();
        RunKerberosDemo();
        RunWin32Demo();
        RunInjectorDemo();
        RunSyscallsDemo();
        RunPacketCrafterDemo();
        await RunPacketCrafterAsyncDemo();
    }

    private static async Task RunHttpAgentDemo()
    {
        Console.WriteLine("\n[HttpAgent]");

        using var agent = new HttpAgent();
        agent.SetUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) SharpKit/1.0");
        agent.SetTimeout(TimeSpan.FromSeconds(10));
        agent.SetHeader("X-Custom-Header", "SharpKit");

        try
        {
            var body = await agent.GetStringAsync("https://httpbin.org/get");
            Console.WriteLine($"  GET https://httpbin.org/get -> {body.Length} chars");

            var resp = await agent.PostJsonAsync("https://httpbin.org/post", "{\"tool\":\"SharpKit\",\"op\":\"test\"}");
            Console.WriteLine($"  POST https://httpbin.org/post -> HTTP {(int)resp.StatusCode}");

            var headers = await agent.GetResponseHeadersAsync("https://httpbin.org/headers");
            Console.WriteLine($"  Response headers: {headers.Count} entries");
            foreach (var kv in headers.Take(3))
                Console.WriteLine($"    {kv.Key}: {kv.Value}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  Network unreachable (expected in offline env): {ex.Message}");
        }

        Console.WriteLine("  Proxy constructor (no connection attempt):");
        using var proxyAgent = new HttpAgent("http://127.0.0.1:8080");
        proxyAgent.SetBasicAuth("user", "pass");
        Console.WriteLine("    HttpAgent with proxy+BasicAuth constructed OK");

        using var ntlmAgent = new HttpAgent();
        ntlmAgent.SetNtlmAuth("CORP\\jsmith", "P@ssw0rd1", "CORP");
        Console.WriteLine("    HttpAgent with NTLM auth constructed OK");

        Console.WriteLine("  [HttpAgent] done");
    }

    private static void RunKerberosDemo()
    {
        Console.WriteLine("\n[Kerberos]");

        var opts = new KerberosOptions
        {
            DomainController = "dc01.corp.local",
            Port = 88,
            Timeout = TimeSpan.FromSeconds(15),
            SupportedEncTypes =
            [
                KerberosEncryptionType.Aes256CtsHmacSha196,
                KerberosEncryptionType.Aes128CtsHmacSha196,
                KerberosEncryptionType.Rc4Hmac
            ]
        };

        var asReqBytes = Kerberos.BuildAsReq("jsmith", "CORP.LOCAL", opts);
        Console.WriteLine($"  BuildAsReq -> {asReqBytes.Length} bytes, msg type=0x{asReqBytes[0]:X2}");

        var fakeTicket = new KerberosTicket
        {
            Realm = "CORP.LOCAL",
            ServiceName = "MSSQLSvc/sql01.corp.local:1433",
            ClientName = "jsmith",
            EncryptedTicket = new byte[256],
            EncryptionType = KerberosEncryptionType.Rc4Hmac,
            AuthTime = DateTime.UtcNow,
            StartTime = DateTime.UtcNow,
            EndTime = DateTime.UtcNow.AddHours(10),
            RenewTill = DateTime.UtcNow.AddDays(7),
            SessionKey = new byte[16]
        };

        var tgsReqBytes = Kerberos.BuildTgsReq(fakeTicket, "MSSQLSvc/sql01.corp.local:1433", opts);
        Console.WriteLine($"  BuildTgsReq -> {tgsReqBytes.Length} bytes");

        var apReqBytes = Kerberos.BuildApReq(fakeTicket, new byte[32]);
        Console.WriteLine($"  BuildApReq -> {apReqBytes.Length} bytes");

        var kerberoastHash = Kerberos.FormatKerberoastHash(fakeTicket);
        Console.WriteLine($"  FormatKerberoastHash -> {kerberoastHash[..60]}...");

        var kirbi = Kerberos.EncodeKirbiTicket(fakeTicket);
        Console.WriteLine($"  EncodeKirbiTicket -> {kirbi.Length} bytes, magic=0x{kirbi[0]:X2}{kirbi[1]:X2}");

        var decoded = Kerberos.DecodeKirbiTicket(kirbi);
        Console.WriteLine($"  DecodeKirbiTicket -> {(decoded == null ? "placeholder null (expected)" : "decoded")}");

        var aesKey = Kerberos.DeriveKey("P@ssw0rd1", "CORP.LOCALjsmith", KerberosEncryptionType.Aes256CtsHmacSha196);
        Console.WriteLine($"  DeriveKey AES-256 -> {aesKey.Length * 8}-bit key");

        var rc4Key = Kerberos.DeriveKey("P@ssw0rd1", "", KerberosEncryptionType.Rc4Hmac);
        Console.WriteLine($"  DeriveKey RC4 -> {rc4Key.Length * 8}-bit key");

        var s4uSelf = Kerberos.BuildS4U2SelfReq(fakeTicket, "Administrator", opts);
        Console.WriteLine($"  BuildS4U2SelfReq -> {s4uSelf.Length} bytes");

        var s4uProxy = Kerberos.BuildS4U2ProxyReq(fakeTicket, fakeTicket, "cifs/fs01.corp.local", opts);
        Console.WriteLine($"  BuildS4U2ProxyReq -> {s4uProxy.Length} bytes");

        var parsed = Kerberos.ParseAsRep(asReqBytes);
        Console.WriteLine($"  ParseAsRep (non-AS-REP input) -> {(parsed == null ? "null (correct)" : "parsed")}");

        var currentSpn = Kerberos.GetCurrentUserSpn();
        Console.WriteLine($"  GetCurrentUserSpn -> {(string.IsNullOrEmpty(currentSpn) ? "(empty)" : currentSpn)}");

        Console.WriteLine("  [Kerberos] done");
    }

    private static void RunWin32Demo()
    {
        Console.WriteLine("\n[Win32]");

        var hSelf = Win32.GetCurrentProcess();
        var selfPid = (int)Win32.GetCurrentProcessId();
        Console.WriteLine($"  GetCurrentProcess -> 0x{hSelf.ToInt64():X}");
        Console.WriteLine($"  GetCurrentProcessId -> {selfPid}");

        Win32.GetSystemInfo(out var sysInfo);
        Console.WriteLine($"  GetSystemInfo -> PageSize={sysInfo.dwPageSize}, Processors={sysInfo.dwNumberOfProcessors}");
        Console.WriteLine($"    AddressRange: 0x{sysInfo.lpMinimumApplicationAddress.ToInt64():X} - 0x{sysInfo.lpMaximumApplicationAddress.ToInt64():X}");

        var allocated = Win32.VirtualAlloc(IntPtr.Zero, 0x1000, Win32.MEM_COMMIT | Win32.MEM_RESERVE, Win32.PAGE_READWRITE);
        Console.WriteLine($"  VirtualAlloc 4KB RW -> 0x{allocated.ToInt64():X}");

        if (allocated != IntPtr.Zero)
        {
            var testData = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };
            Marshal.Copy(testData, 0, allocated, testData.Length);
            var readBack = new byte[4];
            Marshal.Copy(allocated, readBack, 0, 4);
            Console.WriteLine($"  Write/read 0xDEADBEEF -> 0x{BitConverter.ToUInt32(readBack, 0):X8}");

            Win32.VirtualProtect(allocated, 0x1000, Win32.PAGE_EXECUTE_READ, out var oldProt);
            Console.WriteLine($"  VirtualProtect RW->XR, old prot=0x{oldProt:X2}");

            Win32.VirtualFree(allocated, 0, Win32.MEM_RELEASE);
            Console.WriteLine("  VirtualFree -> OK");
        }

        var hSelfProc = Win32.OpenProcess(Win32.PROCESS_QUERY_INFORMATION | Win32.PROCESS_VM_READ, false, selfPid);
        Console.WriteLine($"  OpenProcess(self) -> 0x{hSelfProc.ToInt64():X}");

        if (hSelfProc != IntPtr.Zero)
        {
            var regions = Win32.EnumerateMemoryRegions(hSelfProc);
            var committed = regions.Count(r => r.State == 0x1000);
            var execRegions = regions.Count(r => r.State == 0x1000 && (r.Protect & 0xF0) != 0);
            Console.WriteLine($"  EnumerateMemoryRegions -> {regions.Count} total, {committed} committed, {execRegions} executable");
            Win32.CloseHandle(hSelfProc);
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            var tokenResult = Win32.OpenProcessToken(hSelf, Win32.TOKEN_QUERY | Win32.TOKEN_ADJUST_PRIVILEGES, out var hToken);
            Console.WriteLine($"  OpenProcessToken(self) -> {tokenResult}, handle=0x{hToken.ToInt64():X}");

            if (tokenResult && hToken != IntPtr.Zero)
            {
                var privResult = Win32.EnablePrivilege(hToken, "SeDebugPrivilege");
                Console.WriteLine($"  EnablePrivilege(SeDebugPrivilege) -> {privResult}");
                Win32.CloseHandle(hToken);
            }
        }

        Console.WriteLine("  [Win32] done");
    }

    private static void RunInjectorDemo()
    {
        Console.WriteLine("\n[Injector]");

        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            Console.WriteLine("  Skipped (Windows-only)");
            return;
        }

        var selfPid = (int)Win32.GetCurrentProcessId();

        var shellcode = new byte[]
        {
            0x90, 0x90, 0x90, 0x90,
            0xC3
        };

        Console.WriteLine($"  Target PID for demo: {selfPid} (self)");
        Console.WriteLine($"  Shellcode: {shellcode.Length} bytes (NOP sled + RET)");

        var crtResult = Injector.InjectCreateRemoteThread(selfPid, shellcode);
        Console.WriteLine($"  CreateRemoteThread -> Success={crtResult.Success}, Base=0x{crtResult.RemoteBaseAddress.ToInt64():X}, TID={crtResult.ThreadId}");
        if (!crtResult.Success)
            Console.WriteLine($"    Error: {crtResult.ErrorMessage} (LastError={crtResult.LastError})");

        var ntResult = Injector.InjectNtCreateThreadEx(selfPid, shellcode);
        Console.WriteLine($"  NtCreateThreadEx -> Success={ntResult.Success}, Base=0x{ntResult.RemoteBaseAddress.ToInt64():X}");

        var apcResult = Injector.InjectQueueUserAPC(selfPid, shellcode);
        Console.WriteLine($"  QueueUserAPC -> Success={apcResult.Success}");
        if (!apcResult.Success)
            Console.WriteLine($"    Error: {apcResult.ErrorMessage}");

        Console.WriteLine("  HollowProcess: skipped (requires a valid target PE path)");
        Console.WriteLine("  [Injector] done");
    }

    private static void RunSyscallsDemo()
    {
        Console.WriteLine("\n[Syscalls]");

        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            Console.WriteLine("  Skipped (Windows-only)");
            return;
        }

        Syscalls.Initialize();

        var knownFunctions = new[]
        {
            "NtAllocateVirtualMemory", "NtFreeVirtualMemory", "NtProtectVirtualMemory",
            "NtReadVirtualMemory", "NtWriteVirtualMemory", "NtCreateThreadEx",
            "NtOpenProcess", "NtClose", "NtSuspendProcess", "NtResumeProcess",
            "NtTerminateProcess", "NtOpenProcessToken"
        };

        Console.WriteLine($"  SSN table for {knownFunctions.Length} known functions:");
        foreach (var fn in knownFunctions)
        {
            var ssn = Syscalls.GetSyscallNumber(fn);
            var hooked = Syscalls.IsHooked(fn);
            Console.WriteLine($"    {fn,-42} SSN=0x{ssn:X4}  hooked={hooked}");
        }

        var auditTargets = new[] { "NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtCreateThreadEx" };
        var auditResults = Syscalls.AuditNtFunctions(auditTargets);
        Console.WriteLine($"  AuditNtFunctions ({auditTargets.Length} targets):");
        foreach (var kv in auditResults)
            Console.WriteLine($"    {kv.Key,-42} hooked={kv.Value}");

        var gadget = Syscalls.GetSyscallGadget();
        Console.WriteLine($"  GetSyscallGadget -> 0x{gadget.ToInt64():X}");

        var hSelf = Win32.GetCurrentProcess();
        var baseAddr = IntPtr.Zero;
        var regionSize = (IntPtr)0x1000;

        var allocStatus = Syscalls.NtAllocateVirtualMemory(
            hSelf, ref baseAddr, ref regionSize,
            Win32.MEM_COMMIT | Win32.MEM_RESERVE, Win32.PAGE_READWRITE);
        Console.WriteLine($"  NtAllocateVirtualMemory(self) -> 0x{allocStatus:X8}, base=0x{baseAddr.ToInt64():X}");

        if (allocStatus == 0 && baseAddr != IntPtr.Zero)
        {
            var payload = new byte[] { 0x41, 0x42, 0x43, 0x44 };
            var writeStatus = Syscalls.NtWriteVirtualMemory(hSelf, baseAddr, payload, out var written);
            Console.WriteLine($"  NtWriteVirtualMemory -> 0x{writeStatus:X8}, written={written}");

            var protAddr = baseAddr;
            var protSize = (IntPtr)0x1000;
            var protStatus = Syscalls.NtProtectVirtualMemory(hSelf, ref protAddr, ref protSize, Win32.PAGE_EXECUTE_READ, out var oldProt);
            Console.WriteLine($"  NtProtectVirtualMemory RW->XR -> 0x{protStatus:X8}, oldProt=0x{oldProt:X2}");

            var readBuf = new byte[4];
            var readStatus = Syscalls.NtReadVirtualMemory(hSelf, baseAddr, readBuf, out var bytesRead);
            Console.WriteLine($"  NtReadVirtualMemory -> 0x{readStatus:X8}, data=0x{BitConverter.ToUInt32(readBuf, 0):X8}");

            var freeAddr = baseAddr;
            var freeSize = IntPtr.Zero;
            Syscalls.NtFreeVirtualMemory(hSelf, ref freeAddr, ref freeSize, Win32.MEM_RELEASE);
            Console.WriteLine("  NtFreeVirtualMemory -> OK");
        }

        var allocSsn = Syscalls.GetSyscallNumber("NtAllocateVirtualMemory");
        if (allocSsn != 0)
        {
            var gadgetAddr = Syscalls.GetSyscallGadget();
            using var stub = new SyscallStub(allocSsn, gadgetAddr);
            Console.WriteLine($"  SyscallStub(NtAllocateVirtualMemory) at 0x{stub.StubAddress.ToInt64():X}");
        }

        Console.WriteLine("  [Syscalls] done");
    }

    private static void RunPacketCrafterDemo()
    {
        Console.WriteLine("\n[PacketCrafter]");

        var myMac = NetworkInterface.GetAllNetworkInterfaces()
            .Where(i => i.OperationalStatus == OperationalStatus.Up && i.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .Select(i => i.GetPhysicalAddress())
            .FirstOrDefault(m => m.GetAddressBytes().Length == 6)
            ?? new PhysicalAddress(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01 });

        var srcIp = IPAddress.Parse("192.168.1.50");
        var dstIp = IPAddress.Parse("192.168.1.1");
        var targetMac = new PhysicalAddress(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF });

        var arpReq = PacketCrafter.BuildArpRequest(myMac, srcIp, dstIp);
        Console.WriteLine($"  BuildArpRequest -> {arpReq.Length} bytes");
        Console.WriteLine($"    EtherType: 0x{arpReq[12]:X2}{arpReq[13]:X2}");
        Console.WriteLine($"    ARP op: {arpReq[20]:X2}{arpReq[21]:X2} (0001=request)");

        var arpReply = PacketCrafter.BuildArpReply(myMac, srcIp, targetMac, dstIp);
        Console.WriteLine($"  BuildArpReply -> {arpReply.Length} bytes, op=0x{arpReply[20]:X2}{arpReply[21]:X2}");

        var dnsQuery = PacketCrafter.BuildDnsQuery("target.corp.local", DnsType.A, 0xBEEF);
        Console.WriteLine($"  BuildDnsQuery(A, target.corp.local) -> {dnsQuery.Length} bytes");
        Console.WriteLine($"    TxID: 0x{dnsQuery[0]:X2}{dnsQuery[1]:X2}");
        Console.WriteLine($"    Flags: 0x{dnsQuery[2]:X2}{dnsQuery[3]:X2}");
        Console.WriteLine($"    Questions: {dnsQuery[4]:X2}{dnsQuery[5]:X2}");

        var dnsQueryMx = PacketCrafter.BuildDnsQuery("corp.local", DnsType.MX);
        Console.WriteLine($"  BuildDnsQuery(MX, corp.local) -> {dnsQueryMx.Length} bytes");

        var fakeAnswers = new[] { IPAddress.Parse("10.10.10.10"), IPAddress.Parse("10.10.10.11") };
        var dnsResponse = PacketCrafter.BuildDnsResponse(dnsQuery, fakeAnswers);
        Console.WriteLine($"  BuildDnsResponse (2 A records) -> {dnsResponse.Length} bytes");
        Console.WriteLine($"    Answer count field: {dnsResponse[6]:X2}{dnsResponse[7]:X2}");

        var synPacket = PacketCrafter.BuildTcpSyn(
            IPAddress.Parse("10.0.0.5"),
            IPAddress.Parse("10.0.0.1"),
            srcPort: 54321,
            dstPort: 443,
            sequenceNumber: 0xCAFEBABE);
        Console.WriteLine($"  BuildTcpSyn -> {synPacket.Length} bytes");
        Console.WriteLine($"    IP version/IHL: 0x{synPacket[0]:X2}");
        Console.WriteLine($"    Protocol: {synPacket[9]} (6=TCP)");
        Console.WriteLine($"    Dst port: {(synPacket[22] << 8) | synPacket[23]} (443)");
        Console.WriteLine($"    TCP flags: 0x{synPacket[33]:X2} (0x02=SYN)");

        var synAck = PacketCrafter.BuildTcpSynAck(
            IPAddress.Parse("10.0.0.1"),
            IPAddress.Parse("10.0.0.5"),
            srcPort: 443,
            dstPort: 54321,
            seqNumber: 0x12345678,
            ackNumber: 0xCAFEBABF);
        Console.WriteLine($"  BuildTcpSynAck -> {synAck.Length} bytes, flags=0x{synAck[33]:X2} (0x12=SYN|ACK)");

        var rst = PacketCrafter.BuildTcpRst(
            IPAddress.Parse("10.0.0.1"),
            IPAddress.Parse("10.0.0.5"),
            srcPort: 443, dstPort: 54321, seqNumber: 0x12345679);
        Console.WriteLine($"  BuildTcpRst -> {rst.Length} bytes, flags=0x{rst[33]:X2} (0x04=RST)");

        var udpPayload = PacketCrafter.BuildDnsQuery("example.com", DnsType.AAAA);
        var udpPacket = PacketCrafter.BuildUdpPacket(
            IPAddress.Parse("10.0.0.5"),
            IPAddress.Parse("10.0.0.1"),
            srcPort: 12345, dstPort: 53, payload: udpPayload);
        Console.WriteLine($"  BuildUdpPacket (DNS/AAAA payload) -> {udpPacket.Length} bytes");
        Console.WriteLine($"    IP protocol: {udpPacket[9]} (17=UDP)");

        Console.WriteLine("  [PacketCrafter] done");
    }

    private static async Task RunPacketCrafterAsyncDemo()
    {
        Console.WriteLine("\n[PacketCrafter async]");

        Console.WriteLine("  TcpSynScan 127.0.0.1:1-1024 (500ms timeout)...");
        var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        try
        {
            var openPorts = await PacketCrafter.TcpSynScanAsync(
                IPAddress.Loopback,
                Enumerable.Range(1, 1024).Select(p => (ushort)p),
                IPAddress.Loopback,
                timeout: TimeSpan.FromMilliseconds(500),
                ct: cts.Token);
            Console.WriteLine($"  Open ports on 127.0.0.1: [{string.Join(", ", openPorts)}]");
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine("  Scan timed out (expected in restricted env)");
        }

        Console.WriteLine("  SendDnsQueryAsync to 127.0.0.53 (expected failure in offline env):");
        try
        {
            using var dnsCts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            var resolved = await PacketCrafter.SendDnsQueryAsync(
                "example.com",
                IPAddress.Parse("127.0.0.53"),
                queryType: DnsType.A,
                ct: dnsCts.Token);
            Console.WriteLine($"  DNS query success: {resolved}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  DNS query failed (expected): {ex.Message}");
        }

        Console.WriteLine("  [PacketCrafter async] done");
        Console.WriteLine("\n" + new string('=', 60));
        Console.WriteLine("SharpKit demo complete.");
    }
}