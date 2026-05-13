using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace SharpKit;

public enum EtherType : ushort
{
    IPv4 = 0x0800,
    IPv6 = 0x86DD,
    ARP = 0x0806,
    VLAN = 0x8100
}

public enum ArpOperation : ushort
{
    Request = 1,
    Reply = 2
}

public enum IpProtocol : byte
{
    ICMP = 1,
    TCP = 6,
    UDP = 17
}

public enum DnsType : ushort
{
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    AAAA = 28,
    TXT = 16,
    ANY = 255
}

public enum DnsClass : ushort
{
    IN = 1,
    ANY = 255
}

[Flags]
public enum TcpFlags : byte
{
    FIN = 0x01,
    SYN = 0x02,
    RST = 0x04,
    PSH = 0x08,
    ACK = 0x10,
    URG = 0x20
}

public static class PacketCrafter
{
    public static byte[] BuildArpRequest(PhysicalAddress senderMac, IPAddress senderIp, IPAddress targetIp)
    {
        var packet = new byte[42];

        var target = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        var src = senderMac.GetAddressBytes();
        var senderIpBytes = senderIp.GetAddressBytes();
        var targetIpBytes = targetIp.GetAddressBytes();

        Buffer.BlockCopy(target, 0, packet, 0, 6);
        Buffer.BlockCopy(src, 0, packet, 6, 6);
        packet[12] = (byte)((ushort)EtherType.ARP >> 8);
        packet[13] = (byte)((ushort)EtherType.ARP & 0xFF);

        packet[14] = 0x00; packet[15] = 0x01;
        packet[16] = 0x08; packet[17] = 0x00;
        packet[18] = 0x06;
        packet[19] = 0x04;

        var op = (ushort)ArpOperation.Request;
        packet[20] = (byte)(op >> 8);
        packet[21] = (byte)(op & 0xFF);

        Buffer.BlockCopy(src, 0, packet, 22, 6);
        Buffer.BlockCopy(senderIpBytes, 0, packet, 28, 4);
        Buffer.BlockCopy(new byte[6], 0, packet, 32, 6);
        Buffer.BlockCopy(targetIpBytes, 0, packet, 38, 4);

        return packet;
    }

    public static byte[] BuildArpReply(PhysicalAddress senderMac, IPAddress senderIp, PhysicalAddress targetMac, IPAddress targetIp)
    {
        var packet = new byte[42];

        var srcBytes = senderMac.GetAddressBytes();
        var dstBytes = targetMac.GetAddressBytes();
        var senderIpBytes = senderIp.GetAddressBytes();
        var targetIpBytes = targetIp.GetAddressBytes();

        Buffer.BlockCopy(dstBytes, 0, packet, 0, 6);
        Buffer.BlockCopy(srcBytes, 0, packet, 6, 6);
        packet[12] = (byte)((ushort)EtherType.ARP >> 8);
        packet[13] = (byte)((ushort)EtherType.ARP & 0xFF);

        packet[14] = 0x00; packet[15] = 0x01;
        packet[16] = 0x08; packet[17] = 0x00;
        packet[18] = 0x06;
        packet[19] = 0x04;

        var op = (ushort)ArpOperation.Reply;
        packet[20] = (byte)(op >> 8);
        packet[21] = (byte)(op & 0xFF);

        Buffer.BlockCopy(srcBytes, 0, packet, 22, 6);
        Buffer.BlockCopy(senderIpBytes, 0, packet, 28, 4);
        Buffer.BlockCopy(dstBytes, 0, packet, 32, 6);
        Buffer.BlockCopy(targetIpBytes, 0, packet, 38, 4);

        return packet;
    }

    public static byte[] BuildDnsQuery(string hostname, DnsType queryType = DnsType.A, ushort transactionId = 0)
    {
        if (transactionId == 0)
            transactionId = (ushort)Random.Shared.Next(1, 65535);

        var ms = new MemoryStream();

        ms.WriteByte((byte)(transactionId >> 8));
        ms.WriteByte((byte)(transactionId & 0xFF));

        ms.WriteByte(0x01); ms.WriteByte(0x00);

        ms.WriteByte(0x00); ms.WriteByte(0x01);
        ms.WriteByte(0x00); ms.WriteByte(0x00);
        ms.WriteByte(0x00); ms.WriteByte(0x00);
        ms.WriteByte(0x00); ms.WriteByte(0x00);

        foreach (var label in hostname.Split('.'))
        {
            ms.WriteByte((byte)label.Length);
            foreach (var c in label)
                ms.WriteByte((byte)c);
        }
        ms.WriteByte(0x00);

        var qt = (ushort)queryType;
        ms.WriteByte((byte)(qt >> 8));
        ms.WriteByte((byte)(qt & 0xFF));

        var qc = (ushort)DnsClass.IN;
        ms.WriteByte((byte)(qc >> 8));
        ms.WriteByte((byte)(qc & 0xFF));

        return ms.ToArray();
    }

    public static byte[] BuildDnsResponse(byte[] query, IPAddress[] answers)
    {
        if (query.Length < 12) throw new ArgumentException("Invalid DNS query");

        var ms = new MemoryStream();
        ms.Write(query, 0, query.Length);

        ms.GetBuffer()[2] = 0x81;
        ms.GetBuffer()[3] = 0x80;

        var answerCount = (ushort)answers.Length;
        ms.GetBuffer()[6] = (byte)(answerCount >> 8);
        ms.GetBuffer()[7] = (byte)(answerCount & 0xFF);

        foreach (var ip in answers)
        {
            ms.WriteByte(0xC0); ms.WriteByte(0x0C);

            ms.WriteByte(0x00); ms.WriteByte((byte)DnsType.A);
            ms.WriteByte(0x00); ms.WriteByte((byte)DnsClass.IN);

            ms.WriteByte(0x00); ms.WriteByte(0x00);
            ms.WriteByte(0x00); ms.WriteByte(0x3C);

            ms.WriteByte(0x00); ms.WriteByte(0x04);

            var ipBytes = ip.GetAddressBytes();
            ms.Write(ipBytes, 0, 4);
        }

        return ms.ToArray();
    }

    public static byte[] BuildTcpSyn(IPAddress srcIp, IPAddress dstIp, ushort srcPort, ushort dstPort, uint sequenceNumber = 0)
    {
        if (sequenceNumber == 0)
            sequenceNumber = (uint)Random.Shared.Next();

        var ipHeader = BuildIpHeader(srcIp, dstIp, IpProtocol.TCP, 40);
        var tcpHeader = BuildTcpHeader(srcPort, dstPort, sequenceNumber, 0, TcpFlags.SYN, 65535, 0, Array.Empty<byte>());

        var pseudoHeader = BuildPseudoHeader(srcIp, dstIp, IpProtocol.TCP, (ushort)tcpHeader.Length);
        var tcpChecksum = CalculateChecksum(Combine(pseudoHeader, tcpHeader));
        tcpHeader[16] = (byte)(tcpChecksum >> 8);
        tcpHeader[17] = (byte)(tcpChecksum & 0xFF);

        return Combine(ipHeader, tcpHeader);
    }

    public static byte[] BuildTcpSynAck(IPAddress srcIp, IPAddress dstIp, ushort srcPort, ushort dstPort, uint seqNumber, uint ackNumber)
    {
        var ipHeader = BuildIpHeader(srcIp, dstIp, IpProtocol.TCP, 40);
        var tcpHeader = BuildTcpHeader(srcPort, dstPort, seqNumber, ackNumber, TcpFlags.SYN | TcpFlags.ACK, 65535, 0, Array.Empty<byte>());

        var pseudoHeader = BuildPseudoHeader(srcIp, dstIp, IpProtocol.TCP, (ushort)tcpHeader.Length);
        var checksum = CalculateChecksum(Combine(pseudoHeader, tcpHeader));
        tcpHeader[16] = (byte)(checksum >> 8);
        tcpHeader[17] = (byte)(checksum & 0xFF);

        return Combine(ipHeader, tcpHeader);
    }

    public static byte[] BuildTcpRst(IPAddress srcIp, IPAddress dstIp, ushort srcPort, ushort dstPort, uint seqNumber)
    {
        var ipHeader = BuildIpHeader(srcIp, dstIp, IpProtocol.TCP, 40);
        var tcpHeader = BuildTcpHeader(srcPort, dstPort, seqNumber, 0, TcpFlags.RST, 0, 0, Array.Empty<byte>());

        var pseudoHeader = BuildPseudoHeader(srcIp, dstIp, IpProtocol.TCP, (ushort)tcpHeader.Length);
        var checksum = CalculateChecksum(Combine(pseudoHeader, tcpHeader));
        tcpHeader[16] = (byte)(checksum >> 8);
        tcpHeader[17] = (byte)(checksum & 0xFF);

        return Combine(ipHeader, tcpHeader);
    }

    public static byte[] BuildUdpPacket(IPAddress srcIp, IPAddress dstIp, ushort srcPort, ushort dstPort, byte[] payload)
    {
        var udpLength = (ushort)(8 + payload.Length);
        var ipHeader = BuildIpHeader(srcIp, dstIp, IpProtocol.UDP, (ushort)(20 + udpLength));

        var udpHeader = new byte[8 + payload.Length];
        udpHeader[0] = (byte)(srcPort >> 8);
        udpHeader[1] = (byte)(srcPort & 0xFF);
        udpHeader[2] = (byte)(dstPort >> 8);
        udpHeader[3] = (byte)(dstPort & 0xFF);
        udpHeader[4] = (byte)(udpLength >> 8);
        udpHeader[5] = (byte)(udpLength & 0xFF);

        Buffer.BlockCopy(payload, 0, udpHeader, 8, payload.Length);

        var pseudoHeader = BuildPseudoHeader(srcIp, dstIp, IpProtocol.UDP, udpLength);
        var checksum = CalculateChecksum(Combine(pseudoHeader, udpHeader));
        udpHeader[6] = (byte)(checksum >> 8);
        udpHeader[7] = (byte)(checksum & 0xFF);

        return Combine(ipHeader, udpHeader);
    }

    public static async Task<List<ushort>> TcpSynScanAsync(IPAddress target, IEnumerable<ushort> ports, IPAddress sourceIp, TimeSpan timeout, CancellationToken ct = default)
    {
        var open = new List<ushort>();

        foreach (var port in ports)
        {
            ct.ThrowIfCancellationRequested();
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, System.Net.Sockets.ProtocolType.Tcp);
            socket.Blocking = false;

            try
            {
                await socket.ConnectAsync(new IPEndPoint(target, port), ct).ConfigureAwait(false);
                open.Add(port);
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
            {
            }
            catch (SocketException)
            {
                using var cts = new CancellationTokenSource(timeout);
                try
                {
                    await socket.ConnectAsync(new IPEndPoint(target, port), cts.Token).ConfigureAwait(false);
                    open.Add(port);
                }
                catch { }
            }
        }

        return open;
    }

    public static async Task<bool> SendDnsQueryAsync(string hostname, IPAddress dnsServer, int port = 53, DnsType queryType = DnsType.A, CancellationToken ct = default)
    {
        var query = BuildDnsQuery(hostname, queryType);
        using var udpClient = new UdpClient();
        await udpClient.SendAsync(query, query.Length, new IPEndPoint(dnsServer, port)).ConfigureAwait(false);

        udpClient.Client.ReceiveTimeout = 3000;
        try
        {
            var result = await udpClient.ReceiveAsync(ct).ConfigureAwait(false);
            return result.Buffer.Length > 0 && (result.Buffer[2] & 0x80) != 0;
        }
        catch
        {
            return false;
        }
    }

    private static byte[] BuildIpHeader(IPAddress srcIp, IPAddress dstIp, IpProtocol protocol, ushort totalLength)
    {
        var header = new byte[20];
        header[0] = 0x45;
        header[1] = 0x00;
        header[2] = (byte)(totalLength >> 8);
        header[3] = (byte)(totalLength & 0xFF);

        var id = (ushort)Random.Shared.Next(1, 65535);
        header[4] = (byte)(id >> 8);
        header[5] = (byte)(id & 0xFF);

        header[6] = 0x40; header[7] = 0x00;
        header[8] = 64;
        header[9] = (byte)protocol;
        header[10] = 0x00; header[11] = 0x00;

        var srcBytes = srcIp.GetAddressBytes();
        var dstBytes = dstIp.GetAddressBytes();
        Buffer.BlockCopy(srcBytes, 0, header, 12, 4);
        Buffer.BlockCopy(dstBytes, 0, header, 16, 4);

        var checksum = CalculateChecksum(header);
        header[10] = (byte)(checksum >> 8);
        header[11] = (byte)(checksum & 0xFF);

        return header;
    }

    private static byte[] BuildTcpHeader(ushort srcPort, ushort dstPort, uint seqNum, uint ackNum, TcpFlags flags, ushort windowSize, ushort urgentPointer, byte[] options)
    {
        var headerLen = 20 + options.Length;
        var dataOffset = (byte)((headerLen / 4) << 4);
        var header = new byte[headerLen];

        header[0] = (byte)(srcPort >> 8);
        header[1] = (byte)(srcPort & 0xFF);
        header[2] = (byte)(dstPort >> 8);
        header[3] = (byte)(dstPort & 0xFF);

        header[4] = (byte)(seqNum >> 24);
        header[5] = (byte)(seqNum >> 16);
        header[6] = (byte)(seqNum >> 8);
        header[7] = (byte)(seqNum & 0xFF);

        header[8] = (byte)(ackNum >> 24);
        header[9] = (byte)(ackNum >> 16);
        header[10] = (byte)(ackNum >> 8);
        header[11] = (byte)(ackNum & 0xFF);

        header[12] = dataOffset;
        header[13] = (byte)flags;

        header[14] = (byte)(windowSize >> 8);
        header[15] = (byte)(windowSize & 0xFF);

        header[16] = 0x00; header[17] = 0x00;

        header[18] = (byte)(urgentPointer >> 8);
        header[19] = (byte)(urgentPointer & 0xFF);

        if (options.Length > 0)
            Buffer.BlockCopy(options, 0, header, 20, options.Length);

        return header;
    }

    private static byte[] BuildPseudoHeader(IPAddress srcIp, IPAddress dstIp, IpProtocol protocol, ushort length)
    {
        var pseudo = new byte[12];
        Buffer.BlockCopy(srcIp.GetAddressBytes(), 0, pseudo, 0, 4);
        Buffer.BlockCopy(dstIp.GetAddressBytes(), 0, pseudo, 4, 4);
        pseudo[8] = 0x00;
        pseudo[9] = (byte)protocol;
        pseudo[10] = (byte)(length >> 8);
        pseudo[11] = (byte)(length & 0xFF);
        return pseudo;
    }

    private static ushort CalculateChecksum(byte[] data)
    {
        uint sum = 0;
        int i = 0;

        while (i < data.Length - 1)
        {
            sum += (uint)((data[i] << 8) | data[i + 1]);
            i += 2;
        }

        if (i < data.Length)
            sum += (uint)(data[i] << 8);

        while ((sum >> 16) != 0)
            sum = (sum & 0xFFFF) + (sum >> 16);

        return (ushort)~sum;
    }

    private static byte[] Combine(byte[] a, byte[] b)
    {
        var result = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, result, 0, a.Length);
        Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
        return result;
    }
}
