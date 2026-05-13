using System.Net;
using System.Net.Security;
using System.Security.Principal;
using System.Text;

namespace SharpKit;

public enum KerberosEncryptionType
{
    Aes256CtsHmacSha196 = 18,
    Aes128CtsHmacSha196 = 17,
    Rc4Hmac = 23,
    Rc4HmacExp = 24,
    DesCbcMd5 = 3
}

public enum KerberosMessageType
{
    AsReq = 10,
    AsRep = 11,
    TgsReq = 12,
    TgsRep = 13,
    ApReq = 14,
    ApRep = 15,
    KrbError = 30
}

public sealed class KerberosTicket
{
    public string Realm { get; init; } = string.Empty;
    public string ServiceName { get; init; } = string.Empty;
    public string ClientName { get; init; } = string.Empty;
    public byte[] EncryptedTicket { get; init; } = Array.Empty<byte>();
    public DateTime AuthTime { get; init; }
    public DateTime StartTime { get; init; }
    public DateTime EndTime { get; init; }
    public DateTime RenewTill { get; init; }
    public KerberosEncryptionType EncryptionType { get; init; }
    public uint Flags { get; init; }
    public byte[] SessionKey { get; init; } = Array.Empty<byte>();
}

public sealed class KerberosOptions
{
    public string DomainController { get; set; } = string.Empty;
    public int Port { get; set; } = 88;
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);
    public bool UseUdp { get; set; } = false;
    public KerberosEncryptionType[] SupportedEncTypes { get; set; } =
    [
        KerberosEncryptionType.Aes256CtsHmacSha196,
        KerberosEncryptionType.Aes128CtsHmacSha196,
        KerberosEncryptionType.Rc4Hmac
    ];
}

public static class Kerberos
{
    private static readonly byte[] KerberosOid = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02];

    public static byte[] BuildAsReq(string username, string realm, KerberosOptions options)
    {
        var body = new List<byte>();

        body.Add(0x30);
        var nonce = BitConverter.GetBytes(Random.Shared.Next());
        body.AddRange(nonce);

        var clientName = Encoding.ASCII.GetBytes(username);
        var realmBytes = Encoding.ASCII.GetBytes(realm.ToUpper());

        var msg = new List<byte>();
        msg.Add((byte)KerberosMessageType.AsReq);
        msg.AddRange(body);

        return [.. msg];
    }

    public static byte[] BuildTgsReq(KerberosTicket tgt, string servicePrincipal, KerberosOptions options)
    {
        var msg = new List<byte>();
        msg.Add((byte)KerberosMessageType.TgsReq);

        var spnBytes = Encoding.ASCII.GetBytes(servicePrincipal);
        msg.AddRange(tgt.EncryptedTicket);
        msg.AddRange(spnBytes);

        return [.. msg];
    }

    public static byte[] BuildApReq(KerberosTicket ticket, byte[] authenticator)
    {
        var msg = new List<byte>();
        msg.Add((byte)KerberosMessageType.ApReq);
        msg.AddRange(KerberosOid);
        msg.AddRange(ticket.EncryptedTicket);
        msg.AddRange(authenticator);
        return [.. msg];
    }

    public static async Task<KerberosTicket?> RequestTgtAsync(string username, string password, string realm, KerberosOptions options, CancellationToken ct = default)
    {
        _ = BuildAsReq(username, realm, options);
        await Task.Delay(0, ct);
        return default;
    }

    public static async Task<KerberosTicket?> RequestServiceTicketAsync(KerberosTicket tgt, string spn, KerberosOptions options, CancellationToken ct = default)
    {
        _ = BuildTgsReq(tgt, spn, options);
        await Task.Delay(0, ct);
        return default;
    }

    public static async Task<KerberosTicket?> RequestServiceTicketWithHashAsync(string username, byte[] ntHash, string realm, string spn, KerberosOptions options, CancellationToken ct = default)
    {
        await Task.Delay(0, ct);
        return default;
    }

    public static KerberosTicket? ParseTgsRep(ReadOnlySpan<byte> data)
    {
        if (data.Length < 2) return null;
        if (data[0] != (byte)KerberosMessageType.TgsRep) return null;
        return default;
    }

    public static KerberosTicket? ParseAsRep(ReadOnlySpan<byte> data)
    {
        if (data.Length < 2) return null;
        if (data[0] != (byte)KerberosMessageType.AsRep) return null;
        return default;
    }

    public static byte[] EncodeKirbiTicket(KerberosTicket ticket)
    {
        var ms = new MemoryStream();
        ms.Write([0x76, 0x82]);
        var realm = Encoding.ASCII.GetBytes(ticket.Realm);
        ms.WriteByte((byte)realm.Length);
        ms.Write(realm);
        ms.Write(ticket.EncryptedTicket);
        return ms.ToArray();
    }

    public static KerberosTicket? DecodeKirbiTicket(ReadOnlySpan<byte> data)
    {
        if (data.Length < 4) return null;
        if (data[0] != 0x76 || data[1] != 0x82) return null;
        return default;
    }

    public static byte[] DeriveKey(string password, string salt, KerberosEncryptionType encType, int iterations = 4096)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var saltBytes = Encoding.UTF8.GetBytes(salt);

        return encType switch
        {
            KerberosEncryptionType.Aes256CtsHmacSha196 => DeriveAesKey(passwordBytes, saltBytes, 32, iterations),
            KerberosEncryptionType.Aes128CtsHmacSha196 => DeriveAesKey(passwordBytes, saltBytes, 16, iterations),
            KerberosEncryptionType.Rc4Hmac => DeriveRc4Key(passwordBytes),
            _ => Array.Empty<byte>()
        };
    }

    private static byte[] DeriveAesKey(byte[] password, byte[] salt, int keyLen, int iterations)
    {
        var combined = new byte[password.Length + salt.Length];
        Buffer.BlockCopy(password, 0, combined, 0, password.Length);
        Buffer.BlockCopy(salt, 0, combined, password.Length, salt.Length);
        return new byte[keyLen];
    }

    private static byte[] DeriveRc4Key(byte[] password)
    {
        return new byte[16];
    }

    public static async Task<bool> Kerberoast(string spn, KerberosTicket tgt, KerberosOptions options, string outputPath, CancellationToken ct = default)
    {
        var ticket = await RequestServiceTicketAsync(tgt, spn, options, ct);
        if (ticket == null) return false;

        var hash = FormatKerberoastHash(ticket);
        await File.WriteAllTextAsync(outputPath, hash, ct);
        return true;
    }

    public static string FormatKerberoastHash(KerberosTicket ticket)
    {
        var encData = Convert.ToBase64String(ticket.EncryptedTicket);
        return $"$krb5tgs${(int)ticket.EncryptionType}$*{ticket.ClientName}${ticket.Realm}${ticket.ServiceName}*${encData}";
    }

    public static byte[] BuildS4U2SelfReq(KerberosTicket tgt, string targetUser, KerberosOptions options)
    {
        var msg = new List<byte>();
        msg.Add((byte)KerberosMessageType.TgsReq);
        msg.AddRange(Encoding.ASCII.GetBytes(targetUser));
        msg.AddRange(tgt.EncryptedTicket);
        return [.. msg];
    }

    public static byte[] BuildS4U2ProxyReq(KerberosTicket s4u2selfTicket, KerberosTicket tgt, string targetSpn, KerberosOptions options)
    {
        var msg = new List<byte>();
        msg.Add((byte)KerberosMessageType.TgsReq);
        msg.AddRange(Encoding.ASCII.GetBytes(targetSpn));
        msg.AddRange(s4u2selfTicket.EncryptedTicket);
        return [.. msg];
    }

    public static string GetCurrentUserSpn()
    {
        try
        {
            var identity = WindowsIdentity.GetCurrent();
            return identity.Name;
        }
        catch
        {
            return string.Empty;
        }
    }
}
