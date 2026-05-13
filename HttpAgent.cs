using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;

namespace SharpKit;

public sealed class HttpAgent : IDisposable
{
    private readonly HttpClient _client;
    private readonly HttpClientHandler _handler;
    private bool _disposed;

    public HttpAgent()
    {
        _handler = new HttpClientHandler
        {
            AllowAutoRedirect = true,
            MaxAutomaticRedirections = 10,
            UseCookies = true,
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        };
        _client = new HttpClient(_handler);
    }

    public HttpAgent(string proxyUri) : this()
    {
        _handler.UseProxy = true;
        _handler.Proxy = new WebProxy(proxyUri, false);
    }

    public HttpAgent(string proxyUri, string username, string password) : this()
    {
        _handler.UseProxy = true;
        _handler.Proxy = new WebProxy(proxyUri, false)
        {
            Credentials = new NetworkCredential(username, password)
        };
    }

    public void SetBasicAuth(string username, string password)
    {
        var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}"));
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", encoded);
    }

    public void SetBearerToken(string token)
    {
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
    }

    public void SetNtlmAuth(string username, string password, string domain)
    {
        _handler.Credentials = new NetworkCredential(username, password, domain);
        _handler.PreAuthenticate = true;
    }

    public void SetHeader(string name, string value)
    {
        _client.DefaultRequestHeaders.Remove(name);
        _client.DefaultRequestHeaders.TryAddWithoutValidation(name, value);
    }

    public void SetUserAgent(string userAgent)
    {
        _client.DefaultRequestHeaders.Remove("User-Agent");
        _client.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", userAgent);
    }

    public void SetTimeout(TimeSpan timeout)
    {
        _client.Timeout = timeout;
    }

    public async Task<HttpResponseMessage> GetAsync(string url, CancellationToken ct = default)
    {
        return await _client.GetAsync(url, ct).ConfigureAwait(false);
    }

    public async Task<string> GetStringAsync(string url, CancellationToken ct = default)
    {
        return await _client.GetStringAsync(url, ct).ConfigureAwait(false);
    }

    public async Task<byte[]> GetBytesAsync(string url, CancellationToken ct = default)
    {
        return await _client.GetByteArrayAsync(url, ct).ConfigureAwait(false);
    }

    public async Task<HttpResponseMessage> PostJsonAsync(string url, string json, CancellationToken ct = default)
    {
        var content = new StringContent(json, Encoding.UTF8, "application/json");
        return await _client.PostAsync(url, content, ct).ConfigureAwait(false);
    }

    public async Task<HttpResponseMessage> PostFormAsync(string url, Dictionary<string, string> fields, CancellationToken ct = default)
    {
        var content = new FormUrlEncodedContent(fields);
        return await _client.PostAsync(url, content, ct).ConfigureAwait(false);
    }

    public async Task<HttpResponseMessage> PostBytesAsync(string url, byte[] data, string contentType = "application/octet-stream", CancellationToken ct = default)
    {
        var content = new ByteArrayContent(data);
        content.Headers.ContentType = new MediaTypeHeaderValue(contentType);
        return await _client.PostAsync(url, content, ct).ConfigureAwait(false);
    }

    public async Task<HttpResponseMessage> PutJsonAsync(string url, string json, CancellationToken ct = default)
    {
        var content = new StringContent(json, Encoding.UTF8, "application/json");
        return await _client.PutAsync(url, content, ct).ConfigureAwait(false);
    }

    public async Task<HttpResponseMessage> DeleteAsync(string url, CancellationToken ct = default)
    {
        return await _client.DeleteAsync(url, ct).ConfigureAwait(false);
    }

    public async Task<HttpResponseMessage> SendRawAsync(HttpRequestMessage request, CancellationToken ct = default)
    {
        return await _client.SendAsync(request, ct).ConfigureAwait(false);
    }

    public async Task<byte[]> DownloadAsync(string url, IProgress<double>? progress = null, CancellationToken ct = default)
    {
        using var response = await _client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        var totalBytes = response.Content.Headers.ContentLength ?? -1L;
        using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var ms = new MemoryStream();

        var buffer = new byte[81920];
        long bytesRead = 0;
        int read;

        while ((read = await stream.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
        {
            await ms.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
            bytesRead += read;
            if (progress != null && totalBytes > 0)
                progress.Report((double)bytesRead / totalBytes);
        }

        return ms.ToArray();
    }

    public async Task<Dictionary<string, string>> GetResponseHeadersAsync(string url, CancellationToken ct = default)
    {
        using var response = await _client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var header in response.Headers)
            headers[header.Key] = string.Join(", ", header.Value);
        foreach (var header in response.Content.Headers)
            headers[header.Key] = string.Join(", ", header.Value);
        return headers;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _client.Dispose();
        _handler.Dispose();
    }
}
