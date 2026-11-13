using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ProxyForWin.Core;

/// <summary>
/// Opens connections either directly (bypass) or through the upstream HTTP proxy
/// using the CONNECT method with Proxy-Authorization.
///
/// All sockets are bound to a dedicated source-port range (45000-45999). The
/// WinDivert redirector excludes that range, otherwise the proxy's own upstream
/// connections would be redirected into the proxy again (an endless loop).
/// </summary>
public sealed class UpstreamConnector
{
    public const int BindPortMin = 45000;
    public const int BindPortMax = 45999;

    private readonly ProxySettings _settings;
    private readonly Logger _log;
    private int _nextPort = Random.Shared.Next(BindPortMin, BindPortMax + 1);

    public UpstreamConnector(ProxySettings settings, Logger log)
    {
        _settings = settings;
        _log = log;
    }

    public sealed class Tunnel : IDisposable
    {
        public required Socket Socket { get; init; }

        /// <summary>Bytes that arrived after the proxy response headers.</summary>
        public byte[] Leftover { get; init; } = Array.Empty<byte>();

        public void Dispose() => Socket.Dispose();
    }

    public async Task<Tunnel> ConnectAsync(string targetHost, int targetPort, bool useUpstream, CancellationToken ct)
    {
        if (useUpstream)
        {
            return await ConnectViaUpstreamAsync(targetHost, targetPort, ct).ConfigureAwait(false);
        }

        var socket = await ConnectBoundAsync(targetHost, targetPort, ct).ConfigureAwait(false);
        return new Tunnel { Socket = socket };
    }

    private async Task<Tunnel> ConnectViaUpstreamAsync(string targetHost, int targetPort, CancellationToken ct)
    {
        var socket = await ConnectBoundAsync(_settings.UpstreamHost, _settings.UpstreamPort, ct).ConfigureAwait(false);
        try
        {
            var builder = new StringBuilder();
            builder.Append("CONNECT ").Append(targetHost).Append(':').Append(targetPort).Append(" HTTP/1.1\r\n");
            builder.Append("Host: ").Append(targetHost).Append(':').Append(targetPort).Append("\r\n");
            builder.Append("Proxy-Connection: Keep-Alive\r\n");
            if (!string.IsNullOrEmpty(_settings.Username))
            {
                builder.Append("Proxy-Authorization: ")
                    .Append(HttpUtil.BuildBasicAuth(_settings.Username, _settings.Password))
                    .Append("\r\n");
            }

            builder.Append("\r\n");
            var request = Encoding.ASCII.GetBytes(builder.ToString());
            await socket.SendAsync(request, SocketFlags.None, ct).ConfigureAwait(false);

            var (status, leftover) = await ReadResponseAsync(socket, ct).ConfigureAwait(false);
            if (status != 200)
            {
                throw new IOException($"Upstream proxy answered HTTP {status} for CONNECT {targetHost}:{targetPort}");
            }

            return new Tunnel { Socket = socket, Leftover = leftover };
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    private async Task<Socket> ConnectBoundAsync(string host, int port, CancellationToken ct)
    {
        var addresses = await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);
        var address = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                      ?? throw new IOException($"Не удалось разрешить {host} в IPv4-адрес");

        Exception? lastError = null;
        for (var attempt = 0; attempt < 32; attempt++)
        {
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
            {
                NoDelay = true,
            };

            try
            {
                socket.Bind(new IPEndPoint(IPAddress.Any, NextBindPort()));
            }
            catch (SocketException ex)
            {
                socket.Dispose();
                lastError = ex;
                continue;
            }

            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeout.CancelAfter(TimeSpan.FromSeconds(20));
                await socket.ConnectAsync(new IPEndPoint(address, port), timeout.Token).ConfigureAwait(false);
                return socket;
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                socket.Dispose();
                throw new IOException($"Таймаут подключения к {host}:{port}");
            }
            catch (SocketException ex)
            {
                socket.Dispose();
                lastError = ex;
                break;
            }
        }

        throw new IOException($"Не удалось подключиться к {host}:{port}: {lastError?.Message}", lastError);
    }

    private int NextBindPort()
    {
        var port = Interlocked.Increment(ref _nextPort);
        if (port > BindPortMax)
        {
            Interlocked.CompareExchange(ref _nextPort, BindPortMin - 1, port);
            port = Interlocked.Increment(ref _nextPort);
        }

        return port;
    }

    private static async Task<(int Status, byte[] Leftover)> ReadResponseAsync(Socket socket, CancellationToken ct)
    {
        var buffer = new byte[8192];
        var total = 0;

        while (total < buffer.Length)
        {
            var n = await socket.ReceiveAsync(buffer.AsMemory(total), SocketFlags.None, ct).ConfigureAwait(false);
            if (n == 0)
            {
                throw new IOException("Upstream proxy closed the connection during CONNECT");
            }

            total += n;
            var headerEnd = HttpUtil.IndexOfHeaderEnd(buffer.AsSpan(0, total));
            if (headerEnd < 0)
            {
                continue;
            }

            var headers = Encoding.ASCII.GetString(buffer, 0, headerEnd);
            var firstLine = headers.Split("\r\n", 2)[0];
            var parts = firstLine.Split(' ');
            var status = parts.Length >= 2 && int.TryParse(parts[1], out var code) ? code : 0;

            var leftover = new byte[total - headerEnd];
            Array.Copy(buffer, headerEnd, leftover, 0, leftover.Length);
            return (status, leftover);
        }

        throw new IOException("Upstream proxy response headers are too large");
    }
}
