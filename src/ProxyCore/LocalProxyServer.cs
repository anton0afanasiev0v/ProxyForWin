using System.Buffers;
using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ProxyForWin.Core;

using Tunnel = UpstreamConnector.Tunnel;

public enum ClientRequestKind
{
    Connect,
    HttpProxy,
    Transparent,
}

public sealed record ClientRequest(
    ClientRequestKind Kind,
    string? Host,
    int Port,
    int HeaderLength);

/// <summary>
/// Local HTTP proxy on 127.0.0.1 (system-proxy mode) and on all interfaces
/// (full-traffic mode, where WinDivert reflects connections into it).
///
/// Supports:
///   * CONNECT host:port  (HTTPS and everything else) with upstream auth;
///   * absolute-form HTTP requests (GET http://host/...);
///   * transparent mode, where the destination is taken from the NAT table
///     and the host name is sniffed from TLS SNI / HTTP Host.
/// </summary>
public sealed class LocalProxyServer : IAsyncDisposable
{
    private const int MaxPrefixBytes = 32 * 1024;
    private const int SniffBytes = 2048;
    private static readonly TimeSpan SniffTimeout = TimeSpan.FromMilliseconds(700);

    private readonly ProxySettings _settings;
    private readonly BypassList _bypass;
    private readonly BypassList? _vpn;
    private readonly Logger _log;
    private readonly NatTable? _nat;
    private readonly UpstreamConnector _connector;
    private readonly LogThrottle _errorThrottle = new(TimeSpan.FromSeconds(10));
    private readonly LogThrottle _requestLogThrottle = new(TimeSpan.FromSeconds(1));
    private readonly object _sync = new();

    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    private Task? _acceptTask;

    private long _connections;
    private long _active;
    private long _bytesUp;
    private long _bytesDown;

    public LocalProxyServer(
        ProxySettings settings,
        BypassList bypass,
        Logger log,
        NatTable? nat,
        BypassList? vpn = null,
        SelfConnectionRegistry? selfConnections = null)
    {
        _settings = settings;
        _bypass = bypass;
        _vpn = vpn;
        _log = log;
        _nat = nat;
        _connector = new UpstreamConnector(settings, log, selfConnections);
    }

    public bool IsRunning => _listener is not null;

    public int ListenPort => _settings.ListenPort;

    public long TotalConnections => Interlocked.Read(ref _connections);

    public long ActiveConnections => Interlocked.Read(ref _active);

    public long BytesUp => Interlocked.Read(ref _bytesUp);

    public long BytesDown => Interlocked.Read(ref _bytesDown);

    public bool IsTransparent => _nat is not null;

    public Task StartAsync()
    {
        lock (_sync)
        {
            if (_listener is not null)
            {
                return Task.CompletedTask;
            }

            var listener = new TcpListener(_nat is null ? IPAddress.Loopback : IPAddress.Any, _settings.ListenPort)
            {
                ExclusiveAddressUse = false,
            };
            listener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            listener.Start(512);

            _listener = listener;
            _cts = new CancellationTokenSource();
            _acceptTask = Task.Run(() => AcceptLoopAsync(listener, _cts.Token));
        }

        _log.Info($"Локальный прокси запущен на порту {_settings.ListenPort}" +
                  (_nat is null ? " (режим системного прокси)" : " (режим полного перехвата)"));
        return Task.CompletedTask;
    }

    public async Task StopAsync()
    {
        TcpListener? listener;
        CancellationTokenSource? cts;
        Task? acceptTask;

        lock (_sync)
        {
            listener = _listener;
            cts = _cts;
            acceptTask = _acceptTask;
            _listener = null;
            _cts = null;
            _acceptTask = null;
        }

        if (listener is null)
        {
            return;
        }

        try
        {
            cts?.Cancel();
            listener.Stop();
        }
        catch
        {
            // ignored
        }

        if (acceptTask is not null)
        {
            try
            {
                await acceptTask.ConfigureAwait(false);
            }
            catch
            {
                // ignored
            }
        }

        cts?.Dispose();
        _log.Info("Локальный прокси остановлен");
    }

    private async Task AcceptLoopAsync(TcpListener listener, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await listener.AcceptTcpClientAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (SocketException ex)
            {
                if (ct.IsCancellationRequested)
                {
                    break;
                }

                _log.Warn("Ошибка accept: " + ex.Message);
                continue;
            }

            _ = Task.Run(() => HandleClientAsync(client, ct), CancellationToken.None);
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
    {
        var remote = client.Client.RemoteEndPoint as IPEndPoint;
        Interlocked.Increment(ref _connections);
        Interlocked.Increment(ref _active);

        ClientRequest? request = null;
        Tunnel? tunnel = null;
        NetworkStream? stream = null;
        var connectEstablished = false;
        var forwardMode = false;
        try
        {
            client.NoDelay = true;
            stream = client.GetStream();

            if (!IsClientAllowed(remote))
            {
                _log.Warn($"Отклонено подключение с {remote}");
                return;
            }

            var prefix = await ReadPrefixAsync(stream, ct).ConfigureAwait(false);
            if (prefix.Length == 0)
            {
                return;
            }

            request = ParseRequest(prefix, remote);
            if (request is null)
            {
                _log.Debug($"Не удалось разобрать запрос от {remote}");
                return;
            }

            // Transparent mode knows only the IP; the real host name (if any) comes
            // from TLS SNI or the HTTP Host header. Sending the name upstream lets
            // the proxy resolve it and keeps SNI/name-based ACLs working.
            var hostname = request.Host;
            if (request.Kind == ClientRequestKind.Transparent && !IsVpnEndpoint(request.Host))
            {
                // VPN clients (XRay/Reality, Cloak) deliberately put a decoy name
                // into SNI. For them the destination IP is authoritative, otherwise
                // the tunnel would be opened to the decoy site instead of the server.
                hostname = SniffHostname(prefix) ?? request.Host;
            }

            var bypass = IsBypassed(hostname, request.Host);
            var useUpstream = _settings.HasUpstream && !bypass;

            // Direct connections must use the numeric address from the NAT table;
            // the sniffed name is only meaningful for the upstream proxy.
            var targetHost = useUpstream && !string.IsNullOrEmpty(hostname) ? hostname : request.Host!;

            // Plain HTTP (port 80) is sent to the upstream proxy in forward-proxy
            // form (absolute URI). A CONNECT tunnel to port 80 is refused by many
            // corporate proxies with 403, while a normal HTTP request is allowed.
            forwardMode = CanForwardPlainHttp(useUpstream, request, prefix);

            if (_requestLogThrottle.ShouldLog($"{request.Kind}:{request.Host}:{request.Port}"))
            {
                _log.Debug($"{(request.Kind == ClientRequestKind.Transparent ? "transparent" : request.Kind.ToString())} " +
                           $"{request.Host}:{request.Port}" +
                           (targetHost != request.Host ? $" (как {targetHost})" : string.Empty) +
                           $" -> {(_settings.UpstreamEndpoint)}" +
                           (bypass ? " (bypass)" : forwardMode ? " (forward)" : string.Empty));
            }

            if (forwardMode)
            {
                await RelayForwardHttpAsync(stream, prefix, request, hostname, ct).ConfigureAwait(false);
                return;
            }

            tunnel = await _connector.ConnectAsync(targetHost, request.Port, useUpstream, ct).ConfigureAwait(false);

            if (request.Kind == ClientRequestKind.Connect)
            {
                var response = Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\nProxy-Agent: ProxyForWin\r\n\r\n");
                await stream.WriteAsync(response, ct).ConfigureAwait(false);
                connectEstablished = true;
            }

            var buffered = request.Kind == ClientRequestKind.Connect
                ? prefix[request.HeaderLength..]
                : prefix;
            using var upstream = new NetworkStream(tunnel.Socket, ownsSocket: false);

            if (tunnel.Leftover.Length > 0)
            {
                await stream.WriteAsync(tunnel.Leftover, ct).ConfigureAwait(false);
                Interlocked.Add(ref _bytesDown, tunnel.Leftover.Length);
            }

            if (buffered.Length > 0)
            {
                await upstream.WriteAsync(buffered, ct).ConfigureAwait(false);
                Interlocked.Add(ref _bytesUp, buffered.Length);
            }

            await RelayAsync(stream, upstream, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // shutdown
        }
        catch (Exception ex)
        {
            if (ex is UpstreamProxyException or IOException)
            {
                var key = $"upstream:{request?.Host}:{request?.Port}";
                if (_errorThrottle.ShouldLog(key))
                {
                    _log.Warn(ex.Message);
                }

                if (request?.Kind == ClientRequestKind.Connect && !connectEstablished)
                {
                    await WriteBadGatewayAsync(stream, ex.Message).ConfigureAwait(false);
                }
                else if (forwardMode && request is not null)
                {
                    await WriteBadGatewayAsync(stream, ex.Message).ConfigureAwait(false);
                }
            }
            else
            {
                _log.Debug("Ошибка обработки соединения: " + ex.Message);
            }
        }
        finally
        {
            tunnel?.Dispose();
            stream?.Dispose();
            try
            {
                client.Dispose();
            }
            catch
            {
                // ignored
            }

            Interlocked.Decrement(ref _active);
        }
    }

    /// <summary>
    /// Port 80 with a real HTTP request: use the upstream proxy's forward mode
    /// instead of CONNECT. TLS and other protocols on port 80 still use CONNECT.
    /// </summary>
    private static bool CanForwardPlainHttp(bool useUpstream, ClientRequest request, ReadOnlySpan<byte> prefix)
    {
        if (!useUpstream || request.Port != 80 || request.Kind == ClientRequestKind.Connect)
        {
            return false;
        }

        if (!HttpUtil.LooksLikeHttpRequest(prefix))
        {
            return false;
        }

        // TLS ClientHello on port 80 — CONNECT is the only option.
        return !(prefix.Length >= 3 && prefix[0] == 0x16 && prefix[1] == 0x03);
    }

    /// <summary>
    /// Forwards one plain HTTP request through the upstream proxy in absolute-URI
    /// form, adding Proxy-Authorization. The request is forced to
    /// <c>Connection: close</c>, so a blind relay stays correct for exactly one
    /// request/response exchange.
    /// </summary>
    private async Task RelayForwardHttpAsync(
        NetworkStream client,
        byte[] prefix,
        ClientRequest request,
        string? hostname,
        CancellationToken ct)
    {
        var headerEnd = HttpUtil.IndexOfHeaderEnd(prefix);
        if (headerEnd < 0)
        {
            throw new IOException("Не удалось разобрать HTTP-запрос.");
        }

        var head = Encoding.ASCII.GetString(prefix, 0, headerEnd);
        var lines = head.Split("\r\n");
        var requestLine = lines[0].Split(' ');
        if (requestLine.Length < 3)
        {
            throw new IOException("Не удалось разобрать строку HTTP-запроса.");
        }

        var host = string.IsNullOrEmpty(hostname) ? request.Host! : hostname;
        var authority = FormatAuthority(host, request.Port);
        var target = requestLine[1];
        var absolute = target.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            ? target
            : $"http://{authority}{(target.StartsWith('/') ? target : "/" + target)}";

        var forwarded = new StringBuilder();
        forwarded.Append(requestLine[0]).Append(' ').Append(absolute).Append(' ')
            .Append(string.Join(' ', requestLine[2..])).Append("\r\n");

        var hasHost = false;
        for (var i = 1; i < lines.Length; i++)
        {
            var line = lines[i];
            var colon = line.IndexOf(':');
            if (colon <= 0)
            {
                continue;
            }

            var name = line[..colon];
            if (name.Equals("Proxy-Authorization", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("Proxy-Connection", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("Connection", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("Keep-Alive", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (name.Equals("Host", StringComparison.OrdinalIgnoreCase))
            {
                hasHost = true;
            }

            forwarded.Append(line).Append("\r\n");
        }

        if (!hasHost)
        {
            forwarded.Append("Host: ").Append(authority).Append("\r\n");
        }

        if (!string.IsNullOrEmpty(_settings.Username))
        {
            forwarded.Append("Proxy-Authorization: ")
                .Append(HttpUtil.BuildBasicAuth(_settings.Username, _settings.Password))
                .Append("\r\n");
        }

        forwarded.Append("Connection: close\r\n\r\n");

        var tunnel = await _connector
            .ConnectAsync(_settings.UpstreamHost, _settings.UpstreamPort, useUpstream: false, ct)
            .ConfigureAwait(false);
        try
        {
            using var upstream = new NetworkStream(tunnel.Socket, ownsSocket: false);

            var headBytes = Encoding.ASCII.GetBytes(forwarded.ToString());
            await upstream.WriteAsync(headBytes, ct).ConfigureAwait(false);
            Interlocked.Add(ref _bytesUp, headBytes.Length);

            var body = prefix[headerEnd..];
            if (body.Length > 0)
            {
                await upstream.WriteAsync(body, ct).ConfigureAwait(false);
                Interlocked.Add(ref _bytesUp, body.Length);
            }

            await RelayAsync(client, upstream, ct).ConfigureAwait(false);
        }
        finally
        {
            tunnel.Dispose();
        }
    }

    private static string FormatAuthority(string host, int port)
    {
        var name = host.Contains(':') && !host.StartsWith('[') ? $"[{host}]" : host;
        return port == 80 ? name : $"{name}:{port}";
    }

    /// <summary>Explains a failed tunnel to CONNECT clients instead of silently closing.</summary>
    private static async Task WriteBadGatewayAsync(NetworkStream? stream, string message)
    {
        if (stream is null)
        {
            return;
        }

        try
        {
            var body = Encoding.UTF8.GetBytes("ProxyForWin: " + message + "\r\n");
            var head = Encoding.ASCII.GetBytes(
                "HTTP/1.1 502 Bad Gateway\r\n" +
                "Proxy-Agent: ProxyForWin\r\n" +
                "Content-Type: text/plain; charset=utf-8\r\n" +
                "Connection: close\r\n" +
                $"Content-Length: {body.Length}\r\n\r\n");

            await stream.WriteAsync(head).ConfigureAwait(false);
            await stream.WriteAsync(body).ConfigureAwait(false);
            await stream.FlushAsync().ConfigureAwait(false);
        }
        catch
        {
            // The client may already be gone.
        }
    }

    private bool IsClientAllowed(IPEndPoint? remote)
    {
        if (remote is null)
        {
            return false;
        }

        if (IPAddress.IsLoopback(remote.Address))
        {
            return true;
        }

        // In full-traffic mode the source address is spoofed by the redirector,
        // but the connection must exist in the NAT table.
        if (_nat is not null)
        {
            var bytes = remote.Address.GetAddressBytes();
            if (bytes.Length == 4)
            {
                var address = BinaryPrimitives.ReadUInt32BigEndian(bytes);
                return _nat.Contains(address, (ushort)remote.Port);
            }
        }

        return false;
    }

    private ClientRequest? ParseRequest(ReadOnlySpan<byte> prefix, IPEndPoint? remote)
    {
        if (HttpUtil.LooksLikeHttpRequest(prefix))
        {
            var headerEnd = HttpUtil.IndexOfHeaderEnd(prefix);
            if (headerEnd < 0)
            {
                return null;
            }

            var headers = Encoding.ASCII.GetString(prefix[..headerEnd]);
            var firstLine = headers.Split("\r\n", 2)[0];
            var parts = firstLine.Split(' ');

            if (parts.Length >= 3 && parts[0].Equals("CONNECT", StringComparison.OrdinalIgnoreCase))
            {
                return HttpUtil.TryParseAuthority(parts[1], 443, out var host, out var port)
                    ? new ClientRequest(ClientRequestKind.Connect, host, port, headerEnd)
                    : null;
            }

            if (parts.Length >= 3 && HttpUtil.TryParseAbsoluteUri(parts[1], out var absHost, out var absPort))
            {
                return new ClientRequest(ClientRequestKind.HttpProxy, absHost, absPort, headerEnd);
            }

            // Origin-form request sent to the proxy: use the Host header.
            var hostHeader = HttpUtil.GetHeader(headers, "Host");
            if (hostHeader is not null && HttpUtil.TryParseAuthority(hostHeader, 80, out var hostFromHeader, out var portFromHeader))
            {
                return new ClientRequest(ClientRequestKind.HttpProxy, hostFromHeader, portFromHeader, headerEnd);
            }

            return null;
        }

        // Transparent mode: destination comes from the WinDivert NAT table.
        if (_nat is not null && remote is not null)
        {
            var bytes = remote.Address.GetAddressBytes();
            if (bytes.Length != 4)
            {
                return null;
            }

            var address = BinaryPrimitives.ReadUInt32BigEndian(bytes);
            if (!_nat.TryGetTarget(address, (ushort)remote.Port, out var targetPort))
            {
                return null;
            }

            return new ClientRequest(ClientRequestKind.Transparent, remote.Address.ToString(), targetPort, 0);
        }

        return null;
    }

    private bool IsVpnEndpoint(string? ipHost)
        => _vpn is not null
           && IPAddress.TryParse(ipHost, out var ip)
           && _vpn.MatchesIp(ip);

    private bool IsBypassed(string? hostname, string? ipHost)
    {
        if (_bypass.MatchesHost(hostname))
        {
            return true;
        }

        if (IPAddress.TryParse(ipHost, out var ip) && _bypass.MatchesIp(ip))
        {
            return true;
        }

        return false;
    }

    private static string? SniffHostname(ReadOnlySpan<byte> prefix)
    {
        if (prefix.Length >= 5 && prefix[0] == 0x16 && prefix[1] == 0x03)
        {
            var sni = TlsSniParser.TryGetServerName(prefix);
            if (!string.IsNullOrEmpty(sni))
            {
                return sni;
            }
        }

        if (HttpUtil.LooksLikeHttpRequest(prefix))
        {
            var text = Encoding.ASCII.GetString(prefix);
            var headerEnd = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            var headers = headerEnd >= 0 ? text[..headerEnd] : text;
            return HttpUtil.GetHeader(headers, "Host")?.Split(':')[0];
        }

        return null;
    }

    private static async Task<byte[]> ReadPrefixAsync(NetworkStream stream, CancellationToken ct)
    {
        var buffer = new byte[MaxPrefixBytes];
        var total = 0;

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(SniffTimeout);

        try
        {
            while (total < buffer.Length)
            {
                var n = await stream.ReadAsync(buffer.AsMemory(total), timeout.Token).ConfigureAwait(false);
                if (n == 0)
                {
                    break;
                }

                total += n;

                if (IsPrefixComplete(buffer, total))
                {
                    break;
                }
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            // Sniff window expired; use whatever arrived.
        }

        return buffer[..total];
    }

    private static bool IsPrefixComplete(byte[] buffer, int total)
    {
        var span = buffer.AsSpan(0, total);

        if (HttpUtil.LooksLikeHttpRequest(span))
        {
            return HttpUtil.IndexOfHeaderEnd(span) >= 0;
        }

        return IsCompleteTlsRecord(span) || total >= SniffBytes;
    }

    private static bool IsCompleteTlsRecord(ReadOnlySpan<byte> data)
    {
        if (data.Length < 5 || data[0] != 0x16)
        {
            return false;
        }

        var length = (data[3] << 8) | data[4];
        return data.Length >= 5 + length;
    }

    private async Task RelayAsync(NetworkStream client, NetworkStream upstream, CancellationToken ct)
    {
        var up = PumpAsync(client, upstream, n => Interlocked.Add(ref _bytesUp, n), ct);
        var down = PumpAsync(upstream, client, n => Interlocked.Add(ref _bytesDown, n), ct);

        var first = await Task.WhenAny(up, down).ConfigureAwait(false);
        try
        {
            await first.ConfigureAwait(false);
        }
        catch
        {
            // ignored
        }

        ShutdownSend(client);
        ShutdownSend(upstream);

        var second = ReferenceEquals(first, up) ? down : up;
        await Task.WhenAny(second, Task.Delay(TimeSpan.FromSeconds(5), ct)).ConfigureAwait(false);
    }

    private static async Task PumpAsync(Stream from, Stream to, Action<int> onBytes, CancellationToken ct)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(64 * 1024);
        try
        {
            while (true)
            {
                var n = await from.ReadAsync(buffer.AsMemory(0, buffer.Length), ct).ConfigureAwait(false);
                if (n == 0)
                {
                    break;
                }

                await to.WriteAsync(buffer.AsMemory(0, n), ct).ConfigureAwait(false);
                onBytes(n);
            }
        }
        catch
        {
            // Connection reset/timeout: stop pumping.
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
            ShutdownSend(to);
        }
    }

    private static void ShutdownSend(Stream stream)
    {
        try
        {
            if (stream is NetworkStream ns && ns.Socket.Connected)
            {
                ns.Socket.Shutdown(SocketShutdown.Send);
            }
        }
        catch
        {
            // ignored
        }
    }

    public async ValueTask DisposeAsync() => await StopAsync().ConfigureAwait(false);
}
