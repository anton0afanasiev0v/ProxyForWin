using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ProxyForWin.Core;

/// <summary>
/// Thrown when the upstream proxy refuses a CONNECT. Carries the HTTP status and the
/// <c>Proxy-Authenticate</c> challenge so the UI can explain *why* (bad password vs
/// an unsupported NTLM/Negotiate scheme).
/// </summary>
public sealed class UpstreamProxyException : IOException
{
    public UpstreamProxyException(
        string target,
        int status,
        string statusLine,
        string? authenticateHeader,
        bool usedAuth,
        string message)
        : base(message)
    {
        Target = target;
        Status = status;
        StatusLine = statusLine;
        AuthenticateHeader = authenticateHeader;
        UsedAuth = usedAuth;
    }

    public string Target { get; }

    public int Status { get; }

    public string StatusLine { get; }

    public string? AuthenticateHeader { get; }

    public bool UsedAuth { get; }
}

/// <summary>
/// Opens connections either directly (bypass) or through the upstream HTTP proxy
/// using the CONNECT method with Proxy-Authorization.
///
/// Source ports are ordinary ephemeral ports. Every socket is registered in a
/// <see cref="SelfConnectionRegistry"/> before it connects, and the WinDivert
/// redirector lets those exact flows through untouched. A fixed port range was
/// used before, but Windows (Hyper-V/WSL/Docker) can reserve it and endpoint
/// security can forbid binds to it — that produced WSAEACCES on bind() and broke
/// every proxied connection on some machines.
/// </summary>
public sealed class UpstreamConnector
{
    private const int ConnectAttempts = 3;
    private static readonly TimeSpan ResponseTimeout = TimeSpan.FromSeconds(30);

    private readonly ProxySettings _settings;
    private readonly Logger _log;
    private readonly SelfConnectionRegistry _selfConnections;
    private readonly LogThrottle _connectLogThrottle = new(TimeSpan.FromSeconds(1));

    public UpstreamConnector(
        ProxySettings settings,
        Logger log,
        SelfConnectionRegistry? selfConnections = null)
    {
        _settings = settings;
        _log = log;
        _selfConnections = selfConnections ?? new SelfConnectionRegistry();
    }

    public sealed class Tunnel : IDisposable
    {
        private readonly SelfConnectionRegistry? _registry;
        private readonly int _localPort;
        private int _disposed;

        internal Tunnel(Socket socket, byte[]? leftover, SelfConnectionRegistry? registry, int localPort)
        {
            Socket = socket;
            Leftover = leftover ?? Array.Empty<byte>();
            _registry = registry;
            _localPort = localPort;
        }

        public Socket Socket { get; }

        /// <summary>Bytes that arrived after the proxy response headers.</summary>
        public byte[] Leftover { get; }

        /// <summary>Local (source) port of this socket, as registered for the redirector.</summary>
        public int LocalPort => _localPort;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            Socket.Dispose();
            _registry?.Unregister(_localPort);
        }
    }

    private sealed record UpstreamResponse(int Status, string StatusLine, string Headers, byte[] Leftover);

    public async Task<Tunnel> ConnectAsync(string targetHost, int targetPort, bool useUpstream, CancellationToken ct)
    {
        if (useUpstream)
        {
            return await ConnectViaUpstreamAsync(targetHost, targetPort, ct).ConfigureAwait(false);
        }

        var (socket, localPort) = await OpenSocketAsync(targetHost, targetPort, ct).ConfigureAwait(false);
        return new Tunnel(socket, null, _selfConnections, localPort);
    }

    private async Task<Tunnel> ConnectViaUpstreamAsync(string targetHost, int targetPort, CancellationToken ct)
    {
        var target = $"{targetHost}:{targetPort}";
        var usedAuth = !string.IsNullOrEmpty(_settings.Username);

        if (_connectLogThrottle.ShouldLog(target))
        {
            _log.Debug($"CONNECT {target} через {_settings.UpstreamEndpoint}; " +
                       $"авторизация: {(usedAuth ? "Basic, логин " + _settings.Username : "не настроена")}");
        }

        var (socket, localPort) = await OpenSocketAsync(_settings.UpstreamHost, _settings.UpstreamPort, ct)
            .ConfigureAwait(false);
        try
        {
            var builder = new StringBuilder();
            builder.Append("CONNECT ").Append(target).Append(" HTTP/1.1\r\n");
            builder.Append("Host: ").Append(target).Append("\r\n");
            builder.Append("Proxy-Connection: Keep-Alive\r\n");
            if (usedAuth)
            {
                builder.Append("Proxy-Authorization: ")
                    .Append(HttpUtil.BuildBasicAuth(_settings.Username, _settings.Password))
                    .Append("\r\n");
            }

            builder.Append("\r\n");
            var request = Encoding.ASCII.GetBytes(builder.ToString());
            await socket.SendAsync(request, SocketFlags.None, ct).ConfigureAwait(false);

            UpstreamResponse response;
            using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                timeout.CancelAfter(ResponseTimeout);
                try
                {
                    response = await ReadResponseAsync(socket, timeout.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    throw new IOException(
                        $"Upstream {_settings.UpstreamEndpoint} не ответил на CONNECT {target} за " +
                        $"{ResponseTimeout.TotalSeconds:F0} с");
                }
            }

            if (response.Status != 200)
            {
                throw BuildException(target, response, usedAuth);
            }

            return new Tunnel(socket, response.Leftover, _selfConnections, localPort);
        }
        catch
        {
            socket.Dispose();
            _selfConnections.Unregister(localPort);
            throw;
        }
    }

    private static UpstreamProxyException BuildException(string target, UpstreamResponse response, bool usedAuth)
    {
        var challenge = HttpUtil.GetHeader(response.Headers, "Proxy-Authenticate");
        var offersBasic = challenge is not null &&
                          challenge.Contains("Basic", StringComparison.OrdinalIgnoreCase);
        var offersOther = !string.IsNullOrWhiteSpace(challenge) && !offersBasic;

        var message = response.Status switch
        {
            407 => usedAuth
                ? $"Upstream отклонил логин/пароль (407) для {target}."
                : $"Upstream требует авторизацию (407) для {target}, а логин не задан.",
            403 => $"Upstream запретил CONNECT на {target} (403). Обычно это ограничение " +
                   "списка разрешённых портов на прокси-сервере.",
            502 or 503 or 504 => $"Upstream не смог подключиться к {target} ({response.Status}).",
            _ => $"Upstream ответил {response.Status} на CONNECT {target}.",
        };

        if (response.Status == 407 && offersOther)
        {
            message += $" Прокси предлагает схему «{challenge}», программа поддерживает только Basic.";
        }
        else if (response.Status == 407 && !offersBasic)
        {
            message += " Прокси не предложил Basic — вероятно, он требует NTLM/Kerberos.";
        }

        return new UpstreamProxyException(target, response.Status, response.StatusLine, challenge, usedAuth, message);
    }

    /// <summary>
    /// Opens a TCP socket on an ephemeral port and registers it so the redirector can
    /// tell the proxy's own traffic apart from application traffic.
    /// </summary>
    private async Task<(Socket Socket, int LocalPort)> OpenSocketAsync(string host, int port, CancellationToken ct)
    {
        var addresses = await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);
        var address = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                      ?? throw new IOException($"Не удалось разрешить {host} в IPv4-адрес");

        Exception? lastError = null;
        for (var attempt = 0; attempt < ConnectAttempts; attempt++)
        {
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            int localPort;
            try
            {
                ConfigureSocket(socket);
                socket.Bind(new IPEndPoint(IPAddress.Any, 0));
                localPort = ((IPEndPoint)socket.LocalEndPoint!).Port;
                _selfConnections.Register(localPort, ToUInt32(address), (ushort)port);
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
                return (socket, localPort);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                _selfConnections.Unregister(localPort);
                socket.Dispose();
                throw new IOException($"Таймаут подключения к {host}:{port}");
            }
            catch (Exception ex)
            {
                _selfConnections.Unregister(localPort);
                socket.Dispose();
                lastError = ex;
                if (ex is not SocketException)
                {
                    throw;
                }
            }
        }

        var hint = (lastError as SocketException)?.SocketErrorCode == SocketError.AccessDenied
            ? " Windows или защитное ПО запрещает такие исходящие подключения."
            : string.Empty;

        throw new IOException(
            $"Не удалось подключиться к {host}:{port}: {lastError?.Message}{hint}", lastError);
    }

    private static uint ToUInt32(IPAddress address)
    {
        Span<byte> bytes = stackalloc byte[4];
        address.TryWriteBytes(bytes, out _);
        return BinaryPrimitives.ReadUInt32BigEndian(bytes);
    }

    /// <summary>
    /// Long-lived tunnels (VPN, SSH, websockets) must not be dropped by an idle
    /// timeout on the upstream proxy, so TCP keep-alive is enabled explicitly.
    /// </summary>
    private static void ConfigureSocket(Socket socket)
    {
        socket.NoDelay = true;

        try
        {
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
            socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveTime, 30);
            socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveInterval, 5);
            socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveRetryCount, 3);
        }
        catch
        {
            // Not supported everywhere; keep-alive is a nice-to-have, not a requirement.
        }
    }

    private static async Task<UpstreamResponse> ReadResponseAsync(Socket socket, CancellationToken ct)
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
            return new UpstreamResponse(status, firstLine, headers, leftover);
        }

        throw new IOException("Upstream proxy response headers are too large");
    }
}
