using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using ProxyForWin.Core;

namespace ProxyForWin.Tests;

internal static class Program
{
    private static int _passed;
    private static int _failed;

    private static async Task<int> Main()
    {
        Console.WriteLine("ProxyForWin core tests");
        Console.WriteLine("======================");

        BypassTests();
        PacketRewriterTests();
        NatTableTests();
        SelfConnectionRegistryTests();
        SniParserTests();
        LogThrottleTests();
        SettingsStoreTests();
        await LocalProxyConnectTest();
        await LocalProxyTransparentTest();
        await LocalProxyTransparentSniTest();
        await LocalProxyVpnEndpointTest();
        await LocalProxyAbsoluteFormTest();
        await UpstreamRejectedTest();
        await SelfConnectionRegistryTunnelTest();

        Console.WriteLine();
        Console.WriteLine($"Пройдено: {_passed}, провалено: {_failed}");
        return _failed == 0 ? 0 : 1;
    }

    private static void BypassTests()
    {
        var bypass = new BypassList(new[]
        {
            "example.com",
            "*.corp.local",
            "203.0.113.0/24",
            "192.168.5.5",
            "# comment",
            "http://site.test/path",
        });

        Check("exact host", bypass.MatchesHost("example.com"));
        Check("exact host case", bypass.MatchesHost("EXAMPLE.COM"));
        Check("subdomain of exact host", bypass.MatchesHost("api.example.com"));
        Check("wildcard subdomain", bypass.MatchesHost("vpn.corp.local"));
        Check("wildcard does not match root", !bypass.MatchesHost("corp.local"));
        Check("domain negative", !bypass.MatchesHost("example.org"));
        Check("url entry normalized", bypass.MatchesHost("site.test"));
        Check("private range", bypass.MatchesIp(IPAddress.Parse("10.0.0.5")));
        Check("custom cidr inside", bypass.MatchesIp(IPAddress.Parse("203.0.113.77")));
        Check("custom cidr outside", !bypass.MatchesIp(IPAddress.Parse("203.0.114.1")));
        Check("single ip", bypass.MatchesIp(IPAddress.Parse("192.168.5.5")));
        Check("loopback auto", bypass.MatchesIp(IPAddress.Parse("127.0.0.1")));
        Check("lan auto", bypass.MatchesIp(IPAddress.Parse("192.168.1.10")));
        Check("ipv6 loopback auto", bypass.MatchesIp(IPAddress.Parse("::1")));
        Check("public ip not bypassed", !bypass.MatchesIp(IPAddress.Parse("8.8.8.8")));
        Check("glob star", BypassList.GlobMatch("*.example.com", "a.b.example.com"));
        Check("glob question", BypassList.GlobMatch("ab?", "abc"));
        Check("has domain rules", bypass.HasDomainRules);
        Check("override contains local", bypass.ToWinInetOverride().Contains("<local>"));
        Check("override wildcard for class A", bypass.ToWinInetOverride().Contains("10.*"));
        Check("override no cidr syntax", !bypass.ToWinInetOverride().Contains("/"));
    }

    private static void PacketRewriterTests()
    {
        var packet = BuildTcpPacket(
            srcAddress: ParseIp("192.168.1.10"),
            dstAddress: ParseIp("93.184.216.34"),
            srcPort: 51234,
            dstPort: 443,
            payload: new byte[] { 1, 2, 3, 4 });

        Check("parse tcp", PacketRewriter.TryParseIpv4Tcp(packet, out var info));
        Check("parse src port", info.SrcPort == 51234);
        Check("parse dst port", info.DstPort == 443);

        var toProxy = packet.ToArray();
        PacketRewriter.RewriteAppToProxy(toProxy, info, 8899);
        Check("to proxy: src addr is server", PacketRewriter.TryParseIpv4Tcp(toProxy, out var proxied)
                                             && proxied.SrcAddress == ParseIp("93.184.216.34"));
        Check("to proxy: dst addr is client", proxied.DstAddress == ParseIp("192.168.1.10"));
        Check("to proxy: dst port is proxy", proxied.DstPort == 8899);
        Check("to proxy: src port preserved", proxied.SrcPort == 51234);

        var toApp = BuildTcpPacket(
            srcAddress: ParseIp("192.168.1.10"),
            dstAddress: ParseIp("93.184.216.34"),
            srcPort: 8899,
            dstPort: 51234,
            payload: Array.Empty<byte>());

        Check("proxy reply parses", PacketRewriter.TryParseIpv4Tcp(toApp, out var replyInfo));
        PacketRewriter.RewriteProxyToApp(toApp, replyInfo, 443);
        Check("to app: src addr is server", PacketRewriter.TryParseIpv4Tcp(toApp, out var restored)
                                             && restored.SrcAddress == ParseIp("93.184.216.34"));
        Check("to app: src port is target", restored.SrcPort == 443);
        Check("to app: dst addr is client", restored.DstAddress == ParseIp("192.168.1.10"));
        Check("to app: dst port is app", restored.DstPort == 51234);

        var nonTcp = BuildTcpPacket(0, 0, 1, 2, Array.Empty<byte>());
        nonTcp[9] = 17; // UDP protocol
        Check("reject non-tcp", !PacketRewriter.TryParseIpv4Tcp(nonTcp, out _));
    }

    private static void NatTableTests()
    {
        var nat = new NatTable();
        nat.Register(ParseIp("1.2.3.4"), 51000, 443);
        Check("nat hit", nat.TryGetTarget(ParseIp("1.2.3.4"), 51000, out var port) && port == 443);
        Check("nat miss", !nat.TryGetTarget(ParseIp("1.2.3.4"), 51001, out _));
        Check("nat count", nat.Count == 1);
        nat.Prune(TimeSpan.FromMilliseconds(-1));
        Check("nat pruned", nat.Count == 0);
    }

    private static void SelfConnectionRegistryTests()
    {
        var registry = new SelfConnectionRegistry();
        registry.Register(51234, ParseIp("203.0.113.9"), 443);

        Check("self port match", registry.Matches(51234, ParseIp("203.0.113.9"), 443));
        Check("self port wrong address", !registry.Matches(51234, ParseIp("203.0.113.10"), 443));
        Check("self port wrong destination port", !registry.Matches(51234, ParseIp("203.0.113.9"), 80));
        Check("self port unknown local port", !registry.Matches(51235, ParseIp("203.0.113.9"), 443));
        Check("self port count", registry.Count == 1);

        registry.Register(51234, ParseIp("203.0.113.9"), 444);
        Check("self port re-register replaces", registry.Matches(51234, ParseIp("203.0.113.9"), 444));

        registry.Unregister(51234);
        Check("self port unregistered", !registry.Matches(51234, ParseIp("203.0.113.9"), 444));

        registry.Register(40000, ParseIp("1.1.1.1"), 443);
        registry.Prune(TimeSpan.FromMilliseconds(-1));
        Check("self port pruned", registry.Count == 0);
    }

    private static void SniParserTests()
    {
        var hello = BuildClientHello("secure.example.org");
        Check("sni parsed", TlsSniParser.TryGetServerName(hello) == "secure.example.org");
        Check("sni null on garbage", TlsSniParser.TryGetServerName(new byte[] { 1, 2, 3, 4, 5 }) is null);
    }

    private static void LogThrottleTests()
    {
        var throttle = new LogThrottle(TimeSpan.FromMilliseconds(200));
        Check("throttle allows first", throttle.ShouldLog("dest"));
        Check("throttle suppresses repeat", !throttle.ShouldLog("dest"));
        Check("throttle independent keys", throttle.ShouldLog("other"));
        throttle.Clear();
        Check("throttle clear", throttle.ShouldLog("dest"));
    }

    private static void SettingsStoreTests()
    {
        var dir = Path.Combine(Path.GetTempPath(), "proxyforwin-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var path = Path.Combine(dir, "settings.json");
            var store = new SettingsStore(path, new Base64Protector());
            var settings = ProxySettings.CreateDefault();
            settings.UpstreamHost = "proxy.example.com";
            settings.UpstreamPort = 3128;
            settings.Username = "user";
            settings.Password = "secret-password";
            settings.Mode = ProxyMode.FullTraffic;
            settings.Bypass.Add("*.internal");

            store.Save(settings);

            var raw = File.ReadAllText(path);
            Check("password not stored in plain text", !raw.Contains("secret-password"));

            var loaded = store.Load();
            Check("host round-trip", loaded.UpstreamHost == "proxy.example.com");
            Check("port round-trip", loaded.UpstreamPort == 3128);
            Check("password round-trip", loaded.Password == "secret-password");
            Check("mode round-trip", loaded.Mode == ProxyMode.FullTraffic);
            Check("bypass round-trip", loaded.Bypass.Contains("*.internal"));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    private static async Task LocalProxyConnectTest()
    {
        var fakeProxy = new FakeHttpProxy();
        var proxyPort = GetFreePort();
        fakeProxy.Start(proxyPort);

        var listenPort = GetFreePort();
        var settings = new ProxySettings
        {
            UpstreamHost = "127.0.0.1",
            UpstreamPort = proxyPort,
            Username = "alice",
            Password = "s3cret",
            ListenPort = listenPort,
        };

        var logger = new Logger();
        await using var server = new LocalProxyServer(settings, new BypassList(Array.Empty<string>()), logger, nat: null);
        await server.StartAsync();

        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, listenPort);
            var stream = client.GetStream();

            var connect = Encoding.ASCII.GetBytes("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n");
            await stream.WriteAsync(connect);

            var response = await ReadUntilAsync(stream, "\r\n\r\n", TimeSpan.FromSeconds(10));
            Check("connect status 200", response.StartsWith("HTTP/1.1 200", StringComparison.Ordinal));

            await stream.WriteAsync(Encoding.ASCII.GetBytes("hello through tunnel"));
            var echoed = await ReadExactlyAsync(stream, "hello through tunnel".Length, TimeSpan.FromSeconds(10));
            Check("tunnel data relayed", echoed == "hello through tunnel");
            Check("upstream CONNECT target", fakeProxy.LastTarget == "example.com:443");
            Check("upstream auth header", fakeProxy.LastAuthorization == "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("alice:s3cret")));
        }
        finally
        {
            await server.StopAsync();
            fakeProxy.Stop();
        }
    }

    private static async Task LocalProxyTransparentTest()
    {
        var fakeProxy = new FakeHttpProxy();
        var proxyPort = GetFreePort();
        fakeProxy.Start(proxyPort);

        var listenPort = GetFreePort();
        var nat = new NatTable();
        var settings = new ProxySettings
        {
            UpstreamHost = "127.0.0.1",
            UpstreamPort = proxyPort,
            ListenPort = listenPort,
        };

        var logger = new Logger();
        await using var server = new LocalProxyServer(settings, new BypassList(Array.Empty<string>(), includePrivateRanges: false), logger, nat);
        await server.StartAsync();

        const int appPort = 40123;
        try
        {
            using var client = new TcpClient(new IPEndPoint(IPAddress.Loopback, appPort));
            nat.Register(ParseIp("127.0.0.1"), appPort, 8443);

            await client.ConnectAsync(IPAddress.Loopback, listenPort);
            var stream = client.GetStream();

            await stream.WriteAsync(Encoding.ASCII.GetBytes("raw transparent bytes"));
            var echoed = await ReadExactlyAsync(stream, "raw transparent bytes".Length, TimeSpan.FromSeconds(10));
            Check("transparent data relayed", echoed == "raw transparent bytes");
            Check("transparent target from NAT", fakeProxy.LastTarget == "127.0.0.1:8443");
        }
        finally
        {
            await server.StopAsync();
            fakeProxy.Stop();
        }
    }

    private static async Task LocalProxyTransparentSniTest()
    {
        var fakeProxy = new FakeHttpProxy();
        var proxyPort = GetFreePort();
        fakeProxy.Start(proxyPort);

        var listenPort = GetFreePort();
        var nat = new NatTable();
        var settings = new ProxySettings
        {
            UpstreamHost = "127.0.0.1",
            UpstreamPort = proxyPort,
            ListenPort = listenPort,
        };

        var logger = new Logger();
        await using var server = new LocalProxyServer(settings, new BypassList(Array.Empty<string>(), includePrivateRanges: false), logger, nat);
        await server.StartAsync();

        const int appPort = 40124;
        try
        {
            using var client = new TcpClient(new IPEndPoint(IPAddress.Loopback, appPort));
            nat.Register(ParseIp("127.0.0.1"), appPort, 8443);

            await client.ConnectAsync(IPAddress.Loopback, listenPort);
            var stream = client.GetStream();

            var hello = BuildClientHello("secure.example.org");
            await stream.WriteAsync(hello);
            var echoed = await ReadExactlyBytesAsync(stream, hello.Length, TimeSpan.FromSeconds(10));
            Check("transparent tls relayed", echoed.AsSpan().SequenceEqual(hello));
            Check("transparent SNI used as CONNECT target", fakeProxy.LastTarget == "secure.example.org:8443");
        }
        finally
        {
            await server.StopAsync();
            fakeProxy.Stop();
        }
    }

    private static async Task LocalProxyVpnEndpointTest()
    {
        var fakeProxy = new FakeHttpProxy();
        var proxyPort = GetFreePort();
        fakeProxy.Start(proxyPort);

        var listenPort = GetFreePort();
        var nat = new NatTable();
        var settings = new ProxySettings
        {
            UpstreamHost = "127.0.0.1",
            UpstreamPort = proxyPort,
            ListenPort = listenPort,
        };

        var logger = new Logger();
        var vpn = new BypassList(new[] { "127.0.0.1" }, includePrivateRanges: false);
        await using var server = new LocalProxyServer(
            settings,
            new BypassList(Array.Empty<string>(), includePrivateRanges: false),
            logger,
            nat,
            vpn);
        await server.StartAsync();

        const int appPort = 40125;
        try
        {
            using var client = new TcpClient(new IPEndPoint(IPAddress.Loopback, appPort));
            nat.Register(ParseIp("127.0.0.1"), appPort, 8443);

            await client.ConnectAsync(IPAddress.Loopback, listenPort);
            var stream = client.GetStream();

            // Reality-style decoy SNI must not become the CONNECT target.
            var hello = BuildClientHello("decoy.example.com");
            await stream.WriteAsync(hello);
            await ReadExactlyBytesAsync(stream, hello.Length, TimeSpan.FromSeconds(10));
            Check("vpn endpoint: decoy SNI ignored", fakeProxy.LastTarget == "127.0.0.1:8443");
        }
        finally
        {
            await server.StopAsync();
            fakeProxy.Stop();
        }
    }

    private static async Task LocalProxyAbsoluteFormTest()
    {
        var fakeProxy = new FakeHttpProxy();
        var proxyPort = GetFreePort();
        fakeProxy.Start(proxyPort);

        var listenPort = GetFreePort();
        var settings = new ProxySettings
        {
            UpstreamHost = "127.0.0.1",
            UpstreamPort = proxyPort,
            Username = "alice",
            Password = "s3cret",
            ListenPort = listenPort,
        };

        var logger = new Logger();
        await using var server = new LocalProxyServer(settings, new BypassList(Array.Empty<string>()), logger, nat: null);
        await server.StartAsync();

        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, listenPort);
            var stream = client.GetStream();

            const string request = "GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n";
            await stream.WriteAsync(Encoding.ASCII.GetBytes(request));

            var response = await ReadUntilAsync(stream, "hello", TimeSpan.FromSeconds(10));
            Check("forward mode answered", response.StartsWith("HTTP/1.1 200", StringComparison.Ordinal));
            Check("forward mode body relayed", response.Contains("hello", StringComparison.Ordinal));
            Check("forward absolute-form target", fakeProxy.LastTarget == "http://example.com/path");
            Check("forward auth header", fakeProxy.LastAuthorization ==
                                          "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("alice:s3cret")));
            Check("forward sends Connection close", fakeProxy.LastConnectionClose);
        }
        finally
        {
            await server.StopAsync();
            fakeProxy.Stop();
        }
    }

    private static async Task SelfConnectionRegistryTunnelTest()
    {
        var fakeProxy = new FakeHttpProxy();
        var proxyPort = GetFreePort();
        fakeProxy.Start(proxyPort);

        var settings = new ProxySettings
        {
            UpstreamHost = "127.0.0.1",
            UpstreamPort = proxyPort,
            ListenPort = GetFreePort(),
        };

        var registry = new SelfConnectionRegistry();
        var connector = new UpstreamConnector(settings, new Logger(), registry);
        var tunnel = await connector.ConnectAsync("example.com", 443, useUpstream: true, CancellationToken.None);
        try
        {
            Check("tunnel port registered",
                registry.Matches(tunnel.LocalPort, ParseIp("127.0.0.1"), (ushort)proxyPort));
            Check("tunnel registered once", registry.Count == 1);
        }
        finally
        {
            tunnel.Dispose();
            fakeProxy.Stop();
        }

        Check("tunnel unregisters port on dispose", registry.Count == 0);
    }

    private static async Task UpstreamRejectedTest()
    {
        var fakeProxy = new FakeHttpProxy
        {
            Status = 407,
            AuthenticateHeader = "NTLM",
        };
        var proxyPort = GetFreePort();
        fakeProxy.Start(proxyPort);

        var listenPort = GetFreePort();
        var settings = new ProxySettings
        {
            UpstreamHost = "127.0.0.1",
            UpstreamPort = proxyPort,
            Username = "alice",
            Password = "s3cret",
            ListenPort = listenPort,
        };

        var logger = new Logger();
        await using var server = new LocalProxyServer(settings, new BypassList(Array.Empty<string>()), logger, nat: null);
        await server.StartAsync();

        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, listenPort);
            var stream = client.GetStream();

            var connect = Encoding.ASCII.GetBytes("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n");
            await stream.WriteAsync(connect);

            var response = await ReadUntilAsync(stream, "Basic", TimeSpan.FromSeconds(10));
            Check("407 answered with 502", response.StartsWith("HTTP/1.1 502", StringComparison.Ordinal));
            Check("407 explains NTLM challenge", response.Contains("NTLM", StringComparison.Ordinal)
                                                 && response.Contains("Basic", StringComparison.Ordinal));
            Check("407 status mentioned", response.Contains("(407)", StringComparison.Ordinal));
        }
        finally
        {
            await server.StopAsync();
            fakeProxy.Stop();
        }
    }

    private static uint ParseIp(string value)
    {
        var bytes = IPAddress.Parse(value).GetAddressBytes();
        return BinaryPrimitives.ReadUInt32BigEndian(bytes);
    }

    private static byte[] BuildTcpPacket(uint srcAddress, uint dstAddress, ushort srcPort, ushort dstPort, byte[] payload)
    {
        var packet = new byte[20 + 20 + payload.Length];
        packet[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), (ushort)packet.Length);
        packet[8] = 64;
        packet[9] = 6;
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(12), srcAddress);
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(16), dstAddress);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(20), srcPort);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(22), dstPort);
        packet[32] = 0x50;
        payload.CopyTo(packet, 40);
        return packet;
    }

    private static byte[] BuildClientHello(string host)
    {
        var hostBytes = Encoding.ASCII.GetBytes(host);

        var sniList = new List<byte>();
        sniList.AddRange(new byte[] { 0x00, 0x00 }); // placeholder for list length
        sniList.Add(0x00); // host_name
        sniList.Add((byte)(hostBytes.Length >> 8));
        sniList.Add((byte)hostBytes.Length);
        sniList.AddRange(hostBytes);
        var listLength = sniList.Count - 2;
        sniList[0] = (byte)(listLength >> 8);
        sniList[1] = (byte)listLength;

        var extension = new List<byte>();
        extension.AddRange(new byte[] { 0x00, 0x00 }); // server_name
        extension.Add((byte)(sniList.Count >> 8));
        extension.Add((byte)sniList.Count);
        extension.AddRange(sniList);

        var body = new List<byte>();
        body.AddRange(new byte[] { 0x03, 0x03 }); // TLS 1.2
        body.AddRange(new byte[32]); // random
        body.Add(0x00); // session id
        body.AddRange(new byte[] { 0x00, 0x02, 0x2F, 0x35 }); // cipher suites
        body.AddRange(new byte[] { 0x01, 0x00 }); // compression
        body.Add((byte)(extension.Count >> 8));
        body.Add((byte)extension.Count);
        body.AddRange(extension);

        var handshake = new List<byte> { 0x01 };
        handshake.Add((byte)(body.Count >> 16));
        handshake.Add((byte)(body.Count >> 8));
        handshake.Add((byte)body.Count);
        handshake.AddRange(body);

        var record = new List<byte> { 0x16, 0x03, 0x01 };
        record.Add((byte)(handshake.Count >> 8));
        record.Add((byte)handshake.Count);
        record.AddRange(handshake);
        return record.ToArray();
    }

    private static async Task<string> ReadUntilAsync(NetworkStream stream, string marker, TimeSpan timeout)
    {
        using var cts = new CancellationTokenSource(timeout);
        var buffer = new List<byte>();
        var single = new byte[1];
        while (true)
        {
            var n = await stream.ReadAsync(single.AsMemory(0, 1), cts.Token);
            if (n == 0)
            {
                break;
            }

            buffer.Add(single[0]);
            var text = Encoding.ASCII.GetString(buffer.ToArray());
            if (text.Contains(marker, StringComparison.Ordinal))
            {
                return text;
            }
        }

        return Encoding.ASCII.GetString(buffer.ToArray());
    }

    private static async Task<string> ReadExactlyAsync(NetworkStream stream, int count, TimeSpan timeout)
    {
        using var cts = new CancellationTokenSource(timeout);
        var buffer = new byte[count];
        var read = 0;
        while (read < count)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(read, count - read), cts.Token);
            if (n == 0)
            {
                break;
            }

            read += n;
        }

        return Encoding.ASCII.GetString(buffer, 0, read);
    }

    private static async Task<byte[]> ReadExactlyBytesAsync(NetworkStream stream, int count, TimeSpan timeout)
    {
        using var cts = new CancellationTokenSource(timeout);
        var buffer = new byte[count];
        var read = 0;
        while (read < count)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(read, count - read), cts.Token);
            if (n == 0)
            {
                break;
            }

            read += n;
        }

        return buffer[..read];
    }

    private static int GetFreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private static void Check(string name, bool condition)
    {
        if (condition)
        {
            _passed++;
            Console.WriteLine($"  ok   {name}");
        }
        else
        {
            _failed++;
            Console.WriteLine($"  FAIL {name}");
        }
    }

    /// <summary>Minimal HTTP proxy: accepts CONNECT, answers 200, echoes everything.</summary>
    private sealed class FakeHttpProxy
    {
        private TcpListener? _listener;
        private CancellationTokenSource? _cts;

        public string? LastTarget { get; private set; }

        public string? LastAuthorization { get; private set; }

        public bool LastConnectionClose { get; private set; }

        /// <summary>HTTP status returned to CONNECT (200 echoes the tunnel).</summary>
        public int Status { get; init; } = 200;

        /// <summary>Optional Proxy-Authenticate value for non-200 responses.</summary>
        public string? AuthenticateHeader { get; init; }

        public void Start(int port)
        {
            _listener = new TcpListener(IPAddress.Loopback, port);
            _listener.Start();
            _cts = new CancellationTokenSource();
            _ = Task.Run(() => AcceptLoopAsync(_listener, _cts.Token));
        }

        public void Stop()
        {
            _cts?.Cancel();
            _listener?.Stop();
        }

        private async Task AcceptLoopAsync(TcpListener listener, CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await listener.AcceptTcpClientAsync(ct);
                }
                catch
                {
                    break;
                }

                _ = Task.Run(() => HandleAsync(client, ct), CancellationToken.None);
            }
        }

        private async Task HandleAsync(TcpClient client, CancellationToken ct)
        {
            using (client)
            {
                var stream = client.GetStream();
                var headers = await ReadUntilAsync(stream, "\r\n\r\n", TimeSpan.FromSeconds(10));
                var firstLine = headers.Split("\r\n", 2)[0];
                LastTarget = firstLine.Split(' ').ElementAtOrDefault(1);
                LastAuthorization = HttpUtil.GetHeader(headers, "Proxy-Authorization");
                LastConnectionClose = string.Equals(
                    HttpUtil.GetHeader(headers, "Connection"), "close", StringComparison.OrdinalIgnoreCase);

                if (Status != 200)
                {
                    var rejection = new StringBuilder();
                    rejection.Append($"HTTP/1.1 {Status} Rejected\r\n");
                    rejection.Append("Content-Length: 0\r\n");
                    if (!string.IsNullOrEmpty(AuthenticateHeader))
                    {
                        rejection.Append("Proxy-Authenticate: ").Append(AuthenticateHeader).Append("\r\n");
                    }

                    rejection.Append("\r\n");
                    await stream.WriteAsync(Encoding.ASCII.GetBytes(rejection.ToString()), ct);
                    return;
                }

                if (!firstLine.StartsWith("CONNECT ", StringComparison.OrdinalIgnoreCase))
                {
                    // Forward-proxy request: answer with a tiny document, as a real
                    // HTTP proxy would, and close (the client asked for close).
                    await stream.WriteAsync(Encoding.ASCII.GetBytes(
                        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"), ct);
                    return;
                }

                await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n"), ct);

                var buffer = new byte[8192];
                while (true)
                {
                    var n = await stream.ReadAsync(buffer, ct);
                    if (n == 0)
                    {
                        break;
                    }

                    await stream.WriteAsync(buffer.AsMemory(0, n), ct);
                }
            }
        }
    }
}
