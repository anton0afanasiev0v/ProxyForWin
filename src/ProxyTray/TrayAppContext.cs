using ProxyForWin.Core;

namespace ProxyForWin.Tray;

internal sealed class TrayAppContext : ApplicationContext
{
    private readonly string _dataDir;
    private readonly Logger _log;
    private readonly SettingsStore _store;
    private readonly ProxyEngine _engine;
    private readonly NotifyIcon _notifyIcon;
    private readonly ToolStripMenuItem _toggleItem;
    private readonly ToolStripMenuItem _statusItem;
    private readonly Icon _onIcon;
    private readonly Icon _offIcon;
    private readonly SynchronizationContext? _uiContext;

    private SettingsForm? _form;
    private bool _busy;

    public TrayAppContext()
    {
        _uiContext = SynchronizationContext.Current;

        _dataDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "ProxyForWin");
        Directory.CreateDirectory(_dataDir);

        _log = new Logger(Path.Combine(_dataDir, "proxy.log"));
        _store = new SettingsStore(Path.Combine(_dataDir, "settings.json"), new DpapiProtector());

        var settings = _store.Load();
        var systemProxy = new SystemProxyManager(Path.Combine(_dataDir, "state.json"), _log);
        systemProxy.RestorePending();

        _engine = new ProxyEngine(settings, systemProxy, _log);
        _engine.Changed += OnEngineChanged;

        _onIcon = IconFactory.Create(Color.FromArgb(0x2E, 0xCC, 0x71));
        _offIcon = IconFactory.Create(Color.FromArgb(0x95, 0xA5, 0xA6));

        _statusItem = new ToolStripMenuItem("Выключен") { Enabled = false };
        _statusItem.Font = new Font(_statusItem.Font, FontStyle.Bold);

        _toggleItem = new ToolStripMenuItem("Включить");
        _toggleItem.Click += async (_, _) => await ToggleAsync().ConfigureAwait(true);

        var settingsItem = new ToolStripMenuItem("Настройки…");
        settingsItem.Click += (_, _) => ShowSettings();

        var logItem = new ToolStripMenuItem("Журнал…");
        logItem.Click += (_, _) => ShowSettings(showLog: true);

        var folderItem = new ToolStripMenuItem("Открыть папку с логом");
        folderItem.Click += (_, _) => OpenDataFolder();

        var exitItem = new ToolStripMenuItem("Выход");
        exitItem.Click += async (_, _) => await ExitAsync().ConfigureAwait(true);

        var menu = new ContextMenuStrip();
        menu.Items.Add(_statusItem);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(_toggleItem);
        menu.Items.Add(settingsItem);
        menu.Items.Add(logItem);
        menu.Items.Add(folderItem);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(exitItem);

        _notifyIcon = new NotifyIcon
        {
            Icon = _offIcon,
            Text = "ProxyForWin — выключен",
            Visible = true,
            ContextMenuStrip = menu,
        };
        _notifyIcon.DoubleClick += (_, _) => ShowSettings();

        _log.Info("ProxyForWin запущен");
        UpdateUi();

        if (settings.EnableOnStartup)
        {
            _ = StartAsync();
        }
    }

    private async Task ToggleAsync()
    {
        if (_engine.IsRunning)
        {
            await StopAsync().ConfigureAwait(true);
        }
        else
        {
            await StartAsync().ConfigureAwait(true);
        }
    }

    private async Task StartAsync()
    {
        if (_busy)
        {
            return;
        }

        _busy = true;
        try
        {
            await _engine.StartAsync().ConfigureAwait(true);
            ShowBalloon("Прокси включён", _engine.StatusText);
        }
        catch (Exception ex)
        {
            _log.Error("Не удалось включить прокси: " + ex.Message);
            ShowError(ex.Message);
        }
        finally
        {
            _busy = false;
            UpdateUi();
        }
    }

    private async Task StopAsync()
    {
        if (_busy)
        {
            return;
        }

        _busy = true;
        try
        {
            await _engine.StopAsync().ConfigureAwait(true);
            ShowBalloon("Прокси выключен", "Настройки Windows восстановлены");
        }
        catch (Exception ex)
        {
            _log.Error("Не удалось выключить прокси: " + ex.Message);
            ShowError(ex.Message);
        }
        finally
        {
            _busy = false;
            UpdateUi();
        }
    }

    private async Task ExitAsync()
    {
        try
        {
            await _engine.StopAsync().ConfigureAwait(true);
        }
        catch
        {
            // ignored
        }

        _notifyIcon.Visible = false;
        _notifyIcon.Dispose();
        ExitThread();
    }

    private void ShowSettings(bool showLog = false)
    {
        if (_form is { IsDisposed: false })
        {
            _form.Show();
            _form.Activate();
            if (showLog)
            {
                _form.ShowLogTab();
            }

            return;
        }

        _form = new SettingsForm(_engine, _store, _log)
        {
            StartPosition = FormStartPosition.CenterScreen,
        };
        _form.FormClosed += (_, _) =>
        {
            _form = null;
            UpdateUi();
        };
        _form.Show();

        if (showLog)
        {
            _form.ShowLogTab();
        }
    }

    private void OnEngineChanged()
    {
        if (_uiContext is not null)
        {
            _uiContext.Post(_ => UpdateUi(), null);
        }
        else
        {
            UpdateUi();
        }
    }

    private void UpdateUi()
    {
        if (_notifyIcon is null)
        {
            return;
        }

        var running = _engine.IsRunning;
        _notifyIcon.Icon = running ? _onIcon : _offIcon;
        _statusItem.Text = _engine.StatusText;
        _toggleItem.Text = running ? "Выключить" : "Включить";

        var upstream = _engine.Settings.HasUpstream ? _engine.Settings.UpstreamEndpoint : "не задан";
        var text = running
            ? $"ProxyForWin — включён ({upstream})"
            : "ProxyForWin — выключен";
        _notifyIcon.Text = text.Length > 63 ? text[..63] : text;
    }

    private void ShowBalloon(string title, string text)
    {
        try
        {
            _notifyIcon.BalloonTipTitle = title;
            _notifyIcon.BalloonTipText = text;
            _notifyIcon.ShowBalloonTip(3000);
        }
        catch
        {
            // ignored
        }
    }

    private void ShowError(string message)
    {
        MessageBox.Show(message, "ProxyForWin", MessageBoxButtons.OK, MessageBoxIcon.Warning);
    }

    private void OpenDataFolder()
    {
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = _dataDir,
                UseShellExecute = true,
            });
        }
        catch
        {
            // ignored
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _engine.Dispose();
            _notifyIcon.Dispose();
            _onIcon.Dispose();
            _offIcon.Dispose();
        }

        base.Dispose(disposing);
    }
}
