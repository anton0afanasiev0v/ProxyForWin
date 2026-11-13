using ProxyForWin.Core;

namespace ProxyForWin.Tray;

internal sealed class SettingsForm : Form
{
    private readonly ProxyEngine _engine;
    private readonly SettingsStore _store;
    private readonly Logger _log;

    private readonly TabControl _tabs;
    private readonly TabPage _connectionTab;
    private readonly TabPage _logTab;
    private readonly TextBox _hostBox;
    private readonly NumericUpDown _portBox;
    private readonly TextBox _userBox;
    private readonly TextBox _passwordBox;
    private readonly CheckBox _showPasswordBox;
    private readonly NumericUpDown _listenPortBox;
    private readonly RadioButton _modeSystem;
    private readonly RadioButton _modeFull;
    private readonly TextBox _bypassBox;
    private readonly CheckBox _winHttpBox;
    private readonly CheckBox _quicBox;
    private readonly CheckBox _ipv6Box;
    private readonly CheckBox _autostartBox;
    private readonly CheckBox _enableOnStartupBox;
    private readonly Button _testButton;
    private readonly Label _testResult;
    private readonly Button _saveButton;
    private readonly Button _cancelButton;
    private readonly TextBox _logBox;
    private readonly Button _clearLogButton;

    public SettingsForm(ProxyEngine engine, SettingsStore store, Logger log)
    {
        _engine = engine;
        _store = store;
        _log = log;

        Text = "ProxyForWin — настройки";
        MinimumSize = new Size(560, 620);
        Size = new Size(640, 720);
        StartPosition = FormStartPosition.CenterScreen;
        AutoScaleMode = AutoScaleMode.Dpi;

        var settings = engine.Settings;

        _hostBox = new TextBox { Text = settings.UpstreamHost, Dock = DockStyle.Fill };
        _portBox = new NumericUpDown { Minimum = 1, Maximum = 65535, Value = Math.Clamp(settings.UpstreamPort, 1, 65535), Dock = DockStyle.Fill };
        _userBox = new TextBox { Text = settings.Username, Dock = DockStyle.Fill };
        _passwordBox = new TextBox { Text = settings.Password, UseSystemPasswordChar = true, Dock = DockStyle.Fill };
        _showPasswordBox = new CheckBox { Text = "Показать", AutoSize = true };
        _showPasswordBox.CheckedChanged += (_, _) => _passwordBox.UseSystemPasswordChar = !_showPasswordBox.Checked;

        _listenPortBox = new NumericUpDown { Minimum = 1024, Maximum = 65535, Value = Math.Clamp(settings.ListenPort, 1024, 65535), Dock = DockStyle.Fill };

        _modeSystem = new RadioButton { Text = "Системный прокси Windows (браузеры и большинство программ)", AutoSize = true, Checked = settings.Mode == ProxyMode.SystemProxy };
        _modeFull = new RadioButton { Text = "Весь трафик (перехват через WinDivert, нужны права администратора)", AutoSize = true, Checked = settings.Mode == ProxyMode.FullTraffic };

        _bypassBox = new TextBox
        {
            Multiline = true,
            ScrollBars = ScrollBars.Vertical,
            Dock = DockStyle.Fill,
            Height = 110,
            Text = string.Join(Environment.NewLine, settings.Bypass),
            PlaceholderText = "example.com" + Environment.NewLine + "*.corp.local" + Environment.NewLine + "10.0.0.0/8",
        };

        _winHttpBox = new CheckBox { Text = "Настраивать также WinHTTP (службы, Windows Update)", AutoSize = true, Checked = settings.ApplyWinHttp };
        _quicBox = new CheckBox { Text = "Блокировать QUIC (UDP/443), чтобы браузеры работали через TCP", AutoSize = true, Checked = settings.BlockQuic };
        _ipv6Box = new CheckBox { Text = "Блокировать IPv6 в режиме полного перехвата", AutoSize = true, Checked = settings.BlockIpv6 };
        _autostartBox = new CheckBox { Text = "Запускать при входе в Windows (Task Scheduler)", AutoSize = true, Checked = settings.RunAtLogon };
        _enableOnStartupBox = new CheckBox { Text = "Включать прокси сразу при запуске программы", AutoSize = true, Checked = settings.EnableOnStartup };

        _testResult = new Label { AutoSize = true, ForeColor = Color.DimGray, Text = "" };
        _testButton = new Button { Text = "Проверить прокси", AutoSize = true };
        _testButton.Click += OnTestClick;

        _saveButton = new Button { Text = "Сохранить", AutoSize = true, DialogResult = DialogResult.None };
        _saveButton.Click += OnSaveClick;
        _cancelButton = new Button { Text = "Отмена", AutoSize = true, DialogResult = DialogResult.Cancel };

        _logBox = new TextBox
        {
            Multiline = true,
            ReadOnly = true,
            Dock = DockStyle.Fill,
            ScrollBars = ScrollBars.Both,
            WordWrap = false,
            Font = new Font("Consolas", 9f),
            BackColor = Color.FromArgb(250, 250, 250),
        };
        _clearLogButton = new Button { Text = "Очистить", AutoSize = true, Dock = DockStyle.Right };
        _clearLogButton.Click += (_, _) => _logBox.Clear();

        _tabs = new TabControl { Dock = DockStyle.Fill };
        _connectionTab = new TabPage("Подключение");
        _logTab = new TabPage("Журнал");

        BuildConnectionTab();
        BuildLogTab();

        _tabs.TabPages.Add(_connectionTab);
        _tabs.TabPages.Add(_logTab);

        var buttons = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            FlowDirection = FlowDirection.RightToLeft,
            AutoSize = true,
            Padding = new Padding(8),
        };
        buttons.Controls.Add(_saveButton);
        buttons.Controls.Add(_cancelButton);

        Controls.Add(_tabs);
        Controls.Add(buttons);

        AcceptButton = _saveButton;
        CancelButton = _cancelButton;

        _log.EntryWritten += OnLogEntry;
        foreach (var entry in _log.Recent)
        {
            AppendLog(entry.ToString());
        }

        FormClosed += (_, _) => _log.EntryWritten -= OnLogEntry;
    }

    private void BuildConnectionTab()
    {
        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(12),
            ColumnCount = 2,
            AutoScroll = true,
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 190));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

        var row = 0;

        AddRow(layout, ref row, "Адрес прокси-сервера", _hostBox);
        AddRow(layout, ref row, "Порт", _portBox);
        AddRow(layout, ref row, "Логин", _userBox);

        var passwordPanel = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, AutoSize = true };
        passwordPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        passwordPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        passwordPanel.Controls.Add(_passwordBox, 0, 0);
        passwordPanel.Controls.Add(_showPasswordBox, 1, 0);
        AddRow(layout, ref row, "Пароль", passwordPanel);

        AddRow(layout, ref row, "Локальный порт", _listenPortBox);

        var modePanel = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, AutoSize = true };
        modePanel.Controls.Add(_modeSystem);
        modePanel.Controls.Add(_modeFull);
        AddRow(layout, ref row, "Режим", modePanel);

        var bypassPanel = new Panel { Dock = DockStyle.Fill, MinimumSize = new Size(0, 120) };
        _bypassBox.Dock = DockStyle.Fill;
        _bypassBox.MinimumSize = new Size(0, 110);
        bypassPanel.Controls.Add(_bypassBox);
        AddRow(layout, ref row, "Исключения (домены, IP, CIDR — по одному в строке)", bypassPanel);

        var optionsPanel = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, AutoSize = true };
        optionsPanel.Controls.Add(_winHttpBox);
        optionsPanel.Controls.Add(_quicBox);
        optionsPanel.Controls.Add(_ipv6Box);
        optionsPanel.Controls.Add(_autostartBox);
        optionsPanel.Controls.Add(_enableOnStartupBox);
        AddRow(layout, ref row, "Параметры", optionsPanel);

        var testPanel = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.LeftToRight, AutoSize = true };
        testPanel.Controls.Add(_testButton);
        testPanel.Controls.Add(_testResult);
        AddRow(layout, ref row, "", testPanel);

        var hint = new Label
        {
            AutoSize = true,
            MaximumSize = new Size(420, 0),
            ForeColor = Color.DimGray,
            Text = "Пароль хранится в зашифрованном виде (DPAPI). " +
                   "HTTP-прокси передаёт только TCP-соединения: игры и VoIP по UDP через него не пойдут, " +
                   "поэтому QUIC блокируется, чтобы программы перешли на TCP.",
        };
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.Controls.Add(hint, 0, row);
        layout.SetColumnSpan(hint, 2);
        layout.RowCount = layout.RowStyles.Count;

        _connectionTab.Controls.Add(layout);
    }

    private static void AddRow(TableLayoutPanel layout, ref int row, string label, Control control)
    {
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var caption = new Label
        {
            Text = label,
            TextAlign = ContentAlignment.MiddleLeft,
            AutoSize = true,
            Padding = new Padding(0, 6, 8, 0),
        };
        layout.Controls.Add(caption, 0, row);
        layout.Controls.Add(control, 1, row);
        row++;
    }

    private void BuildLogTab()
    {
        var panel = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 2, Padding = new Padding(8) };
        panel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        panel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        panel.Controls.Add(_logBox, 0, 0);

        var bottom = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft, AutoSize = true };
        bottom.Controls.Add(_clearLogButton);
        panel.Controls.Add(bottom, 0, 1);

        _logTab.Controls.Add(panel);
    }

    public void ShowLogTab() => _tabs.SelectedTab = _logTab;

    private async void OnSaveClick(object? sender, EventArgs e)
    {
        if (!TryBuildSettings(out var settings, out var error))
        {
            MessageBox.Show(this, error, "Проверьте настройки", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        _saveButton.Enabled = false;
        try
        {
            _store.Save(settings);
            await _engine.ApplyAsync(settings).ConfigureAwait(true);

            try
            {
                var enabled = AutostartManager.IsEnabled();
                if (settings.RunAtLogon && !enabled)
                {
                    AutostartManager.Enable();
                }
                else if (!settings.RunAtLogon && enabled)
                {
                    AutostartManager.Disable();
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "Автозапуск: " + ex.Message, "ProxyForWin", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }

            DialogResult = DialogResult.OK;
            Close();
        }
        catch (Exception ex)
        {
            _log.Error("Ошибка применения настроек: " + ex.Message);
            MessageBox.Show(this, ex.Message, "Ошибка", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            _saveButton.Enabled = true;
        }
    }

    private async void OnTestClick(object? sender, EventArgs e)
    {
        if (!TryBuildSettings(out var settings, out var error))
        {
            _testResult.ForeColor = Color.Firebrick;
            _testResult.Text = error;
            return;
        }

        _testButton.Enabled = false;
        _testResult.ForeColor = Color.DimGray;
        _testResult.Text = "Проверка…";
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            var elapsed = await _engine.TestUpstreamAsync(settings, cts.Token).ConfigureAwait(true);
            _testResult.ForeColor = Color.SeaGreen;
            _testResult.Text = $"Успешно, {elapsed.TotalMilliseconds:F0} мс";
        }
        catch (Exception ex)
        {
            _testResult.ForeColor = Color.Firebrick;
            _testResult.Text = "Ошибка: " + ex.Message;
        }
        finally
        {
            _testButton.Enabled = true;
        }
    }

    private bool TryBuildSettings(out ProxySettings settings, out string error)
    {
        settings = _engine.Settings.Clone();
        error = string.Empty;

        var host = _hostBox.Text.Trim();
        if (host.Length == 0)
        {
            error = "Укажите адрес прокси-сервера.";
            return false;
        }

        settings.UpstreamHost = host;
        settings.UpstreamPort = (int)_portBox.Value;
        settings.Username = _userBox.Text.Trim();
        settings.Password = _passwordBox.Text;
        settings.ListenPort = (int)_listenPortBox.Value;
        settings.Mode = _modeFull.Checked ? ProxyMode.FullTraffic : ProxyMode.SystemProxy;
        settings.ApplyWinHttp = _winHttpBox.Checked;
        settings.BlockQuic = _quicBox.Checked;
        settings.BlockIpv6 = _ipv6Box.Checked;
        settings.RunAtLogon = _autostartBox.Checked;
        settings.EnableOnStartup = _enableOnStartupBox.Checked;
        settings.Bypass = _bypassBox.Lines
            .Select(line => line.Trim())
            .Where(line => line.Length > 0 && !line.StartsWith('#'))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (settings.ListenPort is < 1024 or > 65535)
        {
            error = "Локальный порт должен быть в диапазоне 1024-65535.";
            return false;
        }

        if (settings.ListenPort == settings.UpstreamPort && IPAddressLooksLocal(host))
        {
            error = "Локальный порт не должен совпадать с портом локального прокси-сервера.";
            return false;
        }

        return true;
    }

    private static bool IPAddressLooksLocal(string host)
        => host is "127.0.0.1" or "localhost" or "::1";

    private void OnLogEntry(LogEntry entry)
    {
        if (IsDisposed || !IsHandleCreated)
        {
            return;
        }

        try
        {
            BeginInvoke(new Action(() => AppendLog(entry.ToString())));
        }
        catch
        {
            // ignored
        }
    }

    private void AppendLog(string line)
    {
        if (_logBox.TextLength > 200_000)
        {
            _logBox.Text = _logBox.Text[^100_000..];
        }

        _logBox.AppendText(line + Environment.NewLine);
    }
}
