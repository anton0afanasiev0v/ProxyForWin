using System.Collections.Concurrent;

namespace ProxyForWin.Core;

public sealed record LogEntry(DateTimeOffset Timestamp, string Level, string Message)
{
    public override string ToString()
        => $"{Timestamp:yyyy-MM-dd HH:mm:ss.fff} [{Level}] {Message}";
}

/// <summary>Thread-safe logger with a ring buffer for the UI and an optional file sink.</summary>
public sealed class Logger
{
    private const int RingSize = 1000;
    private readonly ConcurrentQueue<LogEntry> _recent = new();
    private readonly object _fileLock = new();
    private string? _filePath;

    public event Action<LogEntry>? EntryWritten;

    /// <summary>When true, DEBUG entries are also written to the log file.</summary>
    public bool Verbose { get; set; }

    public Logger(string? filePath = null)
    {
        _filePath = filePath;
        if (!string.IsNullOrEmpty(_filePath))
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(_filePath)!);
            }
            catch
            {
                _filePath = null;
            }
        }
    }

    public string? FilePath => _filePath;

    public IReadOnlyList<LogEntry> Recent => _recent.ToArray();

    public void Info(string message) => Write("INFO", message);

    public void Warn(string message) => Write("WARN", message);

    public void Error(string message) => Write("ERROR", message);

    public void Debug(string message) => Write("DEBUG", message);

    public void Write(string level, string message)
    {
        var entry = new LogEntry(DateTimeOffset.Now, level, message);
        _recent.Enqueue(entry);
        while (_recent.Count > RingSize)
        {
            _recent.TryDequeue(out _);
        }

        if (level != "DEBUG" || Verbose)
        {
            var path = _filePath;
            if (!string.IsNullOrEmpty(path))
            {
                try
                {
                    lock (_fileLock)
                    {
                        File.AppendAllText(path, entry + Environment.NewLine);
                    }
                }
                catch
                {
                    // Logging must never crash the app.
                }
            }
        }

        try
        {
            EntryWritten?.Invoke(entry);
        }
        catch
        {
            // UI handler failures are ignored.
        }
    }
}
