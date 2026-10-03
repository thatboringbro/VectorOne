using System.IO;
using System.Security.Cryptography;
using System.Text.Json;

namespace VectorOne;

public class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private static readonly HttpClient _httpClient = new HttpClient();
    private const string DefaultApiUrl = "http://127.0.0.1:8000/api/telemetry";
    private static readonly string TargetApiUrl = Environment.GetEnvironmentVariable("VECTORONE_API_URL") ?? DefaultApiUrl;
    private readonly List<FileSystemWatcher> _watchers = new();

    public Worker(ILogger<Worker> logger)
    {
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var watchPaths = GetWatchDirectories();

        if (watchPaths.Count == 0)
        {
            _logger.LogWarning("No valid watch directories were found for this user profile. VectorOne will stay idle.");

            while (!stoppingToken.IsCancellationRequested)
            {
                await Task.Delay(1000, stoppingToken);
            }

            return;
        }

        foreach (var watchPath in watchPaths)
        {
            if (!Directory.Exists(watchPath))
            {
                _logger.LogInformation("Skipping missing watch directory: {path}", watchPath);
                continue;
            }

            try
            {
                var watcher = new FileSystemWatcher(watchPath)
                {
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime | NotifyFilters.LastWrite,
                    Filter = "*.*",
                    IncludeSubdirectories = false
                };

                watcher.Created += (_, e) =>
                {
                    if (string.IsNullOrWhiteSpace(e.FullPath))
                    {
                        return;
                    }

                    _logger.LogWarning("VectorOne ALERT: New file created -> {path}", e.FullPath);
                    _ = GetDetailsAsync(e.FullPath);
                };

                watcher.EnableRaisingEvents = true;
                _watchers.Add(watcher);
                _logger.LogInformation("VectorOne watcher active on: {path}", watchPath);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to initialize watcher for {path}", watchPath);
            }
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(1000, stoppingToken);
        }
    }

    public static IReadOnlyList<string> GetWatchDirectories()
    {
        var discovered = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void TryAdd(string? directory)
        {
            if (string.IsNullOrWhiteSpace(directory))
            {
                return;
            }

            try
            {
                var fullPath = Path.GetFullPath(directory);
                if (Directory.Exists(fullPath))
                {
                    discovered.Add(fullPath);
                }
            }
            catch
            {
                // Ignore invalid paths on non-standard systems.
            }
        }

        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        TryAdd(userProfile);
        TryAdd(Path.Combine(userProfile, "Downloads"));
        TryAdd(Path.Combine(userProfile, "Desktop"));
        TryAdd(Path.Combine(userProfile, "Documents"));

        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
        {
            TryAdd(Path.Combine("/tmp"));
        }

        return discovered
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private async Task GetDetailsAsync(string filePath)
    {
        try
        {
            var fileInfo = new FileInfo(filePath);
            var fileName = fileInfo.Name;
            var fileExtension = fileInfo.Extension;
            var dateCreated = fileInfo.CreationTime.ToString("yyyy-MM-dd HH:mm:ss");
            var userName = Environment.UserName;

            string fileHash;

            using (var stream = File.OpenRead(filePath))
            {
                var hashBytes = SHA256.HashData(stream);
                fileHash = Convert.ToHexString(hashBytes);
            }

            var fileData = new
            {
                filename = fileName,
                username = userName,
                filetype = fileExtension,
                datecreated = dateCreated,
                filehash = fileHash
            };

            var json = JsonSerializer.Serialize(fileData, new JsonSerializerOptions { WriteIndented = true });
            _logger.LogInformation("File details extracted:\n{details}", json);

            await PostTelemetryAsync(json);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get details for {file}", filePath);
        }
    }

    private async Task PostTelemetryAsync(string jsonPayload)
    {
        try
        {
            using var content = new StringContent(jsonPayload, System.Text.Encoding.UTF8, "application/json");
            _logger.LogInformation("Sending telemetry for analysis...");

            using var response = await _httpClient.PostAsync(TargetApiUrl, content);
            var responseBody = await response.Content.ReadAsStringAsync();

            if (response.IsSuccessStatusCode)
            {
                _logger.LogInformation("Telemetry sent! Verdict: {responseBody}", responseBody);
            }
            else
            {
                _logger.LogWarning("Telemetry request failed with status {statusCode}. Response: {responseBody}", response.StatusCode, responseBody);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Connection failed while sending telemetry.");
        }
    }
}