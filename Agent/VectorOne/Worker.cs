using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace VectorOne;

public class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private static readonly HttpClient _httpClient = new HttpClient();
    private const string DefaultApiUrl = "http://127.0.0.1:8000/api/telemetry";
    private static readonly string? DotEnvPath = FindBackendDotEnv();
    private static readonly IReadOnlyDictionary<string, string> DotEnvSettings = LoadDotEnv(DotEnvPath);
    private static readonly string TargetApiUrl = DotEnvSettings.TryGetValue("VECTORONE_API_URL", out var apiUrl)
        ? apiUrl
        : DefaultApiUrl;
    private static readonly string BrainBaseUrl = new Uri(TargetApiUrl).GetLeftPart(UriPartial.Authority);
    private static readonly string AgentToken = DotEnvSettings.GetValueOrDefault("VECTORONE_AGENT_TOKEN", string.Empty);
    private static readonly string PendingCommandsUrl = $"{BrainBaseUrl}/api/commands/pending";
    private static readonly string AgentHeartbeatUrl = $"{BrainBaseUrl}/api/agents/heartbeat";
    private static readonly string DeviceName = Environment.MachineName;
    private static readonly string AgentId = LoadOrCreateAgentId();
    private static readonly string DeviceId = AgentId;
    private static readonly HashSet<string> ExcludedDirectoryNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ".git",
        ".idea",
        ".cache",
        ".gradle",
        ".nuget",
        ".vscode",
        ".vs",
        "__pycache__",
        "bin",
        "node_modules",
        "obj",
        "packages",
        "target"
    };
    private readonly List<FileSystemWatcher> _watchers = new();

    public Worker(ILogger<Worker> logger)
    {
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (string.IsNullOrWhiteSpace(AgentToken))
        {
            throw new InvalidOperationException(
                $"VECTORONE_AGENT_TOKEN is missing from the shared Brain .env file ({DotEnvPath ?? "file not found"}).");
        }

        var commandPollingTask = PollCommandsAsync(stoppingToken);
        var endpointHeartbeatTask = SendEndpointHeartbeatsAsync(stoppingToken);
        var watchPaths = GetWatchDirectories();

        if (watchPaths.Count == 0)
        {
            _logger.LogWarning("No valid watch directories were found for this user profile. VectorOne will stay idle.");
            await Task.WhenAll(commandPollingTask, endpointHeartbeatTask);
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
                    Filter = "*",
                    IncludeSubdirectories = false
                };

                watcher.Created += (_, e) =>
                {
                    if (string.IsNullOrWhiteSpace(e.FullPath))
                    {
                        return;
                    }

                    if (IsExcludedFile(e.FullPath))
                    {
                        _logger.LogDebug("Skipping excluded file from telemetry: {path}", e.FullPath);
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

        await Task.WhenAll(commandPollingTask, endpointHeartbeatTask);
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
        if (!string.IsNullOrWhiteSpace(userProfile))
        {
            TryAdd(Path.Combine(userProfile, "Downloads"));
        }
        TryAdd(Path.GetTempPath());

        var localApplicationData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (!string.IsNullOrWhiteSpace(localApplicationData))
        {
            TryAdd(Path.Combine(localApplicationData, "Temp"));
        }

        var windowsDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (!string.IsNullOrWhiteSpace(windowsDirectory))
        {
            TryAdd(Path.Combine(windowsDirectory, "Temp"));
        }

        var commonApplicationData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        if (!string.IsNullOrWhiteSpace(commonApplicationData))
        {
            TryAdd(Path.Combine(commonApplicationData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"));
        }

        var startMenu = Environment.GetFolderPath(Environment.SpecialFolder.StartMenu);
        if (!string.IsNullOrWhiteSpace(startMenu))
        {
            TryAdd(Path.Combine(startMenu, "Programs", "Startup"));
        }

        TryAdd(Path.Combine(Path.DirectorySeparatorChar.ToString(), "etc", "init.d"));

        return discovered
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public static bool IsExcludedFile(string filePath)
    {
        var fileName = Path.GetFileName(filePath);
        if (fileName.StartsWith(".", StringComparison.Ordinal))
        {
            return true;
        }

        var extension = Path.GetExtension(fileName);
        if (extension.Equals(".tmp", StringComparison.OrdinalIgnoreCase) ||
            extension.Equals(".crdownload", StringComparison.OrdinalIgnoreCase) ||
            extension.Equals(".part", StringComparison.OrdinalIgnoreCase) ||
            extension.Equals(".lock", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith('~'))
        {
            return true;
        }

        return filePath
            .Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            .Any(ExcludedDirectoryNames.Contains);
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
                filehash = fileHash,
                filepath = fileInfo.FullName,
                device_name = DeviceName,
                device_id = DeviceId
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

            using var request = CreateAgentRequest(HttpMethod.Post, TargetApiUrl);
            request.Content = content;
            using var response = await _httpClient.SendAsync(request);
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

    private async Task PollCommandsAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(10));

        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                await ProcessPendingCommandsAsync(stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Expected during service shutdown.
        }
    }

    private async Task SendEndpointHeartbeatsAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(60));
        try
        {
            do
            {
                try
                {
                    var heartbeat = new
                    {
                        agent_id = AgentId,
                        hostname = DeviceName,
                        ip_address = GetLocalIpAddress(),
                        os_version = RuntimeInformation.OSDescription
                    };
                    using var request = CreateAgentRequest(HttpMethod.Post, AgentHeartbeatUrl);
                    request.Content = new StringContent(
                        JsonSerializer.Serialize(heartbeat),
                        System.Text.Encoding.UTF8,
                        "application/json");
                    using var response = await _httpClient.SendAsync(request, stoppingToken);
                    if (response.IsSuccessStatusCode)
                    {
                        _logger.LogInformation("Endpoint inventory heartbeat registered for {deviceName}.", DeviceName);
                    }
                    else
                    {
                        _logger.LogWarning("Endpoint heartbeat failed with status {statusCode}.", response.StatusCode);
                    }
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Endpoint heartbeat failed; it will retry in 60 seconds.");
                }
            }
            while (await timer.WaitForNextTickAsync(stoppingToken));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Expected during service shutdown.
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to register endpoint heartbeat.");
        }
    }

    private async Task ProcessPendingCommandsAsync(CancellationToken stoppingToken)
    {
        try
        {
            using var request = CreateAgentRequest(HttpMethod.Get, PendingCommandsUrl);
            using var response = await _httpClient.SendAsync(request, stoppingToken);
            response.EnsureSuccessStatusCode();

            var responseBody = await response.Content.ReadAsStringAsync(stoppingToken);
            var commands = JsonNode.Parse(responseBody)?.AsArray();
            if (commands is null)
            {
                _logger.LogWarning("Brain returned an invalid pending-command response.");
                return;
            }

            foreach (var command in commands)
            {
                var commandId = command?["id"]?.GetValue<int>();
                var filepath = command?["filepath"]?.GetValue<string>();
                var action = command?["action"]?.GetValue<string>();
                if (commandId is null || string.IsNullOrWhiteSpace(filepath) || action is not ("delete" or "quarantine"))
                {
                    _logger.LogWarning("Ignoring pending command with missing fields or unsupported action.");
                    continue;
                }

                if (!IsWithinWatchedDirectories(filepath))
                {
                    _logger.LogCritical("Rejected delete command {commandId} outside watched directories: {path}", commandId, filepath);
                    continue;
                }

                try
                {
                    File.Delete(filepath);
                    _logger.LogWarning("Quarantined file from analyst command {commandId}: {path}", commandId, filepath);
                }
                catch (IOException ex)
                {
                    _logger.LogCritical(ex, "Could not delete file from analyst command {commandId}; it may be locked: {path}", commandId, filepath);
                    continue;
                }
                catch (UnauthorizedAccessException ex)
                {
                    _logger.LogCritical(ex, "Access denied while processing analyst delete command {commandId}: {path}", commandId, filepath);
                    continue;
                }

                await CompleteCommandAsync(commandId.Value, stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to poll or process pending Brain commands.");
        }
    }

    private async Task CompleteCommandAsync(int commandId, CancellationToken stoppingToken)
    {
        try
        {
            using var request = CreateAgentRequest(
                HttpMethod.Post,
                $"{BrainBaseUrl}/api/commands/complete/{commandId}");
            using var response = await _httpClient.SendAsync(request, stoppingToken);
            response.EnsureSuccessStatusCode();
            _logger.LogInformation("Completed analyst command {commandId}.", commandId);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !stoppingToken.IsCancellationRequested)
        {
            _logger.LogError(ex, "Failed to acknowledge completed command {commandId}.", commandId);
        }
    }

    private static bool IsWithinWatchedDirectories(string filepath)
    {
        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(filepath);
        }
        catch
        {
            return false;
        }

        foreach (var directory in GetWatchDirectories())
        {
            var relativePath = Path.GetRelativePath(directory, fullPath);
            if (relativePath != "." &&
                !relativePath.Equals("..", StringComparison.Ordinal) &&
                !relativePath.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal) &&
                !Path.IsPathRooted(relativePath))
            {
                return true;
            }
        }

        return false;
    }

    private static HttpRequestMessage CreateAgentRequest(HttpMethod method, string url)
    {
        var request = new HttpRequestMessage(method, url);
        if (!string.IsNullOrWhiteSpace(AgentToken))
        {
            request.Headers.Add("X-Agent-Token", AgentToken);
        }
        return request;
    }

    private static string LoadOrCreateAgentId()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var idDirectory = string.IsNullOrWhiteSpace(localAppData)
            ? AppContext.BaseDirectory
            : Path.Combine(localAppData, "VectorOne");
        var idPath = Path.Combine(idDirectory, ".vectorone_id");

        try
        {
            Directory.CreateDirectory(idDirectory);
            if (File.Exists(idPath))
            {
                var existingId = File.ReadAllText(idPath).Trim();
                if (Guid.TryParse(existingId, out var parsedId))
                {
                    return parsedId.ToString();
                }
            }

            var agentId = Guid.NewGuid().ToString();
            File.WriteAllText(idPath, agentId);
            return agentId;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return DeviceName;
        }
    }

    private static string GetLocalIpAddress()
    {
        try
        {
            var addresses = Dns.GetHostAddresses(Dns.GetHostName())
                .Where(address => !IPAddress.IsLoopback(address))
                .ToArray();
            return addresses.FirstOrDefault(address => address.AddressFamily == AddressFamily.InterNetwork)
                ?.ToString()
                ?? addresses.FirstOrDefault()?.ToString()
                ?? string.Empty;
        }
        catch (SocketException)
        {
            return string.Empty;
        }
    }

    private static string? FindBackendDotEnv()
    {
        var startingDirectories = new[] { Directory.GetCurrentDirectory(), AppContext.BaseDirectory };
        foreach (var startingDirectory in startingDirectories)
        {
            for (var directory = new DirectoryInfo(startingDirectory); directory is not null; directory = directory.Parent)
            {
                var candidate = Path.Combine(directory.FullName, "Brain", "VectorOneBackend", ".env");
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }
        }

        return null;
    }

    private static IReadOnlyDictionary<string, string> LoadDotEnv(string? dotenvPath)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        if (dotenvPath is null)
        {
            return values;
        }

        foreach (var sourceLine in File.ReadLines(dotenvPath))
        {
            var line = sourceLine.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            if (line.StartsWith("export ", StringComparison.Ordinal))
            {
                line = line[7..].TrimStart();
            }

            var separator = line.IndexOf('=');
            if (separator <= 0)
            {
                continue;
            }

            var key = line[..separator].Trim();
            var value = line[(separator + 1)..].Trim();
            if (value.Length >= 2 &&
                ((value[0] == '"' && value[^1] == '"') || (value[0] == '\'' && value[^1] == '\'')))
            {
                value = value[1..^1];
            }

            if (key.Length > 0)
            {
                values[key] = value;
            }
        }

        return values;
    }
}