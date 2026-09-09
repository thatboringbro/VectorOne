using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;

namespace VectorOne;

public class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private static readonly HttpClient _httpClient = new HttpClient();
    private const string TARGET_API_URL = "http://127.0.0.1:8000/api/telemetry";

    public Worker(ILogger<Worker> logger)
    {
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // This works on windows & linux. Tryna find the downloads folder dynamically
        
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string downloadFolder = Path.Combine(userProfile, "Downloads");
        
        // Setting up a watcher to watch the downloadsPath e.g. {/home/redacted/Downloads} s

        using FileSystemWatcher watcher = new FileSystemWatcher(downloadFolder);
        
        // Tell my watcher to look for files being created in {/home/redacted/Downloads} and the time it was created/
            
        watcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime;
        watcher.Filter = "*.*";
            
        // create a trigger (i.e. what to do when a new file is created)

        watcher.Created += (sender, e) =>
        {
            _logger.LogWarning("VectorOne ALERT: New file created -> {path}", e.FullPath);
            getDetails(e.FullPath);
        };
        
        watcher.EnableRaisingEvents = true;
        _logger.LogInformation("VectorOne watcher active on: {path}", downloadFolder);


        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(1000, stoppingToken);
        }
        
    }

    async Task getDetails(string filePath)
    {
        try
        {
            FileInfo fileInfo = new FileInfo(filePath);
            string fileName = fileInfo.Name;
            string fileExtension = fileInfo.Extension;
            string dateCreated = fileInfo.CreationTime.ToString("yyyy-MM-dd HH:mm:ss");
            string userName = Environment.UserName;

            string fileHash = "";

            using (var stream = File.OpenRead(filePath))
            {
                byte[] hashBytes = SHA256.HashData(stream);
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

            string json = JsonSerializer.Serialize(fileData, new JsonSerializerOptions { WriteIndented = true });
            
            _logger.LogInformation("File details extracted:\n{details}", json);

            await PostTelemetry(json);
        }
        catch (Exception ex)
        {
            _logger.LogError("failed to get details for {file}. Reason: {msg}", filePath, ex.Message);
        }

    }

    private async Task PostTelemetry(string jsonPayload)
    {
        try
        {
            var content = new StringContent(jsonPayload, System.Text.Encoding.UTF8, "application/json");
            _logger.LogInformation("Sending telemetry for analysis...");
            HttpResponseMessage response = await _httpClient.PostAsync(TARGET_API_URL, content);

            if (response.IsSuccessStatusCode)
            {
                string responseBody = await response.Content.ReadAsStringAsync();
                _logger.LogInformation($"Telemetry sent! \nVerdict: {responseBody}");
            }
            else
            {
                _logger.LogWarning("An error occured.");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError($"Connection failed. Reason: {ex.Message}");
        }
    }
    
}