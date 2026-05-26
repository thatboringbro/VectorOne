using System.IO;

namespace VectorOne;

public class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;

    public Worker(ILogger<Worker> logger)
    {
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // This works on windows & linux. Tryna find the downloads folder dynamically
        
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string downloadFolder = Path.Combine(userProfile, "Downloads");
        
        // Setting up a watcher to watch the downloadsPath

        using FileSystemWatcher watcher = new FileSystemWatcher(downloadFolder);
        
        // Tell my watcher to look for files being created and the time
            
        watcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime;
        watcher.Filter = "*.*";
            
        // create a trigger (i.e. what to do when a new file is created)

        watcher.Created += (sender, e) =>
        {
            _logger.LogWarning("VectorOne ALERT: New file created -> {path}", e.FullPath);
        };


        watcher.EnableRaisingEvents = true;
        _logger.LogInformation("VectorOne watcher active on: {path}", downloadFolder);


        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(1000, stoppingToken);
        }
        
        
        
    }
}