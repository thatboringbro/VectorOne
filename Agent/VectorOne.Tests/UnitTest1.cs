using VectorOne;

namespace VectorOne.Tests;

public class WorkerTests
{
    [Fact]
    public void GetWatchDirectories_AlwaysIncludesUserProfile()
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var directories = Worker.GetWatchDirectories();

        Assert.NotEmpty(directories);
        Assert.Contains(directories, path =>
            string.Equals(Path.GetFullPath(path), Path.GetFullPath(userProfile), StringComparison.OrdinalIgnoreCase));
        Assert.All(directories, path => Assert.True(Directory.Exists(path), $"Expected existing directory: {path}"));
    }
}