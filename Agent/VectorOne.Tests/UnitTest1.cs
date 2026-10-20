using VectorOne;

namespace VectorOne.Tests;

public class WorkerTests
{
    [Fact]
    public void GetWatchDirectories_IncludesHighRiskPathsWithoutWatchingWholeProfile()
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var directories = Worker.GetWatchDirectories();

        Assert.NotEmpty(directories);
        Assert.Contains(directories, path =>
            string.Equals(Path.GetFullPath(path), Path.GetFullPath(Path.GetTempPath()), StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(directories, path =>
            string.Equals(Path.GetFullPath(path), Path.GetFullPath(userProfile), StringComparison.OrdinalIgnoreCase));
        var downloads = Path.Combine(userProfile, "Downloads");
        if (Directory.Exists(downloads))
        {
            Assert.Contains(directories, path =>
                string.Equals(Path.GetFullPath(path), Path.GetFullPath(downloads), StringComparison.OrdinalIgnoreCase));
        }
        if (OperatingSystem.IsLinux())
        {
            var initDirectory = Path.Combine(Path.DirectorySeparatorChar.ToString(), "etc", "init.d");
            if (Directory.Exists(initDirectory))
            {
                Assert.Contains(directories, path =>
                    string.Equals(Path.GetFullPath(path), Path.GetFullPath(initDirectory), StringComparison.OrdinalIgnoreCase));
            }
        }
        Assert.All(directories, path => Assert.True(Directory.Exists(path), $"Expected existing directory: {path}"));
    }

    [Theory]
    [InlineData(".profile")]
    [InlineData("download.tmp")]
    [InlineData("download.crdownload")]
    [InlineData("download.part")]
    [InlineData("build.lock")]
    [InlineData("autosave~")]
    [InlineData("obj/generated.dll")]
    [InlineData(".git/config")]
    [InlineData(".gradle/caches/artifact.jar")]
    [InlineData("packages/SomePackage/build.dll")]
    [InlineData("node_modules/package/index.js")]
    public void IsExcludedFile_SkipsKnownNoise(string filePath)
    {
        Assert.True(Worker.IsExcludedFile(filePath));
    }

    [Fact]
    public void IsExcludedFile_AllowsRegularFile()
    {
        Assert.False(Worker.IsExcludedFile(Path.Combine("Downloads", "invoice.pdf")));
    }
}