using System.Windows;

namespace FalsumApp;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Ensure Falsum directories exist
        var falsumDir = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Falsum");

        foreach (var dir in new[] { falsumDir, $"{falsumDir}\\vault", $"{falsumDir}\\ai", $"{falsumDir}\\bridge" })
        {
            if (!System.IO.Directory.Exists(dir))
                System.IO.Directory.CreateDirectory(dir);
        }
    }
}
