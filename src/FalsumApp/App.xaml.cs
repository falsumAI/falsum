using System.Windows;
using FalsumApp.Services;
using FalsumApp.Views;

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

        // NATIVE HOST MODE: Chrome/Edge launches Falsum.exe directly as the native
        // messaging host. Chrome always passes the extension origin as an argument
        // (chrome-extension://<id>/). When we see it, we run the message loop on
        // stdin/stdout with NO window, and exit when Chrome closes the pipe.
        // This is the umbilical cord: the extension is the inner eye, this process
        // is the gate. No PowerShell, no scripts — the real application.
        if (IsNativeHostLaunch(e.Args))
        {
            RunNativeHost();
            Shutdown(0);
            return;
        }

        // Normal launch: open the desktop UI.
        MainWindow = new MainWindow();
        MainWindow.Show();
    }

    private static bool IsNativeHostLaunch(string[] args)
    {
        foreach (var arg in args)
        {
            if (arg.StartsWith("chrome-extension://", StringComparison.OrdinalIgnoreCase))
                return true;
        }
        // Explicit override for testing: Falsum.exe --native-host
        foreach (var arg in args)
        {
            if (arg.Equals("--native-host", StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private static void RunNativeHost()
    {
        try
        {
            var host = new NativeMessagingHost();
            // Blocking loop: reads stdin until Chrome closes it, then returns.
            host.RunLoop();
        }
        catch
        {
            // Never crash the browser's host process loudly — just exit.
        }
    }
}
