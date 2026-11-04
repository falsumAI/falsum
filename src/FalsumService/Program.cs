using FalsumApp.Service;

using var svc = new FalsumService();
if (Environment.UserInteractive)
{
    // Console mode for debugging: run the OnStart logic directly.
    Console.WriteLine("FalsumService running in console mode. Press Ctrl+C to stop.");
    var onStart = svc.GetType().GetMethod("OnStart",
        System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
    onStart?.Invoke(svc, new object[] { Array.Empty<string>() });
    await Task.Delay(-1);
}
else
{
    System.ServiceProcess.ServiceBase.Run(svc);
}
