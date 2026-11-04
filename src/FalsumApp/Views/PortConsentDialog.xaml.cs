using System.Windows;

namespace FalsumApp.Views;

/// <summary>
/// The consent prompt: an application tried the network, the owner decides.
/// Fail-closed: closing without choosing, or no UI at all, means Block.
/// </summary>
public partial class PortConsentDialog : Window
{
    public enum ConsentChoice { AllowAlways, AllowOnce, Block }

    public ConsentChoice Choice { get; private set; } = ConsentChoice.Block;

    public PortConsentDialog(string appName, string appPath, string dest)
    {
        InitializeComponent();
        AppText.Text = $"{appName}\n{appPath}";
        DestText.Text = $"Tried to reach: {dest}";
    }

    private void AllowAlwaysButton_Click(object sender, RoutedEventArgs e)
    {
        Choice = ConsentChoice.AllowAlways;
        Close();
    }

    private void AllowOnceButton_Click(object sender, RoutedEventArgs e)
    {
        Choice = ConsentChoice.AllowOnce;
        Close();
    }

    private void BlockButton_Click(object sender, RoutedEventArgs e)
    {
        Choice = ConsentChoice.Block;
        Close();
    }
}
