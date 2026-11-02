using System.Windows;
using FalsumApp.Services;

namespace FalsumApp.Views;

public partial class BrowserControlWindow : Window
{
    private readonly BrowserControlService _browserControl;

    public BrowserControlWindow()
    {
        InitializeComponent();
        _browserControl = new BrowserControlService();
        PolicyList.ItemsSource = _browserControl.DetectedPolicies;
    }

    private void ScanButton_Click(object sender, RoutedEventArgs e)
    {
        PolicyCount.Text = "Scanning...";
        ScanButton.IsEnabled = false;

        try
        {
            _browserControl.ScanForPolicies();

            var count = _browserControl.DetectedPolicies.Count;
            if (count == 0)
            {
                PolicyCount.Text = "No policies found. Your browser is under YOUR control.";
                PolicyCount.Foreground = new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Colors.LightGreen);
            }
            else
            {
                PolicyCount.Text = $"{count} policies locking your browser. These are what grey out your settings.";
                PolicyCount.Foreground = new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Colors.OrangeRed);
                RemoveButton.IsEnabled = true;
            }
        }
        catch (Exception ex)
        {
            PolicyCount.Text = $"Scan failed: {ex.Message}";
        }
        finally
        {
            ScanButton.IsEnabled = true;
        }
    }

    private void RemoveButton_Click(object sender, RoutedEventArgs e)
    {
        var result = MessageBox.Show(
            "This will remove ALL browser policies and unlock your settings.\n\n" +
            "A backup will be saved first.\n\n" +
            "Continue?",
            "Take Back Control",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (result != MessageBoxResult.Yes) return;

        try
        {
            var (removed, backupPath) = _browserControl.RemoveAllPolicies();

            MessageBox.Show(
                $"Removed {removed} policy trees.\n\n" +
                $"Backup saved to:\n{backupPath}\n\n" +
                "Restart Chrome/Edge. Your greyed-out settings should now be unlocked.",
                "Browser Unlocked",
                MessageBoxButton.OK,
                MessageBoxImage.Information);

            PolicyCount.Text = "Policies removed. Restart your browser.";
            RemoveButton.IsEnabled = false;
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                $"Failed to remove policies: {ex.Message}\n\n" +
                "Try running Falsum as Administrator (right-click → Run as administrator).",
                "Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }
}
