using System.Windows;
using FalsumApp.Services;

namespace FalsumApp.Views;

public partial class BrowserControlWindow : Window
{
    private readonly BrowserControlService _browserControl;
    private readonly SystemPolicyService _systemPolicy;

    public BrowserControlWindow()
    {
        InitializeComponent();
        _browserControl = new BrowserControlService();
        _systemPolicy = new SystemPolicyService();
        PolicyList.ItemsSource = _browserControl.DetectedPolicies;
        SysPolicyList.ItemsSource = _systemPolicy.DetectedPolicies;
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
                PolicyCount.Text = "No browser policies. Your browser is yours.";
                PolicyCount.Foreground = new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Colors.LightGreen);
            }
            else
            {
                PolicyCount.Text = $"{count} policies locking your browser.";
                PolicyCount.Foreground = new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Colors.OrangeRed);
                RemoveButton.IsEnabled = true;
            }
        }
        catch (Exception ex) { PolicyCount.Text = $"Failed: {ex.Message}"; }
        finally { ScanButton.IsEnabled = true; }
    }

    private void ScanSysButton_Click(object sender, RoutedEventArgs e)
    {
        SysPolicyCount.Text = "Scanning...";
        ScanSysButton.IsEnabled = false;

        try
        {
            _systemPolicy.ScanForPolicies();
            var count = _systemPolicy.DetectedPolicies.Count;
            if (count == 0)
            {
                SysPolicyCount.Text = "No system policies. Windows is under your control.";
                SysPolicyCount.Foreground = new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Colors.LightGreen);
            }
            else
            {
                SysPolicyCount.Text = $"{count} policies controlling Windows. This is what blocks your downloads.";
                SysPolicyCount.Foreground = new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Colors.OrangeRed);
                RemoveButton.IsEnabled = true;
            }
        }
        catch (Exception ex) { SysPolicyCount.Text = $"Failed: {ex.Message}"; }
        finally { ScanSysButton.IsEnabled = true; }
    }

    private void RemoveButton_Click(object sender, RoutedEventArgs e)
    {
        var result = MessageBox.Show(
            "Remove ALL browser AND system policies?\n\n" +
            "This unlocks greyed-out settings and removes 'your organization' blocks.\n" +
            "Backups saved first.\n\nContinue?",
            "Take Back Control",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (result != MessageBoxResult.Yes) return;

        try
        {
            var (browserRemoved, browserBackup) = _browserControl.RemoveAllPolicies();
            var (sysRemoved, sysBackup) = _systemPolicy.RemoveAllPolicies();

            MessageBox.Show(
                $"Browser policies removed: {browserRemoved}\n" +
                $"System policies removed: {sysRemoved}\n\n" +
                $"Backups:\n{browserBackup}\n{sysBackup}\n\n" +
                "Restart your computer. Download Codex again.",
                "Control Restored",
                MessageBoxButton.OK,
                MessageBoxImage.Information);

            PolicyCount.Text = "Policies removed.";
            SysPolicyCount.Text = "Policies removed.";
            RemoveButton.IsEnabled = false;
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                $"Failed: {ex.Message}\n\n" +
                "Right-click Falsum → Run as administrator, then try again.",
                "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e) => Close();
}
