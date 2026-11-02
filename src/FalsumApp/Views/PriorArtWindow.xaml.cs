using System.Windows;
using FalsumApp.Services;

namespace FalsumApp.Views;

public partial class PriorArtWindow : Window
{
    private readonly PriorArtService _priorArt;

    public PriorArtWindow()
    {
        InitializeComponent();
        _priorArt = new PriorArtService();
        RefreshRecords();
    }

    private void RefreshRecords()
    {
        RecordsList.ItemsSource = _priorArt.GetAllRecords()
            .OrderByDescending(r => r.PublishedAt).ToList();
    }

    private void PublishButton_Click(object sender, RoutedEventArgs e)
    {
        var title = TitleBox.Text.Trim();
        var inventor = InventorBox.Text.Trim();
        var description = DescriptionBox.Text.Trim();

        if (string.IsNullOrEmpty(title) || string.IsNullOrEmpty(inventor))
        {
            MessageBox.Show("Title and Inventor name are required.",
                "Missing Info", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        try
        {
            var record = _priorArt.PublishInvention(title, description, inventor, new[] { "defensive-publication" });

            MessageBox.Show(
                $"Published as prior art.\n\n" +
                $"Record ID: {record.Id}\n" +
                $"Timestamp: {record.PublishedAt:yyyy-MM-dd HH:mm:ss} UTC\n" +
                $"Hash: {record.RecordHash.Substring(0, 16)}...\n\n" +
                $"Your name is cryptographically bound to this record. " +
                $"It cannot be stripped or de-identified.",
                "Prior Art Published",
                MessageBoxButton.OK, MessageBoxImage.Information);

            TitleBox.Text = "";
            DescriptionBox.Text = "";
            // Keep inventor name for convenience
            RefreshRecords();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Failed to publish: {ex.Message}",
                "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void VerifyButton_Click(object sender, RoutedEventArgs e)
    {
        var (valid, count, error) = _priorArt.VerifyChain();

        if (valid)
        {
            VerifyResult.Text = $"✓ Chain valid. {count} records verified.";
            VerifyResult.Foreground = new System.Windows.Media.SolidColorBrush(
                System.Windows.Media.Colors.LightGreen);
        }
        else
        {
            VerifyResult.Text = $"✗ CHAIN BROKEN: {error}";
            VerifyResult.Foreground = new System.Windows.Media.SolidColorBrush(
                System.Windows.Media.Colors.OrangeRed);
        }
    }
    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }

}
