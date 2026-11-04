using System.Windows;
using FalsumApp.Models;

namespace FalsumApp.Views;

public partial class GovernmentWatchWindow : Window
{
    public GovernmentWatchWindow()
    {
        InitializeComponent();
        SectorList.ItemsSource = GovernmentSector.AllSectors;
    }

    private void SectorAction_Click(object sender, RoutedEventArgs e)
    {
        if (sender is System.Windows.Controls.Button btn && btn.Tag is GovernmentSector sector)
        {
            // Route to the appropriate action based on sector
            switch (sector.Name)
            {
                case "Defense & Public Safety":
                    System.Windows.MessageBox.Show("Surveillance scan: Check Active Defense and Packet Witness modules.",
                        sector.Name, MessageBoxButton.OK, MessageBoxImage.Information);
                    break;
                case "Healthcare":
                    System.Windows.MessageBox.Show("Health data protection: Run Broker Eradicator to remove your data from 958 brokers.",
                        sector.Name, MessageBoxButton.OK, MessageBoxImage.Information);
                    break;
                case "Education":
                    System.Windows.MessageBox.Show("Student protection: Tracker Block and Browser Shield are active.",
                        sector.Name, MessageBoxButton.OK, MessageBoxImage.Information);
                    break;
                case "Tax & Revenue":
                    System.Windows.MessageBox.Show("Tax data guard: Scam Shield blocks IRS-impersonation addresses.",
                        sector.Name, MessageBoxButton.OK, MessageBoxImage.Information);
                    break;
                case "Transportation":
                    System.Windows.MessageBox.Show("Location tracking block: Use the Android app's VPN filter.",
                        sector.Name, MessageBoxButton.OK, MessageBoxImage.Information);
                    break;
                case "Judiciary":
                    System.Windows.MessageBox.Show("Legal evidence: Evidence Vault creates tamper-proof logs.",
                        sector.Name, MessageBoxButton.OK, MessageBoxImage.Information);
                    break;
                case "Citizen Services":
                    var chat = new AIChatWindow();
                    chat.Show();
                    break;
            }
        }
    }
    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }

}
