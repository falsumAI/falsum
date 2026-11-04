using System.Windows;
using FalsumApp.Services.Modules;

namespace FalsumApp.Views;

/// <summary>
/// Shows module results to the user. Every card click that runs a module
/// lands here — findings are never computed and hidden.
/// </summary>
public partial class ResultsWindow : Window
{
    public sealed class Row
    {
        public string Header { get; set; } = "";
        public string Message { get; set; } = "";
    }

    public ResultsWindow(string title, List<ModuleResult> results)
    {
        InitializeComponent();
        TitleText.Text = title;
        var rows = new List<Row>();
        foreach (var r in results)
        {
            string mark = r.Ok ? "✓" : "✗";
            rows.Add(new Row
            {
                Header = $"{mark} {r.Name}",
                Message = r.Message,
            });
        }
        if (rows.Count == 0)
            rows.Add(new Row { Header = "No results", Message = "The module returned nothing." });
        ResultsList.ItemsSource = rows;
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e) => Close();
}
