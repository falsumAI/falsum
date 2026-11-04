using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using FalsumApp.Services;

namespace FalsumApp.Views;

public partial class AIChatWindow : Window
{
    private readonly LocalAIService _ai;

    public AIChatWindow()
    {
        InitializeComponent();
        _ai = new LocalAIService();
        _ = CheckServerStatus();
        AddMessage("Falsum", "Hey. I'm running on your computer — nothing you say leaves this machine. What do you need?", false);
    }

    private async Task CheckServerStatus()
    {
        var running = await _ai.IsServerRunning();
        Dispatcher.Invoke(() =>
        {
            if (running)
            {
                StatusBadgeText.Text = "Local AI Online";
                StatusBadge.Background = new SolidColorBrush(Color.FromRgb(0x2E, 0x7D, 0x32));
                StatusBadgeText.Foreground = new SolidColorBrush(Colors.White);
            }
            else
            {
                StatusBadgeText.Text = "Server Offline";
                StatusBadge.Background = new SolidColorBrush(Color.FromRgb(0xC6, 0x28, 0x28));
                StatusBadgeText.Foreground = new SolidColorBrush(Colors.White);
            }
        });
    }

    private void AddMessage(string sender, string text, bool isUser)
    {
        var border = new Border
        {
            Background = isUser
                ? new SolidColorBrush(Color.FromRgb(0xE9, 0x45, 0x60))
                : new SolidColorBrush(Color.FromRgb(0x1E, 0x2A, 0x4A)),
            CornerRadius = new CornerRadius(12),
            Padding = new Thickness(16, 12, 16, 12),
            Margin = new Thickness(0, 0, 0, 12),
            HorizontalAlignment = isUser ? HorizontalAlignment.Right : HorizontalAlignment.Left,
            MaxWidth = 600
        };

        var panel = new StackPanel();
        if (!isUser)
        {
            panel.Children.Add(new TextBlock
            {
                Text = sender,
                FontWeight = FontWeights.SemiBold,
                FontSize = 12,
                Foreground = new SolidColorBrush(Color.FromRgb(0xE9, 0x45, 0x60)),
                Margin = new Thickness(0, 0, 0, 4)
            });
        }
        panel.Children.Add(new TextBlock
        {
            Text = text,
            FontSize = 14,
            Foreground = new SolidColorBrush(Colors.White),
            TextWrapping = TextWrapping.Wrap
        });

        border.Child = panel;
        ChatMessages.Children.Add(border);
        ChatScroll.ScrollToBottom();
    }

    private async void SendMessage()
    {
        var text = InputBox.Text.Trim();
        if (string.IsNullOrEmpty(text)) return;

        InputBox.Text = "";
        AddMessage("You", text, true);

        // Show typing indicator
        var typing = new TextBlock
        {
            Text = "Thinking...",
            FontSize = 13,
            Foreground = new SolidColorBrush(Color.FromRgb(0xA0, 0xA0, 0xA0)),
            Margin = new Thickness(0, 0, 0, 12),
            FontStyle = FontStyles.Italic
        };
        ChatMessages.Children.Add(typing);
        ChatScroll.ScrollToBottom();

        try
        {
            var response = await _ai.Chat(text);
            ChatMessages.Children.Remove(typing);
            AddMessage("Falsum", response, false);
        }
        catch (Exception ex)
        {
            ChatMessages.Children.Remove(typing);
            AddMessage("Falsum", $"Something went wrong: {ex.Message}", false);
        }
    }

    private void SendButton_Click(object sender, RoutedEventArgs e) => SendMessage();

    private void InputBox_KeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key == Key.Enter && !Keyboard.IsKeyDown(Key.LeftShift))
        {
            e.Handled = true;
            SendMessage();
        }
    }
}
