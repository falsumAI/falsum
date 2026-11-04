using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace FalsumApp.Converters;

/// <summary>
/// Converts an icon resource key (e.g. "IconShield") to the actual
/// PathGeometry from the application resources. Lets cards reference
/// vector icons by name without code-behind lookups.
/// </summary>
public class IconKeyConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is string key && !string.IsNullOrEmpty(key))
        {
            // Try window resources first, then app resources.
            if (System.Windows.Application.Current?.MainWindow?.TryFindResource(key) is Geometry g)
                return g;
            if (System.Windows.Application.Current?.TryFindResource(key) is Geometry g2)
                return g2;
        }
        // Fallback: simple shield outline.
        return Geometry.Parse("M12,2 L20,6 V11 C20,16 16.5,19.5 12,21 C7.5,19.5 4,16 4,11 V6 Z");
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>
/// Converts a brush resource key (e.g. "CatProtection") to the actual brush.
/// </summary>
public class BrushKeyConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is string key && !string.IsNullOrEmpty(key))
        {
            if (System.Windows.Application.Current?.MainWindow?.TryFindResource(key) is Brush b)
                return b;
            if (System.Windows.Application.Current?.TryFindResource(key) is Brush b2)
                return b2;
        }
        return new SolidColorBrush(Color.FromRgb(0xE9, 0x45, 0x60));
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
