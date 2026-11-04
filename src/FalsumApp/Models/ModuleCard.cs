namespace FalsumApp.Models;

public class ModuleCard
{
    public string Title { get; set; } = "";
    public string Description { get; set; } = "";
    public string Category { get; set; } = "";
    public string ModuleDir { get; set; } = "";
    public string Action { get; set; } = "";  // Function to call when clicked

    // Vector icon: resolved from XAML resources by IconKey.
    // No emoji, no image files — pure XAML geometry, sharp at any size.
    public string IconKey { get; set; } = "IconShield";

    // Category color brush resource key.
    public string CategoryBrushKey { get; set; } = "CatProtection";
}
