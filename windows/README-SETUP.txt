falsum — Setup Guide
=========================

ONE installer. Everything. Run INSTALL.bat.

WHAT YOU GET:
- Desktop application (Falsum-GUI.ps1) — Windows Forms GUI with buttons
- Console version (Falsum.ps1) — for scripting
- 30 modules, 834 functions
- Browser extension (in browser-extension/)
- Local AI setup (Setup-AI.ps1) — downloads model on demand
- Your EIUAE math in the coherence core

INSTALLATION:
1. Unzip falsum-unified.zip
2. Run INSTALL.bat (as admin for full capabilities)
3. Choose whether to download the AI model (~600MB for your 5.8GB machine)
4. Desktop shortcut "Falsum" is created

BROWSER EXTENSION:
1. Open Chrome → chrome://extensions
2. Enable "Developer mode"
3. Click "Load unpacked" → select the browser-extension/ folder
4. Copy the extension ID (long string under the extension name)
5. Edit browser-extension/com.falsum.native.json
   Replace [YOUR-EXTENSION-ID-HERE] with your extension ID
6. Run in PowerShell (as admin):
   New-Item -Path "HKCU:\SOFTWARE\Google\Chrome\NativeMessagingHosts\com.falsum.native" -Force
   Set-ItemProperty -Path "HKCU:\SOFTWARE\Google\Chrome\NativeMessagingHosts\com.falsum.native" -Name "(Default)" -Value "C:\path\to\browser-extension\com.falsum.native.json"
   (Replace C:\path\to with your actual path)
7. For Edge, replace Chrome with Edge in the registry path.

The extension and desktop app will see each other via native messaging.

AI MODEL:
Run Setup-AI.ps1 separately, or choose 'y' during INSTALL.bat.
- Downloads llama.cpp from GitHub
- Downloads TinyLlama (600MB) for machines with <8GB RAM
  OR Phi-4-mini (2.5GB) for machines with 8GB+ RAM
- Tests the model
- Saves config to ai-config.json

The intelligence core uses the local model. No cloud. No tokens.

UNINSTALL:
Run UNINSTALL.bat. Removes shortcut. Preserves logs.

FILES:
- Falsum-GUI.ps1 ......... Windows application (GUI)
- Falsum.ps1 .............. Console version
- Setup-AI.ps1 .............. AI model downloader
- INSTALL.bat ............... One-click installer
- UNINSTALL.bat ............. Remover
- modules/ .................. 30 modules
- browser-extension/ ........ Chrome/Edge extension
- tools/ .................... Auditor
- CODE-PAIN-POINTS.md ....... 70 documented issues (honest)
- PROBLEMS.md ............... 2,000 end-user problems catalog
