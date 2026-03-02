<# 
RSD CleanAgent - Intune Proactive Remediation Detection (Embedded JSON)
PowerShell 5.1 compatible
Version: 2026.02.27.2

How to update targets:
- Paste the JSON array into $TargetsJson between the @' and '@ markers.

Exit codes:
  0 = compliant (no forbidden apps detected AND local agent is installed/up-to-date)
  1 = noncompliant (forbidden apps detected OR agent missing/outdated)
#>

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'SilentlyContinue'

$AgentRoot   = 'C:\ProgramData\RSD\Agent'
$AgentScript = Join-Path $AgentRoot 'cleanAGENT.ps1'
$VersionFile = Join-Path $AgentRoot 'version.txt'

$ExpectedVersion = '2026.02.27.2'

# --- Embedded targets.json payload ---
$TargetsJson = @'
[
    {
        "Name":  "Angry Birds 2",
        "UWPFamily":  "1ED5AEA5.4160926B82DB_p2gbknwb5d8r2",
        "ARPName":  null,
        "Publisher":  null,
        "InstallerSignatures":  {
                                    "ProductName":  "Store Installer",
                                    "CompanyName":  "Microsoft Corporation",
                                    "OriginalFilename":  "Angry Birds 2 Installer.exe",
                                    "CertThumbprint":  "A85A56572A16C89BE458C5B22D11877071586023",
                                    "SignerSimpleName":  "Microsoft Corporation",
                                    "FileDescriptions":  "Store Installer Angry Birds 2 Installer.exe"
                                },
        "PortableExeSignatures":  null,
        "PathAnchors":  "1ED5AEA5.4160926B82DB_p2gbknwb5d8r2"
    },
    {
        "Name":  "Autoclicker",
        "UWPFamily":  null,
        "ARPName":  null,
        "Publisher":  null,
        "InstallerSignatures":  {
                                    "ProductName":  "OP Auto Clicker",
                                    "CompanyName":  null,
                                    "OriginalFilename":  "AutoClicker-*.exe",
                                    "CertThumbprint":  "562E77844B63A3EAB2B2B6D77A76DCFA52DD9846",
                                    "SignerSimpleName":  "AMSTION LIMITED",
                                    "FileDescriptions":  "OP Auto Clicker Auto Clicker-*.exe"
                                },
        "PortableExeSignatures":  {
                                      "ProductName":  "OP Auto Clicker",
                                      "CompanyName":  null,
                                      "OriginalFilename":  null,
                                      "CertThumbprint":  "562E77844B63A3EAB2B2B6D77A76DCFA52DD9846",
                                      "SignerSimpleName":  "AMSTION LIMITED",
                                      "FileDescriptions":  "OP Auto Clicker"
                                  },
        "PathAnchors":  null
    },
    {
        "Name":  "AVG Secure Browser",
        "UWPFamily":  null,
        "ARPName":  "AVG Secure Browser*",
        "Publisher":  "Gen Digital Inc.",
        "InstallerSignatures":  {
                                    "ProductName":  "AVG Secure Browser Setup",
                                    "CompanyName":  "Gen Digital Inc.",
                                    "OriginalFilename":  "avg_secure_browser_setup.exe",
                                    "CertThumbprint":  "79A1F7262575EC7D1304F9CDAC161C91DA814B87",
                                    "SignerSimpleName":  "AVG Technologies USA",
                                    "FileDescriptions":  "AVG Secure Browser Setupavg_secure_browser_setup.exe"
                                },
        "PortableExeSignatures":  null,
        "PathAnchors":  [
                            "AVG Secure Browser",
                            "Gen Digital Inc."
                        ]
    },
    {
        "Name":  "BlueStacks",
        "UWPFamily":  null,
        "ARPName":  "BlueStacks*",
        "Publisher":  "now.gg, Inc.",
        "InstallerSignatures":  {
                                    "ProductName":  "BlueStacks 5",
                                    "CompanyName":  "now.gg, Inc.",
                                    "OriginalFilename":  "BlueStacksInstaller_*_native_b2a81b8bb*e90d9fc*_MzsxNSwwOzUsMTsxNSw0OzE1LDU7MTU=.exe",
                                    "CertThumbprint":  "19FE0C50C1E150B1C044D1AC3AC2E8E886E00AA1",
                                    "SignerSimpleName":  "Now.gg",
                                    "FileDescriptions":  "Blue Stacks Setup Blue Stacks Installer_*_native_b2a81b8bb*e90d9fc*_Mzsx NSww Oz Us MTsx NSw0Oz E1LDU7MTU=.exe"
                                },
        "PortableExeSignatures":  null,
        "PathAnchors":  [
                            "BlueStacks Store",
                            "BlueStacks X",
                            "BlueStacks_nxt",
                            "bluestacks-services",
                            "now.gg, Inc."
                        ]
    },
    {
        "Name":  "Brave",
        "UWPFamily":  null,
        "ARPName":  "Brave*",
        "Publisher":  "Brave Software Inc",
        "InstallerSignatures":  {
                                    "ProductName":  "BraveSoftware Update",
                                    "CompanyName":  "BraveSoftware Inc.",
                                    "OriginalFilename":  "BraveBrowserSetup-BRV*.exe",
                                    "CertThumbprint":  "F8AC5F11DE7E26383B7A389FC19A2613835799D7",
                                    "SignerSimpleName":  "Brave Software",
                                    "FileDescriptions":  "Brave Software Update Setup Brave Browser Setup-BRV*.exe"
                                },
        "PortableExeSignatures":  null,
        "PathAnchors":  [
                            "Brave Browser",
                            "Brave Software Inc",
                            "Brave Software, Inc.",
                            "Brave-Browser",
                            "BraveSoftware"
                        ]
    },
    {
        "Name":  "Craftmine",
        "UWPFamily":  null,
        "ARPName":  null,
        "Publisher":  null,
        "InstallerSignatures":  null,
        "PortableExeSignatures":  {
                                      "ProductName":  "CraftMine - Definitive Edition",
                                      "CompanyName":  null,
                                      "OriginalFilename":  null,
                                      "CertThumbprint":  null,
                                      "SignerSimpleName":  null,
                                      "FileDescriptions":  null
                                  },
        "PathAnchors":  [
                            "CraftMine - Definitive Edition",
                            "minecraft-*-alpha.25.14.craftmine-*",
                            "Simply Craftmine"
                        ]
    },
    {
        "Name":  "CurseForge",
        "UWPFamily":  null,
        "ARPName":  "CurseForge*",
        "Publisher":  "Overwolf",
        "InstallerSignatures":  {
                                    "ProductName":  "Curseforge",
                                    "CompanyName":  "Overwolf Ltd.",
                                    "OriginalFilename":  "CurseForge Windows - Installer.exe",
                                    "CertThumbprint":  "962A9D59796B8C6AE1A7D8FAE72EC3729A898814",
                                    "SignerSimpleName":  "Overwolf Ltd",
                                    "FileDescriptions":  "Curseforge Curse Forge Windows - Installer.exe"
                                },
        "PortableExeSignatures":  null,
        "PathAnchors":  [
                            "CurseForge",
                            "CurseForge Windows",
                            "curseforge-updater",
                            "Overwolf"
                        ]
    },
    {
        "Name":  "Discord",
        "UWPFamily":  null,
        "ARPName":  "Discord*",
        "Publisher":  "Discord Inc.",
        "InstallerSignatures":  {
                                    "ProductName":  "Discord - https://discord.com/",
                                    "CompanyName":  "Discord Inc.",
                                    "OriginalFilename":  "DiscordSetup.exe",
                                    "CertThumbprint":  "6C7552617E892DFCA5CEB96FA2870F4F1904820E",
                                    "SignerSimpleName":  "Discord Inc.",
                                    "FileDescriptions":  "Discord - https://discord.com/Discord Setup.exe"
                                },
        "PortableExeSignatures":  null,
        "PathAnchors":  [
                            "Discord",
                            "Discord Inc."
                        ]
    },
    {
        "Name":  "Dragon City",
        "UWPFamily":  "SocialPoint.DragonCityMobile_jahftqv9k5jer",
        "ARPName":  null,
        "Publisher":  null,
        "InstallerSignatures":  {
                                    "ProductName":  "Store Installer",
                                    "CompanyName":  "Microsoft Corporation",
                                    "OriginalFilename":  "Dragon City Installer.exe",
                                    "CertThumbprint":  "CB603439DC30897FCED64CA353AA902DBD3540E3",
                                    "SignerSimpleName":  "Microsoft Corporation",
                                    "FileDescriptions":  "Store Installer Dragon City Installer.exe"
                                },
        "PortableExeSignatures":  null,
        "PathAnchors":  [
                            "DragonCity",
                            "Social Point",
                            "SocialPoint.DragonCityMobile_*"
                        ]
    },
    {
        "Name":  "DuckDuckGo",
        "UWPFamily":  "DuckDuckGo.DesktopBrowser_ya2fgkz3nks94",
        "ARPName":  null,
        "Publisher":  null,
        "InstallerSignatures":  {
                                    "ProductName":  "DuckDuckGo® Browser Installer",
                                    "CompanyName":  "DuckDuckGo LLC",
                                    "OriginalFilename":  "DuckDuckGo.Installer.exe",
                                    "CertThumbprint":  "69441D863214355EC15AEE0164ACCDEE3CEFC373",
                                    "SignerSimpleName":  "Duck Duck Go",
                                    "FileDescriptions":  "Duck Duck Go.Installer Duck Duck Go.Installer.exe"
                                },
        "PortableExeSignatures":  null,
        "PathAnchors":  "DuckDuckGo.DesktopBrowser_ya2fgkz3nks94"
    },
    {
        "Name":  "Endless Sky",
        "UWPFamily":  null,
        "ARPName":  null,
        "Publisher":  null,
        "InstallerSignatures":  {
                                    "ProductName":  "Endless Sky",
                                    "CompanyName":  null,
                                    "OriginalFilename":  "Endless Sky.exe",
                                    "CertThumbprint":  null,
                                    "SignerSimpleName":  null,
                                    "FileDescriptions":  [
                                                             "Space exploration and combat game",
                                                             "Endless Sky",
                                                             "Endless Sky.exe"
                                                         ]
                                },
        "PortableExeSignatures":  {
                                      "ProductName":  "Endless Sky",
                                      "CompanyName":  null,
                                      "OriginalFilename":  "Endless Sky.exe",
                                      "CertThumbprint":  null,
                                      "SignerSimpleName":  null,
                                      "FileDescriptions":  [
                                                               "Space exploration and combat game",
                                                               "Endless Sky"
                                                           ]
                                  },
        "PathAnchors":  [
                            "endless-sky*",
                            "EndlessSky-win64-v0.10.16",
                            "https_endless-sky.fandom.com_0.indexeddb.leveldb"
                        ]
    },
    {
        "Name":  "eve-online",
        "UWPFamily":  null,
        "ARPName":  "eve-online*",
        "Publisher":  "CCP ehf",
        "InstallerSignatures":  {
                                    "ProductName":  "A launcher for EVE Online",
                                    "CompanyName":  "CCP ehf",
                                    "OriginalFilename":  "eve-online-latest+Setup.exe",
                                    "CertThumbprint":  "BE688C28E20108AB16E53BA40990765EE8536F2B",
                                    "SignerSimpleName":  "CCP ehf.",
                                    "FileDescriptions":  "A launcher for EVE Onlineeve-online-latest+Setup.exe"
                                },
        "PortableExeSignatures":  null,
        "PathAnchors":  [
                            "CCP ehf",
                            "EVE Online",
                            "eve-online"
                        ]
    },
    {
        "Name":  "FCEUX",
        "UWPFamily":  null,
        "ARPName":  null,
        "Publisher":  null,
        "InstallerSignatures":  {
                                    "ProductName":  null,
                                    "CompanyName":  null,
                                    "OriginalFilename":  "fceux.exe",
                                    "CertThumbprint":  null,
                                    "SignerSimpleName":  null,
                                    "FileDescriptions":  "fceux.exe"
                                },
        "PortableExeSignatures":  {
                                      "ProductName":  "fceux",
                                      "CompanyName":  null,
                                      "OriginalFilename":  null,
                                      "CertThumbprint":  null,
                                      "SignerSimpleName":  null,
                                      "FileDescriptions":  null
                                  },
        "PathAnchors":  "fceux*"
    },
    {
        "Name":  "Free Download Manager",
        "UWPFamily":  null,
        "ARPName":  "Free Download Manager*",
        "Publisher":  "Softdeluxe",
        "InstallerSignatures":  {
                                    "ProductName":  "Free Download Manager",
                                    "CompanyName":  "Softdeluxe",
                                    "OriginalFilename":  null,
                                    "CertThumbprint":  "F145211219978C65FF322D9C16EC82FA90F88671",
                                    "SignerSimpleName":  "E=administrator@softdeluxe.com",
                                    "FileDescriptions":  "Free Download Manager Setup"
                                },
        "PortableExeSignatures":  null,
        "PathAnchors":  [
                            "Free Download Manager",
                            "Softdeluxe"
                        ]
    },
    {
        "Name":  "game",
        "UWPFamily":  null,
        "ARPName":  null,
        "Publisher":  null,
        "InstallerSignatures":  {
                                    "ProductName":  "mkxp-z",
                                    "CompanyName":  null,
                                    "OriginalFilename":  "Game-performance.exe",
                                    "CertThumbprint":  null,
                                    "SignerSimpleName":  null,
                                    "FileDescriptions":  "Game-performance.exe"
                                },
        "PortableExeSignatures":  {
                                      "ProductName":  "mkxp-z",
                                      "CompanyName":  null,
                                      "OriginalFilename":  "mkxp-z.exe",
                                      "CertThumbprint":  null,
                                      "SignerSimpleName":  null,
                                      "FileDescriptions":  null
                                  },
        "PathAnchors":  [
                            "003_Game processing",
                            "004_Game classes",
                            "https_count-masters-stickman-games.game-files.crazygames.com_0.indexeddb.leveldb",
                            "https_gamesfrog.com_0.indexeddb.leveldb",
                            "https_ragdoll-archers.game-files.crazygames.com_0.indexeddb.leveldb",
                            "https_survival-rush.game-files.crazygames.com_0.indexeddb.leveldb"
                        ]
    },
    {
        "Name":  "Gang Beasts",
        "UWPFamily":  "DoubleFineProductionsInc.GangBeasts_s9zt93y1rpe5a",
        "ARPName":  null,
        "Publisher":  null,
        "InstallerSignatures":  null,
        "PortableExeSignatures":  null,
        "PathAnchors":  [
                            "DoubleFineProductionsInc.GangBeasts_*",
                            "Gang Beasts"
                        ]
    },
    {
        "Name":  "GeometryDash",
        "UWPFamily":  null,
        "ARPName":  null,
        "Publisher":  null,
        "InstallerSignatures":  {
                                    "ProductName":  null,
                                    "CompanyName":  null,
                                    "OriginalFilename":  "GeometryDash.exe",
                                    "CertThumbprint":  null,
                                    "SignerSimpleName":  null,
                                    "FileDescriptions":  "Geometry Dash.exe"
                                },
        "PortableExeSignatures":  {
                                      "ProductName":  null,
                                      "CompanyName":  null,
                                      "OriginalFilename":  "GeometryDash",
                                      "CertThumbprint":  null,
                                      "SignerSimpleName":  null,
                                      "FileDescriptions":  "GeometryDash"
                                  },
        "PathAnchors":  "Geometry DashGeometryDash"
    },
    {
        "Name":  "Google Play Games",
        "UWPFamily":  null,
        "ARPName":  "Google Play Games*",
        "Publisher":  "Google LLC",
        "InstallerSignatures":  null,
        "PortableExeSignatures":  null,
        "PathAnchors":  [
                            "Apps",
                            "Google Play Games",
                            "Google.Play.Games",
                            "Install-Clash Royale-GooglePlayGames*",
                            "Install-Drift Max Pro Car Racing Game-GooglePlayGames*",
                            "Install-Geometry Dash Lite-GooglePlayGames*",
                            "Install-Hill Climb Racing-GooglePlayGames*",
                            "Play Games"
                        ]
    },
    {
        "Name":  "Hill Climb Racing",
        "UWPFamily":  "FINGERSOFT.HILLCLIMBRACING_r6rtpscs7gwyg",
        "ARPName":  null,
        "Publisher":  null,
        "InstallerSignatures":  {
                                    "ProductName":  "Store Installer",
                                    "CompanyName":  "Microsoft Corporation",
                                    "OriginalFilename":  "Hill Climb Racing Installer.exe",
                                    "CertThumbprint":  "CB603439DC30897FCED64CA353AA902DBD3540E3",
                                    "SignerSimpleName":  "Microsoft Corporation",
                                    "FileDescriptions":  "Store Installer Hill Climb Racing Installer.exe"
                                },
        "PortableExeSignatures":  null,
        "PathAnchors":  [
                            "FINGERSOFT.HILLCLIMBRACING_*",
                            "HCR-Trainer"
                        ]
    },
    {
        "Name":  "Instagram",
        "UWPFamily":  "Facebook.InstagramBeta_8xx8rvfyw5nnt",
        "ARPName":  null,
        "Publisher":  null,
        "InstallerSignatures":  null,
        "PortableExeSignatures":  null,
        "PathAnchors":  "Facebook.InstagramBeta_*"
    },
    {
        "Name":  "Lively",
        "UWPFamily":  "12030rocksdanister.LivelyWallpaper_97hta09mmv6hy",
        "ARPName":  null,
        "Publisher":  null,
        "InstallerSignatures":  {
                                    "ProductName":  "Store Installer",
                                    "CompanyName":  "Microsoft Corporation",
                                    "OriginalFilename":  "Lively Wallpaper Installer.exe",
                                    "CertThumbprint":  "CB603439DC30897FCED64CA353AA902DBD3540E3",
                                    "SignerSimpleName":  "Microsoft Corporation",
                                    "FileDescriptions":  "Store Installer Lively Wallpaper Installer.exe"
                                },
        "PortableExeSignatures":  null,
        "PathAnchors":  [
                            "12030rocksdanister.LivelyWallpaper_*",
                            "Lively Wallpaper"
                        ]
    },
    {
        "Name":  "Lunar Client",
        "UWPFamily":  null,
        "ARPName":  "Uninstall Lunar Client*",
        "Publisher":  "Moonsworth LLC",
        "InstallerSignatures":  {
                                    "ProductName":  "Lunar Client",
                                    "CompanyName":  "Overwolf Ltd.",
                                    "OriginalFilename":  "Lunar Client - Installer.exe",
                                    "CertThumbprint":  "962A9D59796B8C6AE1A7D8FAE72EC3729A898814",
                                    "SignerSimpleName":  "Overwolf Ltd",
                                    "FileDescriptions":  "Lunar Client Lunar Client - Installer.exe"
                                },
        "PortableExeSignatures":  null,
        "PathAnchors":  [
                            ".lunarclient",
                            "Lunar Client",
                            "lunarclient",
                            "lunarclient-updater",
                            "Moonsworth LLC"
                        ]
    },
    {
        "Name":  "mGBA",
        "UWPFamily":  null,
        "ARPName":  "mGBA*",
        "Publisher":  "Jeffrey Pfau",
        "InstallerSignatures":  null,
        "PortableExeSignatures":  {
                                      "ProductName":  null,
                                      "CompanyName":  null,
                                      "OriginalFilename":  "mgba",
                                      "CertThumbprint":  null,
                                      "SignerSimpleName":  null,
                                      "FileDescriptions":  "mgba"
                                  },
        "PathAnchors":  [
                            "Jeffrey Pfau",
                            "mGBA",
                            "mGBA-*-win32-installer",
                            "shaders"
                        ]
    },
    {
        "Name":  "Minecraft for Windows",
        "UWPFamily":  "MICROSOFT.MINECRAFTUWP_8wekyb3d8bbwe",
        "ARPName":  null,
        "Publisher":  null,
        "InstallerSignatures":  {
                                    "ProductName":  "MinecraftInstaller",
                                    "CompanyName":  "Microsoft Corporation",
                                    "OriginalFilename":  "MinecraftInstaller.exe",
                                    "CertThumbprint":  null,
                                    "SignerSimpleName":  null,
                                    "FileDescriptions":  "Minecraft Installer"
                                },
        "PortableExeSignatures":  null,
        "PathAnchors":  [
                            "Minecraft for Windows",
                            "Minecraft Launcher",
                            "MinecraftLauncher"
                        ]
    },
    {
        "Name":  "Minecraft Launcher",
        "UWPFamily":  null,
        "ARPName":  null,
        "Publisher":  null,
        "InstallerSignatures":  null,
        "PortableExeSignatures":  {
                                      "ProductName":  null,
                                      "CompanyName":  null,
                                      "OriginalFilename":  "Minecraft Launcher",
                                      "CertThumbprint":  null,
                                      "SignerSimpleName":  null,
                                      "FileDescriptions":  "Minecraft Launcher"
                                  },
        "PathAnchors":  "Minecraft Launcher"
    },
    {
        "Name":  "Modrinth App",
        "UWPFamily":  null,
        "ARPName":  "Modrinth App*",
        "Publisher":  "ModrinthApp",
        "InstallerSignatures":  {
                                    "ProductName":  "Modrinth App",
                                    "CompanyName":  null,
                                    "OriginalFilename":  "Modrinth App_*_x64-setup.exe",
                                    "CertThumbprint":  "F82EABB60BB01A0DB764F4E3A737FC1483EC4434",
                                    "SignerSimpleName":  "Rinth",
                                    "FileDescriptions":  "Modrinth App Modrinth App_*_x64-setup.exe"
                                },
        "PortableExeSignatures":  null,
        "PathAnchors":  [
                            "Modrinth App",
                            "Modrinth App-0.10.15-updater-SJXQCk",
                            "ModrinthApp"
                        ]
    },
    {
        "Name":  "Mozilla Firefox",
        "UWPFamily":  null,
        "ARPName":  "Mozilla Firefox (x64 en-US)*",
        "Publisher":  "Mozilla",
        "InstallerSignatures":  {
                                    "ProductName":  "Firefox",
                                    "CompanyName":  "Mozilla",
                                    "OriginalFilename":  "Firefox Installer.exe",
                                    "CertThumbprint":  "40890F2FE1ACAE18072FA7F3C0AE456AACC8570D",
                                    "SignerSimpleName":  "Mozilla Corporation",
                                    "FileDescriptions":  "Firefox Firefox Installer.exe"
                                },
        "PortableExeSignatures":  null,
        "PathAnchors":  [
                            "Firefox",
                            "Mozilla",
                            "Mozilla Firefox",
                            "Old Firefox Data"
                        ]
    },
    {
        "Name":  "Opera Air Stable",
        "UWPFamily":  null,
        "ARPName":  "Opera Air Stable*",
        "Publisher":  "Opera Software",
        "InstallerSignatures":  {
                                    "ProductName":  "Opera installer",
                                    "CompanyName":  null,
                                    "OriginalFilename":  "OperaAirSetup.exe",
                                    "CertThumbprint":  "25F4C2A374C779AB087B79B7740216416CAF0EE0",
                                    "SignerSimpleName":  "Opera Norway AS",
                                    "FileDescriptions":  [
                                                             "Opera installer SFX",
                                                             "Opera Air Setup.exe"
                                                         ]
                                },
        "PortableExeSignatures":  null,
        "PathAnchors":  [
                            "Opera Air",
                            "Opera Air Stable",
                            "Opera Software"
                        ]
    },
    {
        "Name":  "Opera GX Stable",
        "UWPFamily":  null,
        "ARPName":  "Opera GX Stable*",
        "Publisher":  "Opera Software",
        "InstallerSignatures":  {
                                    "ProductName":  "Opera installer",
                                    "CompanyName":  null,
                                    "OriginalFilename":  "OperaGXSetup.exe",
                                    "CertThumbprint":  "25F4C2A374C779AB087B79B7740216416CAF0EE0",
                                    "SignerSimpleName":  "Opera Norway AS",
                                    "FileDescriptions":  [
                                                             "Opera installer SFX",
                                                             "Opera GXSetup.exe"
                                                         ]
                                },
        "PortableExeSignatures":  null,
        "PathAnchors":  [
                            "Opera GX",
                            "Opera GX Stable",
                            "Opera Software"
                        ]
    },
    {
        "Name":  "Opera Stable",
        "UWPFamily":  null,
        "ARPName":  "Opera Stable*",
        "Publisher":  "Opera Software",
        "InstallerSignatures":  {
                                    "ProductName":  "Opera installer",
                                    "CompanyName":  null,
                                    "OriginalFilename":  "OperaSetup.exe",
                                    "CertThumbprint":  "BF684995EFEA2306448FF2930367C60AC0F7172C",
                                    "SignerSimpleName":  "Opera Norway AS",
                                    "FileDescriptions":  [
                                                             "Opera installer SFX",
                                                             "Opera Setup.exe"
                                                         ]
                                },
        "PortableExeSignatures":  null,
        "PathAnchors":  [
                            "Opera Software",
                            "Opera Stable"
                        ]
    },
    {
        "Name":  "PPSSPP",
        "UWPFamily":  null,
        "ARPName":  null,
        "Publisher":  null,
        "InstallerSignatures":  null,
        "PortableExeSignatures":  {
                                      "ProductName":  null,
                                      "CompanyName":  null,
                                      "OriginalFilename":  "ppsspp_win",
                                      "CertThumbprint":  null,
                                      "SignerSimpleName":  null,
                                      "FileDescriptions":  "ppsspp_win"
                                  },
        "PathAnchors":  "ppsspp_win"
    },
    {
        "Name":  "retroarch",
        "UWPFamily":  null,
        "ARPName":  null,
        "Publisher":  null,
        "InstallerSignatures":  null,
        "PortableExeSignatures":  {
                                      "ProductName":  null,
                                      "CompanyName":  null,
                                      "OriginalFilename":  "RetroArch-MSVC10-Win64",
                                      "CertThumbprint":  null,
                                      "SignerSimpleName":  null,
                                      "FileDescriptions":  "RetroArch-MSVC10-Win64"
                                  },
        "PathAnchors":  "RetroArch-MSVC10-Win64"
    },
    {
        "Name":  "Riot Client",
        "UWPFamily":  null,
        "ARPName":  "Riot Client*",
        "Publisher":  "Riot Games, Inc",
        "InstallerSignatures":  {
                                    "ProductName":  "RiotClient",
                                    "CompanyName":  "Riot Games, Inc.",
                                    "OriginalFilename":  "Install VALORANT.exe",
                                    "CertThumbprint":  "7FEEA8A5B55F34023287495F77CE55B0887CAA05",
                                    "SignerSimpleName":  "Riot Games",
                                    "FileDescriptions":  [
                                                             "Riot Client",
                                                             "Riot",
                                                             "Install VALORANT.exe"
                                                         ]
                                },
        "PortableExeSignatures":  null,
        "PathAnchors":  [
                            "C:\\Riot Games\\Riot Client",
                            "Riot",
                            "Riot Client",
                            "Riot Games",
                            "Riot Games, Inc.",
                            "RiotClient"
                        ]
    },
    {
        "Name":  "Roblox",
        "UWPFamily":  "ROBLOXCORPORATION.ROBLOX_55nm5eh3cm0pr",
        "ARPName":  null,
        "Publisher":  null,
        "InstallerSignatures":  null,
        "PortableExeSignatures":  null,
        "PathAnchors":  "ROBLOXCORPORATION.ROBLOX_*"
    },
    {
        "Name":  "Roblox Player",
        "UWPFamily":  null,
        "ARPName":  "Roblox Player*",
        "Publisher":  "Roblox Corporation",
        "InstallerSignatures":  {
                                    "ProductName":  "Roblox Bootstrapper",
                                    "CompanyName":  "Roblox Corporation",
                                    "OriginalFilename":  "RobloxPlayerInstaller-JQGXMWMQ6Y.exe",
                                    "CertThumbprint":  "813CA29445456DC3447C173347A0CE5B9494B24C",
                                    "SignerSimpleName":  "Roblox Corporation",
                                    "FileDescriptions":  "Roblox Roblox Player Installer-JQGXMWMQ6Y.exe"
                                },
        "PortableExeSignatures":  null,
        "PathAnchors":  [
                            "https_roblox.fandom.com_0.indexeddb.leveldb",
                            "https_www.roblox.com_0.indexeddb.leveldb",
                            "roblox",
                            "Roblox Bootstrapper",
                            "Roblox Corporation"
                        ]
    },
    {
        "Name":  "Roblox Studio",
        "UWPFamily":  null,
        "ARPName":  "Roblox Studio*",
        "Publisher":  "Roblox Corporation",
        "InstallerSignatures":  {
                                    "ProductName":  "Roblox Bootstrapper",
                                    "CompanyName":  "Roblox Corporation",
                                    "OriginalFilename":  "RobloxPlayerInstaller-JQGXMWMQ6Y.exe",
                                    "CertThumbprint":  "813CA29445456DC3447C173347A0CE5B9494B24C",
                                    "SignerSimpleName":  "Roblox Corporation",
                                    "FileDescriptions":  "Roblox Roblox Player Installer-JQGXMWMQ6Y.exe"
                                },
        "PortableExeSignatures":  null,
        "PathAnchors":  [
                            "Roblox",
                            "Roblox Bootstrapper",
                            "Roblox Corporation",
                            "RobloxStudio",
                            "roblox-studio"
                        ]
    },
    {
        "Name":  "Snapchat",
        "UWPFamily":  "SnapInc.Snapchat_k1zn018256b8e",
        "ARPName":  null,
        "Publisher":  null,
        "InstallerSignatures":  null,
        "PortableExeSignatures":  null,
        "PathAnchors":  "SnapInc.Snapchat_*"
    },
    {
        "Name":  "SNES",
        "UWPFamily":  null,
        "ARPName":  null,
        "Publisher":  null,
        "InstallerSignatures":  {
                                    "ProductName":  "Snes9x SNES Emulator",
                                    "CompanyName":  "http://www.snes9x.com",
                                    "OriginalFilename":  "Advanced_SNES_ROM_Utility.exe",
                                    "CertThumbprint":  null,
                                    "SignerSimpleName":  null,
                                    "FileDescriptions":  [
                                                             "Snes9x",
                                                             "Advanced SNES ROM Utility",
                                                             "Advanced_SNES_ROM_Utility.exe"
                                                         ]
                                },
        "PortableExeSignatures":  {
                                      "ProductName":  "Snes9x SNES Emulator",
                                      "CompanyName":  "http://www.snes9x.com",
                                      "OriginalFilename":  "Snes9x.exe",
                                      "CertThumbprint":  null,
                                      "SignerSimpleName":  null,
                                      "FileDescriptions":  [
                                                               "Snes9x",
                                                               "Advanced SNES ROM Utility"
                                                           ]
                                  },
        "PathAnchors":  [
                            "SNES",
                            "snes9x-1.62.3-win32-x64"
                        ]
    },
    {
        "Name":  "Stardew Valley",
        "UWPFamily":  null,
        "ARPName":  null,
        "Publisher":  null,
        "InstallerSignatures":  {
                                    "ProductName":  "Stardew Valley",
                                    "CompanyName":  "ConcernedApe",
                                    "OriginalFilename":  "Stardew Valley.dll",
                                    "CertThumbprint":  null,
                                    "SignerSimpleName":  null,
                                    "FileDescriptions":  "Stardew Valley Stardew Valley.dll"
                                },
        "PortableExeSignatures":  {
                                      "ProductName":  "Stardew Valley",
                                      "CompanyName":  "ConcernedApe",
                                      "OriginalFilename":  "Stardew Valley.dll",
                                      "CertThumbprint":  null,
                                      "SignerSimpleName":  null,
                                      "FileDescriptions":  "Stardew Valley"
                                  },
        "PathAnchors":  [
                            "Stardew Valley",
                            "StardewValley"
                        ]
    },
    {
        "Name":  "TASEditor",
        "UWPFamily":  null,
        "ARPName":  null,
        "Publisher":  null,
        "InstallerSignatures":  null,
        "PortableExeSignatures":  {
                                      "ProductName":  null,
                                      "CompanyName":  null,
                                      "OriginalFilename":  "taseditor",
                                      "CertThumbprint":  null,
                                      "SignerSimpleName":  null,
                                      "FileDescriptions":  "taseditor"
                                  },
        "PathAnchors":  [
                            "luaScripts",
                            "taseditor"
                        ]
    },
    {
        "Name":  "TikTok",
        "UWPFamily":  "BytedancePte.Ltd.TikTok_6yccndn6064se",
        "ARPName":  null,
        "Publisher":  null,
        "InstallerSignatures":  {
                                    "ProductName":  "Store Installer",
                                    "CompanyName":  "Microsoft Corporation",
                                    "OriginalFilename":  "TikTok Installer.exe",
                                    "CertThumbprint":  "CB603439DC30897FCED64CA353AA902DBD3540E3",
                                    "SignerSimpleName":  "Microsoft Corporation",
                                    "FileDescriptions":  "Store Installer Tik Tok Installer.exe"
                                },
        "PortableExeSignatures":  null,
        "PathAnchors":  "BytedancePte.Ltd.TikTok_*"
    },
    {
        "Name":  "Tor Browser",
        "UWPFamily":  null,
        "ARPName":  null,
        "Publisher":  null,
        "InstallerSignatures":  {
                                    "ProductName":  "Tor Browser",
                                    "CompanyName":  "Mozilla Foundation",
                                    "OriginalFilename":  "tor-browser-windows-x86_64-portable-*.exe",
                                    "CertThumbprint":  "4DEB8C027FFF4DD8DE3AE9BEFAA7898618ADCF15",
                                    "SignerSimpleName":  "THE TOR PROJECT",
                                    "FileDescriptions":  "Tor Browser Software Updatertor-browser-windows-x86_64-portable-*.exe"
                                },
        "PortableExeSignatures":  {
                                      "ProductName":  "Tor Browser",
                                      "CompanyName":  "Mozilla Foundation",
                                      "OriginalFilename":  "updater.exe",
                                      "CertThumbprint":  "4DEB8C027FFF4DD8DE3AE9BEFAA7898618ADCF15",
                                      "SignerSimpleName":  "THE TOR PROJECT",
                                      "FileDescriptions":  "Tor Browser Software Updater"
                                  },
        "PathAnchors":  "Tor Browser"
    },
    {
        "Name":  "Visual Boy Advance",
        "UWPFamily":  null,
        "ARPName":  null,
        "Publisher":  null,
        "InstallerSignatures":  {
                                    "ProductName":  "VisualBoyAdvance-M",
                                    "CompanyName":  "http://vba-m.com/",
                                    "OriginalFilename":  "VisualBoyAdvance-M.exe",
                                    "CertThumbprint":  "34025714D92839B99F89F8E80BBDDBCC465C7459",
                                    "SignerSimpleName":  "Rafael Kitover",
                                    "FileDescriptions":  "Visual Boy Advance-MVisual Boy Advance-M.exe"
                                },
        "PortableExeSignatures":  {
                                      "ProductName":  "VisualBoyAdvance-M",
                                      "CompanyName":  "http://vba-m.com/",
                                      "OriginalFilename":  "VisualBoyAdvance-M.exe",
                                      "CertThumbprint":  "34025714D92839B99F89F8E80BBDDBCC465C7459",
                                      "SignerSimpleName":  "Rafael Kitover",
                                      "FileDescriptions":  "Visual Boy Advance-M"
                                  },
        "PathAnchors":  [
                            "Emus",
                            "visualboyadvance-m",
                            "visualboyadvance-m-Win-x86_64"
                        ]
    },
    {
        "Name":  "Wave Browser",
        "UWPFamily":  null,
        "ARPName":  "Wave Browser*",
        "Publisher":  "Wavesor Software",
        "InstallerSignatures":  {
                                    "ProductName":  "WaveBrowser",
                                    "CompanyName":  "Wavesor Software",
                                    "OriginalFilename":  "Wave Browser.exe",
                                    "CertThumbprint":  "2EA4ADE8719DE01274C5A3BAF694B91E339BDA79",
                                    "SignerSimpleName":  "Wavesor Software (Eightpoint Technologies Ltd. SEZC)",
                                    "FileDescriptions":  "Wave Browser Wave Browser.exe"
                                },
        "PortableExeSignatures":  null,
        "PathAnchors":  [
                            "WaveBrowser",
                            "Wavesor Software"
                        ]
    },
    {
        "Name":  "Wesnoth",
        "UWPFamily":  "Wesnoth1.18",
        "ARPName":  null,
        "Publisher":  null,
        "InstallerSignatures":  {
                                    "ProductName":  "The Battle for Wesnoth",
                                    "CompanyName":  "The Battle for Wesnoth Project",
                                    "OriginalFilename":  "wesnoth-*-win64.exe",
                                    "CertThumbprint":  null,
                                    "SignerSimpleName":  null,
                                    "FileDescriptions":  [
                                                             "Wesnoth Game Client",
                                                             "Wesnoth Multiplayer Server",
                                                             "wesnoth-*-win64.exe"
                                                         ]
                                },
        "PortableExeSignatures":  {
                                      "ProductName":  "The Battle for Wesnoth",
                                      "CompanyName":  "The Battle for Wesnoth Project",
                                      "OriginalFilename":  "wesnoth.exe",
                                      "CertThumbprint":  null,
                                      "SignerSimpleName":  null,
                                      "FileDescriptions":  [
                                                               "Wesnoth Game Client",
                                                               "Wesnoth Multiplayer Server"
                                                           ]
                                  },
        "PathAnchors":  [
                            "battle-for-wesnoth-win-stable",
                            "https_wesnoth.fandom.com_0.indexeddb.leveldb",
                            "Wesnoth1.18"
                        ]
    },
    {
        "Name":  "XENIA-MASTER",
        "UWPFamily":  null,
        "ARPName":  null,
        "Publisher":  null,
        "InstallerSignatures":  null,
        "PortableExeSignatures":  {
                                      "ProductName":  null,
                                      "CompanyName":  null,
                                      "OriginalFilename":  "xenia_master",
                                      "CertThumbprint":  null,
                                      "SignerSimpleName":  null,
                                      "FileDescriptions":  "xenia_master"
                                  },
        "PathAnchors":  [
                            "xenia_master",
                            "xenia-master"
                        ]
    }
]
'@

function Get-Targets {
  try {
    $t = $TargetsJson | ConvertFrom-Json
    if ($t -isnot [System.Array]) { return @() + $t }
    return $t
  } catch {
    return @()
  }
}

function Snapshot-UwpFamilies {
  $set = @{}
  try {
    Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | ForEach-Object {
      if ($_.PackageFamilyName) { $set[$_.PackageFamilyName.ToLowerInvariant()] = $true }
    }
  } catch {}
  return $set
}

function Snapshot-ArpDisplayNames {
  $list = @()
  $paths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
  )
  foreach ($p in $paths) {
    try {
      Get-ItemProperty -Path $p -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.DisplayName) { $list += $_ }
      }
    } catch {}
  }
  return $list
}

function Test-UwpPresent($uwpSet, $t) {
  if (-not $t.UWPFamily) { return $false }
  $k = ($t.UWPFamily.ToString()).ToLowerInvariant()
  return $uwpSet.ContainsKey($k)
}

function Test-ArpPresent($arpList, $t) {
  if (-not $t.ARPName) { return $false }
  try {
    $hit = $arpList | Where-Object { $_.DisplayName -like $t.ARPName } | Select-Object -First 1
    return [bool]$hit
  } catch {
    return $false
  }
}

# 1) Agent presence/version
$agentOk = $false
if ((Test-Path $AgentScript) -and (Test-Path $VersionFile)) {
  try {
    $installedVer = (Get-Content -Raw -Path $VersionFile -Encoding UTF8).Trim()
    if ($installedVer -eq $ExpectedVersion) { $agentOk = $true }
  } catch {}
}

# 2) Fast forbidden app detection (UWP + ARP only, done via one-time snapshots)
$targets = Get-Targets
if (-not $targets -or $targets.Count -eq 0) {
  # If JSON is empty/broken, treat as noncompliant so you notice the issue.
  exit 1
}

$uwpSet = Snapshot-UwpFamilies
$arpList = Snapshot-ArpDisplayNames

$found = $false
foreach ($t in $targets) {
  if (Test-UwpPresent $uwpSet $t) { $found = $true; break }
  if (Test-ArpPresent $arpList $t) { $found = $true; break }
}

if (-not $agentOk) { exit 1 }
if ($found) { exit 1 }
exit 0
