using System;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;
using System.Text.Json;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.IO.Compression;
using System.Linq;
using System.Xml.Linq;
using Microsoft.Win32;

namespace BootstrapMate
{
    class Program
    {
        private static string LogDirectory = @"C:\ProgramData\ManagedBootstrap\logs";
        private static string CacheDirectory = @"C:\ProgramData\ManagedBootstrap\cache";
        
        // Version in YYYY.MM.DD.HHMM format - dynamically generated at build time
        private static readonly string Version = GenerateVersion();

        static string GetCacheDirectory()
        {
            try
            {
                Directory.CreateDirectory(CacheDirectory);
                return CacheDirectory;
            }
            catch (Exception ex)
            {
                Logger.Warning($"Could not create cache directory {CacheDirectory}: {ex.Message}");
                Logger.Debug("Falling back to temp directory for cache");
                
                // Fallback to temp directory if we can't create the ProgramData cache
                string fallbackDir = Path.Combine(Path.GetTempPath(), "BootstrapMate");
                Directory.CreateDirectory(fallbackDir);
                return fallbackDir;
            }
        }

        static string GenerateVersion()
        {
            // Generate version in YYYY.MM.DD.HHMM format based on current build time
            var now = DateTime.Now;
            return $"{now.Year:D4}.{now.Month:D2}.{now.Day:D2}.{now.Hour:D2}{now.Minute:D2}";
        }

        static bool IsRunningAsAdministrator()
        {
            try
            {
                var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        static bool TryRestartAsAdministrator(string[] args)
        {
            try
            {
                // Check if we're in silent mode - if so, don't try to restart with GUI
                bool silentMode = args.Any(arg => arg.Equals("--silent", StringComparison.OrdinalIgnoreCase));
                
                if (silentMode)
                {
                    Logger.Error("Running in silent mode but not elevated - cannot show UAC prompt");
                    return false;
                }
                
                var startInfo = new ProcessStartInfo
                {
                    FileName = Environment.ProcessPath ?? Path.Combine(AppContext.BaseDirectory, "installapplications.exe"),
                    Arguments = string.Join(" ", args),
                    UseShellExecute = true,
                    Verb = "runas",  // Request elevation
                    CreateNoWindow = true,  // Don't create console window
                    WindowStyle = ProcessWindowStyle.Hidden
                };

                Logger.Info("BootstrapMate requires administrator privileges. Requesting elevation...");
                Console.WriteLine("BootstrapMate requires administrator privileges. Requesting elevation...");
                
                using var process = Process.Start(startInfo);
                if (process != null)
                {
                    Logger.Info($"Elevated process started with PID: {process.Id}");
                    Console.WriteLine("Elevated process started. This instance will now exit.");
                    return true;
                }
                else
                {
                    Logger.Warning("Failed to start elevated process - user may have denied elevation");
                    Console.WriteLine("Failed to start elevated process. User may have denied elevation.");
                    return false;
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"Error attempting to restart as administrator: {ex.Message}");
                Console.WriteLine($"Error attempting to restart as administrator: {ex.Message}");
                return false;
            }
        }

        // Legacy WriteLog method for compatibility with StatusManager
        static void WriteLog(string message)
        {
            Logger.Debug(message);
        }

        static int Main(string[] args)
        {
            // Handle version request immediately without admin check or verbose logging
            if (args.Length > 0 && (args[0].Equals("--version", StringComparison.OrdinalIgnoreCase) || 
                                   args[0].Equals("-v", StringComparison.OrdinalIgnoreCase)))
            {
                Console.WriteLine(Version);
                return 0;
            }
            
            // Check for silent mode - suppress all console output
            bool silentMode = args.Any(arg => arg.Equals("--silent", StringComparison.OrdinalIgnoreCase));
            
            // Check for verbose mode
            bool verboseMode = args.Any(arg => arg.Equals("--verbose", StringComparison.OrdinalIgnoreCase) || 
                                              arg.Equals("-v", StringComparison.OrdinalIgnoreCase));
            
            Logger.Initialize(LogDirectory, Version, verboseMode, silentMode);
            Logger.Debug("Main() called with arguments: " + string.Join(" ", args));
            
            // Check if running as administrator
            if (!IsRunningAsAdministrator())
            {
                if (!silentMode)
                {
                    // Immediate clear message without logger initialization noise
                    Console.WriteLine();
                    Console.WriteLine("❌ ERROR: BootstrapMate must be run as Administrator");
                    Console.WriteLine();
                    Console.WriteLine("   BootstrapMate requires elevated privileges to:");
                    Console.WriteLine("   • Install packages to Program Files");
                    Console.WriteLine("   • Write to HKLM registry keys");
                    Console.WriteLine("   • Install Windows services");
                    Console.WriteLine("   • Manage system components");
                    Console.WriteLine();
                    Console.WriteLine("   Please run BootstrapMate as Administrator, or use:");
                    Console.WriteLine($"   sudo {Path.GetFileName(Environment.ProcessPath ?? "installapplications.exe")} {string.Join(" ", args)}");
                    Console.WriteLine();
                }
                
                Logger.Info("BootstrapMate is not running as Administrator");
                
                if (!silentMode)
                {
                    // Ask user if they want to restart as admin
                    Console.Write("   Would you like to restart as Administrator? (y/n): ");
                    var response = Console.ReadLine()?.Trim().ToLowerInvariant();
                    
                    if (response == "y" || response == "yes")
                    {
                        Console.WriteLine("   Attempting to restart with administrator privileges...");
                        
                        // Attempt to restart as administrator
                        if (TryRestartAsAdministrator(args))
                        {
                            Logger.Info("Successfully launched elevated process. Exiting current instance.");
                            return 0; // Success - elevated process will handle the work
                        }
                        else
                        {
                            Logger.Error("Failed to obtain administrator privileges. Cannot continue.");
                            Console.WriteLine("   ❌ Failed to restart with administrator privileges.");
                            Console.WriteLine("   Please manually run as Administrator or use sudo.");
                            return 1; // Error - elevation failed
                        }
                    }
                    else
                    {
                        Logger.Error("User declined to restart as administrator. Cannot continue.");
                        Console.WriteLine("   Operation cancelled. BootstrapMate requires administrator privileges.");
                        return 1; // Error - user declined elevation
                    }
                }
                else
                {
                    // In silent mode, just attempt to restart as administrator automatically
                    if (TryRestartAsAdministrator(args))
                    {
                        Logger.Info("Successfully launched elevated process in silent mode. Exiting current instance.");
                        return 0; // Success - elevated process will handle the work
                    }
                    else
                    {
                        Logger.Error("Failed to obtain administrator privileges in silent mode. Cannot continue.");
                        return 1; // Error - elevation failed
                    }
                }
            }
            
            Logger.Debug("Running with administrator privileges");
            if (!silentMode)
            {
                Console.WriteLine("[+] Running with administrator privileges");
                Console.WriteLine();
            }
            
            return MainAsync(args).GetAwaiter().GetResult();
        }
        
        static async Task<int> MainAsync(string[] args)
        {
            // Check for silent mode flag
            bool silentMode = args.Any(arg => arg.Equals("--silent", StringComparison.OrdinalIgnoreCase));
            
            if (!silentMode)
            {
                Logger.WriteHeader($"BootstrapMate for Windows v{Version}");
                Console.WriteLine("MDM-agnostic bootstrapping tool for Windows");
                Console.WriteLine("Windows Admins Open Source 2025");
            }
            
            // Clean up old statuses (older than 24 hours) on startup
            try
            {
                StatusManager.CleanupOldStatuses(TimeSpan.FromHours(24));
                Logger.Debug("Cleaned up old installation statuses");
            }
            catch (Exception ex)
            {
                Logger.Warning($"Failed to cleanup old statuses: {ex.Message}");
            }
            
            // Clean up old cached packages (older than 7 days) on startup
            try
            {
                CleanupOldCache(TimeSpan.FromDays(7));
                Logger.Debug("Cleaned up old cached packages");
            }
            catch (Exception ex)
            {
                Logger.Warning($"Failed to cleanup old cache files: {ex.Message}");
            }
            
            // Parse command line arguments
            bool forceDownload = false;
            string manifestUrl = "";
            
            if (args.Length == 0)
            {
                if (!silentMode)
                {
                    Console.WriteLine("Usage:");
                    Console.WriteLine("  installapplications.exe --url <manifest-url>");
                    Console.WriteLine("  installapplications.exe --help");
                    Console.WriteLine("  installapplications.exe --version");
                    Console.WriteLine("  installapplications.exe --status");
                    Console.WriteLine("  installapplications.exe --clear-cache");
                    Console.WriteLine("  installapplications.exe --reset-chocolatey");
                    Console.WriteLine("  installapplications.exe --url <manifest-url> --force");
                    Console.WriteLine("  installapplications.exe --url <manifest-url> --verbose");
                    Console.WriteLine("  installapplications.exe --url <manifest-url> --silent");
                    Console.WriteLine();
                    Console.WriteLine("Options:");
                    Console.WriteLine("  --url <url>     URL to the bootstrapmate.json manifest");
                    Console.WriteLine("  --force         Force re-download of all packages (ignore cache)");
                    Console.WriteLine("  --verbose       Show detailed logging output");
                    Console.WriteLine("  --silent        Run completely silently (no console output)");
                    Console.WriteLine("  --help          Show this help message");
                    Console.WriteLine("  --version       Show version information");
                    Console.WriteLine("  --status        Show current installation status");
                    Console.WriteLine("  --clear-status  Clear all installation status data");
                    Console.WriteLine("  --clear-cache   Aggressively clear all caches (BootstrapMate + Chocolatey)");
                    Console.WriteLine("  --reset-chocolatey  Complete Chocolatey reset (removes corrupted lib folder)");
                }
                return 0;
            }
            
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i].ToLower())
                {
                    case "--help":
                    case "-h":
                        Console.WriteLine("BootstrapMate Help");
                        Console.WriteLine("========================");
                        Console.WriteLine();
                        Console.WriteLine("This tool downloads and processes a bootstrapmate.json manifest file");
                        Console.WriteLine("to automatically install packages during Windows OOBE or setup scenarios.");
                        Console.WriteLine();
                        Console.WriteLine("Usage Examples:");
                        Console.WriteLine("  installapplications.exe --url https://example.com/bootstrap/bootstrapmate.json");
                        Console.WriteLine();
                        Console.WriteLine("Features:");
                        Console.WriteLine("  - Supports multiple package types: MSI, EXE, PowerShell, Chocolatey (.nupkg)");
                        Console.WriteLine("  - Handles setupassistant (OOBE) and userland installation phases");
                        Console.WriteLine("  - Admin privilege escalation for elevated packages");
                        Console.WriteLine("  - Architecture-specific conditional installation");
                        Console.WriteLine("  - Registry-based status tracking for detection scripts");
                        return 0;

                    case "--status":
                        return ShowStatus();

                    case "--clear-status":
                        return ClearStatus();

                    case "--clear-cache":
                        return ClearCache();

                    case "--reset-chocolatey":
                        return ResetChocolatey();

                    case "--force":
                        forceDownload = true;
                        break;

                    case "--verbose":
                        // Verbose mode is already handled in Main()
                        break;
                        
                    case "--silent":
                        // Silent mode is already handled in Main()
                        break;
                        
                    case "--url":
                        if (i + 1 < args.Length)
                        {
                            manifestUrl = args[i + 1];
                            i++; // Skip the next argument since we consumed it
                        }
                        else
                        {
                            Console.WriteLine("ERROR: --url requires a URL parameter");
                            return 1;
                        }
                        break;
                }
            }

            // Process manifest if URL was provided
            if (!string.IsNullOrEmpty(manifestUrl))
            {
                return await ProcessManifest(manifestUrl, forceDownload);
            }
            
            Console.WriteLine("ERROR: Invalid arguments. Use --help for usage information.");
            return 1;
        }
        
        static async Task<int> ProcessManifest(string manifestUrl, bool forceDownload = false)
        {
            try
            {
                // Clear cache if force download is requested
                if (forceDownload)
                {
                    Logger.Debug("Force download requested - aggressively clearing all caches");
                    Logger.Info("Force download requested - aggressively clearing all caches");
                    ClearAllCachesAggressive();
                }

                // Initialize status tracking
                StatusManager.Initialize(manifestUrl, Version);
                Logger.Debug($"Initialized status tracking with RunId: {StatusManager.GetCurrentRunId()}");

                Logger.Info($"Downloading manifest from: {manifestUrl}");
                
                using var httpClient = new HttpClient();
                httpClient.DefaultRequestHeaders.Add("User-Agent", $"BootstrapMate/{Version}");
                
                string jsonContent = await httpClient.GetStringAsync(manifestUrl);
                Logger.Debug("Manifest downloaded successfully");
                
                // Parse the JSON manifest
                using var doc = JsonDocument.Parse(jsonContent);
                var root = doc.RootElement;
                
                // Process setupassistant packages first
                if (root.TryGetProperty("setupassistant", out var setupAssistant))
                {
                    StatusManager.SetPhaseStatus(InstallationPhase.SetupAssistant, InstallationStage.Starting);
                    Logger.WriteSection("Processing Setup Assistant packages");
                    StatusManager.SetPhaseStatus(InstallationPhase.SetupAssistant, InstallationStage.Running);
                    
                    try
                    {
                        await ProcessPackages(setupAssistant, "setupassistant", forceDownload);
                        StatusManager.SetPhaseStatus(InstallationPhase.SetupAssistant, InstallationStage.Completed);
                        Logger.Debug("Setup Assistant packages completed successfully");
                    }
                    catch (Exception ex)
                    {
                        StatusManager.SetPhaseStatus(InstallationPhase.SetupAssistant, InstallationStage.Failed, ex.Message, 1);
                        throw; // Re-throw to maintain existing error handling
                    }
                }
                else
                {
                    // Mark as skipped if no setupassistant packages
                    StatusManager.SetPhaseStatus(InstallationPhase.SetupAssistant, InstallationStage.Skipped);
                    Logger.Debug("No Setup Assistant packages found - marked as skipped");
                }
                
                // Process userland packages
                if (root.TryGetProperty("userland", out var userland))
                {
                    StatusManager.SetPhaseStatus(InstallationPhase.Userland, InstallationStage.Starting);
                    Logger.Debug("Processing Userland packages...");
                    Logger.WriteSection("Processing Userland packages");
                    StatusManager.SetPhaseStatus(InstallationPhase.Userland, InstallationStage.Running);
                    
                    try
                    {
                        await ProcessPackages(userland, "userland", forceDownload);
                        StatusManager.SetPhaseStatus(InstallationPhase.Userland, InstallationStage.Completed);
                        Logger.Debug("Userland packages completed successfully");
                    }
                    catch (Exception ex)
                    {
                        StatusManager.SetPhaseStatus(InstallationPhase.Userland, InstallationStage.Failed, ex.Message, 1);
                        throw; // Re-throw to maintain existing error handling
                    }
                }
                else
                {
                    // Mark as skipped if no userland packages
                    StatusManager.SetPhaseStatus(InstallationPhase.Userland, InstallationStage.Skipped);
                    Logger.Debug("No Userland packages found - marked as skipped");
                }

                Logger.Debug("BootstrapMate completed successfully!");
                Logger.WriteCompletion("BootstrapMate completed successfully!");
                
                // Write successful completion to registry for Intune detection
                StatusManager.WriteSuccessfulCompletionRegistry();
                
                // Auto-cleanup all caches aggressively after successful completion
                try
                {
                    ClearAllCachesAggressive();
                    Logger.Info("Auto-cleanup: All caches cleared aggressively after successful completion");
                }
                catch (Exception cacheEx)
                {
                    Logger.Warning($"Auto-cleanup: Could not clear caches aggressively: {cacheEx.Message}");
                    // Don't fail the entire process if cache cleanup fails
                }
                
                return 0;
            }
            catch (Exception ex)
            {
                Logger.Error($"Error processing manifest: {ex.Message}");
                Logger.Debug($"Stack trace: {ex.StackTrace}");
                Logger.WriteError($"Error processing manifest: {ex.Message}");
                
                // Ensure status is marked as failed on any unhandled exception
                try
                {
                    // Try to determine which phase failed based on current state
                    var setupStatus = StatusManager.GetPhaseStatus(InstallationPhase.SetupAssistant);
                    var userlandStatus = StatusManager.GetPhaseStatus(InstallationPhase.Userland);
                    
                    if (setupStatus.Stage == InstallationStage.Running)
                    {
                        StatusManager.SetPhaseStatus(InstallationPhase.SetupAssistant, InstallationStage.Failed, ex.Message, 1);
                    }
                    else if (userlandStatus.Stage == InstallationStage.Running)
                    {
                        StatusManager.SetPhaseStatus(InstallationPhase.Userland, InstallationStage.Failed, ex.Message, 1);
                    }
                }
                catch
                {
                    // Don't let status update failures mask the original error
                }
                
                return 1;
            }
        }
        
        static async Task ProcessPackages(JsonElement packages, string phase, bool forceDownload = false)
        {
            Logger.Debug($"Processing packages for phase: {phase}");
            
            foreach (var package in packages.EnumerateArray())
            {
                string displayName = "Unknown Package"; // Default value for error handling
                try
                {
                    displayName = package.GetProperty("name").GetString() ?? "Unknown";
                    var url = package.GetProperty("url").GetString() ?? "";
                    var fileName = package.GetProperty("file").GetString() ?? "";
                    var type = package.GetProperty("type").GetString() ?? "";
                    
                    Logger.Debug($"Processing package: {displayName} (Type: {type}, File: {fileName})");
                    Logger.WriteProgress("Processing", displayName);
                    
                    // Check architecture condition if specified
                    if (package.TryGetProperty("condition", out var condition))
                    {
                        var conditionStr = condition.GetString() ?? "";
                        Logger.Debug($"Checking condition: {conditionStr}");
                        
                        // Get actual processor architecture - use RuntimeInformation for accurate detection
                        string actualArchitecture = System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture.ToString().ToUpperInvariant();
                        Logger.Debug($"Detected runtime architecture: {actualArchitecture}");
                        
                        // Skip x64 packages on non-x64 systems 
                        // Note: RuntimeInformation reports "X64" for AMD64/Intel 64-bit, "ARM64" for ARM64
                        if (conditionStr.Contains("architecture_x64") && actualArchitecture != "X64")
                        {
                            Logger.Debug($"Skipping {displayName} - x64 condition not met on {actualArchitecture} architecture");
                            Logger.WriteSkipped($"Skipping - x64 condition not met on {actualArchitecture}");
                            continue;
                        }
                        
                        // Skip ARM64 packages on non-ARM64 systems
                        if (conditionStr.Contains("architecture_arm64") && actualArchitecture != "ARM64")
                        {
                            Logger.Debug($"Skipping {displayName} - ARM64 condition not met on {actualArchitecture} architecture");
                            Logger.WriteSkipped($"Skipping - ARM64 condition not met on {actualArchitecture}");
                            continue;
                        }
                    }
                    
                    await DownloadAndInstallPackage(displayName, url, fileName, type, package, forceDownload);
                    Logger.Debug($"Successfully completed package: {displayName}");
                    Logger.WriteSuccess($"{displayName} installed successfully");
                }
                catch (Exception ex)
                {
                    Logger.Error($"Failed to install package {displayName}: {ex.Message}");
                    Logger.WriteError($"Failed to install package {displayName}: {ex.Message}");
                    // Continue with next package instead of stopping entire process
                    // Note: We don't re-throw because we want to continue with other packages
                }
            }
        }
        
        static async Task DownloadAndInstallPackage(string displayName, string url, string fileName, string type, JsonElement packageInfo, bool forceDownload = false)
        {
            try
            {
                // Create cache download directory
                string cacheDir = GetCacheDirectory();
                
                string localPath = Path.Combine(cacheDir, fileName);
                
                // Check if file exists and force download if requested
                bool needsDownload = forceDownload || !File.Exists(localPath);
                
                if (needsDownload)
                {
                    Logger.Debug($"Downloading {displayName} from: {url}");
                    Logger.WriteSubProgress("Downloading from", url);
                    
                    using var httpClient = new HttpClient();
                    using var response = await httpClient.GetAsync(url);
                    if (!response.IsSuccessStatusCode)
                    {
                        throw new Exception($"Download failed: {response.StatusCode}");
                    }
                    
                    // Ensure the file stream is completely closed before proceeding
                    {
                        await using var fileStream = File.Create(localPath);
                        await response.Content.CopyToAsync(fileStream);
                        await fileStream.FlushAsync();
                    } // fileStream is disposed here
                    
                    // Add a small delay to ensure file handle is released
                    await Task.Delay(100);
                    
                    var fileInfo = new FileInfo(localPath);
                    Logger.Debug($"Downloaded {displayName} to: {localPath} (Size: {fileInfo.Length / 1024 / 1024:F2} MB)");
                    Logger.WriteSubProgress("Downloaded", $"{fileInfo.Length / 1024 / 1024:F1} MB");
                }
                else
                {
                    Logger.Debug($"Using cached file for {displayName}: {localPath}");
                    Logger.WriteSubProgress("Using cached file", Path.GetFileName(localPath));
                }
                
                // Install based on type
                Logger.Debug($"Installing {displayName} using {type} installer...");
                await InstallPackage(localPath, type, packageInfo);
                
                Logger.Debug($"Successfully installed: {displayName}");
            }
            catch (Exception ex)
            {
                Logger.Error($"Failed to install {displayName}: {ex.Message}");
                // Re-throw the exception so the caller knows the installation failed
                throw;
            }
        }
        
        static async Task InstallPackage(string filePath, string type, JsonElement packageInfo)
        {
            Logger.Debug($"Installing package: {filePath} (Type: {type})");
            
            switch (type.ToLower())
            {
                case "powershell":
                case "ps1":
                    await RunPowerShellScript(filePath, packageInfo);
                    break;
                    
                case "msi":
                    await RunMsiInstaller(filePath, packageInfo);
                    break;
                    
                case "exe":
                    await RunExecutable(filePath, packageInfo);
                    break;
                    
                case "nupkg":
                    await RunChocolateyInstall(filePath, packageInfo);
                    break;
                    
                default:
                    Logger.Warning($"Unknown package type: {type}");
                    Logger.WriteWarning($"Unknown package type: {type}");
                    break;
            }
        }
        
        static async Task RunPowerShellScript(string scriptPath, JsonElement packageInfo)
        {
            var args = GetArguments(packageInfo);
            string arguments = $"-ExecutionPolicy Bypass -File \"{scriptPath}\" {string.Join(" ", args)}";
            
            // Since BootstrapMate is already running as admin, all PowerShell scripts should inherit admin privileges
            // This ensures chocolatey and other system installers work properly
            bool needsElevation = true; // Always run elevated since we're in an admin context
            
            WriteLog($"Running PowerShell script: {scriptPath}");
            WriteLog($"Arguments: {arguments}");
            WriteLog($"Elevated: {needsElevation}");
            
            var startInfo = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = arguments,
                UseShellExecute = false, // Use CreateProcess to inherit admin privileges
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            
            Console.WriteLine($"     🔧 Running PowerShell: {arguments}");
            
            using var process = Process.Start(startInfo);
            if (process != null)
            {
                await process.WaitForExitAsync();
                
                // Capture output for debugging
                if (startInfo.RedirectStandardOutput)
                {
                    string output = await process.StandardOutput.ReadToEndAsync();
                    if (!string.IsNullOrWhiteSpace(output))
                    {
                        WriteLog($"PowerShell output: {output}");
                    }
                }
                
                if (startInfo.RedirectStandardError)
                {
                    string error = await process.StandardError.ReadToEndAsync();
                    if (!string.IsNullOrWhiteSpace(error))
                    {
                        WriteLog($"PowerShell error: {error}");
                    }
                }
                
                WriteLog($"PowerShell script completed with exit code: {process.ExitCode}");
                
                if (process.ExitCode != 0)
                {
                    throw new Exception($"PowerShell script failed with exit code: {process.ExitCode}");
                }
            }
        }
        
        static bool RequiresElevation(string scriptPath, JsonElement packageInfo)
        {
            // Get the script filename to check for known patterns
            string scriptFileName = Path.GetFileName(scriptPath).ToLowerInvariant();
            
            // Get package name/ID for specific package checks
            string packageName = "";
            if (packageInfo.TryGetProperty("name", out var nameProp))
            {
                packageName = nameProp.GetString()?.ToLowerInvariant() ?? "";
            }
            
            string packageId = "";
            if (packageInfo.TryGetProperty("packageid", out var idProp))
            {
                packageId = idProp.GetString()?.ToLowerInvariant() ?? "";
            }
            
            // Scripts that definitely need elevation
            if (scriptFileName.Contains("chocolatey") || 
                scriptFileName.Contains("install-chocolatey") ||
                packageName.Contains("chocolatey") ||
                packageId.Contains("chocolatey"))
            {
                return true;
            }
            
            // Any script that installs system-wide components needs elevation
            if (scriptFileName.Contains("install") && 
                (scriptFileName.Contains("system") || scriptFileName.Contains("global")))
            {
                return true;
            }
            
            // Package manager installers typically need elevation
            if (packageName.Contains("package manager") || 
                packageId.Contains("package-manager"))
            {
                return true;
            }
            
            return false;
        }
        
        static async Task RunMsiInstaller(string msiPath, JsonElement packageInfo)
        {
            var args = GetArguments(packageInfo);
            string arguments = $"/i \"{msiPath}\" /quiet /norestart {string.Join(" ", args)}";
            
            var startInfo = new ProcessStartInfo
            {
                FileName = "msiexec.exe",
                Arguments = arguments,
                UseShellExecute = false, // Inherit admin privileges from parent process
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            
            WriteLog($"Running MSI installer: {arguments}");
            Console.WriteLine($"     📦 Running MSI installer: {arguments}");
            
            using var process = Process.Start(startInfo);
            if (process != null)
            {
                await process.WaitForExitAsync();
                WriteLog($"MSI installer completed with exit code: {process.ExitCode}");
                if (process.ExitCode != 0)
                {
                    throw new Exception($"MSI installer failed with exit code: {process.ExitCode}");
                }
            }
        }
        
        static async Task RunExecutable(string exePath, JsonElement packageInfo)
        {
            var args = GetArguments(packageInfo);
            string arguments = string.Join(" ", args);
            
            WriteLog($"Running executable: {exePath} {arguments}");
            Console.WriteLine($"     🔧 Running executable: {exePath} {arguments}");
            
            var startInfo = new ProcessStartInfo
            {
                FileName = exePath,
                Arguments = arguments,
                UseShellExecute = false,  // Inherit admin privileges from parent process
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            
            using var process = Process.Start(startInfo);
            if (process != null)
            {
                await process.WaitForExitAsync();
                
                // Capture output for debugging
                if (startInfo.RedirectStandardOutput)
                {
                    string output = await process.StandardOutput.ReadToEndAsync();
                    if (!string.IsNullOrWhiteSpace(output))
                    {
                        WriteLog($"Executable output: {output}");
                    }
                }
                
                if (startInfo.RedirectStandardError)
                {
                    string error = await process.StandardError.ReadToEndAsync();
                    if (!string.IsNullOrWhiteSpace(error))
                    {
                        WriteLog($"Executable error: {error}");
                    }
                }
                
                WriteLog($"Executable completed with exit code: {process.ExitCode}");
                
                if (process.ExitCode != 0)
                {
                    throw new Exception($"Executable failed with exit code: {process.ExitCode}");
                }
            }
        }
        
        static string FindChocolateyExecutable()
        {
            // Try common Chocolatey installation paths in order of preference
            string[] candidatePaths = {
                // Check environment variable first
                Environment.GetEnvironmentVariable("ChocolateyInstall") + @"\bin\choco.exe",
                // Standard installation paths
                @"C:\ProgramData\chocolatey\bin\choco.exe",
                @"C:\Chocolatey\bin\choco.exe",
                @"C:\tools\chocolatey\bin\choco.exe"
            };
            
            foreach (string candidatePath in candidatePaths)
            {
                if (!string.IsNullOrEmpty(candidatePath) && File.Exists(candidatePath))
                {
                    Logger.Debug($"Found Chocolatey executable at: {candidatePath}");
                    return candidatePath;
                }
            }
            
            // Fallback to PATH resolution
            try
            {
                var startInfo = new ProcessStartInfo
                {
                    FileName = "where.exe",
                    Arguments = "choco.exe",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };
                
                using var process = Process.Start(startInfo);
                if (process != null)
                {
                    process.WaitForExit(5000); // 5 second timeout
                    if (process.ExitCode == 0)
                    {
                        string output = process.StandardOutput.ReadToEnd().Trim();
                        if (!string.IsNullOrEmpty(output))
                        {
                            var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                            if (lines.Length > 0 && File.Exists(lines[0]))
                            {
                                Logger.Debug($"Found Chocolatey executable via WHERE command: {lines[0]}");
                                return lines[0];
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Debug($"WHERE command failed: {ex.Message}");
            }
            
            // Instead of falling back to "choco.exe", return null to indicate no executable found
            Logger.Warning("Could not locate Chocolatey executable anywhere on the system");
            return null;
        }
        
        static bool IsBrokenChocolateyInstallation()
        {
            // Check if we have a broken Chocolatey installation:
            // - Folder exists at C:\ProgramData\chocolatey
            // - But no working choco.exe executable
            
            string chocolateyRoot = @"C:\ProgramData\chocolatey";
            string chocoExe = Path.Combine(chocolateyRoot, "bin", "choco.exe");
            
            if (Directory.Exists(chocolateyRoot))
            {
                // Folder exists, check if executable works
                if (!File.Exists(chocoExe))
                {
                    Logger.Warning($"Broken Chocolatey detected: folder exists at {chocolateyRoot} but no choco.exe found");
                    return true;
                }
                
                // Executable exists, test if it actually works
                try
                {
                    var testProcess = new ProcessStartInfo
                    {
                        FileName = chocoExe,
                        Arguments = "--version",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    };
                    
                    using var process = Process.Start(testProcess);
                    if (process != null)
                    {
                        process.WaitForExit(5000); // 5 second timeout
                        if (process.ExitCode != 0)
                        {
                            Logger.Warning($"Broken Chocolatey detected: choco.exe exists but fails to run (exit code: {process.ExitCode})");
                            return true;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logger.Warning($"Broken Chocolatey detected: choco.exe exists but cannot be executed: {ex.Message}");
                    return true;
                }
            }
            
            return false;
        }

        static void CleanupChocolateyLib()
        {
            try
            {
                string chocolateyLibPath = @"C:\ProgramData\chocolatey\lib";
                
                if (!Directory.Exists(chocolateyLibPath))
                {
                    Logger.Debug("Chocolatey lib directory does not exist - no cleanup needed");
                    return;
                }
                
                Logger.Debug("Cleaning up potentially corrupted Chocolatey lib directory...");
                Logger.WriteSubProgress("Cleaning Chocolatey cache", "Removing corrupted packages");
                
                // Get all subdirectories in the lib folder
                var libDirectories = Directory.GetDirectories(chocolateyLibPath);
                int cleanedCount = 0;
                
                foreach (string libDir in libDirectories)
                {
                    try
                    {
                        string packageName = Path.GetFileName(libDir);
                        
                        // Look for .nupkg files in this package directory
                        var nupkgFiles = Directory.GetFiles(libDir, "*.nupkg", SearchOption.TopDirectoryOnly);
                        
                        foreach (string nupkgFile in nupkgFiles)
                        {
                            try
                            {
                                // Test if the .nupkg file is a valid ZIP archive
                                using var archive = ZipFile.OpenRead(nupkgFile);
                                var entries = archive.Entries; // This will throw if corrupted
                                Logger.Debug($"Package {packageName} - nupkg file is valid");
                            }
                            catch (Exception ex)
                            {
                                Logger.Warning($"Found corrupted nupkg file: {nupkgFile} - {ex.Message}");
                                Logger.Debug($"Removing corrupted package directory: {libDir}");
                                
                                // Remove the entire package directory if nupkg is corrupted
                                Directory.Delete(libDir, true);
                                cleanedCount++;
                                
                                Logger.Debug($"Cleaned corrupted package: {packageName}");
                                break; // Move to next package directory
                            }
                        }
                        
                        // Also check for directories without .nupkg files (incomplete installations)
                        if (nupkgFiles.Length == 0)
                        {
                            // Check if this looks like an incomplete installation
                            var filesInDir = Directory.GetFiles(libDir, "*", SearchOption.AllDirectories);
                            var directoriesInDir = Directory.GetDirectories(libDir, "*", SearchOption.AllDirectories);
                            
                            // If there are no nupkg files but there are other files/dirs, it might be incomplete
                            if (filesInDir.Length > 0 || directoriesInDir.Length > 0)
                            {
                                Logger.Warning($"Found package directory without nupkg file: {packageName}");
                                Logger.Debug($"Removing incomplete package directory: {libDir}");
                                
                                Directory.Delete(libDir, true);
                                cleanedCount++;
                                
                                Logger.Debug($"Cleaned incomplete package: {packageName}");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Warning($"Could not process package directory {libDir}: {ex.Message}");
                        // Continue with other packages
                    }
                }
                
                if (cleanedCount > 0)
                {
                    Logger.Info($"Cleaned up {cleanedCount} corrupted/incomplete Chocolatey packages");
                    Logger.WriteSubProgress("Chocolatey cleanup complete", $"Removed {cleanedCount} corrupted packages");
                }
                else
                {
                    Logger.Debug("No corrupted Chocolatey packages found");
                }
                
                // Also clean up any orphaned temp files in the chocolatey root
                try
                {
                    string chocolateyRoot = @"C:\ProgramData\chocolatey";
                    var tempFiles = Directory.GetFiles(chocolateyRoot, "*.tmp", SearchOption.TopDirectoryOnly);
                    var lockFiles = Directory.GetFiles(chocolateyRoot, "*.lock", SearchOption.AllDirectories);
                    
                    foreach (string tempFile in tempFiles.Concat(lockFiles))
                    {
                        try
                        {
                            File.Delete(tempFile);
                            Logger.Debug($"Removed temp/lock file: {Path.GetFileName(tempFile)}");
                        }
                        catch
                        {
                            // Ignore errors deleting temp files
                        }
                    }
                }
                catch
                {
                    // Ignore errors in temp file cleanup
                }
            }
            catch (Exception ex)
            {
                Logger.Warning($"Chocolatey lib cleanup failed: {ex.Message}");
                // Don't fail the entire process if cleanup fails
            }
        }
        
        static async Task<bool> PerformAggressiveChocolateyCleanup()
        {
            try
            {
                string chocolateyRoot = @"C:\ProgramData\chocolatey";
                Logger.Info($"Starting aggressive cleanup of broken Chocolatey installation at: {chocolateyRoot}");
                
                // Step 1: Kill all Chocolatey processes
                Logger.Debug("Step 1: Terminating all Chocolatey processes...");
                var chocoProcesses = Process.GetProcessesByName("choco");
                foreach (var proc in chocoProcesses)
                {
                    try
                    {
                        Logger.Debug($"Terminating chocolatey process (PID: {proc.Id})");
                        proc.Kill();
                        proc.WaitForExit(5000);
                        proc.Dispose();
                    }
                    catch (Exception ex)
                    {
                        Logger.Debug($"Could not kill process {proc.Id}: {ex.Message}");
                    }
                }
                
                // Step 2: Clean environment variables first (critical for forcing reinstall)
                Logger.Debug("Step 2: Cleaning Chocolatey environment variables...");
                try
                {
                    Environment.SetEnvironmentVariable("ChocolateyInstall", null, EnvironmentVariableTarget.Machine);
                    Environment.SetEnvironmentVariable("ChocolateyInstall", null, EnvironmentVariableTarget.User);
                    Environment.SetEnvironmentVariable("ChocolateyInstall", null, EnvironmentVariableTarget.Process);
                    Logger.Debug("Environment variables cleaned");
                }
                catch (Exception ex)
                {
                    Logger.Warning($"Could not clean environment variables: {ex.Message}");
                }
                
                // Step 3: CRITICAL - Complete nuclear removal of Chocolatey directory
                // This MUST succeed or Chocolatey installer will think it's already installed
                if (Directory.Exists(chocolateyRoot))
                {
                    Logger.Warning($"CRITICAL: Performing nuclear removal of broken Chocolatey at: {chocolateyRoot}");
                    Logger.Info("This is necessary because Chocolatey installer detects existing folder and skips installation");
                    
                    bool removalSuccess = false;
                    
                    // Method 1: Use PowerShell with maximum force
                    Logger.Debug("Method 1: Using PowerShell Remove-Item with maximum force...");
                    try
                    {
                        string psCommand = @"
                            $ErrorActionPreference = 'Stop'
                            $path = 'C:\ProgramData\chocolatey'
                            if (Test-Path $path) {
                                Write-Host 'Attempting PowerShell removal...'
                                Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                                Start-Sleep -Seconds 2
                                if (Test-Path $path) {
                                    Write-Host 'Standard removal failed, trying takeown + icacls...'
                                    takeown /f $path /r /d y | Out-Null
                                    icacls $path /grant administrators:F /t | Out-Null
                                    Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                                }
                            }
                        ";
                        
                        var psProcess = new ProcessStartInfo
                        {
                            FileName = "powershell.exe",
                            Arguments = $"-ExecutionPolicy Bypass -Command \"{psCommand}\"",
                            UseShellExecute = true, // Run elevated
                            CreateNoWindow = true,
                            WindowStyle = ProcessWindowStyle.Hidden
                        };
                        
                        using var process = Process.Start(psProcess);
                        if (process != null)
                        {
                            await process.WaitForExitAsync();
                            Logger.Debug($"PowerShell cleanup completed with exit code: {process.ExitCode}");
                        }
                        
                        await Task.Delay(2000); // Wait for file handles to release
                        
                        if (!Directory.Exists(chocolateyRoot))
                        {
                            Logger.Info("✅ PowerShell nuclear removal successful");
                            removalSuccess = true;
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Warning($"PowerShell nuclear removal failed: {ex.Message}");
                    }
                    
                    // Method 2: C# Directory.Delete with multiple retries
                    if (!removalSuccess && Directory.Exists(chocolateyRoot))
                    {
                        Logger.Debug("Method 2: Using C# Directory.Delete with retries...");
                        for (int attempt = 1; attempt <= 5; attempt++)
                        {
                            try
                            {
                                Directory.Delete(chocolateyRoot, true);
                                Logger.Info($"✅ C# Directory.Delete succeeded on attempt {attempt}");
                                removalSuccess = true;
                                break;
                            }
                            catch (Exception ex)
                            {
                                Logger.Warning($"C# Directory.Delete attempt {attempt}/5 failed: {ex.Message}");
                                if (attempt < 5)
                                {
                                    await Task.Delay(3000); // Wait 3 seconds before retry
                                }
                            }
                        }
                    }
                    
                    // Method 3: Last resort - try to remove just enough to make installer think it's not installed
                    if (!removalSuccess && Directory.Exists(chocolateyRoot))
                    {
                        Logger.Warning("Method 3: Last resort - removing critical files to trick installer...");
                        try
                        {
                            // Remove the bin folder specifically (this is what Chocolatey installer checks)
                            string binPath = Path.Combine(chocolateyRoot, "bin");
                            if (Directory.Exists(binPath))
                            {
                                Directory.Delete(binPath, true);
                                Logger.Info("Removed bin folder");
                            }
                            
                            // Remove the lib folder (packages)
                            string libPath = Path.Combine(chocolateyRoot, "lib");
                            if (Directory.Exists(libPath))
                            {
                                Directory.Delete(libPath, true);
                                Logger.Info("Removed lib folder");
                            }
                            
                            // Remove install marker files
                            string[] markerFiles = {
                                Path.Combine(chocolateyRoot, ".chocolatey"),
                                Path.Combine(chocolateyRoot, "choco.exe.manifest"),
                                Path.Combine(chocolateyRoot, "redirects")
                            };
                            
                            foreach (string marker in markerFiles)
                            {
                                if (File.Exists(marker))
                                {
                                    File.Delete(marker);
                                    Logger.Debug($"Removed marker: {marker}");
                                }
                            }
                            
                            removalSuccess = true; // Good enough for installer to proceed
                            Logger.Info("✅ Critical file removal successful - installer should proceed");
                        }
                        catch (Exception ex)
                        {
                            Logger.Error($"Last resort removal also failed: {ex.Message}");
                        }
                    }
                    
                    if (!removalSuccess)
                    {
                        Logger.Error("❌ CRITICAL FAILURE: Could not remove broken Chocolatey installation");
                        Logger.Error("This will prevent proper Chocolatey reinstallation");
                        return false;
                    }
                }
                
                // Step 4: Clean up PATH environment variable
                Logger.Debug("Step 4: Cleaning Chocolatey from PATH...");
                try
                {
                    string currentPath = Environment.GetEnvironmentVariable("PATH", EnvironmentVariableTarget.Machine) ?? "";
                    string cleanedPath = string.Join(";", 
                        currentPath.Split(';')
                                   .Where(p => !p.Contains("chocolatey", StringComparison.OrdinalIgnoreCase))
                                   .Where(p => !string.IsNullOrWhiteSpace(p)));
                    
                    if (cleanedPath != currentPath)
                    {
                        Environment.SetEnvironmentVariable("PATH", cleanedPath, EnvironmentVariableTarget.Machine);
                        Logger.Debug("Cleaned Chocolatey paths from system PATH");
                    }
                }
                catch (Exception ex)
                {
                    Logger.Warning($"Could not clean PATH variable: {ex.Message}");
                }
                
                // Step 5: Final verification and force environment refresh
                Logger.Debug("Step 5: Final verification and environment refresh...");
                try
                {
                    // Force refresh environment variables in current process
                    Environment.SetEnvironmentVariable("ChocolateyInstall", null);
                    
                    // Update PATH in current process
                    string machinePath = Environment.GetEnvironmentVariable("PATH", EnvironmentVariableTarget.Machine) ?? "";
                    string userPath = Environment.GetEnvironmentVariable("PATH", EnvironmentVariableTarget.User) ?? "";
                    Environment.SetEnvironmentVariable("PATH", $"{machinePath};{userPath}");
                    
                    Logger.Debug("Environment variables refreshed in current process");
                }
                catch (Exception ex)
                {
                    Logger.Warning($"Could not refresh environment variables: {ex.Message}");
                }
                
                // Final check
                bool isCleanedUp = !Directory.Exists(chocolateyRoot) || 
                                  !Directory.Exists(Path.Combine(chocolateyRoot, "bin")) ||
                                  !File.Exists(Path.Combine(chocolateyRoot, "bin", "choco.exe"));
                
                if (isCleanedUp)
                {
                    Logger.Info("✅ Nuclear Chocolatey cleanup completed successfully");
                    Logger.Info("Chocolatey installer should now detect a clean system and perform full installation");
                    return true;
                }
                else
                {
                    Logger.Error("❌ Nuclear Chocolatey cleanup failed - installation artifacts still present");
                    return false;
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"Exception during nuclear Chocolatey cleanup: {ex.Message}");
                return false;
            }
        }
        
        static async Task EnsureChocolateyInstalled()
        {
            Logger.Debug("Checking if Chocolatey is installed...");
            
            // FIRST: Check for broken Chocolatey installation and clean it up
            if (IsBrokenChocolateyInstallation())
            {
                Logger.Warning("Detected broken Chocolatey installation - performing aggressive cleanup...");
                Logger.WriteSubProgress("Cleaning broken Chocolatey installation", "Removing corrupted files");
                
                // This is critical - we MUST clean up broken installations or they prevent proper reinstall
                bool cleanupSuccessful = await PerformAggressiveChocolateyCleanup();
                if (!cleanupSuccessful)
                {
                    throw new Exception("Failed to clean up broken Chocolatey installation. Cannot proceed with package installations.");
                }
            }
            
            // Clean up any corrupted Chocolatey lib directory
            CleanupChocolateyLib();
            
            // Find chocolatey executable path using improved method
            string chocoPath = FindChocolateyExecutable();
            
            // If we have a valid path, test if Chocolatey actually works
            if (chocoPath != null)
            {
                var chocoCheck = new ProcessStartInfo
                {
                    FileName = chocoPath,
                    Arguments = "--version",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };
                
                try
                {
                    using var checkProcess = Process.Start(chocoCheck);
                    if (checkProcess != null)
                    {
                        await checkProcess.WaitForExitAsync();
                        if (checkProcess.ExitCode == 0)
                        {
                            Logger.Debug("Chocolatey is already installed and working");
                            Logger.WriteSubProgress("Chocolatey is already installed and working");
                            return; // Chocolatey is available and functional
                        }
                        else
                        {
                            Logger.Warning($"Chocolatey executable found but not working (exit code: {checkProcess.ExitCode})");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logger.Debug($"Chocolatey check failed: {ex.Message}");
                    // choco.exe found but not functional, need to reinstall
                }
            }
            
            Logger.Debug("Chocolatey not found or not working. Installing Chocolatey...");
            Logger.WriteSubProgress("Installing Chocolatey package manager");
            
            // Install Chocolatey using the official installation method
            // CRITICAL: Use -Force parameter to ensure clean installation over broken remains
            string installScript = @"
                Set-ExecutionPolicy Bypass -Scope Process -Force
                [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
                
                # Force clean installation even if remnants exist
                $env:CHOCOLATEY_FORCE = 'true'
                
                # Download and execute installer
                iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
                
                # Verify installation worked
                if (Test-Path 'C:\ProgramData\chocolatey\bin\choco.exe') {
                    Write-Host 'Chocolatey installation verified'
                    exit 0
                } else {
                    Write-Error 'Chocolatey installation failed - executable not found'
                    exit 1
                }
            ";
            
            var chocolateyInstall = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-ExecutionPolicy Bypass -Command \"{installScript.Replace("\"", "\\\"")}\"",
                UseShellExecute = true, // Critical for ESP privilege inheritance
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };
            
            using var installProcess = Process.Start(chocolateyInstall);
            if (installProcess != null)
            {
                await installProcess.WaitForExitAsync();
                
                Logger.Debug($"Chocolatey installation completed with exit code: {installProcess.ExitCode}");
                
                if (installProcess.ExitCode != 0)
                {
                    throw new Exception($"Chocolatey installation failed with exit code: {installProcess.ExitCode}");
                }
                
                Logger.Debug("Chocolatey installed successfully");
                Logger.WriteSubProgress("Chocolatey installed successfully");
                
                // Refresh environment variables to pick up chocolatey PATH
                Logger.Debug("Refreshing environment variables...");
                RefreshEnvironmentPath();
                
                // Wait a moment for the installation to settle
                await Task.Delay(2000);
                
                // Verify installation by re-checking with updated paths
                string newChocoPath = FindChocolateyExecutable();
                if (newChocoPath != null && await VerifyChocolateyInstallation(newChocoPath))
                {
                    Logger.Debug($"Chocolatey installation verified at: {newChocoPath}");
                }
                else
                {
                    Logger.Warning("Chocolatey installation could not be verified, but proceeding anyway");
                }
            }
        }
        
        static async Task<bool> VerifyChocolateyInstallation(string chocoPath)
        {
            try
            {
                var verifyStartInfo = new ProcessStartInfo
                {
                    FileName = chocoPath,
                    Arguments = "--version",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };
                
                using var process = Process.Start(verifyStartInfo);
                if (process != null)
                {
                    await process.WaitForExitAsync();
                    return process.ExitCode == 0;
                }
            }
            catch
            {
                // Verification failed
            }
            
            return false;
        }
        
        static void RefreshEnvironmentPath()
        {
            try
            {
                // Get the current PATH from the registry (machine and user)
                string machinePath = Environment.GetEnvironmentVariable("PATH", EnvironmentVariableTarget.Machine) ?? "";
                string userPath = Environment.GetEnvironmentVariable("PATH", EnvironmentVariableTarget.User) ?? "";
                
                // Check for Chocolatey installation paths and add them if missing
                List<string> additionalPaths = new List<string>();
                
                // Common Chocolatey installation paths
                string[] chocolateyPaths = {
                    @"C:\ProgramData\chocolatey\bin",
                    @"C:\Chocolatey\bin",
                    Environment.GetEnvironmentVariable("ChocolateyInstall") + @"\bin"
                };
                
                foreach (string chocoPath in chocolateyPaths)
                {
                    if (!string.IsNullOrEmpty(chocoPath) && Directory.Exists(chocoPath))
                    {
                        string chocoExePath = Path.Combine(chocoPath, "choco.exe");
                        if (File.Exists(chocoExePath))
                        {
                            // Check if this path is already in the combined PATH
                            string combinedCurrentPath = machinePath + ";" + userPath;
                            if (!combinedCurrentPath.ToLowerInvariant().Contains(chocoPath.ToLowerInvariant()))
                            {
                                additionalPaths.Add(chocoPath);
                                Logger.Debug($"Adding Chocolatey path to PATH: {chocoPath}");
                            }
                            break; // Found a working chocolatey installation
                        }
                    }
                }
                
                // Combine all paths
                string combinedPath = string.Join(";", new[] { machinePath, userPath }.Concat(additionalPaths).Where(p => !string.IsNullOrEmpty(p)));
                
                // Update the current process PATH
                Environment.SetEnvironmentVariable("PATH", combinedPath, EnvironmentVariableTarget.Process);
                
                Logger.Debug($"Environment PATH refreshed with {additionalPaths.Count} additional Chocolatey paths");
            }
            catch (Exception ex)
            {
                Logger.Warning($"Could not refresh PATH environment variable: {ex.Message}");
                // Continue anyway - chocolatey might still work
            }
        }
        
        static async Task<bool> IsChocolateyPackageInstalled(string packageId)
        {
            try
            {
                // Find chocolatey executable path using improved method
                string chocoPath = FindChocolateyExecutable();
                
                if (chocoPath == null)
                {
                    Logger.Warning($"Could not locate Chocolatey executable to check package '{packageId}'");
                    return false; // If no chocolatey, package definitely not installed
                }
                
                // Use 'choco list' to check if package is installed (modern Chocolatey syntax)
                var startInfo = new ProcessStartInfo
                {
                    FileName = chocoPath,
                    Arguments = $"list \"{packageId}\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };
                
                Logger.Debug($"Checking if package '{packageId}' is installed: {chocoPath} {startInfo.Arguments}");
                
                using var process = Process.Start(startInfo);
                if (process != null)
                {
                    await process.WaitForExitAsync();
                    
                    if (process.ExitCode == 0)
                    {
                        string output = await process.StandardOutput.ReadToEndAsync();
                        
                        // Parse the output - if the package is installed, it will be listed
                        // Format is typically: "packagename version"
                        // If not installed, output will be empty or show "0 packages installed"
                        var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                        foreach (var line in lines)
                        {
                            var trimmedLine = line.Trim();
                            if (trimmedLine.StartsWith(packageId, StringComparison.OrdinalIgnoreCase) && 
                                !trimmedLine.Contains("packages installed") &&
                                !trimmedLine.Contains("Chocolatey"))
                            {
                                Logger.Debug($"Package '{packageId}' is installed: {trimmedLine}");
                                return true;
                            }
                        }
                        
                        Logger.Debug($"Package '{packageId}' check output: {output.Trim()}");
                    }
                    else
                    {
                        string error = await process.StandardError.ReadToEndAsync();
                        string output = await process.StandardOutput.ReadToEndAsync();
                        Logger.Warning($"chocolatey list command failed with exit code {process.ExitCode}");
                        Logger.Debug($"Chocolatey list stderr: {error}");
                        Logger.Debug($"Chocolatey list stdout: {output}");
                    }
                }
                
                Logger.Debug($"Package '{packageId}' is not installed");
                return false;
            }
            catch (Exception ex)
            {
                Logger.Warning($"Could not check if package '{packageId}' is installed: {ex.Message}");
                // If we can't determine, assume it's not installed and try to install
                return false;
            }
        }
        
        static async Task RunChocolateyInstall(string nupkgPath, JsonElement packageInfo)
        {
            var args = GetArguments(packageInfo);
            
            // First check if chocolatey is installed, install it if missing
            await EnsureChocolateyInstalled();
            
            // Extract package details from the .nupkg file by reading the .nuspec
            string packageDir = Path.GetDirectoryName(nupkgPath) ?? Path.GetTempPath();
            string packageId = "";
            string packageVersion = "";
            
            try
            {
                // Read the .nuspec file from the .nupkg to get the correct package ID and version
                using var archive = ZipFile.OpenRead(nupkgPath);
                var nuspecEntry = archive.Entries.FirstOrDefault(e => e.FullName.EndsWith(".nuspec"));
                
                if (nuspecEntry != null)
                {
                    using var stream = nuspecEntry.Open();
                    using var reader = new StreamReader(stream);
                    string nuspecContent = await reader.ReadToEndAsync();
                    
                    // Parse XML to extract ID and version
                    var doc = System.Xml.Linq.XDocument.Parse(nuspecContent);
                    var ns = doc.Root?.GetDefaultNamespace();
                    
                    if (ns != null)
                    {
                        packageId = doc.Root?.Element(ns + "metadata")?.Element(ns + "id")?.Value ?? "";
                        packageVersion = doc.Root?.Element(ns + "metadata")?.Element(ns + "version")?.Value ?? "";
                    }
                    
                    Logger.Debug($"Extracted from .nuspec: ID='{packageId}', Version='{packageVersion}'");
                }
            }
            catch (Exception ex)
            {
                Logger.Error($"Failed to read package metadata from {nupkgPath}: {ex.Message}");
                // Fallback to filename parsing
                string packageFileName = Path.GetFileNameWithoutExtension(nupkgPath);
                int lastDashIndex = packageFileName.LastIndexOf('-');
                if (lastDashIndex > 0 && lastDashIndex < packageFileName.Length - 1)
                {
                    string potentialVersion = packageFileName.Substring(lastDashIndex + 1);
                    if (potentialVersion.Contains('.'))
                    {
                        packageId = packageFileName.Substring(0, lastDashIndex);
                        packageVersion = potentialVersion;
                    }
                }
                
                if (string.IsNullOrEmpty(packageId))
                {
                    packageId = packageFileName;
                }
                Logger.Debug($"Fallback filename parsing: ID='{packageId}', Version='{packageVersion}'");
            }
            
            if (string.IsNullOrEmpty(packageId))
            {
                throw new Exception($"Could not determine package ID from {nupkgPath}");
            }
            
            // Check if package is already installed and determine the correct action
            bool isInstalled = await IsChocolateyPackageInstalled(packageId);
            string action = isInstalled ? "upgrade" : "install";
            
            Logger.Debug($"Package '{packageId}' is {(isInstalled ? "already installed" : "not installed")} - using '{action}' command");
            Logger.WriteSubProgress($"Package '{packageId}' is {(isInstalled ? "already installed" : "not installed")} - using '{action}' command");
            
            // Use proper chocolatey syntax with smart install/upgrade logic
            // Always use --force (-f) to handle conflicts and ensure package state
            string arguments;
            if (!string.IsNullOrEmpty(packageVersion))
            {
                arguments = $"{action} \"{packageId}\" --source=\"{packageDir}\" --version=\"{packageVersion}\" -y --ignore-checksums --acceptlicense --confirm --force {string.Join(" ", args)}";
            }
            else
            {
                arguments = $"{action} \"{packageId}\" --source=\"{packageDir}\" -y --ignore-checksums --acceptlicense --confirm --force {string.Join(" ", args)}";
            }

            // Find chocolatey executable path using improved method
            string chocoPath = FindChocolateyExecutable();
            
            if (chocoPath == null)
            {
                throw new Exception("Chocolatey executable not found after installation attempt. Cannot proceed with package installation.");
            }

            // In ESP environment, BootstrapMate should already be running elevated
            // Use PowerShell to run Chocolatey and capture output for better error reporting
            string powershellCommand = $"& '{chocoPath}' {arguments}";
            
            var startInfo = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-ExecutionPolicy Bypass -Command \"{powershellCommand}\"",
                UseShellExecute = false, // Changed to false to capture output
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            
            Logger.Debug($"Running Chocolatey via PowerShell: {powershellCommand}");
            Logger.WriteSubProgress("Running Chocolatey", $"{action} command");
            
            using var process = Process.Start(startInfo);
            if (process != null)
            {
                // Capture output for better error reporting
                var outputTask = process.StandardOutput.ReadToEndAsync();
                var errorTask = process.StandardError.ReadToEndAsync();
                
                await process.WaitForExitAsync();
                
                var stdout = await outputTask;
                var stderr = await errorTask;
                
                Logger.Debug($"Chocolatey completed with exit code: {process.ExitCode}");
                
                // Always log ALL output for debugging - this is critical for troubleshooting
                if (!string.IsNullOrWhiteSpace(stdout))
                {
                    Logger.Debug($"Chocolatey stdout: {stdout.Trim()}");
                }
                
                if (!string.IsNullOrWhiteSpace(stderr))
                {
                    Logger.Debug($"Chocolatey stderr: {stderr.Trim()}");
                }
                
                if (process.ExitCode != 0)
                {
                    // Enhanced error message with all available details
                    var errorParts = new List<string>();
                    
                    if (!string.IsNullOrWhiteSpace(stderr))
                    {
                        errorParts.Add($"STDERR: {stderr.Trim()}");
                    }
                    
                    if (!string.IsNullOrWhiteSpace(stdout))
                    {
                        // Include full stdout for failed commands
                        errorParts.Add($"STDOUT: {stdout.Trim()}");
                    }
                    
                    string errorDetails = errorParts.Count > 0 ? $" - {string.Join(" | ", errorParts)}" : "";
                    
                    Logger.Error($"Chocolatey install failed: {packageId} (exit code {process.ExitCode}){errorDetails}");
                    
                    throw new Exception($"Chocolatey install failed with exit code: {process.ExitCode}{errorDetails}");
                }
                
                // Log successful installation details if verbose
                if (!string.IsNullOrWhiteSpace(stdout) && stdout.ToLower().Contains("successfully installed"))
                {
                    var lines = stdout.Split('\n');
                    var successLines = lines.Where(l => l.ToLower().Contains("successfully")).ToList();
                    if (successLines.Any())
                    {
                        Logger.Debug($"Chocolatey success: {string.Join(", ", successLines.Select(l => l.Trim()))}");
                    }
                }
            }
        }
        
        static List<string> GetArguments(JsonElement packageInfo)
        {
            var arguments = new List<string>();
            
            if (packageInfo.TryGetProperty("arguments", out var argsProperty) && argsProperty.ValueKind == JsonValueKind.Array)
            {
                foreach (var arg in argsProperty.EnumerateArray())
                {
                    if (arg.ValueKind == JsonValueKind.String)
                    {
                        arguments.Add(arg.GetString() ?? "");
                    }
                }
            }
            
            return arguments;
        }

        static int ShowStatus()
        {
            try
            {
                Console.WriteLine("BootstrapMate Status");
                Console.WriteLine("==========================");
                Console.WriteLine();

                foreach (InstallationPhase phase in Enum.GetValues<InstallationPhase>())
                {
                    var status = StatusManager.GetPhaseStatus(phase);
                    
                    Console.WriteLine($"Phase: {phase}");
                    Console.WriteLine($"  Stage: {status.Stage}");
                    Console.WriteLine($"  Architecture: {status.Architecture}");
                    
                    if (!string.IsNullOrEmpty(status.StartTime))
                        Console.WriteLine($"  Start Time: {status.StartTime}");
                    
                    if (!string.IsNullOrEmpty(status.CompletionTime))
                        Console.WriteLine($"  Completion Time: {status.CompletionTime}");
                    
                    if (status.ExitCode != 0)
                        Console.WriteLine($"  Exit Code: {status.ExitCode}");
                    
                    if (!string.IsNullOrEmpty(status.LastError))
                        Console.WriteLine($"  Last Error: {status.LastError}");
                    
                    if (!string.IsNullOrEmpty(status.RunId))
                        Console.WriteLine($"  Run ID: {status.RunId}");
                    
                    if (!string.IsNullOrEmpty(status.BootstrapUrl))
                        Console.WriteLine($"  Bootstrap URL: {status.BootstrapUrl}");
                    
                    Console.WriteLine();
                }

                // Show global version information
                Console.WriteLine("Completion Status:");
                try
                {
                    var views = new[] { RegistryView.Registry64, RegistryView.Registry32 };
                    
                    foreach (var view in views)
                    {
                        try
                        {
                            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                            using var key = baseKey.OpenSubKey(@"SOFTWARE\BootstrapMate");
                            
                            if (key != null)
                            {
                                var lastRunVersion = key.GetValue("LastRunVersion")?.ToString();
                                
                                if (!string.IsNullOrEmpty(lastRunVersion))
                                {
                                    Console.WriteLine($"  Last Run Version ({view}): {lastRunVersion}");
                                    break; // Only show once if found
                                }
                            }
                        }
                        catch
                        {
                            // Continue to next view
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"  ⚠️  Warning: Could not read completion information: {ex.Message}");
                }
                Console.WriteLine();

                // Show registry paths for troubleshooting
                Console.WriteLine("Registry Paths:");
                Console.WriteLine("  Completion Status: HKLM\\SOFTWARE\\BootstrapMate\\LastRunVersion");
                Console.WriteLine("  64-bit Status: HKLM\\SOFTWARE\\BootstrapMate\\Status");
                Console.WriteLine("  32-bit Status: HKLM\\SOFTWARE\\WOW6432Node\\BootstrapMate\\Status");
                Console.WriteLine();
                Console.WriteLine("Status File: C:\\ProgramData\\BootstrapMate\\status.json");

                return 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error retrieving status: {ex.Message}");
                return 1;
            }
        }

        static int ClearStatus()
        {
            try
            {
                Console.WriteLine("Clearing BootstrapMate status...");

                // Clear all phase statuses
                foreach (InstallationPhase phase in Enum.GetValues<InstallationPhase>())
                {
                    try
                    {
                        // Delete registry entries for this phase
                        var views = new[] { RegistryView.Registry64, RegistryView.Registry32 };
                        
                        foreach (var view in views)
                        {
                            try
                            {
                                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                                baseKey.DeleteSubKeyTree($@"SOFTWARE\BootstrapMate\Status\{phase}", false);
                            }
                            catch
                            {
                                // Key might not exist, continue
                            }
                        }
                        
                        Console.WriteLine($"  [+] Cleared {phase} status");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"  ⚠️  Warning: Could not clear {phase} status: {ex.Message}");
                    }
                }

                // Clear version registry entry
                try
                {
                    var views = new[] { RegistryView.Registry64, RegistryView.Registry32 };
                    
                    foreach (var view in views)
                    {
                        try
                        {
                            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                            using var key = baseKey.OpenSubKey(@"SOFTWARE\BootstrapMate", true);
                            if (key != null)
                            {
                                key.DeleteValue("LastRunVersion", false);
                            }
                        }
                        catch
                        {
                            // Values might not exist, continue
                        }
                    }
                    
                    Console.WriteLine("  [+] Cleared completion registry entries");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"  ⚠️  Warning: Could not clear completion registry entries: {ex.Message}");
                }

                // Clear status file
                try
                {
                    var statusFile = @"C:\ProgramData\BootstrapMate\status.json";
                    if (File.Exists(statusFile))
                    {
                        File.Delete(statusFile);
                        Console.WriteLine("  [+] Cleared status file");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"  ⚠️  Warning: Could not clear status file: {ex.Message}");
                }

                Console.WriteLine("\n[+] Status cleanup completed");
                return 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error clearing status: {ex.Message}");
                return 1;
            }
        }

        static void ClearPackageCache()
        {
            try
            {
                string cacheDir = GetCacheDirectory();
                if (Directory.Exists(cacheDir))
                {
                    Directory.Delete(cacheDir, true);
                    Logger.Debug($"Cleared package cache directory: {cacheDir}");
                }
                else
                {
                    Logger.Debug($"Package cache directory does not exist: {cacheDir}");
                }
            }
            catch (Exception ex)
            {
                Logger.Warning($"Could not clear package cache: {ex.Message}");
            }
        }

        static void ClearAllCachesAggressive()
        {
            try
            {
                Logger.Debug("Starting aggressive cache clearing (BootstrapMate + Chocolatey)");
                
                // 1. Clear BootstrapMate package cache
                string cacheDir = GetCacheDirectory();
                if (Directory.Exists(cacheDir))
                {
                    Directory.Delete(cacheDir, true);
                    Logger.Debug($"Aggressively cleared BootstrapMate cache: {cacheDir}");
                }
                
                // 2. Clear Chocolatey caches aggressively - all cache locations
                string[] chocolateyCachePaths = {
                    @"C:\ProgramData\chocolatey\temp",
                    @"C:\ProgramData\chocolatey\lib-bad", 
                    @"C:\ProgramData\chocolatey\.chocolatey",
                    @"C:\ProgramData\chocolatey\logs",
                    @"C:\Users\" + Environment.UserName + @"\AppData\Local\Temp\chocolatey"
                };
                
                foreach (string cachePath in chocolateyCachePaths)
                {
                    try
                    {
                        if (Directory.Exists(cachePath))
                        {
                            Directory.Delete(cachePath, true);
                            Logger.Debug($"Aggressively cleared Chocolatey cache: {cachePath}");
                            
                            // Recreate essential directories
                            if (cachePath.EndsWith("temp") || cachePath.EndsWith(".chocolatey"))
                            {
                                Directory.CreateDirectory(cachePath);
                                Logger.Debug($"Recreated essential cache directory: {cachePath}");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Warning($"Could not clear Chocolatey cache {cachePath}: {ex.Message}");
                    }
                }
                
                // 3. Run chocolatey cache clear command if available
                try
                {
                    string chocoPath = FindChocolateyExecutable();
                    var startInfo = new ProcessStartInfo
                    {
                        FileName = chocoPath,
                        Arguments = "cache clear --all --force --yes",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    };
                    
                    using var process = Process.Start(startInfo);
                    if (process != null)
                    {
                        process.WaitForExit(10000); // 10 second timeout
                        if (process.ExitCode == 0)
                        {
                            Logger.Debug("Successfully ran 'choco cache clear --all --force'");
                        }
                        else
                        {
                            Logger.Debug($"choco cache clear returned exit code: {process.ExitCode}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logger.Debug($"Could not run choco cache clear: {ex.Message}");
                }
                
                Logger.Info("Aggressive cache clearing completed");
            }
            catch (Exception ex)
            {
                Logger.Warning($"Aggressive cache clearing failed: {ex.Message}");
            }
        }

        static void CleanupOldCache(TimeSpan maxAge)
        {
            try
            {
                string cacheDir = GetCacheDirectory();
                if (!Directory.Exists(cacheDir))
                {
                    return; // No cache directory exists
                }

                var cutoffTime = DateTime.Now - maxAge;
                var files = Directory.GetFiles(cacheDir, "*", SearchOption.AllDirectories);
                int cleanedCount = 0;

                foreach (var file in files)
                {
                    try
                    {
                        var fileInfo = new FileInfo(file);
                        if (fileInfo.LastWriteTime < cutoffTime)
                        {
                            File.Delete(file);
                            cleanedCount++;
                            Logger.Debug($"Cleaned old cache file: {Path.GetFileName(file)}");
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Warning($"Could not delete old cache file {file}: {ex.Message}");
                    }
                }

                // Try to remove empty directories
                try
                {
                    var directories = Directory.GetDirectories(cacheDir, "*", SearchOption.AllDirectories);
                    foreach (var dir in directories.OrderByDescending(d => d.Length)) // Delete deepest first
                    {
                        try
                        {
                            if (!Directory.EnumerateFileSystemEntries(dir).Any())
                            {
                                Directory.Delete(dir);
                                Logger.Debug($"Removed empty cache directory: {dir}");
                            }
                        }
                        catch
                        {
                            // Ignore errors when removing empty directories
                        }
                    }
                }
                catch
                {
                    // Ignore directory cleanup errors
                }

                if (cleanedCount > 0)
                {
                    Logger.Debug($"Cleaned up {cleanedCount} old cache files (older than {maxAge.TotalDays:F1} days)");
                }
            }
            catch (Exception ex)
            {
                Logger.Warning($"Could not cleanup old cache files: {ex.Message}");
            }
        }

        static int ClearCache()
        {
            try
            {
                Console.WriteLine("Aggressively clearing all caches (BootstrapMate + Chocolatey)...");
                
                // Use the aggressive cache clearing method
                ClearAllCachesAggressive();
                
                Console.WriteLine("[+] All caches cleared aggressively");
                Logger.Info("Manual aggressive cache clearing completed");

                return 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error clearing caches: {ex.Message}");
                Logger.Error($"Error clearing caches: {ex.Message}");
                return 1;
            }
        }

        static int ResetChocolatey()
        {
            try
            {
                Console.WriteLine("Resetting Chocolatey (complete cleanup)...");
                Console.WriteLine("⚠️  This will remove ALL Chocolatey packages and force a clean reinstall.");
                Console.WriteLine();
                
                // Confirm with user (unless running in automated scenarios)
                Console.Write("Are you sure you want to completely reset Chocolatey? (y/N): ");
                var response = Console.ReadLine()?.Trim().ToLowerInvariant();
                
                if (response != "y" && response != "yes")
                {
                    Console.WriteLine("Chocolatey reset cancelled.");
                    return 0;
                }
                
                Logger.Info("Starting complete Chocolatey reset");
                
                string chocolateyRoot = @"C:\ProgramData\chocolatey";
                int removedItems = 0;
                
                if (Directory.Exists(chocolateyRoot))
                {
                    Console.WriteLine($"[*] Removing Chocolatey directory: {chocolateyRoot}");
                    
                    try
                    {
                        // Try to stop any running chocolatey processes first
                        var chocoProcesses = Process.GetProcessesByName("choco");
                        foreach (var proc in chocoProcesses)
                        {
                            try
                            {
                                Console.WriteLine($"[*] Terminating chocolatey process (PID: {proc.Id})");
                                proc.Kill();
                                proc.WaitForExit(5000);
                            }
                            catch
                            {
                                // Ignore errors killing processes
                            }
                        }
                        
                        // Remove the entire chocolatey directory
                        Directory.Delete(chocolateyRoot, true);
                        removedItems++;
                        Console.WriteLine($"[+] Removed Chocolatey directory");
                        Logger.Info($"Removed Chocolatey directory: {chocolateyRoot}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"❌ Error removing Chocolatey directory: {ex.Message}");
                        Logger.Error($"Error removing Chocolatey directory: {ex.Message}");
                        
                        // Try to remove just the lib directory if full removal fails
                        try
                        {
                            string libDir = Path.Combine(chocolateyRoot, "lib");
                            if (Directory.Exists(libDir))
                            {
                                Directory.Delete(libDir, true);
                                Console.WriteLine($"[+] Removed Chocolatey lib directory (partial cleanup)");
                                Logger.Info($"Removed Chocolatey lib directory: {libDir}");
                                removedItems++;
                            }
                        }
                        catch (Exception libEx)
                        {
                            Console.WriteLine($"❌ Error removing Chocolatey lib directory: {libEx.Message}");
                            Logger.Error($"Error removing Chocolatey lib directory: {libEx.Message}");
                        }
                    }
                }
                else
                {
                    Console.WriteLine($"ℹ️  Chocolatey directory does not exist: {chocolateyRoot}");
                }
                
                // Clean up environment variables
                try
                {
                    Console.WriteLine("[*] Cleaning up Chocolatey environment variables");
                    
                    // Remove ChocolateyInstall environment variable
                    Environment.SetEnvironmentVariable("ChocolateyInstall", null, EnvironmentVariableTarget.Machine);
                    Environment.SetEnvironmentVariable("ChocolateyInstall", null, EnvironmentVariableTarget.User);
                    
                    // Clean PATH environment variables (remove chocolatey paths)
                    string[] pathTargets = { "Machine", "User" };
                    foreach (string target in pathTargets)
                    {
                        try
                        {
                            var envTarget = target == "Machine" ? EnvironmentVariableTarget.Machine : EnvironmentVariableTarget.User;
                            string currentPath = Environment.GetEnvironmentVariable("PATH", envTarget) ?? "";
                            
                            // Remove chocolatey-related paths
                            var pathParts = currentPath.Split(';')
                                .Where(p => !string.IsNullOrWhiteSpace(p) && 
                                           !p.ToLowerInvariant().Contains("chocolatey"))
                                .ToArray();
                            
                            string cleanPath = string.Join(";", pathParts);
                            Environment.SetEnvironmentVariable("PATH", cleanPath, envTarget);
                            
                            Logger.Debug($"Cleaned {target} PATH environment variable");
                        }
                        catch (Exception pathEx)
                        {
                            Logger.Warning($"Could not clean {target} PATH: {pathEx.Message}");
                        }
                    }
                    
                    Console.WriteLine($"[+] Cleaned environment variables");
                    removedItems++;
                }
                catch (Exception envEx)
                {
                    Console.WriteLine($"⚠️  Warning: Could not clean environment variables: {envEx.Message}");
                    Logger.Warning($"Could not clean environment variables: {envEx.Message}");
                }
                
                Console.WriteLine();
                if (removedItems > 0)
                {
                    Console.WriteLine($"[+] Chocolatey reset completed! Removed {removedItems} items.");
                    Console.WriteLine("    Chocolatey will be automatically reinstalled when needed.");
                    Logger.Info($"Chocolatey reset completed successfully. Removed {removedItems} items.");
                }
                else
                {
                    Console.WriteLine("ℹ️  No Chocolatey installation found to reset.");
                }
                
                return 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error resetting Chocolatey: {ex.Message}");
                Logger.Error($"Error resetting Chocolatey: {ex.Message}");
                return 1;
            }
        }
    }
}
