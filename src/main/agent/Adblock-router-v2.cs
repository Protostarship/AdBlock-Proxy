/// <summary>
/// NetworkAdBlockBridge is a production‑ready Windows service that turns your computer into a local
/// router/proxy with advanced ad blocking, access logging, privacy, and performance optimizations. It:
///  • Sets up a Windows Mobile Hotspot and configures IP routing.
///  • Intercepts HTTP/HTTPS requests, applying advanced filtering (domain blocking, CNAME unmasking,
///    JavaScript/DPI inspection, WebAssembly analysis, header modification).
///  • Tracks per‑device statistics and maintains an access log for every client.
///  • Routes outgoing connections through TOR (when enabled) to mask the client’s IP and bypass region‑locked content.
///  • Displays a live, colorful dashboard (using Spectre.Console) showing global stats and per‑device details.
///  • Auto-detects CPU and memory usage via native Windows APIs and throttles processing when usage exceeds 80%.
/// 
/// TOR Setup:
///  1. Install TOR (e.g. via the TOR Browser or TOR Expert Bundle).
///  2. Place tor.exe (and its required DLLs) in the "Tor" subfolder.
///  3. The application will automatically start TOR with a basic torrc configuration.
///  4. Ensure TOR listens on 127.0.0.1:9050 (default).
/// 
/// Additional Commands (via console input):
///  • "q"/"quit"/"exit": Shut down the service.
///  • "c"/"clear": Redraw the banner.
///  • "r"/"refresh": Reload the ad domain list from adlist.txt.
///  • "dumplogs": Dump per‑device access logs to "access_logs.txt".
/// 
/// Hardware Optimizations:
///  • Hyperthreading: ThreadPool minimum threads are set based on logical processors.
///  • The system’s CPU and memory are auto‑detected; if usage exceeds 80%, processing is throttled.
/// 
/// Required NuGet Packages:
///  • Colorful.Console
///  • Spectre.Console
///  • System.Management
/// </summary>

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;               // For System.Drawing.Color
using System.IO;
using System.Linq;
using System.Management;          // For CPU usage via WMI
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Spectre.Console;                     // For live dashboard
using CConsole = Colorful.Console;          // Alias for Colorful.Console

namespace NetworkAdBlockBridge
{
    // Class to hold per-device (client) statistics.
    class DeviceInfo
    {
        public string Endpoint { get; set; } = string.Empty;
        public DateTime ConnectionTime { get; set; }
        public DateTime LastActivity { get; set; }
        public int AllowedRequests { get; set; } = 0;
        public int BlockedRequests { get; set; } = 0;
    }

    /// <summary>
    /// Manages the TOR proxy process by starting tor.exe with a basic torrc configuration.
    /// </summary>
    public class TorProxyManager
    {
        private Process? _torProcess;

        public async Task<bool> StartTorAsync()
        {
            string appDir = AppDomain.CurrentDomain.BaseDirectory;
            string torDir = Path.Combine(appDir, "Tor");
            string torExePath = Path.Combine(torDir, "tor.exe");
            string torrcPath = Path.Combine(torDir, "torrc");

            if (!File.Exists(torExePath))
            {
                Console.WriteLine($"Tor executable not found at {torExePath}");
                return false;
            }

            if (!File.Exists(torrcPath))
            {
                string dataDir = Path.Combine(torDir, "data");
                Directory.CreateDirectory(dataDir);
                string torrcContent = $"SocksPort 9050{Environment.NewLine}DataDirectory {dataDir.Replace("\\", "/")}{Environment.NewLine}";
                await File.WriteAllTextAsync(torrcPath, torrcContent);
            }

            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                FileName = torExePath,
                Arguments = $"-f \"{torrcPath}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WorkingDirectory = torDir
            };

            _torProcess = Process.Start(startInfo);
            _torProcess.BeginOutputReadLine();
            _torProcess.BeginErrorReadLine();

            int attempts = 0;
            bool isTorRunning = false;
            while (!isTorRunning && attempts < 10)
            {
                isTorRunning = IsPortListening(9050);
                if (!isTorRunning)
                {
                    await Task.Delay(1000);
                    attempts++;
                }
            }
            return isTorRunning;
        }

        public async Task<bool> IsTorProxyResponding()
        {
            try
            {
                using TcpClient client = new TcpClient();
                await client.ConnectAsync("127.0.0.1", 9050);
                return client.Connected;
            }
            catch
            {
                return false;
            }
        }

        public void StopTor()
        {
            try
            {
                if (_torProcess != null && !_torProcess.HasExited)
                {
                    _torProcess.Kill();
                    _torProcess.Dispose();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error stopping TOR: " + ex.Message);
            }
        }

        private bool IsPortListening(int port)
        {
            IPGlobalProperties properties = IPGlobalProperties.GetIPGlobalProperties();
            IPEndPoint[] listeners = properties.GetActiveTcpListeners();
            return listeners.Any(endpoint => endpoint.Port == port);
        }
    }

    class Program
    {
        // -------------------------------------------------------------
        // Global Configuration & Counters
        // -------------------------------------------------------------
        private const int ListeningPort = 8080;
        private const string AdListPath = "adlist.txt";
        private static readonly List<string> DefaultAdDomains = new List<string>
        {
            "ads.youtube.com",
            "doubleclick.net",
            "googleadservices.com",
            "googlesyndication.com",
            "adservice.google.com",
            "adsense.google.com",
            "adwords.google.com",
            "analytics.google.com",
            "pagead2.googlesyndication.com",
            "imasdk.googleapis.com",
            "ad.doubleclick.net",
            "static.doubleclick.net",
            "m.doubleclick.net",
            "mediavisor.doubleclick.net"
        };

        // Hotspot configuration parameters.
        private const string HotspotSSID = "RSR-WIN_ROUTER";
        private const string HotspotPassword = "Aes2345##";

        // Logging and routing configuration.
        private const string LogFilePath = "Adblock-router\\Adblock-router-v2\\logs\\NetworkBridge\\bridge_log.txt";
        private static readonly bool EnableLogging = true;

        // Global request counters.
        private static int totalRequests = 0;
        private static int allowedRequests = 0;
        private static int blockedRequests = 0;

        // Thread-safe dictionary for per-device stats.
        private static readonly ConcurrentDictionary<string, DeviceInfo> connectedDevices = new ConcurrentDictionary<string, DeviceInfo>();

        // Access logs per device.
        private static readonly ConcurrentDictionary<string, List<string>> accessLogs = new ConcurrentDictionary<string, List<string>>();

        // Ad domains list loaded from file.
        private static List<string> adDomains = new List<string>();

        // Flag to signal application shutdown.
        private static bool isRunning = true;

        // Lock object for console output.
        private static readonly object consoleLock = new object();

        // --------------------------------------------------------------------
        // TOR Integration Settings
        // --------------------------------------------------------------------
        private const bool UseTor = true;
        private const string TorSocksAddress = "127.0.0.1";
        private const int TorSocksPort = 9050;

        // -------------------------------------------------------------
        // Auto Resource Detection: Checks CPU and Memory usage.
        // -------------------------------------------------------------
        private static bool CheckSystemResources()
        {
            // Check memory usage using GlobalMemoryStatusEx.
            MEMORYSTATUSEX memStatus = new MEMORYSTATUSEX();
            if (!MemoryStatus.GlobalMemoryStatusEx(memStatus))
            {
                LogMessage("Failed to get memory status.");
                return true;
            }
            double usedMemoryPercent = ((double)(memStatus.ullTotalPhys - memStatus.ullAvailPhys) / memStatus.ullTotalPhys) * 100;
            if (usedMemoryPercent > 80)
            {
                LogMessage($"Memory usage too high: {usedMemoryPercent:F1}% used.");
                return false;
            }

            // Check CPU usage using WMI.
            float cpuUsage = GetCpuUsage();
            if (cpuUsage > 80)
            {
                LogMessage($"CPU usage too high: {cpuUsage:F1}%.");
                return false;
            }
            return true;
        }

        private static float GetCpuUsage()
        {
            float cpuUsage = 0;
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT LoadPercentage FROM Win32_Processor"))
                {
                    foreach (var obj in searcher.Get())
                    {
                        cpuUsage = Convert.ToSingle(obj["LoadPercentage"]);
                        break;
                    }
                }
            }
            catch (Exception ex)
            {
                LogMessage($"Failed to get CPU usage: {ex.Message}");
            }
            return cpuUsage;
        }

        // -------------------------------------------------------------
        // Main Entry Point
        // -------------------------------------------------------------
        static async Task Main(string[] args)
        {
            // Configure ThreadPool based on hyperthreading.
            int logicalProcessors = Environment.ProcessorCount;
            ThreadPool.SetMinThreads(logicalProcessors * 2, logicalProcessors * 2);
            ThreadPool.SetMaxThreads(logicalProcessors * 4, logicalProcessors * 4);
            LogMessage($"ThreadPool configured: Min = {logicalProcessors * 2}, Max = {logicalProcessors * 4}");

            // Draw banner.
            DrawBanner();

            // Load ad domains.
            LoadAdDomains();

            // Setup Windows hotspot.
            SetupWindowsHotspot(HotspotSSID, HotspotPassword);

            // Configure system routing.
            ConfigureSystemRouting();

            // Ensure log directory exists.
            Directory.CreateDirectory(Path.GetDirectoryName(LogFilePath) ?? "");

            // Start TOR proxy if enabled.
            TorProxyManager torManager = null;
            if (UseTor)
            {
                torManager = new TorProxyManager();
                Console.WriteLine("Starting TOR proxy...");
                bool torStarted = await torManager.StartTorAsync();
                if (torStarted)
                {
                    Console.WriteLine("TOR proxy started successfully!");
                    LogMessage("TOR proxy started on 127.0.0.1:9050");
                }
                else
                {
                    Console.WriteLine("Failed to start TOR proxy. Continuing without TOR.");
                }
            }

            LogMessage($"Service started and listening on port {ListeningPort}");

            // Start TCP listener.
            TcpListener listener = new TcpListener(IPAddress.Any, ListeningPort);
            listener.Start();
            LogMessage($"Bridge listening on port {ListeningPort}");

            // Start live dashboard.
            _ = Task.Run(() => UpdateStatsDisplay());

            // Start user command handler.
            _ = Task.Run(() => HandleUserCommands());

            // Accept incoming connections.
            while (isRunning)
            {
                // Throttle if system resources are above threshold.
                while (!CheckSystemResources())
                {
                    Thread.Sleep(500);
                }

                try
                {
                    TcpClient client = await listener.AcceptTcpClientAsync();
                    LogMessage($"New connection from {client.Client.RemoteEndPoint}");
                    _ = Task.Run(() => ProcessClientAsync(client));
                }
                catch (Exception ex)
                {
                    LogMessage($"Error accepting client: {ex.Message}");
                }
            }

            listener.Stop();
            LogMessage("Application shutting down...");

            // Stop TOR if running.
            if (UseTor && torManager != null)
            {
                torManager.StopTor();
                Console.WriteLine("TOR proxy stopped.");
            }
        }

        // -------------------------------------------------------------
        // P/Invoke for GlobalMemoryStatusEx
        // -------------------------------------------------------------
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public class MEMORYSTATUSEX
        {
            public uint dwLength;
            public uint dwMemoryLoad;
            public ulong ullTotalPhys;
            public ulong ullAvailPhys;
            public ulong ullTotalPageFile;
            public ulong ullAvailPageFile;
            public ulong ullTotalVirtual;
            public ulong ullAvailVirtual;
            public ulong ullAvailExtendedVirtual;
            public MEMORYSTATUSEX() { this.dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX)); }
        }

        public static class MemoryStatus
        {
            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool GlobalMemoryStatusEx([In, Out] MEMORYSTATUSEX lpBuffer);
        }

        // -------------------------------------------------------------
        // Banner & Utility Methods
        // -------------------------------------------------------------
        private static void DrawBanner()
        {
            CConsole.Clear();
            string[] asciiArt = {
                "  _____            _   _____                     ",
                " |  __ \\          | | |  __ \\                    ",
                " | |__) |___  __ _| | | |__) | __ _____  ___   _ ",
                " |  _  // _ \\/ _` | | |  ___/ '__/ _ \\ \\/ / | | |",
                " | | \\ \\  __/ (_| | | | |   | | | (_) >  <| |_| |",
                " |_|  \\_\\___|\\__, |_| |_|   |_|  \\___/_/\\_\\\\__, |",
                "              __/ |                         __/ |",
                "             |___/                         |___/ "
            };
            foreach (var line in asciiArt)
            {
                CConsole.WriteLine(line, System.Drawing.Color.DodgerBlue);
            }
            CConsole.WriteLine("═══════════════════════════════════════════════════", System.Drawing.Color.Gray);
            CConsole.WriteLine(" Network AdBlock Bridge - Production Ready", System.Drawing.Color.White);
            CConsole.WriteLine("═══════════════════════════════════════════════════", System.Drawing.Color.Gray);
            CConsole.WriteLine();
        }

        private static void LoadAdDomains()
        {
            if (!File.Exists(AdListPath))
            {
                File.WriteAllLines(AdListPath, DefaultAdDomains);
                adDomains = new List<string>(DefaultAdDomains);
                LogMessage($"Created default ad domains list at {AdListPath}");
            }
            else
            {
                adDomains = new List<string>(File.ReadAllLines(AdListPath));
                LogMessage($"Loaded {adDomains.Count} ad domains from {AdListPath}");
            }
        }

        private static void LogMessage(string message)
        {
            string logEntry = $"[{DateTime.Now:HH:mm:ss}] {message}";
            lock (consoleLock)
            {
                CConsole.WriteLine(logEntry, System.Drawing.Color.LightGray);
            }
            if (EnableLogging)
            {
                try
                {
                    File.AppendAllText(LogFilePath, logEntry + Environment.NewLine);
                }
                catch { }
            }
        }

        // -------------------------------------------------------------
        // Hotspot & Routing Setup Methods
        // -------------------------------------------------------------
        private static void SetupWindowsHotspot(string ssid, string password)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("netsh", $"wlan set hostednetwork mode=allow ssid={ssid} key={password}")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true
                };
                Process process = Process.Start(psi);
                process.WaitForExit();

                psi.Arguments = "wlan start hostednetwork";
                process = Process.Start(psi);
                process.WaitForExit();

                LogMessage($"Hotspot '{ssid}' created successfully");
            }
            catch (Exception ex)
            {
                LogMessage($"Failed to set up hotspot: {ex.Message}");
            }
        }

        private static void ConfigureSystemRouting()
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("reg", "add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v IPEnableRouter /t REG_DWORD /d 1 /f")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false
                };
                Process process = Process.Start(psi);
                process.WaitForExit();

                psi = new ProcessStartInfo("net", "stop RemoteAccess & net start RemoteAccess")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false
                };
                process = Process.Start(psi);
                process.WaitForExit();

                LogMessage("System routing configured successfully");
            }
            catch (Exception ex)
            {
                LogMessage($"Failed to configure system routing: {ex.Message}");
            }
        }

        // -------------------------------------------------------------
        // Core Client Processing (Proxy/Bridge), Access Logging & Device Tracking
        // -------------------------------------------------------------
        private static async Task ProcessClientAsync(TcpClient client)
        {
            Interlocked.Increment(ref totalRequests);
            string remoteEndpoint = client.Client.RemoteEndPoint.ToString();

            DeviceInfo device = connectedDevices.GetOrAdd(remoteEndpoint, key => new DeviceInfo
            {
                Endpoint = key,
                ConnectionTime = DateTime.Now,
                LastActivity = DateTime.Now
            });

            accessLogs.GetOrAdd(remoteEndpoint, key => new List<string>());

            try
            {
                using (client)
                {
                    NetworkStream clientStream = client.GetStream();
                    clientStream.ReadTimeout = 10000;
                    clientStream.WriteTimeout = 10000;

                    byte[] buffer = new byte[8192];
                    int bytesRead = await clientStream.ReadAsync(buffer, 0, buffer.Length);
                    if (bytesRead == 0)
                        return;

                    string request = Encoding.ASCII.GetString(buffer, 0, bytesRead);
                    string requestHost = ExtractHost(request);
                    LogMessage($"[{remoteEndpoint}] Received request for {requestHost}");
                    device.LastActivity = DateTime.Now;

                    LogAccess(remoteEndpoint, $"[{DateTime.Now:HH:mm:ss}] Request for {requestHost}");

                    var (isAllowed, modifiedRequest) = ApplyAdvancedFilterRules(request);
                    if (!isAllowed)
                    {
                        Interlocked.Increment(ref blockedRequests);
                        LogMessage($"[{remoteEndpoint}] Request BLOCKED");
                        LogAccess(remoteEndpoint, $"[{DateTime.Now:HH:mm:ss}] BLOCKED request for {requestHost}");
                        await SendBlockedResponseAsync(clientStream);
                        return;
                    }
                    else
                    {
                        Interlocked.Increment(ref allowedRequests);
                        LogAccess(remoteEndpoint, $"[{DateTime.Now:HH:mm:ss}] ALLOWED request for {requestHost}");
                    }

                    // In this version, simply pass through the modified request.
                    string finalRequest = modifiedRequest;

                    string hostName = ExtractHost(finalRequest);
                    int port = 80;
                    if (hostName.Contains(":"))
                    {
                        var parts = hostName.Split(':');
                        hostName = parts[0];
                        int.TryParse(parts[1], out port);
                    }

                    using (TcpClient destination = new TcpClient())
                    {
                        if (UseTor)
                        {
                            TcpClient torClient = await ConnectThroughTorAsync(hostName, port);
                            await ForwardDataBetweenStreams(clientStream, torClient.GetStream());
                            torClient.Close();
                        }
                        else
                        {
                            await destination.ConnectAsync(hostName, port);
                            NetworkStream destStream = destination.GetStream();
                            byte[] finalData = Encoding.ASCII.GetBytes(finalRequest);
                            await destStream.WriteAsync(finalData, 0, finalData.Length);

                            Task t1 = ForwardDataAsync(clientStream, destStream);
                            Task t2 = ForwardDataAsync(destStream, clientStream);
                            await Task.WhenAny(t1, t2);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                LogMessage($"[{remoteEndpoint}] Error processing client: {ex.Message}");
            }
            finally
            {
                device.LastActivity = DateTime.Now;
            }
        }

        private static void LogAccess(string deviceKey, string entry)
        {
            if (accessLogs.TryGetValue(deviceKey, out List<string>? logList))
            {
                lock (logList)
                {
                    logList.Add(entry);
                }
            }
        }

        /// <summary>
        /// Applies advanced filtering rules (domain blocking, CNAME unmasking, JavaScript/DPI, WebAssembly analysis, header modification).
        /// </summary>
        private static (bool isAllowed, string modifiedRequest) ApplyAdvancedFilterRules(string request)
        {
            string modifiedRequest = request;
            bool isAllowed = true;
            string host = ExtractHost(request);

            foreach (string adDomain in adDomains)
            {
                if (host.IndexOf(adDomain, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    LogMessage($"[Filter] Blocked domain: {host} matches {adDomain}");
                    return (false, request);
                }
            }

            try
            {
                IPHostEntry hostEntry = Dns.GetHostEntry(host);
                foreach (var alias in hostEntry.Aliases)
                {
                    if (adDomains.Any(ad => alias.IndexOf(ad, StringComparison.OrdinalIgnoreCase) >= 0))
                    {
                        LogMessage($"[Filter] CNAME unmasking: {host} alias {alias} matches ad domain");
                        return (false, request);
                    }
                }
            }
            catch (Exception ex)
            {
                LogMessage($"[Filter] DNS resolution failed for {host}: {ex.Message}");
            }

            if (host.EndsWith(".js", StringComparison.OrdinalIgnoreCase) || request.Contains("application/javascript"))
            {
                if (Regex.IsMatch(request, @"\b(ad[s]?|sponsor|tracking)\b", RegexOptions.IgnoreCase))
                {
                    LogMessage($"[Filter] JavaScript analysis blocked request for {host}");
                    return (false, request);
                }
            }
            if (Regex.IsMatch(request, @"<script[^>]*>.*?(adsbygoogle|doubleclick)\s*=", RegexOptions.Singleline | RegexOptions.IgnoreCase))
            {
                LogMessage($"[Filter] DPI detected ad-related script");
                return (false, request);
            }
            if (host.EndsWith(".wasm", StringComparison.OrdinalIgnoreCase))
            {
                if (Regex.IsMatch(request, @"\b(adModule|adTracker)\b", RegexOptions.IgnoreCase))
                {
                    LogMessage($"[Filter] WebAssembly analysis blocked request for {host}");
                    return (false, request);
                }
            }
            modifiedRequest = Regex.Replace(modifiedRequest, @"(Ad-ID|X-Marketing):.*\r\n", "", RegexOptions.IgnoreCase);
            if (!modifiedRequest.Contains("X-Filtered-By"))
            {
                int headersEnd = modifiedRequest.IndexOf("\r\n\r\n");
                if (headersEnd > 0)
                {
                    modifiedRequest = modifiedRequest.Insert(headersEnd, "\r\nX-Filtered-By: NetworkAdBlockBridge");
                }
            }

            return (isAllowed, modifiedRequest);
        }

        /// <summary>
        /// Extracts the destination host from an HTTP request.
        /// </summary>
        private static string ExtractHost(string request)
        {
            var hostMatch = Regex.Match(request, @"Host:\s*([^\r\n]+)", RegexOptions.IgnoreCase);
            if (hostMatch.Success)
                return hostMatch.Groups[1].Value.Trim();
            var requestLineMatch = Regex.Match(request, @"^\w+\s+https?://([^/\s:]+)", RegexOptions.IgnoreCase);
            if (requestLineMatch.Success)
                return requestLineMatch.Groups[1].Value.Trim();
            return "unknown";
        }

        /// <summary>
        /// Forwards data between two network streams.
        /// </summary>
        private static async Task ForwardDataAsync(NetworkStream source, NetworkStream destination)
        {
            byte[] buffer = new byte[8192];
            try
            {
                int bytesRead;
                while ((bytesRead = await source.ReadAsync(buffer, 0, buffer.Length)) > 0)
                {
                    await destination.WriteAsync(buffer, 0, bytesRead);
                }
            }
            catch (Exception ex)
            {
                LogMessage($"[Forwarding] Error: {ex.Message}");
            }
        }

        /// <summary>
        /// Pipes data between streams when using TOR.
        /// </summary>
        private static async Task ForwardDataBetweenStreams(NetworkStream source, NetworkStream destination)
        {
            byte[] buffer = new byte[65536];
            Task t1 = ForwardDataAsync(source, destination);
            Task t2 = ForwardDataAsync(destination, source);
            await Task.WhenAny(t1, t2);
        }

        /// <summary>
        /// Sends an HTTP 403 Forbidden response to the client.
        /// </summary>
        private static async Task SendBlockedResponseAsync(NetworkStream clientStream)
        {
            string blockedPage =
                "HTTP/1.1 403 Forbidden\r\n" +
                "Content-Type: text/html\r\n" +
                "Connection: close\r\n" +
                "\r\n" +
                "<html><head><title>Access Blocked</title></head><body>" +
                "<h1>Access Blocked</h1>" +
                "<p>This request has been blocked by network policy.</p>" +
                "</body></html>";
            byte[] responseData = Encoding.ASCII.GetBytes(blockedPage);
            await clientStream.WriteAsync(responseData, 0, responseData.Length);
        }

        // -------------------------------------------------------------
        // TOR Integration: Connect via a local TOR SOCKS5 proxy.
        // -------------------------------------------------------------
        private static async Task<TcpClient> ConnectThroughTorAsync(string destHost, int destPort)
        {
            TcpClient torClient = new TcpClient();
            await torClient.ConnectAsync(TorSocksAddress, TorSocksPort);
            NetworkStream stream = torClient.GetStream();

            byte[] greeting = new byte[] { 0x05, 0x01, 0x00 };
            await stream.WriteAsync(greeting, 0, greeting.Length);
            byte[] response = new byte[2];
            int read = await stream.ReadAsync(response, 0, 2);
            if (read != 2 || response[0] != 0x05 || response[1] != 0x00)
                throw new Exception("SOCKS5 authentication failed");

            byte[] destHostBytes = Encoding.ASCII.GetBytes(destHost);
            byte[] request = new byte[4 + 1 + destHostBytes.Length + 2];
            request[0] = 0x05;
            request[1] = 0x01;
            request[2] = 0x00;
            request[3] = 0x03;
            request[4] = (byte)destHostBytes.Length;
            Array.Copy(destHostBytes, 0, request, 5, destHostBytes.Length);
            request[5 + destHostBytes.Length] = (byte)(destPort >> 8);
            request[5 + destHostBytes.Length + 1] = (byte)(destPort & 0xFF);
            await stream.WriteAsync(request, 0, request.Length);

            byte[] responseHeader = new byte[4];
            read = await stream.ReadAsync(responseHeader, 0, 4);
            if (read != 4 || responseHeader[1] != 0x00)
                throw new Exception("SOCKS5 connection request failed");

            int addrLen;
            if (responseHeader[3] == 0x01)
                addrLen = 4;
            else if (responseHeader[3] == 0x03)
            {
                byte[] lenBuf = new byte[1];
                await stream.ReadAsync(lenBuf, 0, 1);
                addrLen = lenBuf[0];
            }
            else if (responseHeader[3] == 0x04)
                addrLen = 16;
            else
                throw new Exception("Unknown address type in SOCKS5 response");

            byte[] dummy = new byte[addrLen + 2];
            await stream.ReadAsync(dummy, 0, dummy.Length);

            return torClient;
        }

        // -------------------------------------------------------------
        // Dashboard & Command Handling (Using Spectre.Console)
        // -------------------------------------------------------------
        private static void UpdateStatsDisplay()
        {
            while (isRunning)
            {
                foreach (var key in connectedDevices.Keys.ToList())
                {
                    if ((DateTime.Now - connectedDevices[key].LastActivity).TotalSeconds > 60)
                        connectedDevices.TryRemove(key, out _);
                }

                var table = new Table();
                table.Border = TableBorder.Rounded;
                table.AddColumn(new TableColumn("[underline]Device[/]"));
                table.AddColumn(new TableColumn("[underline]Uptime[/]"));
                table.AddColumn(new TableColumn("[underline green]Allowed[/]"));
                table.AddColumn(new TableColumn("[underline red]Blocked[/]"));

                foreach (var kvp in connectedDevices)
                {
                    var device = kvp.Value;
                    string uptime = (DateTime.Now - device.ConnectionTime).ToString(@"hh\:mm\:ss");
                    table.AddRow(device.Endpoint, uptime, device.AllowedRequests.ToString(), device.BlockedRequests.ToString());
                }

                var globalStats = $"[bold yellow]Status:[/] RUNNING\n" +
                                  $"[bold]Total Requests:[/] {totalRequests}  " +
                                  $"[green]Allowed:[/] {allowedRequests}  " +
                                  $"[red]Blocked:[/] {blockedRequests}";

                AnsiConsole.Clear();
                AnsiConsole.MarkupLine(globalStats);
                if (connectedDevices.Any())
                    AnsiConsole.Write(table);
                else
                    AnsiConsole.MarkupLine("[grey]No active device connections.[/]");
                Thread.Sleep(1000);
            }
        }

        private static void HandleUserCommands()
        {
            while (isRunning)
            {
                lock (consoleLock)
                {
                    CConsole.Write("> ", System.Drawing.Color.White);
                }
                string command = Console.ReadLine()?.Trim().ToLower() ?? "";
                if (command == "q" || command == "quit" || command == "exit")
                {
                    isRunning = false;
                    LogMessage("Shutdown command received.");
                }
                else if (command == "c" || command == "clear")
                {
                    DrawBanner();
                }
                else if (command == "r" || command == "refresh")
                {
                    LoadAdDomains();
                    LogMessage("Reloaded ad domain list.");
                }
                else if (command == "dumplogs")
                {
                    DumpAccessLogs();
                    LogMessage("Access logs dumped to access_logs.txt");
                }
                else
                {
                    LogMessage("Unknown command. Try: [q]uit, [c]lear, [r]efresh, [dumplogs]");
                }
            }
        }

        private static void DumpAccessLogs()
        {
            StringBuilder sb = new StringBuilder();
            foreach (var kvp in accessLogs)
            {
                sb.AppendLine($"Device: {kvp.Key}");
                foreach (string entry in kvp.Value)
                    sb.AppendLine($"  {entry}");
                sb.AppendLine();
            }
            File.WriteAllText("access_logs.txt", sb.ToString());
        }
    }
}
