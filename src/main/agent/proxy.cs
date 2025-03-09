using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Titanium.Web.Proxy;
using Titanium.Web.Proxy.EventArguments;
using Titanium.Web.Proxy.Http;
using Titanium.Web.Proxy.Models;
using Console = Colorful.Console;

namespace AdBlockingProxy
{
    class Program
    {
        private static ProxyServer? proxyServer;
        private static List<string>? adDomains;
        private static readonly string adListPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "adlist.txt");
        private static readonly object consoleLock = new object();
        private static bool isRunning = true;
        private static HashSet<string> targetedProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private static int totalRequests = 0;
        private static int blockedRequests = 0;
        private static int allowedRequests = 0;
        private static readonly Dictionary<string, Color> methodColors = new Dictionary<string, Color>
        {
            { "GET", Color.Green },
            { "POST", Color.DarkOrange },
            { "PUT", Color.Blue },
            { "DELETE", Color.Red },
            { "PATCH", Color.Purple },
            { "HEAD", Color.Cyan },
            { "OPTIONS", Color.Yellow },
            { "CONNECT", Color.Magenta },
            { "TRACE", Color.Brown }
        };

        static void Main(string[] args)
        {
            // Install required NuGet packages:
            // Install-Package Titanium.Web.Proxy
            // Install-Package Colorful.Console
            
            Console.WriteLine("Initializing proxy server...", Color.White);
            
            DrawAsciiArt();
            
            // Process command line arguments
            ProcessArguments(args);
            
            // Load ad domains list
            LoadAdDomains();

            // Create a proxy server
            proxyServer = new ProxyServer();
            
            // Create an endpoint
            var explicitEndPoint = new ExplicitProxyEndPoint(IPAddress.Any, 8000, true);
            
            // Register the endpoint
            proxyServer.AddEndPoint(explicitEndPoint);

            // Subscribe to request and response events
            proxyServer.BeforeRequest += OnRequest;
            proxyServer.BeforeResponse += OnResponse;
            
            // Start the proxy server
            proxyServer.Start();
            
            // Set system proxy settings to use our proxy for HTTP and HTTPS
            proxyServer.SetAsSystemProxy(explicitEndPoint, ProxyProtocolType.AllHttp);
            
            // Create a task for displaying stats
            Task.Run(() => UpdateStatsDisplay());
            
            // Start a thread to handle user commands
            Task.Run(() => HandleUserCommands());
            
            // Wait for exit signal
            while (isRunning)
            {
                Thread.Sleep(100);
            }
            
            // Restore system proxy settings
            proxyServer?.RestoreOriginalProxySettings();
            
            // Stop the proxy server
            proxyServer?.Stop();
        }

        private static void ProcessArguments(string[] args)
        {
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i].Equals("-t", StringComparison.OrdinalIgnoreCase) ||
                    args[i].Equals("--target", StringComparison.OrdinalIgnoreCase))
                {
                    if (i + 1 < args.Length)
                    {
                        string[] processes = args[i + 1].Split(',');
                        foreach (var process in processes)
                        {
                            targetedProcesses.Add(process.Trim());
                        }
                        
                        Console.WriteLine($"Targeting specific processes: {string.Join(", ", targetedProcesses)}", Color.Yellow);
                    }
                }
            }
        }

        private static void DrawAsciiArt()
        {
            lock (consoleLock)
            {
                Console.Clear();
                
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

                for (int i = 0; i < asciiArt.Length; i++)
                {
                    // Replace the WriteLineGradient with a regular WriteLine
                    Console.WriteLine(asciiArt[i], Color.DodgerBlue);
                }
                
                Console.WriteLine("═══════════════════════════════════════════════════", Color.Gray);
                Console.WriteLine("Ad Blocking HTTP/HTTPS Proxy with Live Dashboard", Color.White);
                Console.WriteLine("═══════════════════════════════════════════════════", Color.Gray);
                Console.WriteLine();
            }
        }

        private static void LoadAdDomains()
        {
            if (!File.Exists(adListPath))
            {
                // Create a default ad list if none exists
                var defaultAdDomains = new List<string>
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
                    "mediavisor.doubleclick.net",
                };
                
                File.WriteAllLines(adListPath, defaultAdDomains);
                Console.WriteLine($"Created default ad domains list at {adListPath}", Color.Yellow);
                adDomains = defaultAdDomains;
            }
            else
            {
                // Load ad domains from file
                adDomains = File.ReadAllLines(adListPath).ToList();
                Console.WriteLine($"Loaded {adDomains.Count} ad domains from {adListPath}", Color.Cyan);
            }
        }

        private static bool ShouldProcessRequest(SessionEventArgs e)
        {
            // If no targeted processes specified, process all requests
            if (targetedProcesses.Count == 0)
                return true;
            
            // Get the process ID that generated the request
            int processId = e.HttpClient.ProcessId.Value; // Fixed: Use .Value to get the int from Lazy<int>
            
            if (processId > 0)
            {
                try
                {
                    Process process = Process.GetProcessById(processId);
                    string processName = Path.GetFileName(process.MainModule?.FileName ?? "Unknown");
                    
                    // Check if the process name matches any of our targeted processes
                    return targetedProcesses.Contains(processName);
                }
                catch
                {
                    // Process might have exited
                    return false;
                }
            }
            
            return false;
        }

        private static async Task OnRequest(object sender, SessionEventArgs e)
        {
            if (adDomains == null) return;
            
            totalRequests++;
            
            // Check if we should process this request based on process targeting
            if (!ShouldProcessRequest(e))
            {
                allowedRequests++;
                return;
            }
            
            var requestUrl = e.HttpClient.Request.Url;
            var method = e.HttpClient.Request.Method;
            var host = e.HttpClient.Request.Host;
            var contentLength = e.HttpClient.Request.ContentLength;
            
            // Get process information if available
            string processInfo = "Unknown";
            try
            {
                int processId = e.HttpClient.ProcessId.Value; // Fixed: Use .Value to get the int from Lazy<int>
                if (processId > 0)
                {
                    var process = Process.GetProcessById(processId);
                    processInfo = process.ProcessName;
                }
            }
            catch { }
            
            // Check if request URL contains any ad domains
            if (adDomains.Any(ad => requestUrl.Contains(ad)))
            {
                lock (consoleLock)
                {
                    Console.Write($"[{DateTime.Now.ToString("HH:mm:ss")}] ", Color.Gray);
                    Console.Write($"{method} ", methodColors.ContainsKey(method) ? methodColors[method] : Color.White);
                    Console.Write($"{host} → localhost ", Color.White);
                    Console.Write($"[{contentLength} bytes] ", Color.DarkGray);
                    Console.Write($"({processInfo}) ", Color.Gray);
                    Console.WriteLine("BLOCKED", Color.Red);
                }
                
                blockedRequests++;
                
                // Redirect to localhost (block the request)
                e.HttpClient.Request.Url = "http://localhost/blocked";
                e.HttpClient.Request.Host = "localhost";
                
                // Return an empty response
                string html = "<html><body><h1>Ad Blocked</h1></body></html>";
                e.Ok(html);
            }
            else
            {
                lock (consoleLock)
                {
                    Console.Write($"[{DateTime.Now.ToString("HH:mm:ss")}] ", Color.Gray);
                    Console.Write($"{method} ", methodColors.ContainsKey(method) ? methodColors[method] : Color.White);
                    Console.Write($"{host} ", Color.White);
                    Console.Write($"[{contentLength} bytes] ", Color.DarkGray);
                    Console.Write($"({processInfo}) ", Color.Gray);
                    Console.WriteLine("ALLOWED", Color.Green);
                }
                
                allowedRequests++;
            }
        }

        private static async Task OnResponse(object sender, SessionEventArgs e)
        {
            // Only process if this is a targeted process
            if (!ShouldProcessRequest(e))
                return;
                
            // Process YouTube pages to remove ad elements
            if (e.HttpClient.Request.Host.Contains("youtube.com") && e.HttpClient.Response.StatusCode == 200)
            {
                // Only process HTML content
                if (e.HttpClient.Response.ContentType != null && e.HttpClient.Response.ContentType.Contains("text/html"))
                {
                    string body = await e.GetResponseBodyAsString();
                    
                    // Simple example: remove elements with ad-related class names
                    body = Regex.Replace(body, "<div[^>]*class=\"[^\"]*ad[^\"]*\"[^>]*>.*?</div>", "", RegexOptions.Singleline);
                    
                    // Fixed: Changed from await e.SetResponseBodyString(body) to match return type
                    e.SetResponseBodyString(body);
                    
                    lock (consoleLock)
                    {
                        Console.Write($"[{DateTime.Now.ToString("HH:mm:ss")}] ", Color.Gray);
                        Console.Write("YouTube ", Color.Red);
                        Console.WriteLine("page modified to remove ads", Color.Yellow);
                    }
                }
            }
        }

        private static void UpdateStatsDisplay()
        {
            int lastTotalRequests = 0;
            int lastBlockedRequests = 0;
            
            while (isRunning)
            {
                int requestsPerSecond = totalRequests - lastTotalRequests;
                int blocksPerSecond = blockedRequests - lastBlockedRequests;
                
                lastTotalRequests = totalRequests;
                lastBlockedRequests = blockedRequests;
                
                // Update the display with current statistics
                lock (consoleLock)
                {
                    // Fixed: Check if proxyServer is null before dereferencing it
                    if (proxyServer != null)
                    {
                        Console.SetCursorPosition(0, 12);
                        Console.Write(new string(' ', Console.WindowWidth));
                        Console.SetCursorPosition(0, 12);
                        Console.Write("Status: ", Color.White);
                        Console.WriteLine("RUNNING", Color.Green);
                        
                        Console.SetCursorPosition(0, 13);
                        Console.Write(new string(' ', Console.WindowWidth));
                        Console.SetCursorPosition(0, 13);
                        Console.Write("Total Requests: ", Color.White);
                        Console.WriteLine($"{totalRequests} ({requestsPerSecond}/sec)", Color.Cyan);
                        
                        Console.SetCursorPosition(0, 14);
                        Console.Write(new string(' ', Console.WindowWidth));
                        Console.SetCursorPosition(0, 14);
                        Console.Write("Blocked Requests: ", Color.White);
                        Console.WriteLine($"{blockedRequests} ({blocksPerSecond}/sec)", Color.Red);
                        
                        Console.SetCursorPosition(0, 15);
                        Console.Write(new string(' ', Console.WindowWidth));
                        Console.SetCursorPosition(0, 15);
                        Console.Write("Allowed Requests: ", Color.White);
                        Console.WriteLine($"{allowedRequests}", Color.Green);
                        
                        Console.SetCursorPosition(0, 16);
                        Console.Write(new string(' ', Console.WindowWidth));
                        Console.SetCursorPosition(0, 16);
                        Console.Write("Targeted Processes: ", Color.White);
                        Console.WriteLine(targetedProcesses.Count > 0 ? string.Join(", ", targetedProcesses) : "All", Color.Yellow);
                        
                        Console.SetCursorPosition(0, 18);
                        Console.Write(new string(' ', Console.WindowWidth));
                        Console.SetCursorPosition(0, 18);
                        Console.WriteLine("Commands: [q]uit | [c]lear | [t]arget <process> | [r]efresh", Color.DarkGray);
                    }
                }
                
                // Sleep for a second
                Thread.Sleep(1000);
            }
        }

        private static void HandleUserCommands()
        {
            while (isRunning)
            {
                lock (consoleLock)
                {
                    Console.SetCursorPosition(0, 20);
                    Console.Write(new string(' ', Console.WindowWidth));
                    Console.SetCursorPosition(0, 20);
                    Console.Write("> ", Color.White);
                }
                
                string command = Console.ReadLine()?.Trim().ToLower() ?? "";
                
                if (command == "q" || command == "quit" || command == "exit")
                {
                    isRunning = false;
                    Console.WriteLine("Shutting down proxy server...", Color.Yellow);
                }
                else if (command == "c" || command == "clear")
                {
                    DrawAsciiArt();
                }
                else if (command == "r" || command == "refresh")
                {
                    LoadAdDomains();
                    Console.WriteLine("Reloaded ad domain list", Color.Green);
                }
                else if (command.StartsWith("t ") || command.StartsWith("target "))
                {
                    string[] parts = command.Split(new[] { ' ' }, 2);
                    if (parts.Length > 1 && !string.IsNullOrWhiteSpace(parts[1]))
                    {
                        targetedProcesses.Clear();
                        string[] processes = parts[1].Split(',');
                        foreach (var process in processes)
                        {
                            string processName = process.Trim();
                            if (!string.IsNullOrWhiteSpace(processName))
                            {
                                targetedProcesses.Add(processName);
                            }
                        }
                        
                        Console.WriteLine($"Now targeting: {string.Join(", ", targetedProcesses)}", Color.Yellow);
                    }
                    else
                    {
                        targetedProcesses.Clear();
                        Console.WriteLine("Now targeting all processes", Color.Yellow);
                    }
                }
                else
                {
                    Console.WriteLine("Unknown command. Try: [q]uit | [c]lear | [t]arget <process> | [r]efresh", Color.Red);
                }
            }
        }
    }
}
