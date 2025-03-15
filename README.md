# AD Block Agent Projects [![Status](https://img.shields.io/badge/Status-Under%20Development-yellow)](https://img.shields.io/badge/Status-Under%20Development-yellow)

A project in attempt to recreate AD-Blocker for Chrome through Windows SDK's .NET Frameworks directly from it's networks.

**Transform your Windows 10/11 laptop into a powerful router/firewall with advanced ad blocking and privacy features**

- 🌐 Network-based service
- 📶 Requires a stable internet connection.
- ➡️ Data stream processing.
- 📦 Network packet manipulation.

## Overview

[![Status](https://img.shields.io/badge/Status-Under%20Development-yellow)](https://img.shields.io/badge/Status-Under%20Development-yellow) 🌐 📶 ☁️

This project is currently under development and relies on a network connection (Wi-Fi) and cloud infrastructure.

NetworkAdBlockBridge is a production-ready Windows service that converts your standard Windows 10/11 laptop into a sophisticated router/firewall solution with enterprise-grade features. It creates a secure Wi-Fi hotspot that filters traffic, blocks ads, enhances privacy, and provides detailed analytics - all without requiring specialized hardware.

**Key Benefits:**
- ✅ Transform any Windows laptop into a powerful network gateway
- ✅ Block ads across ALL connected devices (phones, tablets, TVs, etc.)  
- ✅ Protect your entire network from tracking and malicious content
- ✅ Monitor per-device network activities with detailed logs
- ✅ Configure advanced routing options including TOR integration

## Core Features

### 🌐 Network Routing & Hotspot Creation

NetworkAdBlockBridge automatically configures your Windows laptop to function as a router:

- **Mobile Hotspot Setup**: Creates and manages a Windows Mobile Hotspot with customizable SSID and password
- **IP Routing Configuration**: Sets up proper IP forwarding between network interfaces
- **NAT Implementation**: Handles Network Address Translation for all connected clients
- **Multi-Device Support**: Connect phones, tablets, smart TVs and other devices simultaneously
- **Bandwidth Management**: Monitors and controls bandwidth usage per device

### 🛡️ Advanced Ad & Content Blocking

Multi-layered filtering approach that blocks ads and unwanted content across your entire network:

- **Domain-based Filtering**: Blocks known ad-serving domains using customizable blocklists
- **CNAME Unmasking**: Detects and blocks disguised ad domains using CNAME resolution
- **Deep Packet Inspection**: Analyzes HTTP/HTTPS request content for ad-related patterns
- **JavaScript Analysis**: Identifies and blocks ad-related JavaScript
- **WebAssembly Inspection**: Detects ad modules hidden in WebAssembly code
- **Header Modification**: Removes tracking headers and adds custom headers

The filtering occurs at the network level, meaning **ALL devices** connected to your hotspot benefit from ad blocking - no need for device-specific ad blockers!

### 🕵️ Privacy Enhancements

Protect your entire network with powerful privacy features:

- **TOR Integration**: Route traffic through TOR network when enabled
  - Mask your IP address and geographic location
  - Access region-restricted content
  - Bypass network surveillance and censorship
- **Header Sanitization**: Remove tracking identifiers from HTTP requests
- **Analytics Blocking**: Prevent tracking scripts and analytics services from collecting data
- **Custom Privacy Rules**: Define your own rules for blocking specific trackers

### 📊 Monitoring & Analytics Dashboard

Real-time visibility into your network with an intuitive console interface:

- **Live Colorful Dashboard**: View global and per-device statistics in real-time
- **Connected Device Tracking**: Monitor all devices connected to your network
- **Request Statistics**: Track allowed vs. blocked requests per device
- **Access Logging**: Maintain detailed logs of all network activity
- **Performance Metrics**: Monitor system resource usage and network throughput
- **Exportable Reports**: Generate and export network activity reports

### ⚡ Performance Optimization

NetworkAdBlockBridge includes sophisticated performance tuning to ensure smooth operation:

- **Hyperthreading Optimization**: Automatically configures thread pools based on CPU capabilities
- **Resource Monitoring**: Tracks CPU and memory usage in real-time
- **Adaptive Throttling**: Automatically adjusts processing when system resources exceed 80% utilization
- **Efficient Memory Management**: Optimized buffer handling for minimal memory footprint
- **Connection Pooling**: Reuses network connections for better performance

### 🔧 Advanced Configuration Options

Fine-tune your router/firewall solution with extensive configuration options:

- **Custom Blocklists**: Import standard filter lists (AdBlock Plus, uBlock Origin formats)
- **Per-Device Rules**: Apply different filtering rules to specific devices
- **Command Line Interface**: Manage the service via intuitive commands
  - `quit`/`exit`: Shut down the service
  - `clear`: Redraw the banner/dashboard
  - `refresh`: Reload ad domain lists
  - `dumplogs`: Export device access logs
- **Scriptable API**: Automate configurations via script or API calls

## System Architecture

NetworkAdBlockBridge employs a sophisticated multi-layered architecture:

```
┌───────────────────────────────────────────────────┐
│                Windows Mobile Hotspot             │
└───────────────────┬───────────────────────────────┘
                    │
┌───────────────────▼───────────────────────────────┐
│               Network Routing Layer               │
└───────────────────┬───────────────────────────────┘
                    │
┌───────────────────▼───────────────────────────────┐
│              Traffic Interception                 │
└───────────────────┬───────────────────────────────┘
                    │
┌───────────────────▼───────────────────────────────┐
│               Multi-Layer Filtering               │
│  ┌─────────────┐ ┌──────────┐ ┌────────────────┐  │
│  │Domain Filter│ │CNAME Scan│ │Content Analysis│  │
│  └─────────────┘ └──────────┘ └────────────────┘  │
└───────────────────┬───────────────────────────────┘
                    │
┌───────────────────▼───────────────────────────────┐
│              Privacy Enhancement                  │
│  ┌─────────────┐ ┌──────────┐ ┌────────────────┐  │
│  │Header Modify│ │TOR Relay │ │Tracker Blocking│  │
│  └─────────────┘ └──────────┘ └────────────────┘  │
└───────────────────┬───────────────────────────────┘
                    │
┌───────────────────▼───────────────────────────────┐
│               Network Analytics                   │
└───────────────────────────────────────────────────┘
```

## Technical Requirements

### Hardware Requirements
- Windows 10/11 laptop or desktop
- Processor: Dual-core CPU or better
- Memory: 4GB RAM minimum (8GB recommended)
- Storage: 100MB available space
- Network: Wi-Fi adapter with mobile hotspot capability
- Secondary network connection (Ethernet or another Wi-Fi adapter)

### Software Requirements
- Windows 10 (1803 or newer) or Windows 11
- .NET Framework 4.8 or .NET 6.0+
- Administrative privileges
- Optional: TOR Browser or TOR Expert Bundle (for TOR functionality)

### Dependent Packages
- Colorful.Console
- Spectre.Console
- System.Management

## Installation Guide

### Quick Start

1. **Download the latest release** from the releases page
2. **Extract the archive** to a location of your choice
3. **Run as Administrator** - right-click `NetworkAdBlockBridge.exe` and select "Run as administrator"
4. **Configure your hotspot** - the default SSID is "RSR-WIN_ROUTER" with password "Aes2345##"
5. **Connect your devices** to the newly created Wi-Fi hotspot
6. **Monitor the dashboard** for real-time network statistics

### TOR Integration Setup

To enable TOR functionality:

1. Install TOR Browser or TOR Expert Bundle
2. Place `tor.exe` and its required DLLs in the `Tor` subfolder
3. The application will automatically configure and start TOR with the correct settings
4. Verify TOR is working by checking the "TOR proxy started successfully!" message

### Custom Ad List Configuration

NetworkAdBlockBridge comes with a default set of ad domains, but you can customize it:

1. Edit the `adlist.txt` file in the application directory
2. Add or remove domain entries (one per line)
3. Use the `refresh` command in the console to reload the list
4. Alternatively, import standard filter lists from AdBlock Plus or uBlock Origin

## Usage Scenarios

### Home Network with Enhanced Privacy

Create a secure home network that blocks ads and tracking across all devices:

1. Set up NetworkAdBlockBridge on a Windows laptop connected to your main internet connection
2. Connect all household devices (phones, tablets, smart TVs) to the created hotspot
3. Enjoy ad-free browsing and enhanced privacy on all connected devices

### Travel Router with Security Features

When traveling, transform your laptop into a secure Wi-Fi hotspot:

1. Connect your laptop to hotel/public Wi-Fi or mobile data
2. Run NetworkAdBlockBridge to create a secure secondary network
3. Connect your devices to your private network instead of public Wi-Fi
4. Enable TOR routing for additional privacy in untrusted environments

### Small Office Network Protection

Protect a small office network from unwanted content:

1. Deploy NetworkAdBlockBridge on a dedicated Windows machine
2. Connect the machine to your primary internet connection
3. Configure office devices to connect through the protected hotspot
4. Monitor network usage and blocked content through the dashboard
5. Export logs for compliance or review purposes

### Educational Network Control

For schools or educational settings:

1. Implement NetworkAdBlockBridge on a central Windows computer
2. Create a filtered hotspot for student devices
3. Block inappropriate content and ads automatically
4. Monitor usage and generate reports of network activity

## Advanced Configuration

### Custom Filtering Rules

Create your own filtering rules by modifying the `ApplyAdvancedFilterRules` method:

```csharp
if (host.Contains("specific-domain") && request.Contains("tracking-pattern")) {
    LogMessage($"[Filter] Custom rule blocked request for {host}");
    return (false, request);
}
```

### Bandwidth Management

Implement per-device bandwidth limits:

```csharp
// In the DeviceInfo class
public int BandwidthLimit { get; set; } = 0; // 0 = unlimited, otherwise in Kbps

// In the ProcessClientAsync method
if (device.BandwidthLimit > 0) {
    clientStream = new ThrottledStream(clientStream, device.BandwidthLimit * 1024 / 8);
}
```

### Custom Blocking Pages

Modify the blocked page response to show a custom message:

```csharp
private static async Task SendBlockedResponseAsync(NetworkStream clientStream, string reason = "")
{
    string blockedPage =
        "HTTP/1.1 403 Forbidden\r\n" +
        "Content-Type: text/html\r\n" +
        "Connection: close\r\n" +
        "\r\n" +
        "<html><head><title>Access Blocked</title>" +
        "<style>body{font-family:Arial;color:#333;text-align:center;}</style></head>" +
        "<body><h1>Access Blocked</h1>" +
        "<p>This request has been blocked by network policy.</p>" +
        (string.IsNullOrEmpty(reason) ? "" : $"<p>Reason: {reason}</p>") +
        "</body></html>";
    byte[] responseData = Encoding.ASCII.GetBytes(blockedPage);
    await clientStream.WriteAsync(responseData, 0, responseData.Length);
}
```

## Troubleshooting

### Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| Hotspot fails to start | Ensure your Wi-Fi adapter supports mobile hotspot functionality. Run `netsh wlan show drivers` to verify "Hosted network supported" is Yes. |
| Devices connect but have no internet | Check that IP forwarding is enabled. Run the service as Administrator. Verify your main internet connection is active. |
| High CPU usage | Check the adlist.txt size. Consider using the throttling feature by setting resource limits in the configuration. |
| TOR connection fails | Verify tor.exe and required DLLs are in the Tor subfolder. Check Windows firewall settings for blocking. |
| HTTPS sites not loading | HTTPS interception requires proper certificate setup. Check certificate trust settings. |

### Performance Tuning

For better performance on resource-constrained systems:

1. Reduce the ad domain list size by focusing on most effective filters
2. Adjust ThreadPool settings to match your hardware capabilities
3. Disable TOR integration if not needed
4. Reduce logging detail level for long-term operation

## Contributing

NetworkAdBlockBridge is an open-source project welcoming contributions:

- **Bug Reports**: Submit detailed bug reports with reproduction steps
- **Feature Requests**: Suggest new features or improvements
- **Code Contributions**: Submit pull requests with new features or fixes
- **Documentation**: Help improve or translate documentation

## Security Considerations

- NetworkAdBlockBridge requires administrator privileges to configure network settings
- The default hotspot password should be changed on first use
- Traffic analysis is performed locally and no data is sent to external servers
- Always keep the application updated for the latest security improvements
- HTTPS interception has security implications; use with care in sensitive environments

## License

NetworkAdBlockBridge is licensed under the MIT License. See the LICENSE file for details.

## Acknowledgments

- The Spectre.Console and Colorful.Console teams for their excellent libraries
- The TOR Project for their privacy-enhancing tools
- Community contributors for their improvements and suggestions

---

**NetworkAdBlockBridge: Advanced Network Protection for Everyone**

*Transform your Windows laptop into a powerful network security appliance today!*
