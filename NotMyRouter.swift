import Cocoa
import WebKit

// ============================================================
// NotMyRouter - Native macOS App
// Launches daemon + server, then shows dashboard in WKWebView
// ============================================================

let APP_DIR  = NSHomeDirectory() + "/network-monitor"
let LOG_DIR  = APP_DIR + "/logs"
let PORT     = 8457
let URL_STR  = "http://localhost:\(PORT)"
let NETPROBE = NSHomeDirectory() + "/bin/netprobe"
let SERVER   = APP_DIR + "/server.py"
let DAEMON_PID = LOG_DIR + "/.netprobe.pid"
let SERVER_PID = LOG_DIR + "/server.pid"

// ============================================================
// Process management
// ============================================================

func isProcessRunning(pidFile: String) -> Bool {
    guard let pidStr = try? String(contentsOfFile: pidFile, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
          let pid = Int32(pidStr) else { return false }
    return kill(pid, 0) == 0
}

func isPortListening(_ port: Int) -> Bool {
    let sock = socket(AF_INET, SOCK_STREAM, 0)
    guard sock >= 0 else { return false }
    defer { close(sock) }
    var addr = sockaddr_in()
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_port = in_port_t(port).bigEndian
    addr.sin_addr.s_addr = inet_addr("127.0.0.1")
    let result = withUnsafePointer(to: &addr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            connect(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
    return result == 0
}

func shellExec(_ cmd: String) {
    let task = Process()
    task.launchPath = "/bin/bash"
    task.arguments = ["-c", cmd]
    task.standardOutput = FileHandle.nullDevice
    task.standardError = FileHandle.nullDevice
    try? task.run()
}

func startServices() {
    // Start daemon if not running
    if !isProcessRunning(pidFile: DAEMON_PID) {
        shellExec("\"\(NETPROBE)\" --daemon")
    }
    // Start server if port not listening
    if !isPortListening(PORT) {
        shellExec("cd \"\(APP_DIR)\" && /usr/bin/python3 \"\(SERVER)\" > \"\(LOG_DIR)/server.log\" 2>&1 &")
        // Wait for server
        for _ in 0..<40 {
            if isPortListening(PORT) { break }
            Thread.sleep(forTimeInterval: 0.25)
        }
    }
}

// ============================================================
// App Delegate
// ============================================================

class AppToolbarDelegate: NSObject, NSToolbarDelegate {
    func toolbarDefaultItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] { [] }
    func toolbarAllowedItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] { [] }
}

class AppDelegate: NSObject, NSApplicationDelegate {
    var window: NSWindow!
    var webView: WKWebView!
    let toolbarDelegate = AppToolbarDelegate()

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Start backend services
        startServices()

        // Configure WebView
        let config = WKWebViewConfiguration()
        config.preferences.setValue(true, forKey: "developerExtrasEnabled")

        webView = WKWebView(frame: .zero, configuration: config)
        webView.customUserAgent = "NotMyRouter/1.0"

        // Create window
        let screenFrame = NSScreen.main?.visibleFrame ?? NSRect(x: 0, y: 0, width: 1400, height: 900)
        let width: CGFloat = min(1440, screenFrame.width * 0.85)
        let height: CGFloat = min(900, screenFrame.height * 0.85)
        let x = screenFrame.origin.x + (screenFrame.width - width) / 2
        let y = screenFrame.origin.y + (screenFrame.height - height) / 2

        window = NSWindow(
            contentRect: NSRect(x: x, y: y, width: width, height: height),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.title = "NotMyRouter"
        window.titlebarAppearsTransparent = true
        window.collectionBehavior.insert(.fullScreenPrimary)

        // Toolbar gives the titlebar proper height for dragging and double-click zoom
        let toolbar = NSToolbar(identifier: "main")
        toolbar.delegate = toolbarDelegate
        // toolbar separator removed in macOS 15+
        window.toolbar = toolbar
        window.toolbarStyle = .unified
        window.backgroundColor = NSColor(red: 0.07, green: 0.07, blue: 0.10, alpha: 1.0)
        window.isReleasedWhenClosed = false
        window.minSize = NSSize(width: 800, height: 500)

        // Container fills the window; WebView is pinned below the titlebar
        // so the titlebar area stays draggable
        let container = NSView(frame: .zero)
        container.wantsLayer = true
        container.layer?.backgroundColor = NSColor(red: 0.07, green: 0.07, blue: 0.10, alpha: 1.0).cgColor
        window.contentView = container

        webView.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(webView)

        // Pin WebView edges, but top to the content layout guide (below titlebar)
        let guide = window.contentLayoutGuide as! NSLayoutGuide
        NSLayoutConstraint.activate([
            webView.topAnchor.constraint(equalTo: guide.topAnchor),
            webView.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            webView.trailingAnchor.constraint(equalTo: container.trailingAnchor),
            webView.bottomAnchor.constraint(equalTo: container.bottomAnchor),
        ])

        // Load dashboard
        if let url = Foundation.URL(string: URL_STR) {
            webView.load(URLRequest(url: url))
        }

        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return true
    }
}

// ============================================================
// Main
// ============================================================

let app = NSApplication.shared
app.setActivationPolicy(.regular)

let delegate = AppDelegate()
app.delegate = delegate
app.run()
