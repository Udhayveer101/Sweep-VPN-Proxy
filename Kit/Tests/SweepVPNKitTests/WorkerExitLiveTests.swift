#if os(macOS)
import XCTest
import Network
@testable import SweepVPNKit

/// Drives the real proxy against the real Worker. Skipped unless
/// SWEEP_LIVE_WORKER_URL and SWEEP_LIVE_WORKER_TOKEN are set, because a test
/// that needs the internet has no business failing the ordinary suite.
final class WorkerExitLiveTests: XCTestCase {

    func testProxyReachesAPublicSiteThroughTheWorker() throws {
        let env = ProcessInfo.processInfo.environment
        guard let urlText = env["SWEEP_LIVE_WORKER_URL"],
              let token = env["SWEEP_LIVE_WORKER_TOKEN"],
              let url = URL(string: urlText) else {
            throw XCTSkip("set SWEEP_LIVE_WORKER_URL and SWEEP_LIVE_WORKER_TOKEN")
        }
        let settings = RelayTunnelSettings(enabled: true, workerURL: url, token: token)

        let proxy = try XCTUnwrap(LocalProxy(port: 19080, upstream: .worker(settings)))
        let listening = expectation(description: "listening")
        proxy.start(upstream: .worker(settings)) { state in
            if case .listening = state { listening.fulfill() }
        }
        wait(for: [listening], timeout: 5)
        defer { proxy.stop() }

        let curl = Process()
        curl.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
        curl.arguments = ["-s", "-x", "socks5h://127.0.0.1:19080", "--max-time", "25",
                          "-o", "/dev/null", "-w", "%{http_code}",
                          "https://checkip.amazonaws.com"]
        let pipe = Pipe()
        curl.standardOutput = pipe
        try curl.run()
        curl.waitUntilExit()
        let code = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        XCTAssertEqual(code, "200", "curl through the Worker proxy said \(code)")
    }
}
#endif
