import SwiftUI
import SweepVPNCore

/// The live connection journal.
///
/// # Why this is not the old error log
///
/// The previous version rendered `model.tunnelFailure` and nothing else, which
/// meant it could only ever describe a connect that had already *failed*. The
/// two cases that actually needed reading were invisible: a connect still in
/// progress, and a connect stuck in "connecting" forever — neither produces a
/// failure record, so both showed "No failed connection recorded".
///
/// This reads the shared journal instead. Both processes write to it, it
/// survives the extension exiting, it is grouped into runs with elapsed times,
/// and it can be opened at any moment — including while a connect is hanging,
/// which is the whole point.
struct ConnectionLogView: View {
    @ObservedObject var model: VPNViewModel
    @Environment(\.dismiss) private var dismiss

    @State private var minimumLevel: LogEntry.Level = .debug
    @State private var follow = true

    private static let levelOrder: [LogEntry.Level] = [.debug, .info, .warn, .error]

    private var visible: [LogEntry] {
        let floor = Self.levelOrder.firstIndex(of: minimumLevel) ?? 0
        return model.logEntries.filter {
            (Self.levelOrder.firstIndex(of: $0.level) ?? 0) >= floor
        }
    }

    /// Newest run first, but the lines inside a run stay oldest-first — reading
    /// a run top to bottom follows the connect in the order it happened, and the
    /// last line is where it stopped.
    private var runs: [(run: String, entries: [LogEntry])] {
        var order: [String] = []
        var grouped: [String: [LogEntry]] = [:]
        for entry in visible {
            if grouped[entry.run] == nil { order.append(entry.run) }
            grouped[entry.run, default: []].append(entry)
        }
        return order.reversed().map { ($0, grouped[$0] ?? []) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            if let failure = model.tunnelFailure { summary(failure); Divider() }
            controls
            Divider()
            if visible.isEmpty { empty } else { journal }
            Divider()
            footer
        }
        .frame(minWidth: 640, minHeight: 520)
        .onAppear { model.startWatchingLog() }
        .onDisappear { model.stopWatchingLog() }
    }

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text("Connection log").font(.headline)
                Text(model.presentation.headline).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Button("Copy") { model.copyLog() }
            Button("Clear") { model.clearLog() }
            Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
        }
        .padding(16)
    }

    /// The last recorded failure, kept above the journal. The journal says where
    /// a connect stopped; this says what the extension called it.
    private func summary(_ failure: TunnelFailure) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                Text(failure.detail.isEmpty ? failure.kind : failure.detail)
                    .font(.callout).fontWeight(.medium)
                    .multilineTextAlignment(.leading)
            }
            Text([failure.rung.map { "Route: \($0)" },
                  "At \(failure.at.formatted(date: .abbreviated, time: .standard))"]
                    .compactMap { $0 }.joined(separator: " · "))
                .font(.caption).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
    }

    private var controls: some View {
        HStack(spacing: 12) {
            Picker("Level", selection: $minimumLevel) {
                Text("All").tag(LogEntry.Level.debug)
                Text("Info").tag(LogEntry.Level.info)
                Text("Warnings").tag(LogEntry.Level.warn)
                Text("Errors").tag(LogEntry.Level.error)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(maxWidth: 320)
            Spacer()
            Toggle("Follow", isOn: $follow).toggleStyle(.switch).font(.caption)
        }
        .padding(.horizontal, 16).padding(.vertical, 10)
    }

    private var journal: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(runs, id: \.run) { group in
                        runHeader(group.run, entries: group.entries)
                        ForEach(group.entries) { row($0) }
                    }
                    // Anchor for follow-mode. The newest run is at the top, so
                    // following means scrolling *there*, not to the bottom.
                    Color.clear.frame(height: 1).id("top")
                }
                .padding(.vertical, 8)
            }
            .onChange(of: model.logEntries.count) {
                guard follow else { return }
                withAnimation { proxy.scrollTo("top", anchor: .top) }
            }
        }
    }

    /// One connect attempt, with how long it ran and how it ended.
    private func runHeader(_ run: String, entries: [LogEntry]) -> some View {
        let duration = entries.compactMap(\.elapsedMs).max()
        let failed = entries.contains { $0.level == .error }
        return HStack(spacing: 8) {
            Image(systemName: failed ? "xmark.octagon.fill" : "circle.dashed")
                .foregroundStyle(failed ? .red : .secondary)
            Text("Run \(run)").font(.caption.weight(.semibold))
            if let duration {
                Text(String(format: "%.1fs", Double(duration) / 1000))
                    .font(.caption).foregroundStyle(.secondary)
            }
            Text("· \(entries.count) steps").font(.caption).foregroundStyle(.secondary)
            Spacer()
            Text(entries.first?.at.formatted(date: .omitted, time: .standard) ?? "")
                .font(.caption2).foregroundStyle(.secondary)
        }
        .padding(.horizontal, 16).padding(.vertical, 8)
        .background(.quaternary.opacity(0.35))
    }

    /// One step. The elapsed column is the reason this reads like a build log:
    /// the gap between two lines is where the time actually went.
    private func row(_ entry: LogEntry) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Text(entry.elapsedMs.map { String(format: "+%.2fs", Double($0) / 1000) } ?? "—")
                .frame(width: 62, alignment: .trailing)
                .foregroundStyle(.secondary)
            Circle().fill(tint(entry.level)).frame(width: 6, height: 6).padding(.top, 5)
            Text("\(entry.process)/\(entry.phase)")
                .frame(width: 110, alignment: .leading)
                .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 1) {
                Text(entry.kind).foregroundStyle(tint(entry.level))
                if !entry.detail.isEmpty {
                    Text(entry.detail).foregroundStyle(.primary).textSelection(.enabled)
                }
            }
            Spacer(minLength: 0)
        }
        .font(.system(.caption, design: .monospaced))
        .padding(.horizontal, 16).padding(.vertical, 2)
    }

    private func tint(_ level: LogEntry.Level) -> Color {
        switch level {
        case .debug: return .secondary
        case .info:  return .primary
        case .warn:  return .orange
        case .error: return .red
        }
    }

    private var empty: some View {
        VStack(spacing: 8) {
            Image(systemName: "text.alignleft").font(.largeTitle).foregroundStyle(.secondary)
            Text("Nothing recorded yet.").font(.callout)
            Text("Press Connect and this fills in step by step, from both the app and the tunnel.")
                .font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(24)
    }

    /// Says plainly that the log is safe to hand over, because the first thing
    /// anyone does with a log is paste it somewhere.
    private var footer: some View {
        HStack {
            Image(systemName: "lock.shield").foregroundStyle(.secondary)
            Text("Addresses and hostnames are removed before anything is written here.")
            Spacer()
            Text("\(visible.count) of \(model.logEntries.count) lines")
        }
        .font(.caption2).foregroundStyle(.secondary)
        .padding(.horizontal, 16).padding(.vertical, 10)
    }
}
