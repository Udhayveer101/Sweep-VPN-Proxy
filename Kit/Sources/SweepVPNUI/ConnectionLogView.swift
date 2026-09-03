import SwiftUI
import SweepVPNCore

/// The organised replacement for the one-line error banner.
///
/// A banner could say *that* a connect failed and, at best, name the rung. It
/// could not say *where* in the sequence it died — which is the only thing that
/// distinguishes "the relay is gone" from "the Worker was unreachable" from
/// "the gateway reset the handshake". The extension already records that
/// sequence and persists it to the shared app group precisely because the
/// process that produced it is dead by the time anyone reads it; this screen is
/// where it becomes visible.
struct ConnectionLogView: View {
    @ObservedObject var model: VPNViewModel
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            if let failure = model.tunnelFailure {
                summary(failure)
                Divider()
                trail(failure.trail)
            } else {
                empty
            }
        }
        .frame(minWidth: 460, minHeight: 420)
    }

    private var header: some View {
        HStack {
            Text("Connection log").font(.headline)
            Spacer()
            if let failure = model.tunnelFailure {
                Button("Copy") { copy(failure) }
            }
            Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
        }
        .padding(16)
    }

    /// The verdict, before the detail: what failed, on which route, and when.
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

    /// Oldest first, so reading top to bottom follows the connect in the order
    /// it actually happened and the last line is where it stopped.
    private func trail(_ events: [String]) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 3) {
                ForEach(Array(events.enumerated()), id: \.offset) { index, line in
                    Text(line)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(index == events.count - 1 ? .primary : .secondary)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .padding(16)
        }
    }

    private var empty: some View {
        VStack(spacing: 8) {
            Image(systemName: "checkmark.seal").font(.largeTitle).foregroundStyle(.secondary)
            Text("No failed connection recorded.").font(.callout)
            Text("This clears itself as soon as a tunnel comes up.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(24)
    }

    /// Addresses and hostnames are already scrubbed by `Diagnostics`, so this is
    /// safe to hand to anyone helping debug it.
    private func copy(_ failure: TunnelFailure) {
        let text = ([failure.kind, failure.detail, failure.rung ?? ""]
                        .filter { !$0.isEmpty }
                        .joined(separator: " · ")) + "\n" + failure.trail.joined(separator: "\n")
        #if os(macOS)
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        #else
        UIPasteboard.general.string = text
        #endif
    }
}
