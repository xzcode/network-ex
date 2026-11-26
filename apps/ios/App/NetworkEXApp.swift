import SwiftUI
import Combine
import NetworkExtension

@main
@MainActor
struct NetworkEXApp: App {
    @StateObject private var model = NetworkModel()
    var body: some Scene {
        WindowGroup { ContentView(model: model) }
    }
}

@MainActor
final class NetworkModel: ObservableObject {
    @Published var profile = "unavailable"
    @Published var busy = false
    @Published var systemStatus: NEVPNStatus = .invalid
    @Published var status: MobileStatus?
    @Published var message = ""
    private var manager: NETunnelProviderManager?
    private var polling = false
    private var generation = 0

    private var providerID: String? {
        Bundle.main.object(forInfoDictionaryKey: "NetworkEXProviderID") as? String
    }
    private func failure(_ text: String) -> NSError {
        NSError(domain: "NetworkEX.App", code: 1, userInfo: [NSLocalizedDescriptionKey: text])
    }
    private func loadManager(create: Bool) async throws -> NETunnelProviderManager? {
        guard let providerID, !providerID.isEmpty, !providerID.contains("$(") else {
            throw failure("Packet tunnel extension identifier is missing")
        }
        let all = try await NETunnelProviderManager.loadAllFromPreferences()
        let ours = all.filter {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == providerID
        }
        guard ours.count <= 1 else {
            throw failure("Multiple Network EX VPN profiles; remove duplicates in Settings")
        }
        if let existing = ours.first { return existing }
        guard create else { return nil }
        let item = NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = providerID
        proto.serverAddress = "Network EX"
        // No credentials, invitation or file path in providerConfiguration.
        proto.providerConfiguration = ["schema": 1]
        item.protocolConfiguration = proto
        item.localizedDescription = "Network EX"
        item.isEnabled = true
        item.isOnDemandEnabled = false
        try await item.saveToPreferences()
        try await item.loadFromPreferences()
        return item
    }
    var active: Bool {
        [.connecting, .connected, .reasserting, .disconnecting].contains(systemStatus)
    }
    var canConnect: Bool { profile == "ready" && !busy && !active }
    func refresh() async {
        if busy || polling { return }
        polling = true
        defer { polling = false }
        let g = generation
        profile = NEXProfileState()
        do {
            if manager == nil { manager = try await loadManager(create: false) }
            guard g == generation else { return }
            systemStatus = manager?.connection.status ?? .disconnected
            guard [.connected, .reasserting].contains(systemStatus),
                  let session = manager?.connection as? NETunnelProviderSession else {
                status = nil
                return
            }
            try session.sendProviderMessage(Data("status".utf8)) { [weak self] response in
                Task { @MainActor in
                    guard let self, self.generation == g,
                          [.connected, .reasserting].contains(self.manager?.connection.status ?? .invalid) else { return }
                    self.status = response.flatMap { try? JSONDecoder().decode(MobileStatus.self, from: $0) }
                }
            }
        } catch { message = error.localizedDescription }
    }
    func enroll(server: String, name: String, invite: String, ca: String) async {
        guard !busy && !polling && !active && profile == "missing" else { return }
        busy = true
        generation += 1
        defer { busy = false; profile = NEXProfileState() }
        let result = await Task.detached(priority: .userInitiated) {
            NEXEnroll(server, name, invite, ca)
        }.value
        message = result ?? String(localized: "Registered. Ask the administrator to approve this device, then connect.")
    }
    func connect() async {
        guard canConnect && !polling else { return }
        busy = true
        generation += 1
        status = nil
        defer { busy = false }
        do {
            guard let item = try await loadManager(create: true) else { throw failure("VPN configuration unavailable") }
            manager = item
            item.isEnabled = true
            item.isOnDemandEnabled = false
            try await item.saveToPreferences()
            try await item.loadFromPreferences()
            try item.connection.startVPNTunnel()
            systemStatus = item.connection.status
            message = String(localized: "Starting VPN. The device must be approved.")
        } catch { message = error.localizedDescription }
    }
    func disconnect() {
        guard !busy else { return }
        generation += 1
        status = nil
        manager?.connection.stopVPNTunnel()
        systemStatus = manager?.connection.status ?? .disconnected
    }
    func forget() async {
        guard !busy && !polling && !active else { return }
        busy = true
        generation += 1
        defer { busy = false; profile = NEXProfileState() }
        do {
            if let item = try await loadManager(create: false) {
                guard [.invalid, .disconnected].contains(item.connection.status) else {
                    throw failure("Disconnect VPN before forgetting its identity")
                }
                try await item.removeFromPreferences()
                manager = nil
            }
            if let error = NEXForget() { throw failure(error) }
            systemStatus = .disconnected
            status = nil
            message = String(localized: "Local identity removed. Server revocation is separate.")
        } catch { message = error.localizedDescription }
    }
}

struct MobileStatus: Decodable {
    struct Peer: Decodable, Identifiable {
        let id: String
        let name: String
        let ip: String
    }
    struct Device: Decodable { let name: String; let ip: String }
    struct Managed: Decodable {
        let state: String
        let device: Device
        let peers: [Peer]?
        let error: String?
    }
    struct Tunnel: Decodable {
        struct Link: Decodable { let ip: String; let mode: String; let rx_bytes: String; let tx_bytes: String }
        let state: String
        let ip: String
        let peers: [Link]?
    }
    let running: Bool
    let error: String?
    let managed: Managed?
    let tunnel: Tunnel?
}

@MainActor
struct ContentView: View {
    @ObservedObject var model: NetworkModel
    @State private var server = ""
    @State private var name = "iPhone"
    @State private var invite = ""
    @State private var ca = ""
    @State private var advanced = false
    @State private var confirmForget = false
    private let timer = Timer.publish(every: 2, on: .main, in: .common).autoconnect()

    var body: some View {
        NavigationStack {
            Form {
                Section("Connection") {
                    LabeledContent("VPN", value: statusLabel)
                    if let ip = model.status?.tunnel?.ip { LabeledContent("Virtual IP", value: ip) }
                    if let state = model.status?.managed?.state { LabeledContent("Authorization", value: state) }
                    if model.profile == "ready" {
                        Button(model.active ? "Disconnect" : "Connect") {
                            if model.active { model.disconnect() } else { Task { await model.connect() } }
                        }.disabled(model.busy || model.systemStatus == .disconnecting)
                    }
                    if model.busy { ProgressView() }
                }
                if model.profile == "missing" {
                    Section("Join a network") {
                        TextField("Management HTTPS URL", text: $server)
                            .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                        TextField("Device name", text: $name)
                        SecureField("One-time invitation", text: $invite)
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                        DisclosureGroup("Private CA (optional)", isExpanded: $advanced) {
                            TextEditor(text: $ca).frame(minHeight: 100)
                                .textInputAutocapitalization(.never).autocorrectionDisabled()
                        }
                        Button("Register device") {
                            let code = invite, cert = ca
                            invite = ""; ca = ""
                            Task { await model.enroll(server: server, name: name, invite: code, ca: cert) }
                        }.disabled(model.busy || invite.count != 43 || server.isEmpty || name.isEmpty)
                    }
                } else if model.profile == "unavailable" {
                    Section { Text("Keychain unavailable. Unlock the device and verify signing entitlements.").foregroundStyle(.secondary) }
                }
                Section("Authorized peers") {
                    if let peers = model.status?.managed?.peers, !peers.isEmpty {
                        ForEach(peers) { peer in
                            VStack(alignment: .leading, spacing: 5) {
                                Text(peer.name).font(.headline)
                                Text(peer.ip).monospacedDigit().foregroundStyle(.secondary)
                                if let link = model.status?.tunnel?.peers?.first(where: { $0.ip == peer.ip }) {
                                    Text("\(link.mode) · RX \(link.rx_bytes) B · TX \(link.tx_bytes) B").font(.caption)
                                }
                            }
                        }
                    } else { Text("No current peer information").foregroundStyle(.secondary) }
                }
                if !model.message.isEmpty || !(model.status?.error ?? "").isEmpty || !(model.status?.managed?.error ?? "").isEmpty {
                    Section("Status") {
                        if !model.message.isEmpty { Text(model.message) }
                        if let e = model.status?.error, !e.isEmpty { Text(e) }
                        if let e = model.status?.managed?.error, !e.isEmpty { Text(e) }
                    }
                }
                Section {
                    Text("Only authorized private IPv4 peers are routed through this VPN. Other traffic uses your normal network. This is not a full Internet VPN.").font(.footnote).foregroundStyle(.secondary)
                    if model.profile == "ready" {
                        Button("Forget local identity", role: .destructive) { confirmForget = true }
                            .disabled(model.active || model.busy)
                    }
                }
            }
            .navigationTitle("Network EX")
            .confirmationDialog("Delete local identity? The server device is not revoked.", isPresented: $confirmForget) {
                Button("Forget local identity", role: .destructive) { Task { await model.forget() } }
                Button("Cancel", role: .cancel) {}
            }
            .task { await model.refresh() }
            .onReceive(timer) { _ in Task { await model.refresh() } }
        }
    }

    private var statusLabel: String {
        switch model.systemStatus {
        case .connected: return String(localized: "Connected")
        case .connecting: return String(localized: "Connecting")
        case .disconnecting: return String(localized: "Disconnecting")
        case .reasserting: return String(localized: "Reconnecting")
        default: return String(localized: "Disconnected")
        }
    }
}
