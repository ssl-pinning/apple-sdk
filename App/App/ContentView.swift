import SwiftUI
import SslPinning

// MARK: - App State

enum AppState {
    case loading
    case error(String)
    case ready
}

enum RequestStatus {
    case idle
    case inFlight
    case success(String)
    case failure(String)
}

struct RequestLogEntry: Identifiable {
    let id = UUID()
    let timestamp = Date()
    let usePinned: Bool
    let url: String
    let statusCode: Int?
    let headers: [(key: String, value: String)]
    let error: String?

    var sessionLabel: String { usePinned ? "Pinned" : "Plain" }
}

// MARK: - ContentView

struct ContentView: View {
    @State private var appState: AppState = .loading
    @State private var pinnedSession: URLSession? = nil
    @State private var plainSession: URLSession? = nil
    @State private var usePinned = false
    @State private var urlInput = "https://www.google.com"
    @State private var requestStatus: RequestStatus = .idle
    @State private var log: [RequestLogEntry] = []

    var body: some View {
        switch appState {
        case .loading:
            loadingView
        case .error(let message):
            errorView(message: message)
        case .ready:
            readyView
        }
    }

    // MARK: Loading

    private var loadingView: some View {
        VStack(spacing: 16) {
            ProgressView()
            Text("Initializing SSL Pinning…")
                .foregroundStyle(.secondary)
        }
        .task { await initSDK() }
    }

    // MARK: Error

    private func errorView(message: String) -> some View {
        VStack(spacing: 16) {
            Image(systemName: "xmark.shield")
                .font(.largeTitle)
                .foregroundStyle(.red)
            Text("Initialization Failed")
                .font(.headline)
            Text(message)
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)
        }
        .padding()
    }

    // MARK: Ready

    private var readyView: some View {
        VStack(spacing: 16) {
            Text("SSL Pinning")
                .font(.largeTitle.bold())
                .padding(.top)

            Toggle(isOn: $usePinned) {
                Label(
                    usePinned ? "Pinned Session" : "Plain Session",
                    systemImage: usePinned ? "lock.shield" : "lock.open"
                )
            }
            .toggleStyle(.button)
            .tint(usePinned ? .green : .gray)

            VStack(alignment: .leading, spacing: 4) {
                Text("URL").font(.caption).foregroundStyle(.secondary)
                TextField("https://…", text: $urlInput)
                    .textFieldStyle(.roundedBorder)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .keyboardType(.URL)
            }

            Button("Send Request") {
                Task { await sendRequest() }
            }
            .buttonStyle(.borderedProminent)
            .disabled(requestStatus == .inFlight)

            statusIndicator
                .frame(minHeight: 24)

            Divider()

            if log.isEmpty {
                Text("No requests yet")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 8) {
                        ForEach(log.reversed()) { entry in
                            RequestLogRow(entry: entry)
                        }
                    }
                    .padding(.horizontal)
                    .padding(.bottom)
                }
            }
        }
        .padding(.horizontal)
    }

    // MARK: Status Indicator

    @ViewBuilder
    private var statusIndicator: some View {
        switch requestStatus {
        case .idle:
            Circle()
                .fill(.gray.opacity(0.4))
                .frame(width: 16, height: 16)
        case .inFlight:
            ProgressView().scaleEffect(0.8)
        case .success(let message):
            HStack(spacing: 6) {
                Circle().fill(.green).frame(width: 12, height: 12)
                Text(message).font(.caption).foregroundStyle(.secondary)
            }
        case .failure(let message):
            HStack(spacing: 6) {
                Circle().fill(.red).frame(width: 12, height: 12)
                Text(message).font(.caption).foregroundStyle(.red).lineLimit(2)
            }
        }
    }

    // MARK: Actions

    private func initSDK() async {
        guard let endpoint = Bundle.main.infoDictionary?["SSL_PINNING_ENDPOINT"] as? String,
              let signingKey = Bundle.main.infoDictionary?["SSL_PINNING_SIGNING_KEY_B64"] as? String else {
            appState = .error("Missing SSL_PINNING_ENDPOINT or SSL_PINNING_SIGNING_KEY_B64 in Info.plist.\nCopy App/Config.xcconfig.example to App/Config.xcconfig and fill in real values.")
            return
        }

        let config = SslPinningConfig(endpointUrl: endpoint, signingKeyBase64: signingKey)
        let result = await SslPinningClient.initialize(config: config)
        switch result {
        case .success(let client):
            pinnedSession = client.create()
            plainSession = URLSession(configuration: .default)
            appState = .ready
        case .failure(let error):
            appState = .error(error.localizedDescription)
        }
    }

    private func sendRequest() async {
        guard let url = URL(string: urlInput) else {
            requestStatus = .failure("Invalid URL: \(urlInput)")
            return
        }
        let sessionPinned = usePinned
        guard let session = sessionPinned ? pinnedSession : plainSession else {
            requestStatus = .failure("Session not initialized")
            return
        }

        requestStatus = .inFlight

        do {
            let (_, response) = try await session.data(from: url)
            let http = response as? HTTPURLResponse
            let statusCode = http?.statusCode
            let headers = (http?.allHeaderFields ?? [:])
                .compactMap { k, v -> (key: String, value: String)? in
                    guard let key = k as? String, let value = v as? String else { return nil }
                    return (key: key, value: value)
                }
                .sorted { $0.key < $1.key }

            log.append(RequestLogEntry(
                usePinned: sessionPinned,
                url: urlInput,
                statusCode: statusCode,
                headers: headers,
                error: nil
            ))
            requestStatus = .success("HTTP \(statusCode.map(String.init) ?? "?") — \(sessionPinned ? "Pinned" : "Plain")")
        } catch {
            log.append(RequestLogEntry(
                usePinned: sessionPinned,
                url: urlInput,
                statusCode: nil,
                headers: [],
                error: error.localizedDescription
            ))
            requestStatus = .failure(error.localizedDescription)
        }
    }
}

// MARK: - RequestLogRow

extension RequestStatus: Equatable {}

struct RequestLogRow: View {
    let entry: RequestLogEntry
    @State private var expanded = false

    private static let timeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f
    }()

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Button {
                withAnimation(.easeInOut(duration: 0.15)) { expanded.toggle() }
            } label: {
                HStack(spacing: 8) {
                    Circle()
                        .fill(entry.error == nil ? Color.green : Color.red)
                        .frame(width: 8, height: 8)
                    Text(Self.timeFormatter.string(from: entry.timestamp))
                        .font(.caption2.monospaced())
                        .foregroundStyle(.secondary)
                    Label(entry.sessionLabel, systemImage: entry.usePinned ? "lock.shield" : "lock.open")
                        .font(.caption.bold())
                        .foregroundStyle(entry.usePinned ? Color.green : Color.gray)
                    if let code = entry.statusCode {
                        Text("HTTP \(code)")
                            .font(.caption.monospaced())
                            .foregroundStyle(.primary)
                    } else if entry.error != nil {
                        Text("ERROR")
                            .font(.caption.monospaced())
                            .foregroundStyle(.red)
                    }
                    Spacer()
                    Image(systemName: expanded ? "chevron.up" : "chevron.down")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
            .buttonStyle(.plain)

            if expanded {
                VStack(alignment: .leading, spacing: 2) {
                    debugRow("url", entry.url)
                    debugRow("session", entry.sessionLabel)
                    if let err = entry.error {
                        debugRow("error", err).foregroundStyle(.red)
                    } else {
                        ForEach(Array(entry.headers.enumerated()), id: \.offset) { _, header in
                            debugRow(header.key, header.value)
                        }
                    }
                }
                .padding(.leading, 16)
                .padding(.top, 2)
            }
        }
        .padding(8)
        .background(.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
    }

    @ViewBuilder
    private func debugRow(_ key: String, _ value: String) -> some View {
        HStack(alignment: .top, spacing: 4) {
            Text(key + ":")
                .font(.caption2.monospaced().bold())
                .foregroundStyle(.secondary)
                .fixedSize()
            Text(value)
                .font(.caption2.monospaced())
                .lineLimit(4)
                .multilineTextAlignment(.leading)
        }
    }
}

#Preview {
    ContentView()
}
