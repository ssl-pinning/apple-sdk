import Foundation

/// Entry point for the SSL pinning SDK.
public final class SslPinningClient: @unchecked Sendable {
    private let pinnedSession: URLSession
    private let plainSession: URLSession

    private init(pinnedSession: URLSession, plainSession: URLSession) {
        self.pinnedSession = pinnedSession
        self.plainSession = plainSession
    }

    /// Initializes the SDK by fetching and verifying the remote key registry.
    /// Fails closed: any error returns `.failure`.
    public static func initialize(config: SslPinningConfig) async -> Result<SslPinningClient, Error> {
        do {
            let sessions = try await SslPinningInitializer().initialize(config: config)
            return .success(SslPinningClient(pinnedSession: sessions.pinned, plainSession: sessions.plain))
        } catch {
            return .failure(error)
        }
    }

    /// Returns a URLSession configured with certificate pinning.
    public func createPinnedSession() -> URLSession { pinnedSession }

    /// Returns a plain URLSession without certificate pinning.
    public func createPlainSession() -> URLSession { plainSession }
}
