import Foundation

public final class SslPinningClient: @unchecked Sendable {
    private let session: URLSession

    private init(session: URLSession) {
        self.session = session
    }

    /// Fetches the key registry, verifies its signature, and returns a ready client.
    /// Fails closed: any error returns `.failure`.
    public static func initialize(config: SslPinningConfig) async -> Result<SslPinningClient, Error> {
        do {
            let session = try await SslPinningInitializer().initialize(config: config)
            return .success(SslPinningClient(session: session))
        } catch {
            return .failure(error)
        }
    }

    /// Returns a URLSession configured with certificate pinning.
    public func create() -> URLSession { session }
}
