import Foundation

enum SslPinningError: Error, LocalizedError {
    case emptyKeyRegistry

    var errorDescription: String? {
        switch self {
        case .emptyKeyRegistry:
            return "The key registry returned no pinning entries."
        }
    }
}

struct SslPinningInitializer {
    private let fetcher: KeysFetcher

    init(fetcher: KeysFetcher = KeysFetcher()) {
        self.fetcher = fetcher
    }

    func initialize(config: SslPinningConfig) async throws -> URLSession {
        let response = try await fetcher.fetch(from: config.endpointUrl)
        let payloadData = try JSONEncoder().encode(response.payload)
        try SignatureVerifier.verifyPayloadSignature(
            payloadJSON: payloadData,
            signatureBase64: response.signature,
            signingKeyBase64: config.signingKeyBase64
        )
        guard !response.payload.keys.isEmpty else {
            throw SslPinningError.emptyKeyRegistry
        }
        return PinnedSessionFactory.create(keys: response.payload.keys)
    }
}
