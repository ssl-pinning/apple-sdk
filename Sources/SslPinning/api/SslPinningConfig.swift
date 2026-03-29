/// Configuration for initializing the SSL pinning SDK.
public struct SslPinningConfig: Sendable {
    /// URL of the signed key registry endpoint.
    public let endpointUrl: String
    /// Base64-encoded RSA public key used to verify the registry signature.
    public let signingKeyBase64: String

    public init(endpointUrl: String, signingKeyBase64: String) {
        self.endpointUrl = endpointUrl
        self.signingKeyBase64 = signingKeyBase64
    }
}
