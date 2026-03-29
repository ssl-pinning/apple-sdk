import Foundation
import Security
import CryptoKit

/// URLSessionDelegate that pins SPKI SHA-256 hashes of server certificates.
final class PinningDelegate: NSObject, URLSessionDelegate, @unchecked Sendable {
    private let keys: [KeysResponse.KeyItem]

    init(keys: [KeysResponse.KeyItem]) {
        self.keys = keys
    }

    // Exposed for testing
    func testDomainMatches(pattern: String, host: String) -> Bool {
        domainMatches(pattern: pattern, host: host)
    }

    nonisolated func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        let host = challenge.protectionSpace.host
        let pinnedKeys = keys.filter { domainMatches(pattern: $0.domainName, host: host) }

        if pinnedKeys.isEmpty {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        guard let spkiHash = extractLeafSPKIHash(from: serverTrust) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        if pinnedKeys.contains(where: { $0.key == spkiHash }) {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }

    private func domainMatches(pattern: String, host: String) -> Bool {
        let p = pattern.lowercased().trimmingCharacters(in: .whitespaces)
        let h = host.lowercased()
        if p.hasPrefix("*.") {
            let suffix = "." + String(p.dropFirst(2))
            guard h.hasSuffix(suffix) else { return false }
            let subdomain = String(h.dropLast(suffix.count))
            return !subdomain.isEmpty && !subdomain.contains(".")
        }
        return p == h
    }

    private func extractLeafSPKIHash(from serverTrust: SecTrust) -> String? {
        guard let chain = SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate],
              let leaf = chain.first,
              let publicKey = SecCertificateCopyKey(leaf),
              let keyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            return nil
        }
        guard let header = spkiHeader(for: publicKey) else { return nil }

        var spki = Data(header)
        spki.append(keyData)
        let hash = SHA256.hash(data: spki)
        return Data(hash).base64EncodedString()
    }

    private func spkiHeader(for key: SecKey) -> [UInt8]? {
        guard let attrs = SecKeyCopyAttributes(key) as? [String: Any] else { return nil }
        let type = attrs[kSecAttrKeyType as String] as? String
        let size = attrs[kSecAttrKeySizeInBits as String] as? Int

        let rsaType = kSecAttrKeyTypeRSA as String
        let ecType = kSecAttrKeyTypeEC as String

        switch (type, size) {
        case (rsaType, 2048):
            return [0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09,
                    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
                    0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0F, 0x00]
        case (rsaType, 4096):
            return [0x30, 0x82, 0x02, 0x22, 0x30, 0x0D, 0x06, 0x09,
                    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
                    0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0F, 0x00]
        case (ecType, 256):
            return [0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86,
                    0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
                    0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03,
                    0x42, 0x00]
        case (ecType, 384):
            return [0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2A, 0x86,
                    0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x05, 0x2B,
                    0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00]
        default:
            return nil
        }
    }
}

enum PinnedSessionFactory {
    static func create(keys: [KeysResponse.KeyItem]) -> URLSession {
        let delegate = PinningDelegate(keys: keys)
        return URLSession(
            configuration: .default,
            delegate: delegate,
            delegateQueue: nil
        )
    }

    static func createPlain() -> URLSession {
        URLSession(configuration: .default)
    }
}
