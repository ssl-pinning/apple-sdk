import Foundation
import Security
import CryptoKit

// MARK: - PinningDelegate

final class PinningDelegate: NSObject, URLSessionDelegate, URLSessionTaskDelegate, @unchecked Sendable {
    private let pinnedHashes: [String]

    init(pinnedHashes: [String]) {
        self.pinnedHashes = pinnedHashes
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard
            challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
            let serverTrust = challenge.protectionSpace.serverTrust
        else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        var certificates: [SecCertificate] = []
        if let chain = SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate] {
            certificates = chain
        }

        guard let hash = spkiHashFromDER(cert: certificates[0]) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        if pinnedHashes.contains(hash) {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }

    // MARK: - SPKI hash extraction (mirrors Go's sha256(cert.RawSubjectPublicKeyInfo))

    private func spkiHashFromDER(cert: SecCertificate) -> String? {
        let certDER = SecCertificateCopyData(cert) as Data
        guard let spki = extractSPKIFromCertDER(certDER) else {
            return nil
        }
        let hash = Data(SHA256.hash(data: spki)).base64EncodedString()
        return hash
    }

    private func extractSPKIFromCertDER(_ der: Data) -> Data? {
        var idx = der.startIndex

        // 1. Certificate — outer SEQUENCE
        guard let certContent = readDERSequenceContent(der, idx: &idx) else { return nil }
        var tbsIdx = certContent.startIndex

        // 2. TBSCertificate — first nested SEQUENCE
        guard let tbsContent = readDERSequenceContent(certContent, idx: &tbsIdx) else { return nil }
        var fieldIdx = tbsContent.startIndex

        // 3. version [0] EXPLICIT — optional, tag 0xA0
        if fieldIdx < tbsContent.endIndex && tbsContent[fieldIdx] == 0xA0 {
            guard skipDERElement(tbsContent, idx: &fieldIdx) else { return nil }
        }

        // serialNumber, signature, issuer, validity, subject — 5 fields
        for _ in 0..<5 {
            guard skipDERElement(tbsContent, idx: &fieldIdx) else { return nil }
        }

        // 4. subjectPublicKeyInfo — the next element
        guard fieldIdx < tbsContent.endIndex else { return nil }
        let spkiStart = fieldIdx
        guard skipDERElement(tbsContent, idx: &fieldIdx) else { return nil }
        let spkiEnd = fieldIdx

        return tbsContent[spkiStart..<spkiEnd]
    }

    // MARK: - Minimal DER parser

    private func readDERSequenceContent(_ data: Data, idx: inout Data.Index) -> Data? {
        guard idx < data.endIndex, data[idx] == 0x30 else { return nil }
        idx = data.index(after: idx)
        guard let length = readDERLength(data, idx: &idx) else { return nil }
        let start = idx
        let end = data.index(start, offsetBy: length, limitedBy: data.endIndex) ?? data.endIndex
        guard end <= data.endIndex else { return nil }
        idx = end
        return data[start..<end]
    }

    private func skipDERElement(_ data: Data, idx: inout Data.Index) -> Bool {
        guard idx < data.endIndex else { return false }
        idx = data.index(after: idx) // skip tag
        guard let length = readDERLength(data, idx: &idx) else { return false }
        guard let end = data.index(idx, offsetBy: length, limitedBy: data.endIndex) else { return false }
        guard end <= data.endIndex else { return false }
        idx = end
        return true
    }

    private func readDERLength(_ data: Data, idx: inout Data.Index) -> Int? {
        guard idx < data.endIndex else { return nil }
        let first = data[idx]
        idx = data.index(after: idx)

        if first & 0x80 == 0 {
            return Int(first)
        }

        let numBytes = Int(first & 0x7F)
        guard numBytes > 0, numBytes <= 4 else { return nil }
        guard data.index(idx, offsetBy: numBytes, limitedBy: data.endIndex) != nil else { return nil }

        var length = 0
        for _ in 0..<numBytes {
            guard idx < data.endIndex else { return nil }
            length = (length << 8) | Int(data[idx])
            idx = data.index(after: idx)
        }
        return length
    }
}

// MARK: - PinnedSessionFactory

enum PinnedSessionFactory {
    static func create(keys: [KeysResponse.KeyItem]) -> URLSession {
        let hashes = keys.map { $0.key }
        let delegate = PinningDelegate(pinnedHashes: hashes)
        return URLSession(
            configuration: .default,
            delegate: delegate,
            delegateQueue: nil
        )
    }
}
