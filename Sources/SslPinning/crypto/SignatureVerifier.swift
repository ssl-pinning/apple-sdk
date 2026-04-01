import Foundation
import Security

enum SignatureVerifier {
    enum VerifierError: Error {
        case invalidPublicKey
        case invalidSignatureEncoding
        case verificationFailed
    }

    static func verifyPayloadSignature(
        payloadJSON: Data,
        signatureBase64: String,
        signingKeyBase64: String
    ) throws {
        let publicKey = try importPublicKey(from: signingKeyBase64)
        let canonicalData = try JSONCanonicalizer.canonicalize(payloadJSON)
        guard let signatureData = Data(base64Encoded: signatureBase64) else {
            throw VerifierError.invalidSignatureEncoding
        }
        var cfError: Unmanaged<CFError>?
        let isValid = SecKeyVerifySignature(
            publicKey,
            .rsaSignatureMessagePKCS1v15SHA512,
            canonicalData as CFData,
            signatureData as CFData,
            &cfError
        )
        guard isValid else {
            throw VerifierError.verificationFailed
        }
    }

    private static func importPublicKey(from base64String: String) throws -> SecKey {
        let cleaned = base64String
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")
            .trimmingCharacters(in: .whitespaces)
        guard let firstDecode = Data(base64Encoded: cleaned) else {
            throw VerifierError.invalidPublicKey
        }
        let keyData: Data
        if let pem = String(data: firstDecode, encoding: .utf8),
           pem.contains("-----BEGIN PUBLIC KEY-----") {
            let innerCleaned = pem
                .replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----", with: "")
                .replacingOccurrences(of: "-----END PUBLIC KEY-----", with: "")
                .replacingOccurrences(of: "\n", with: "")
                .replacingOccurrences(of: "\r", with: "")
                .trimmingCharacters(in: .whitespaces)
            guard let derData = Data(base64Encoded: innerCleaned) else {
                throw VerifierError.invalidPublicKey
            }
            keyData = derData
        } else {
            keyData = firstDecode
        }
        let pkcs1Data = stripSPKIHeaderIfPresent(keyData)
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        ]
        var cfError: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(pkcs1Data as CFData, attributes as CFDictionary, &cfError) else {
            throw VerifierError.invalidPublicKey
        }
        return secKey
    }

    private static func stripSPKIHeaderIfPresent(_ data: Data) -> Data {
        let headers: [[UInt8]] = [
            // RSA-1024
            [0x30, 0x81, 0x9F, 0x30, 0x0D, 0x06, 0x09,
             0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
             0x05, 0x00, 0x03, 0x81, 0x8D, 0x00],
            // RSA-2048
            [0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09,
             0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
             0x05, 0x00, 0x03, 0x82, 0x01, 0x0F, 0x00],
            // RSA-4096
            [0x30, 0x82, 0x02, 0x22, 0x30, 0x0D, 0x06, 0x09,
             0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
             0x05, 0x00, 0x03, 0x82, 0x02, 0x0F, 0x00],
        ]
        let bytes = [UInt8](data)
        for header in headers where bytes.starts(with: header) {
            return Data(bytes.dropFirst(header.count))
        }
        return data
    }
}
