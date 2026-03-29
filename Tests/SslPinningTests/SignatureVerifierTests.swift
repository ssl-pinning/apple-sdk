import Testing
import Foundation
import Security
@testable import SslPinning

struct SignatureVerifierTests {
    private func generateTestKeyPair() throws -> (String, SecKey) {
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
        ]
        var pub: SecKey?, priv: SecKey?
        let status = SecKeyGeneratePair(attrs as CFDictionary, &pub, &priv)
        guard status == errSecSuccess, let publicKey = pub, let privateKey = priv else {
            throw NSError(domain: "test", code: Int(status))
        }
        let pubData = SecKeyCopyExternalRepresentation(publicKey, nil)! as Data
        return (pubData.base64EncodedString(), privateKey)
    }

    private func sign(_ data: Data, with privateKey: SecKey) throws -> String {
        var cfError: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(
            privateKey,
            .rsaSignatureMessagePKCS1v15SHA512,
            data as CFData,
            &cfError
        ) else {
            throw cfError!.takeRetainedValue()
        }
        return (sig as Data).base64EncodedString()
    }

    @Test func verifiesValidSignature() throws {
        let (pubKeyBase64, privateKey) = try generateTestKeyPair()
        let payloadJSON = Data(#"{"keys":[{"domainName":"example.com","key":"abc="}]}"#.utf8)
        let canonical = try JSONCanonicalizer.canonicalize(payloadJSON)
        let signature = try sign(canonical, with: privateKey)
        try SignatureVerifier.verifyPayloadSignature(
            payloadJSON: payloadJSON,
            signatureBase64: signature,
            signingKeyBase64: pubKeyBase64
        )
    }

    @Test func rejectsInvalidSignature() throws {
        let (pubKeyBase64, _) = try generateTestKeyPair()
        let payloadJSON = Data(#"{"keys":[{"domainName":"example.com","key":"abc="}]}"#.utf8)
        let badSignature = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
        #expect(throws: (any Error).self) {
            try SignatureVerifier.verifyPayloadSignature(
                payloadJSON: payloadJSON,
                signatureBase64: badSignature,
                signingKeyBase64: pubKeyBase64
            )
        }
    }

    @Test func rejectsWrongKey() throws {
        let (_, signingKey) = try generateTestKeyPair()
        let (differentPubKey, _) = try generateTestKeyPair()
        let payloadJSON = Data(#"{"keys":[{"domainName":"example.com","key":"abc="}]}"#.utf8)
        let canonical = try JSONCanonicalizer.canonicalize(payloadJSON)
        let signature = try sign(canonical, with: signingKey)
        #expect(throws: (any Error).self) {
            try SignatureVerifier.verifyPayloadSignature(
                payloadJSON: payloadJSON,
                signatureBase64: signature,
                signingKeyBase64: differentPubKey
            )
        }
    }

    @Test func canonicalizesBeforeVerification() throws {
        let (pubKeyBase64, privateKey) = try generateTestKeyPair()
        let nonCanonical = Data(#"{"key":"abc=","domainName":"example.com"}"#.utf8)
        let canonical = try JSONCanonicalizer.canonicalize(
            Data(#"{"domainName":"example.com","key":"abc="}"#.utf8)
        )
        let signature = try sign(canonical, with: privateKey)
        try SignatureVerifier.verifyPayloadSignature(
            payloadJSON: nonCanonical,
            signatureBase64: signature,
            signingKeyBase64: pubKeyBase64
        )
    }
}
