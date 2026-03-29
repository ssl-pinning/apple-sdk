# SSL Pinning iOS SDK

iOS SDK for **SSL/TLS certificate pinning** using a **remote, cryptographically signed key registry**.

Solves the main limitation of traditional SSL pinning — hardcoded certificates require a full app update to rotate keys. This SDK fetches pins from a remote endpoint and verifies them with a signature, allowing safe key rotation without releasing a new app version.

## Sample APP

![](sample-app.png#center)

## Requirements

- iOS **15.0+** / macOS **12.0+**
- Swift **6.1+**
- Xcode **16+**

## Installation

### Swift Package Manager

Add the package to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/ssl-pinning/apple-sdk.git", from: "0.1.0"),
]
```

Or in Xcode: **File → Add Package Dependencies** and enter the repository URL.

## Usage

```swift
import SslPinning

let config = SslPinningConfig(
    endpointUrl: "https://ssl-pinning.example.com/api/v1/google.com.json",
    signingKeyBase64: "<BASE64_OF_pub.pem>"
)

let result = await SslPinningClient.initialize(config: config)

switch result {
case .success(let client):
    let pinnedSession = client.createPinnedSession() // use for all HTTPS requests
    let plainSession  = client.createPlainSession()  // use only for non-pinned requests
case .failure(let error):
    // initialization failed — do not proceed with network requests
}
```

`initialize()` is an `async` function — call it from an async context (e.g. a `Task` or `.task` view modifier).

## How It Works

1. SDK fetches the signed key registry from `endpointUrl` via HTTP GET
2. The response signature is verified using JCS + RSA PKCS#1 v1.5 + SHA-512
3. Each verified key is bound to its `domainName` as an SPKI SHA-256 pin
4. A `URLSession` with a custom `URLSessionDelegate` is built for the pinned session
5. Both sessions (`pinned` and `plain`) are returned

**Fails closed** — initialization returns `.failure` if:
- The endpoint is unreachable
- The response format is invalid
- The cryptographic signature does not verify
- The key list is empty

## Key Registry Response Format

Your backend endpoint must return JSON in the following format:

```json
{
  "payload": {
    "keys": [
      {
        "domainName": "www.example.com",
        "key": "base64-encoded-sha256-spki-hash",
        "expire": 5488607,
        "date": "2025-12-14T21:02:11Z"
      }
    ]
  },
  "signature": "BASE64_ENCODED_RSA_SHA512_SIGNATURE"
}
```

- `domainName` — hostname pattern; supports wildcards (`*.example.com` matches one subdomain level)
- `key` — base64-encoded SHA-256 hash of the certificate's SPKI
- `signature` — RSA PKCS#1 v1.5 + SHA-512 signature over the **JCS-canonicalized JSON** of the `payload` field

## Cryptography

| Property | Value |
|----------|-------|
| Canonicalization | JSON Canonicalization Scheme (JCS, RFC 8785) |
| Signature algorithm | RSA PKCS#1 v1.5 |
| Hash function | SHA-512 |
| Public key format | PEM, base64(PEM), or DER (SPKI) |
| SPKI hash | SHA-256 via CryptoKit |

The `signingKeyBase64` in `SslPinningConfig` is the base64-encoded public key used to verify the registry signature. The corresponding private key must be kept on the backend and used to sign each key registry response.

## Security Properties

- Protects against MITM attacks including custom CA injection
- Prevents silent key substitution via cryptographic signature
- Allows remote key rotation without app updates
- No hardcoded pins in the application binary

## Sample App

The repository includes a SwiftUI sample application demonstrating SDK usage.

To run it, create `App/Config.xcconfig` (copy from the provided example):

```bash
cp App/Config.xcconfig.example App/Config.xcconfig
```

Then fill in your values:

```
SLASH = /
SSL_PINNING_ENDPOINT = https:$(SLASH)$(SLASH)your-backend.com/api/ssl-pinning.json
SSL_PINNING_SIGNING_KEY_B64 = <BASE64_OF_pub.pem>
```

> Note: `$(SLASH)` is required because `//` is treated as a comment in xcconfig files.

Open `SslPinning.xcworkspace` in Xcode, select the `App` scheme, and run.

## License

BSD 3-Clause — see [LICENSE](LICENSE)
