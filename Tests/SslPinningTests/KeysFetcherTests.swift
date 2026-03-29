import Testing
import Foundation
@testable import SslPinning

final class MockURLProtocol: URLProtocol, @unchecked Sendable {
    static nonisolated(unsafe) var handler: ((URLRequest) -> (HTTPURLResponse, Data))?

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let handler = MockURLProtocol.handler else {
            client?.urlProtocol(self, didFailWithError: URLError(.unknown))
            return
        }
        let (response, data) = handler(request)
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

@Suite(.serialized)
struct KeysFetcherTests {
    private func makeMockSession() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        return URLSession(configuration: config)
    }

    @Test func fetchesAndDecodesResponse() async throws {
        let validJSON = """
        {
          "payload": {"keys": [{"domainName": "example.com", "key": "abc="}]},
          "signature": "sig"
        }
        """
        MockURLProtocol.handler = { _ in
            let response = HTTPURLResponse(
                url: URL(string: "https://example.com")!,
                statusCode: 200,
                httpVersion: nil,
                headerFields: nil
            )!
            return (response, Data(validJSON.utf8))
        }

        let fetcher = KeysFetcher(session: makeMockSession())
        let result = try await fetcher.fetch(from: "https://example.com/api.json")
        #expect(result.payload.keys.count == 1)
        #expect(result.payload.keys[0].domainName == "example.com")
        #expect(result.signature == "sig")
    }

    @Test func throwsOnHTTPError() async throws {
        MockURLProtocol.handler = { _ in
            let response = HTTPURLResponse(
                url: URL(string: "https://example.com")!,
                statusCode: 404,
                httpVersion: nil,
                headerFields: nil
            )!
            return (response, Data())
        }

        let fetcher = KeysFetcher(session: makeMockSession())
        await #expect(throws: (any Error).self) {
            try await fetcher.fetch(from: "https://example.com/api.json")
        }
    }

    @Test func throwsOnInvalidURL() async {
        let fetcher = KeysFetcher()
        await #expect(throws: (any Error).self) {
            try await fetcher.fetch(from: "not a url !!!")
        }
    }
}
