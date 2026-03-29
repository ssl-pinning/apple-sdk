import Testing
import Foundation
@testable import SslPinning

struct KeysResponseTests {
    @Test func decodesFullResponse() throws {
        let json = """
        {
          "payload": {
            "keys": [
              {
                "date": "2026-03-29T16:40:22.119292225Z",
                "domainName": "*.example.com",
                "expire": 16528776,
                "fqdn": "example.com",
                "key": "abc=="
              }
            ]
          },
          "signature": "abc123"
        }
        """
        let response = try JSONDecoder().decode(KeysResponse.self, from: Data(json.utf8))
        #expect(response.payload.keys.count == 1)
        #expect(response.payload.keys[0].domainName == "*.example.com")
        #expect(response.payload.keys[0].key == "abc==")
        #expect(response.payload.keys[0].expire == 16528776)
        #expect(response.payload.keys[0].fqdn == "example.com")
        #expect(response.payload.keys[0].date == "2026-03-29T16:40:22.119292225Z")
        #expect(response.signature == "abc123")
    }

    @Test func decodesResponseWithMissingOptionals() throws {
        let json = """
        {
          "payload": {
            "keys": [
              {
                "domainName": "*.example.com",
                "key": "abc="
              }
            ]
          },
          "signature": "sig"
        }
        """
        let response = try JSONDecoder().decode(KeysResponse.self, from: Data(json.utf8))
        #expect(response.payload.keys[0].fqdn == nil)
        #expect(response.payload.keys[0].expire == nil)
        #expect(response.payload.keys[0].date == nil)
    }

    @Test func decodesMultipleKeys() throws {
        let json = """
        {
          "payload": {
            "keys": [
              {"domainName": "a.com", "key": "k1="},
              {"domainName": "*.b.com", "key": "k2="}
            ]
          },
          "signature": "s"
        }
        """
        let response = try JSONDecoder().decode(KeysResponse.self, from: Data(json.utf8))
        #expect(response.payload.keys.count == 2)
    }
}
