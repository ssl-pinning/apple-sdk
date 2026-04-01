import Testing
import Foundation
@testable import SslPinning

struct PinningDelegateTests {
    @Test func createsPinnedSession() {
        let keys = [KeysResponse.KeyItem(domainName: "example.com", key: "abc=", fqdn: nil, expire: nil, date: nil)]
        let session = PinnedSessionFactory.create(keys: keys)
        #expect(session.delegate != nil)
    }
}
