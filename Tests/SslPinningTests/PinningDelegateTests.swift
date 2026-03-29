import Testing
import Foundation
@testable import SslPinning

struct PinningDelegateTests {
    @Test func exactDomainMatches() {
        let delegate = PinningDelegate(keys: [])
        #expect(delegate.testDomainMatches(pattern: "example.com", host: "example.com"))
    }

    @Test func exactDomainDoesNotMatchSubdomain() {
        let delegate = PinningDelegate(keys: [])
        #expect(!delegate.testDomainMatches(pattern: "example.com", host: "sub.example.com"))
    }

    @Test func wildcardMatchesSubdomain() {
        let delegate = PinningDelegate(keys: [])
        #expect(delegate.testDomainMatches(pattern: "*.example.com", host: "sub.example.com"))
    }

    @Test func wildcardDoesNotMatchApex() {
        let delegate = PinningDelegate(keys: [])
        #expect(!delegate.testDomainMatches(pattern: "*.example.com", host: "example.com"))
    }

    @Test func wildcardDoesNotMatchTwoLevels() {
        let delegate = PinningDelegate(keys: [])
        #expect(!delegate.testDomainMatches(pattern: "*.example.com", host: "a.b.example.com"))
    }

    @Test func matchingIsCaseInsensitive() {
        let delegate = PinningDelegate(keys: [])
        #expect(delegate.testDomainMatches(pattern: "Example.COM", host: "example.com"))
    }

    @Test func createsPinnedSession() {
        let keys = [KeysResponse.KeyItem(domainName: "example.com", key: "abc=", fqdn: nil, expire: nil, date: nil)]
        let session = PinnedSessionFactory.create(keys: keys)
        #expect(session.delegate != nil)
    }

    @Test func createsPlainSession() {
        let session = PinnedSessionFactory.createPlain()
        #expect(session.delegate == nil)
    }
}
