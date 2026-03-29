import Foundation

struct KeysResponse: Codable {
    let payload: Payload
    let signature: String

    struct Payload: Codable {
        let keys: [KeyItem]
    }

    struct KeyItem: Codable {
        let domainName: String
        let key: String
        let fqdn: String?
        let expire: Int64?
        let date: String?
    }
}
