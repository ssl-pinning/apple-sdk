import Foundation

struct KeysFetcher: Sendable {
    private let session: URLSession

    init(session: URLSession = .shared) {
        self.session = session
    }

    func fetch(from endpointUrl: String) async throws -> KeysResponse {
        guard let url = URL(string: endpointUrl) else {
            throw URLError(.badURL)
        }

        let (data, response) = try await session.data(from: url)

        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw URLError(.badServerResponse)
        }

        return try JSONDecoder().decode(KeysResponse.self, from: data)
    }
}
