import Testing
import Foundation
@testable import SslPinning

struct JSONCanonicalizerTests {
    private func canonicalize(_ jsonString: String) throws -> String {
        let data = try JSONCanonicalizer.canonicalize(Data(jsonString.utf8))
        return String(decoding: data, as: UTF8.self)
    }

    @Test func canonicalizesEmptyObject() throws {
        #expect(try canonicalize("{}") == "{}")
    }

    @Test func sortsObjectKeys() throws {
        #expect(try canonicalize(#"{"b":1,"a":2}"#) == #"{"a":2,"b":1}"#)
    }

    @Test func sortsNestedObjectKeys() throws {
        #expect(try canonicalize(#"{"a":{"z":1,"a":2}}"#) == #"{"a":{"a":2,"z":1}}"#)
    }

    @Test func preservesArray() throws {
        #expect(try canonicalize("[1,2,3]") == "[1,2,3]")
    }

    @Test func handlesNullBooleans() throws {
        #expect(try canonicalize(#"{"a":null,"b":true,"c":false}"#) == #"{"a":null,"b":true,"c":false}"#)
    }

    @Test func handlesInteger() throws {
        #expect(try canonicalize(#"{"n":16528776}"#) == #"{"n":16528776}"#)
    }

    @Test func escapesControlCharacters() throws {
        let input = "{\"a\":\"hello\\nworld\"}"
        let output = try canonicalize(input)
        #expect(output == "{\"a\":\"hello\\nworld\"}")
    }

    @Test func escapesQuoteAndBackslash() throws {
        let input = "{\"a\":\"say \\\"hi\\\"\"}"
        #expect(try canonicalize(input) == "{\"a\":\"say \\\"hi\\\"\"}")
    }

    @Test func sortsByUnicodeCodePoints() throws {
        // "F" = 70, "f" = 102, so "F" sorts before "f"
        #expect(try canonicalize(#"{"f":1,"F":2}"#) == #"{"F":2,"f":1}"#)
    }

    @Test func handlesNestedArray() throws {
        #expect(try canonicalize(#"{"b":[3,1],"a":2}"#) == #"{"a":2,"b":[3,1]}"#)
    }

    @Test func sortsKeysInArrayObjects() throws {
        let input = #"[{"b":1,"a":2}]"#
        #expect(try canonicalize(input) == #"[{"a":2,"b":1}]"#)
    }
}
