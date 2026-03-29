import Foundation

enum JSONCanonicalizer {
    enum CanonicalizerError: Error {
        case invalidJSON
        case unsupportedType
    }

    static func canonicalize(_ jsonData: Data) throws -> Data {
        guard let value = try? JSONSerialization.jsonObject(with: jsonData, options: [.fragmentsAllowed]) else {
            throw CanonicalizerError.invalidJSON
        }
        var output = ""
        try serialize(value, into: &output)
        return Data(output.utf8)
    }

    private static func serialize(_ value: Any, into output: inout String) throws {
        switch value {
        case is NSNull:
            output += "null"
        case let number as NSNumber:
            if CFGetTypeID(number) == CFBooleanGetTypeID() {
                output += number.boolValue ? "true" : "false"
            } else {
                output += serializeNumber(number)
            }
        case let string as String:
            serializeString(string, into: &output)
        case let array as [Any]:
            output += "["
            for (i, element) in array.enumerated() {
                if i > 0 { output += "," }
                try serialize(element, into: &output)
            }
            output += "]"
        case let dict as [String: Any]:
            let sortedKeys = dict.keys.sorted {
                $0.unicodeScalars.lexicographicallyPrecedes($1.unicodeScalars)
            }
            output += "{"
            for (i, key) in sortedKeys.enumerated() {
                if i > 0 { output += "," }
                serializeString(key, into: &output)
                output += ":"
                try serialize(dict[key]!, into: &output)
            }
            output += "}"
        default:
            throw CanonicalizerError.unsupportedType
        }
    }

    private static func serializeNumber(_ number: NSNumber) -> String {
        let d = number.doubleValue
        if d.truncatingRemainder(dividingBy: 1) == 0,
           d >= -9_007_199_254_740_992,
           d <= 9_007_199_254_740_992 {
            return String(Int64(d))
        }
        return String(d)
    }

    private static func serializeString(_ string: String, into output: inout String) {
        output += "\""
        for scalar in string.unicodeScalars {
            switch scalar.value {
            case 0x22: output += "\\\""
            case 0x5C: output += "\\\\"
            case 0x08: output += "\\b"
            case 0x09: output += "\\t"
            case 0x0A: output += "\\n"
            case 0x0C: output += "\\f"
            case 0x0D: output += "\\r"
            case 0x00..<0x20:
                output += String(format: "\\u%04x", scalar.value)
            default:
                output += String(scalar)
            }
        }
        output += "\""
    }
}
