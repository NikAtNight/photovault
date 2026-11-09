import CryptoKit
import Foundation

/// The phone's P-256 key agreement key. The app uses the Secure Enclave key in
/// KeyStore.swift. Tests supply a software key from the spec's test scalar.
protocol PhoneKey: Sendable {
    /// 65-byte uncompressed X9.63 public key.
    var publicKey: Data { get }
    func sharedSecret(with ephemeral: P256.KeyAgreement.PublicKey) throws -> SharedSecret
}

extension PhoneKey {
    var keyID: String { PublicKeyIdentity.keyID(publicKey) }
    var verificationCode: String { PublicKeyIdentity.verificationCode(publicKey) }
}

enum PublicKeyIdentity {
    /// Lowercase hex of the first 8 bytes of SHA-256(public key).
    static func keyID(_ publicKey: Data) -> String {
        hex(SHA256.hash(data: publicKey).prefix(8), uppercase: false)
    }

    /// First 16 bytes of SHA-256(public key), uppercase hex, 8 groups of 4.
    static func verificationCode(_ publicKey: Data) -> String {
        let digits = hex(SHA256.hash(data: publicKey).prefix(16), uppercase: true)
        var groups: [Substring] = []
        var rest = Substring(digits)
        while !rest.isEmpty {
            groups.append(rest.prefix(4))
            rest = rest.dropFirst(4)
        }
        return groups.joined(separator: " ")
    }

    private static func hex<S: Sequence>(_ bytes: S, uppercase: Bool) -> String where S.Element == UInt8 {
        bytes.map { String(format: uppercase ? "%02X" : "%02x", $0) }.joined()
    }
}

/// The `.pvpair` file the phone sends to the Mac once.
struct PairingFile: Codable, Equatable {
    static let format = "photovault-pair"
    static let fileName = "iPhone.pvpair"

    let format: String
    let version: Int
    let label: String
    let publicKey: String
    let keyID: String

    enum CodingKeys: String, CodingKey {
        case format, version, label
        case publicKey = "public_key"
        case keyID = "key_id"
    }

    init(publicKey: Data) {
        format = Self.format
        version = 1
        label = "iPhone"
        self.publicKey = publicKey.base64EncodedString()
        keyID = PublicKeyIdentity.keyID(publicKey)
    }

    func encoded() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(self)
    }
}
