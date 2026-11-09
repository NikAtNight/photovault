import CryptoKit
import Foundation
@testable import PhotoVault

/// Software key for tests only. It lives in the test target, so it never
/// compiles into the app.
struct SoftwarePhoneKey: PhoneKey {
    let key: P256.KeyAgreement.PrivateKey
    var publicKey: Data { key.publicKey.x963Representation }

    init(key: P256.KeyAgreement.PrivateKey = .init(compactRepresentable: false)) {
        self.key = key
    }

    /// The spec's test-only scalar.
    static func fixtureKey() throws -> SoftwarePhoneKey {
        let scalar = Data(hex: "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
        return SoftwarePhoneKey(key: try P256.KeyAgreement.PrivateKey(rawRepresentation: scalar))
    }

    func sharedSecret(with ephemeral: P256.KeyAgreement.PublicKey) throws -> SharedSecret {
        try key.sharedSecretFromKeyAgreement(with: ephemeral)
    }
}

extension Data {
    init(hex: String) {
        var bytes: [UInt8] = []
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            bytes.append(UInt8(hex[index ..< next], radix: 16)!)
            index = next
        }
        self.init(bytes)
    }

    /// Byte `i` is `i % 251`, as in the fixture.
    static func pattern(_ count: Int) -> Data {
        Data((0 ..< count).map { UInt8($0 % 251) })
    }
}

/// Writes `.pvshare` files the way docs/iphone-sharing.md describes, with
/// knobs to produce specific kinds of damage.
struct ShareWriter {
    struct Item {
        var id: String
        var name: String
        var kind: String
        var original: Data
        var thumb: Data?
    }

    enum LastFlag {
        case correct
        case never
        case always
    }

    var recipient: Data
    var title = "Test Album"
    var items: [Item]
    var lastFlag: LastFlag = .correct
    /// Drop the final chunk of item 0's original and shrink its size to match.
    var dropLastChunkOfFirstOriginal = false
    /// Edit the manifest JSON object before it's encrypted.
    var editManifest: (inout [String: Any]) -> Void = { _ in }
    /// Edit the header JSON object before it's written.
    var editHeader: (inout [String: Any]) -> Void = { _ in }

    let contentKey = SymmetricKey(size: .bits256)

    func write() throws -> Data {
        var blobArea = Data()
        var refs: [[String: Any]] = []
        for item in items {
            var entry: [String: Any] = ["id": item.id, "name": item.name, "kind": item.kind]
            var original = item.original
            var dropLast = false
            if dropLastChunkOfFirstOriginal && item.id == items.first?.id {
                dropLast = true
                let n = max(1, (original.count + 1_048_575) / 1_048_576)
                original = original.prefix((n - 1) * 1_048_576)
            }
            entry["original"] = try appendBlob(original, id: "\(item.id)/original", to: &blobArea,
                                               pretendMoreChunks: dropLast)
            if let thumb = item.thumb {
                entry["thumb"] = try appendBlob(thumb, id: "\(item.id)/thumb", to: &blobArea)
            }
            refs.append(entry)
        }
        var manifest: [String: Any] = ["version": 1, "title": title, "created": 1_767_225_600.0, "items": refs]
        editManifest(&manifest)
        let manifestJSON = try JSONSerialization.data(withJSONObject: manifest)
        let manifestRef = try appendBlob(manifestJSON, id: "manifest", to: &blobArea)

        let ephemeral = P256.KeyAgreement.PrivateKey(compactRepresentable: false)
        let ephemeralPublic = ephemeral.publicKey.x963Representation
        let salt = Data((0 ..< 32).map { _ in UInt8.random(in: 0 ... 255) })
        let shared = try ephemeral.sharedSecretFromKeyAgreement(
            with: P256.KeyAgreement.PublicKey(x963Representation: recipient))
        let info = Data("photovault-share-v1".utf8) + ephemeralPublic + recipient
        let kek = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: info, outputByteCount: 32)
        let rawKey = contentKey.withUnsafeBytes { Data($0) }
        let wrapped = try AES.GCM.seal(rawKey, using: kek, authenticating: Data("PVSHARE1".utf8)).combined!

        var header: [String: Any] = [
            "version": 1,
            "key_id": PublicKeyIdentity.keyID(recipient),
            "ephemeral_public_key": ephemeralPublic.base64EncodedString(),
            "salt": salt.base64EncodedString(),
            "wrapped_key": wrapped.base64EncodedString(),
            "manifest": manifestRef,
        ]
        editHeader(&header)
        let headerJSON = try JSONSerialization.data(withJSONObject: header)
        return Self.assemble(header: headerJSON, blobArea: blobArea)
    }

    static func assemble(header: Data, blobArea: Data) -> Data {
        var file = Data("PVSHARE1".utf8)
        withUnsafeBytes(of: UInt32(header.count).littleEndian) { file.append(contentsOf: $0) }
        file.append(header)
        file.append(blobArea)
        return file
    }

    /// `pretendMoreChunks` encrypts every chunk as non-last, as if the real
    /// last chunk had been cut off.
    private func appendBlob(_ plaintext: Data, id: String, to area: inout Data,
                            pretendMoreChunks: Bool = false) throws -> [String: Any] {
        let prefix = Data((0 ..< 7).map { _ in UInt8.random(in: 0 ... 255) })
        let offset = area.count
        let n = max(1, (plaintext.count + 1_048_575) / 1_048_576)
        for i in 0 ..< n {
            let chunk = plaintext[plaintext.startIndex + i * 1_048_576 ..< plaintext.startIndex + min(plaintext.count, (i + 1) * 1_048_576)]
            let isLast: Bool = switch lastFlag {
            case .correct: i == n - 1 && !pretendMoreChunks
            case .never: false
            case .always: true
            }
            var nonce = prefix
            withUnsafeBytes(of: UInt32(i).bigEndian) { nonce.append(contentsOf: $0) }
            nonce.append(isLast ? 1 : 0)
            let box = try AES.GCM.seal(chunk, using: contentKey, nonce: AES.GCM.Nonce(data: nonce),
                                       authenticating: Data(id.utf8))
            area.append(box.ciphertext + box.tag)
        }
        return ["offset": offset, "length": area.count - offset,
                "nonce_prefix": prefix.base64EncodedString(), "size": plaintext.count]
    }
}

/// Writes data to a temporary test file. Test data only, never real media.
func temporaryShare(_ data: Data) throws -> URL {
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent("test-\(UUID().uuidString).pvshare")
    try data.write(to: url)
    return url
}

/// Header length and blob area start of an assembled file.
func blobAreaStart(of file: Data) -> Int {
    let length = file[8 ..< 12].enumerated().reduce(0) { $0 | Int($1.element) << (8 * $1.offset) }
    return 12 + length
}
