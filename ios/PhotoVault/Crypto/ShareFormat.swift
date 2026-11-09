import CryptoKit
import Foundation

/// Constants and plaintext structures of the `.pvshare` format.
/// The contract is docs/iphone-sharing.md. Change both sides together.
enum ShareFormat {
    static let magic = Data("PVSHARE1".utf8)
    static let version = 1
    static let maxHeaderLength: UInt64 = 65_536
    static let maxManifestSize: UInt64 = 16 * 1_048_576
    static let chunkSize: UInt64 = 1_048_576
    static let tagSize: UInt64 = 16
    static let noncePrefixLength = 7
    static let publicKeyLength = 65
    static let saltLength = 32
    static let contentKeyLength = 32
    /// 12-byte nonce, 32-byte content key, 16-byte tag.
    static let wrappedKeyLength = 12 + contentKeyLength + 16
    static let wrapAAD = Data("PVSHARE1".utf8)
    static let hkdfInfoPrefix = Data("photovault-share-v1".utf8)
    static let manifestBlobID = "manifest"
}

enum ShareError: Error, Equatable, LocalizedError {
    case notAShareFile
    case headerTooLarge
    case malformedHeader(String)
    case unsupportedVersion
    case wrongRecipient
    case blobOutOfBounds
    case blobLengthMismatch
    case manifestTooLarge
    case malformedManifest(String)
    case authenticationFailed
    case keyUnavailable
    case itemTooLarge

    var errorDescription: String? {
        switch self {
        case .notAShareFile: "This isn't a PhotoVault share file."
        case .headerTooLarge, .malformedHeader: "This share file is damaged."
        case .unsupportedVersion: "This share was made by a newer version of PhotoVault. Update the app."
        case .wrongRecipient: "This share was sent to a different iPhone. On your Mac, send it to this iPhone's pairing."
        case .blobOutOfBounds, .blobLengthMismatch: "This share file is incomplete or damaged."
        case .manifestTooLarge, .malformedManifest: "This share file is damaged."
        case .authenticationFailed: "This share file was changed or damaged after it was made."
        case .keyUnavailable: "The pairing key couldn't be used. Unlock again."
        case .itemTooLarge: "This item is too large to show on iPhone."
        }
    }
}

/// Chunk arithmetic for one blob. All arithmetic is checked.
struct ChunkLayout: Equatable, Sendable {
    let size: UInt64
    let length: UInt64
    let chunkCount: UInt64

    init(size: UInt64, length: UInt64) throws {
        // n = max(1, ceil(size / chunk)), written so it can't overflow.
        let n: UInt64 = size == 0 ? 1 : (size - 1) / ShareFormat.chunkSize + 1
        guard n <= (UInt64(1) << 32) else { throw ShareError.blobLengthMismatch }
        let (tags, o1) = n.multipliedReportingOverflow(by: ShareFormat.tagSize)
        let (expected, o2) = size.addingReportingOverflow(tags)
        guard !o1, !o2, expected == length else { throw ShareError.blobLengthMismatch }
        self.size = size
        self.length = length
        self.chunkCount = n
    }

    /// Plaintext byte count of chunk `index`.
    func plaintextLength(ofChunk index: UInt64) -> UInt64 {
        precondition(index < chunkCount)
        if index == chunkCount - 1 { return size - index * ShareFormat.chunkSize }
        return ShareFormat.chunkSize
    }

    /// Offset of chunk `index` within the blob's ciphertext.
    func ciphertextOffset(ofChunk index: UInt64) -> UInt64 {
        precondition(index < chunkCount)
        return index * (ShareFormat.chunkSize + ShareFormat.tagSize)
    }

    /// Chunk index that holds plaintext byte `offset`.
    func chunkIndex(forPlaintextOffset offset: UInt64) -> UInt64 {
        min(offset / ShareFormat.chunkSize, chunkCount - 1)
    }

    /// The last flag is derived from the index, never read from the file.
    func isLast(_ index: UInt64) -> Bool { index == chunkCount - 1 }

    /// nonce_prefix (7) || index (u32 big-endian) || last flag (1).
    static func nonce(prefix: Data, index: UInt32, isLast: Bool) throws -> AES.GCM.Nonce {
        guard prefix.count == ShareFormat.noncePrefixLength else {
            throw ShareError.malformedHeader("nonce_prefix")
        }
        var bytes = Data(prefix)
        withUnsafeBytes(of: index.bigEndian) { bytes.append(contentsOf: $0) }
        bytes.append(isLast ? 0x01 : 0x00)
        return try AES.GCM.Nonce(data: bytes)
    }
}

/// `{ offset, length, nonce_prefix, size }` as it appears in JSON.
struct BlobRef: Decodable, Equatable {
    let offset: UInt64
    let length: UInt64
    let noncePrefix: Data
    let size: UInt64

    enum CodingKeys: String, CodingKey {
        case offset, length, size
        case noncePrefix = "nonce_prefix"
    }

    init(offset: UInt64, length: UInt64, noncePrefix: Data, size: UInt64) {
        self.offset = offset
        self.length = length
        self.noncePrefix = noncePrefix
        self.size = size
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        offset = try c.decode(UInt64.self, forKey: .offset)
        length = try c.decode(UInt64.self, forKey: .length)
        size = try c.decode(UInt64.self, forKey: .size)
        noncePrefix = try c.decodeBase64(.noncePrefix, length: ShareFormat.noncePrefixLength)
    }
}

/// A blob reference that passed every structural check and knows its AAD.
struct Blob: Equatable, Sendable {
    let id: String
    let absoluteOffset: UInt64
    let layout: ChunkLayout
    let noncePrefix: Data

    var size: UInt64 { layout.size }
    var aad: Data { Data(id.utf8) }

    init(id: String, ref: BlobRef, blobAreaStart: UInt64, fileSize: UInt64) throws {
        guard ref.noncePrefix.count == ShareFormat.noncePrefixLength else {
            throw ShareError.malformedHeader("nonce_prefix")
        }
        let layout = try ChunkLayout(size: ref.size, length: ref.length)
        let (start, o1) = blobAreaStart.addingReportingOverflow(ref.offset)
        let (end, o2) = start.addingReportingOverflow(ref.length)
        guard !o1, !o2, end <= fileSize else { throw ShareError.blobOutOfBounds }
        self.id = id
        self.absoluteOffset = start
        self.layout = layout
        self.noncePrefix = ref.noncePrefix
    }
}

struct ShareHeader: Decodable {
    let version: Int
    let keyID: String
    let ephemeralPublicKey: Data
    let salt: Data
    let wrappedKey: Data
    let manifest: BlobRef

    enum CodingKeys: String, CodingKey {
        case version, salt, manifest
        case keyID = "key_id"
        case ephemeralPublicKey = "ephemeral_public_key"
        case wrappedKey = "wrapped_key"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        version = try c.decode(Int.self, forKey: .version)
        guard version == ShareFormat.version else { throw ShareError.unsupportedVersion }
        keyID = try c.decode(String.self, forKey: .keyID)
        guard keyID.count == 16, keyID.allSatisfy({ $0.isHexDigit && !$0.isUppercase }) else {
            throw ShareError.malformedHeader("key_id")
        }
        ephemeralPublicKey = try c.decodeBase64(.ephemeralPublicKey, length: ShareFormat.publicKeyLength)
        guard ephemeralPublicKey.first == 0x04 else { throw ShareError.malformedHeader("ephemeral_public_key") }
        salt = try c.decodeBase64(.salt, length: ShareFormat.saltLength)
        wrappedKey = try c.decodeBase64(.wrappedKey, length: ShareFormat.wrappedKeyLength)
        manifest = try c.decode(BlobRef.self, forKey: .manifest)
    }
}

enum MediaKind: String, Sendable {
    case photo, video
}

struct ManifestItem: Identifiable, Sendable {
    let id: String
    let name: String
    let kind: MediaKind
    let taken: Date?
    let width: Int?
    let height: Int?
    let original: Blob
    let thumb: Blob?
}

struct Manifest: Sendable {
    let title: String
    let created: Date
    let items: [ManifestItem]

    private struct Raw: Decodable {
        let version: Int
        let title: String
        let created: Double
        let items: [RawItem]
    }

    private struct RawItem: Decodable {
        let id: String
        let name: String
        let kind: String
        let taken: Double?
        let width: Int?
        let height: Int?
        let original: BlobRef
        let thumb: BlobRef?
    }

    /// Decodes the decrypted manifest and validates every item and blob range.
    init(json: Data, blobAreaStart: UInt64, fileSize: UInt64) throws {
        let raw: Raw
        do {
            raw = try JSONDecoder().decode(Raw.self, from: json)
        } catch let error as ShareError {
            throw error
        } catch {
            throw ShareError.malformedManifest("json")
        }
        guard raw.version == ShareFormat.version else { throw ShareError.unsupportedVersion }
        var seen = Set<String>()
        var items: [ManifestItem] = []
        items.reserveCapacity(raw.items.count)
        for item in raw.items {
            guard !item.id.isEmpty, seen.insert(item.id).inserted else {
                throw ShareError.malformedManifest("duplicate item id")
            }
            guard let kind = MediaKind(rawValue: item.kind) else {
                throw ShareError.malformedManifest("unknown kind")
            }
            let original = try Blob(id: "\(item.id)/original", ref: item.original,
                                    blobAreaStart: blobAreaStart, fileSize: fileSize)
            let thumb = try item.thumb.map {
                try Blob(id: "\(item.id)/thumb", ref: $0, blobAreaStart: blobAreaStart, fileSize: fileSize)
            }
            items.append(ManifestItem(
                id: item.id, name: item.name, kind: kind,
                taken: item.taken.map(Date.init(timeIntervalSince1970:)),
                width: item.width, height: item.height,
                original: original, thumb: thumb))
        }
        title = raw.title
        created = Date(timeIntervalSince1970: raw.created)
        self.items = items
    }
}

extension KeyedDecodingContainer {
    func decodeBase64(_ key: Key, length: Int) throws -> Data {
        let string = try decode(String.self, forKey: key)
        guard let data = Data(base64Encoded: string), data.count == length else {
            throw ShareError.malformedHeader(key.stringValue)
        }
        return data
    }
}
