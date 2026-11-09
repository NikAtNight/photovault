import CryptoKit
import Foundation

/// A `.pvshare` file opened for reading. Parses only the plaintext header.
/// Reads go through one FileHandle, on demand, behind a lock.
final class ShareFile: @unchecked Sendable {
    let url: URL
    let header: ShareHeader
    let fileSize: UInt64
    /// Byte position where the blob area starts: 12 + header_len.
    let blobAreaStart: UInt64

    private let handle: FileHandle
    private let lock = NSLock()

    init(url: URL) throws {
        let handle = try FileHandle(forReadingFrom: url)
        do {
            let fileSize = try handle.seekToEnd()
            try handle.seek(toOffset: 0)
            guard fileSize >= 12, let prefix = try handle.read(upToCount: 12), prefix.count == 12,
                  prefix.prefix(8) == ShareFormat.magic
            else { throw ShareError.notAShareFile }
            let headerLength = prefix.suffix(4).enumerated().reduce(UInt64(0)) {
                $0 | UInt64($1.element) << (8 * UInt64($1.offset))
            }
            guard headerLength <= ShareFormat.maxHeaderLength else { throw ShareError.headerTooLarge }
            guard 12 + headerLength <= fileSize,
                  let json = try handle.read(upToCount: Int(headerLength)), json.count == Int(headerLength)
            else { throw ShareError.blobOutOfBounds }
            let header: ShareHeader
            do {
                header = try JSONDecoder().decode(ShareHeader.self, from: json)
            } catch let error as ShareError {
                throw error
            } catch {
                throw ShareError.malformedHeader("json")
            }
            self.url = url
            self.handle = handle
            self.header = header
            self.fileSize = fileSize
            self.blobAreaStart = 12 + headerLength
        } catch {
            try? handle.close()
            throw error
        }
    }

    deinit { try? handle.close() }

    func read(at offset: UInt64, count: Int) throws -> Data {
        lock.lock()
        defer { lock.unlock() }
        try handle.seek(toOffset: offset)
        guard let data = try handle.read(upToCount: count), data.count == count else {
            throw ShareError.blobOutOfBounds
        }
        return data
    }
}

/// A share whose content key has been unwrapped. Holds the content key in
/// memory only. `revoke()` forgets it, so work still holding the object fails.
final class OpenShare: @unchecked Sendable {
    let file: ShareFile
    let manifest: Manifest
    private let lock = NSLock()
    /// nil once revoked. Only touched under `lock`.
    private var contentKey: SymmetricKey?

    /// Unwraps the content key with the phone key and decrypts the manifest.
    init(file: ShareFile, phoneKey: PhoneKey) throws {
        let header = file.header
        guard header.keyID == phoneKey.keyID else { throw ShareError.wrongRecipient }
        let contentKey = try Self.unwrapContentKey(header: header, phoneKey: phoneKey)
        guard header.manifest.size <= ShareFormat.maxManifestSize else { throw ShareError.manifestTooLarge }
        let manifestBlob = try Blob(id: ShareFormat.manifestBlobID, ref: header.manifest,
                                    blobAreaStart: file.blobAreaStart, fileSize: file.fileSize)
        let json = try Self.decryptBlob(manifestBlob, file: file, key: { contentKey })
        self.manifest = try Manifest(json: json, blobAreaStart: file.blobAreaStart, fileSize: file.fileSize)
        self.file = file
        self.contentKey = contentKey
    }

    static func unwrapContentKey(header: ShareHeader, phoneKey: PhoneKey) throws -> SymmetricKey {
        let phonePublic = phoneKey.publicKey
        guard phonePublic.count == ShareFormat.publicKeyLength, phonePublic.first == 0x04,
              header.ephemeralPublicKey.count == ShareFormat.publicKeyLength,
              header.ephemeralPublicKey.first == 0x04
        else { throw ShareError.malformedHeader("public key") }
        let ephemeral: P256.KeyAgreement.PublicKey
        do {
            ephemeral = try P256.KeyAgreement.PublicKey(x963Representation: header.ephemeralPublicKey)
        } catch {
            throw ShareError.malformedHeader("ephemeral_public_key")
        }
        let shared = try phoneKey.sharedSecret(with: ephemeral)
        var info = ShareFormat.hkdfInfoPrefix
        info.append(header.ephemeralPublicKey)
        info.append(phonePublic)
        let kek = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: header.salt, sharedInfo: info, outputByteCount: 32)
        do {
            // wrapped_key is nonce || ciphertext || tag, which is the .combined layout.
            let box = try AES.GCM.SealedBox(combined: header.wrappedKey)
            let raw = try AES.GCM.open(box, using: kek, authenticating: ShareFormat.wrapAAD)
            guard raw.count == ShareFormat.contentKeyLength else { throw ShareError.authenticationFailed }
            return SymmetricKey(data: raw)
        } catch {
            throw ShareError.authenticationFailed
        }
    }

    /// Forgets the content key. Every later decrypt throws `keyUnavailable`.
    func revoke() {
        lock.withLock { contentKey = nil }
    }

    var isRevoked: Bool { lock.withLock { contentKey == nil } }

    private func key() throws -> SymmetricKey {
        guard let key = lock.withLock({ contentKey }) else { throw ShareError.keyUnavailable }
        return key
    }

    // MARK: Decryption

    func decryptChunk(_ blob: Blob, index: UInt64) throws -> Data {
        try Self.decryptChunk(blob, index: index, file: file, key: key())
    }

    /// Decrypts a whole blob. Returns only after every chunk authenticates.
    /// Stops between chunks if the task is cancelled or the share is revoked.
    func decryptBlob(_ blob: Blob, limit: UInt64 = .max) throws -> Data {
        guard blob.size <= limit else { throw ShareError.itemTooLarge }
        return try Self.decryptBlob(blob, file: file, key: key)
    }

    /// Plaintext bytes `[offset, offset + count)`, decrypting only the chunks
    /// that overlap the range. Used by the video resource loader.
    func plaintext(_ blob: Blob, offset: UInt64, count: UInt64,
                   chunk: (UInt64) throws -> Data) throws -> Data {
        guard count > 0 else { return Data() }
        let (end, overflow) = offset.addingReportingOverflow(count)
        guard !overflow, end <= blob.size else { throw ShareError.blobOutOfBounds }
        var out = Data()
        out.reserveCapacity(Int(count))
        var index = blob.layout.chunkIndex(forPlaintextOffset: offset)
        while true {
            let chunkStart = index * ShareFormat.chunkSize
            let chunkData = try chunk(index)
            let from = Int(max(offset, chunkStart) - chunkStart)
            let to = Int(min(end, chunkStart + UInt64(chunkData.count)) - chunkStart)
            out.append(chunkData[chunkData.startIndex + from ..< chunkData.startIndex + to])
            if chunkStart + UInt64(chunkData.count) >= end { break }
            index += 1
        }
        return out
    }

    private static func decryptChunk(_ blob: Blob, index: UInt64, file: ShareFile, key: SymmetricKey) throws -> Data {
        let layout = blob.layout
        guard index < layout.chunkCount else { throw ShareError.blobOutOfBounds }
        let plainLength = layout.plaintextLength(ofChunk: index)
        let stored = try file.read(at: blob.absoluteOffset + layout.ciphertextOffset(ofChunk: index),
                                   count: Int(plainLength + ShareFormat.tagSize))
        // index < n <= 2^32, so it fits in a u32.
        let nonce = try ChunkLayout.nonce(prefix: blob.noncePrefix, index: UInt32(index),
                                          isLast: layout.isLast(index))
        do {
            let split = stored.index(stored.endIndex, offsetBy: -Int(ShareFormat.tagSize))
            let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: stored[..<split], tag: stored[split...])
            return try AES.GCM.open(box, using: key, authenticating: blob.aad)
        } catch {
            throw ShareError.authenticationFailed
        }
    }

    private static func decryptBlob(_ blob: Blob, file: ShareFile, key: () throws -> SymmetricKey) throws -> Data {
        var out = Data()
        out.reserveCapacity(Int(blob.size))
        for index in 0 ..< blob.layout.chunkCount {
            try Task.checkCancellation()
            out.append(try decryptChunk(blob, index: index, file: file, key: key()))
        }
        return out
    }
}
