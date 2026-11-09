import CryptoKit
import Foundation
import Testing
@testable import PhotoVault

@Suite("Reader: round trip and tamper checks")
struct ShareReaderTests {
    let phone = SoftwarePhoneKey()
    static let originalSize = 2_621_440 // three chunks, the last one short

    func writer() -> ShareWriter {
        ShareWriter(recipient: phone.publicKey, items: [
            .init(id: "1", name: "a.heic", kind: "photo", original: .pattern(Self.originalSize), thumb: Data([9, 8, 7])),
            .init(id: "2", name: "b.mov", kind: "video", original: .pattern(5), thumb: nil),
        ])
    }

    func open(_ data: Data, key: PhoneKey? = nil) throws -> OpenShare {
        try OpenShare(file: ShareFile(url: temporaryShare(data)), phoneKey: key ?? phone)
    }

    /// Absolute byte position of item 1's original (written first, at offset 0).
    func firstOriginalStart(_ file: Data) -> Int { blobAreaStart(of: file) }

    // MARK: Round trip

    @Test func roundTrip() throws {
        let share = try open(writer().write())
        #expect(share.manifest.title == "Test Album")
        #expect(share.manifest.items.map(\.id) == ["1", "2"])
        let photo = share.manifest.items[0]
        #expect(photo.kind == .photo)
        #expect(try share.decryptBlob(photo.original) == .pattern(Self.originalSize))
        #expect(try share.decryptBlob(try #require(photo.thumb)) == Data([9, 8, 7]))
        #expect(try share.decryptBlob(share.manifest.items[1].original) == .pattern(5))
        #expect(share.manifest.items[1].thumb == nil)
    }

    @Test func randomAccessChunkAndRanges() throws {
        let share = try open(writer().write())
        let blob = share.manifest.items[0].original
        let all = Data.pattern(Self.originalSize)
        // The last chunk decrypts on its own.
        #expect(try share.decryptChunk(blob, index: 2) == all[2_097_152...])
        let fetch: (UInt64) throws -> Data = { try share.decryptChunk(blob, index: $0) }
        for (offset, count) in [(0, 1), (1_048_570, 20), (1_048_576, 1_048_576), (2_621_000, 440), (0, Self.originalSize)] {
            let got = try share.plaintext(blob, offset: UInt64(offset), count: UInt64(count), chunk: fetch)
            #expect(got == all[offset ..< offset + count])
        }
        #expect(throws: ShareError.blobOutOfBounds) {
            try share.plaintext(blob, offset: UInt64(Self.originalSize - 1), count: 2, chunk: fetch)
        }
    }

    @Test func emptyOriginalIsOneEmptyChunk() throws {
        var w = writer()
        w.items[1].original = Data()
        let share = try open(w.write())
        let blob = share.manifest.items[1].original
        #expect(blob.layout.chunkCount == 1)
        #expect(try share.decryptBlob(blob).isEmpty)
    }

    // MARK: Tampering

    @Test func flippedByteFailsOnlyThatChunk() throws {
        var file = try writer().write()
        file[firstOriginalStart(file) + 1_048_592 + 100] ^= 0x01 // inside chunk 1
        let share = try open(file)
        let blob = share.manifest.items[0].original
        #expect(throws: ShareError.authenticationFailed) { try share.decryptChunk(blob, index: 1) }
        #expect(throws: ShareError.authenticationFailed) { try share.decryptBlob(blob) }
        #expect(try share.decryptChunk(blob, index: 0) == Data.pattern(1_048_576))
    }

    @Test func flippedTagByteFails() throws {
        var file = try writer().write()
        file[firstOriginalStart(file) + 1_048_576 + 3] ^= 0x80 // chunk 0's tag
        let share = try open(file)
        #expect(throws: ShareError.authenticationFailed) {
            try share.decryptChunk(share.manifest.items[0].original, index: 0)
        }
    }

    @Test func flippedManifestByteFailsOpen() throws {
        var file = try writer().write()
        file[file.count - 20] ^= 0x01 // the manifest is the last blob
        #expect(throws: ShareError.authenticationFailed) { try open(file) }
    }

    @Test func swappedChunksFail() throws {
        var file = try writer().write()
        let start = firstOriginalStart(file)
        let stride = 1_048_592
        let chunk0 = file[start ..< start + stride]
        let chunk1 = file[start + stride ..< start + 2 * stride]
        file.replaceSubrange(start ..< start + 2 * stride, with: chunk1 + chunk0)
        let share = try open(file)
        let blob = share.manifest.items[0].original
        #expect(throws: ShareError.authenticationFailed) { try share.decryptChunk(blob, index: 0) }
        #expect(throws: ShareError.authenticationFailed) { try share.decryptChunk(blob, index: 1) }
    }

    @Test func blobFromAnotherItemFailsAAD() throws {
        // Point item 2's original at item 1's thumb bytes: right length, wrong AAD.
        var w = writer()
        w.items[1].original = Data([1, 2, 3])
        var file = try w.write()
        let share = try open(file)
        let thumbOffset = share.manifest.items[0].thumb!.absoluteOffset
        let otherOffset = share.manifest.items[1].original.absoluteOffset
        let thumbBytes = file[Int(thumbOffset) ..< Int(thumbOffset) + 19]
        file.replaceSubrange(Int(otherOffset) ..< Int(otherOffset) + 19, with: thumbBytes)
        let tampered = try open(file)
        #expect(throws: ShareError.authenticationFailed) { try tampered.decryptBlob(tampered.manifest.items[1].original) }
    }

    @Test func truncatedFileIsRejected() throws {
        let file = try writer().write()
        #expect(throws: ShareError.blobOutOfBounds) { try open(file.prefix(file.count - 1)) }
        #expect(throws: (any Error).self) { try open(file.prefix(20)) }
    }

    @Test func missingLastChunkIsDetectedByLastFlag() throws {
        var w = writer()
        w.dropLastChunkOfFirstOriginal = true
        let share = try open(w.write())
        let blob = share.manifest.items[0].original
        #expect(blob.layout.chunkCount == 2)
        // The reader expects chunk 1 to be last; the writer sealed it as not last.
        #expect(try share.decryptChunk(blob, index: 0) == Data.pattern(1_048_576))
        #expect(throws: ShareError.authenticationFailed) { try share.decryptChunk(blob, index: 1) }
    }

    @Test func lastFlagNeverSetFails() throws {
        var w = writer()
        w.lastFlag = .never
        // The single-chunk manifest lacks its last flag, so opening fails.
        #expect(throws: ShareError.authenticationFailed) { try open(w.write()) }
    }

    @Test func lastFlagSetEarlyFails() throws {
        var w = writer()
        w.lastFlag = .always
        // Single-chunk blobs are right by accident; the 3-chunk original isn't.
        let share = try open(w.write())
        let blob = share.manifest.items[0].original
        #expect(throws: ShareError.authenticationFailed) { try share.decryptChunk(blob, index: 0) }
        #expect(throws: ShareError.authenticationFailed) { try share.decryptChunk(blob, index: 1) }
        #expect(try share.decryptChunk(blob, index: 2) == Data.pattern(Self.originalSize)[2_097_152...])
    }

    @Test func wrongKeyIDIsRejected() throws {
        let other = SoftwarePhoneKey()
        let file = try ShareWriter(recipient: other.publicKey, items: []).write()
        #expect(throws: ShareError.wrongRecipient) { try open(file) }
    }

    @Test func forgedKeyIDStillFailsUnwrap() throws {
        let other = SoftwarePhoneKey()
        var w = ShareWriter(recipient: other.publicKey, items: [])
        let mine = phone.keyID
        w.editHeader = { $0["key_id"] = mine }
        #expect(throws: ShareError.authenticationFailed) { try open(w.write()) }
    }

    @Test func notAShareFile() throws {
        var file = try writer().write()
        file[0] = UInt8(ascii: "X")
        #expect(throws: ShareError.notAShareFile) { try open(file) }
        #expect(throws: ShareError.notAShareFile) { try open(Data("PVSHARE1".utf8)) }
    }

    @Test func headerLengthLimit() throws {
        var file = Data("PVSHARE1".utf8)
        withUnsafeBytes(of: UInt32(65_537).littleEndian) { file.append(contentsOf: $0) }
        file.append(Data(count: 70_000))
        #expect(throws: ShareError.headerTooLarge) { try open(file) }
    }

    @Test func manifestSizeLimit() throws {
        var w = writer()
        let size = 16 * 1_048_576 + 1
        w.editHeader = { header in
            var manifest = header["manifest"] as! [String: Any]
            manifest["size"] = size
            manifest["length"] = size + 16 * 17
            header["manifest"] = manifest
        }
        #expect(throws: ShareError.manifestTooLarge) { try open(w.write()) }
    }

    @Test func manifestLengthMismatch() throws {
        var w = writer()
        w.editHeader = { header in
            var manifest = header["manifest"] as! [String: Any]
            manifest["length"] = (manifest["length"] as! Int) - 1
            header["manifest"] = manifest
        }
        #expect(throws: ShareError.blobLengthMismatch) { try open(w.write()) }
    }

    @Test func itemLengthMismatch() throws {
        var w = writer()
        w.editManifest = { manifest in
            var items = manifest["items"] as! [[String: Any]]
            var original = items[0]["original"] as! [String: Any]
            original["size"] = (original["size"] as! Int) + 1
            items[0]["original"] = original
            manifest["items"] = items
        }
        #expect(throws: ShareError.blobLengthMismatch) { try open(w.write()) }
    }

    @Test func itemOutOfBounds() throws {
        var w = writer()
        w.editManifest = { manifest in
            var items = manifest["items"] as! [[String: Any]]
            var thumb = items[0]["thumb"] as! [String: Any]
            thumb["offset"] = 1 << 40
            items[0]["thumb"] = thumb
            manifest["items"] = items
        }
        #expect(throws: ShareError.blobOutOfBounds) { try open(w.write()) }
    }

    @Test func duplicateItemIDs() throws {
        var w = writer()
        w.items[1].id = "1"
        #expect(throws: ShareError.malformedManifest("duplicate item id")) { try open(w.write()) }
    }

    @Test func unknownKind() throws {
        var w = writer()
        w.items[0].kind = "audio"
        #expect(throws: ShareError.malformedManifest("unknown kind")) { try open(w.write()) }
    }

    @Test func unknownVersions() throws {
        var manifest = writer()
        manifest.editManifest = { $0["version"] = 2 }
        #expect(throws: ShareError.unsupportedVersion) { try open(manifest.write()) }

        var header = writer()
        header.editHeader = { $0["version"] = 2 }
        #expect(throws: ShareError.unsupportedVersion) { try open(header.write()) }
    }

    @Test func headerFieldLengths() throws {
        let compressed = P256.KeyAgreement.PrivateKey().publicKey.compressedRepresentation
        let cases: [(String, Any)] = [
            ("ephemeral_public_key", compressed.base64EncodedString()),
            ("ephemeral_public_key", (Data([0x05]) + Data(count: 64)).base64EncodedString()),
            ("salt", Data(count: 31).base64EncodedString()),
            ("wrapped_key", Data(count: 59).base64EncodedString()),
            ("key_id", "B18B86CE1389E46D"),
            ("salt", "not base64!"),
        ]
        for (field, value) in cases {
            var w = writer()
            w.editHeader = { $0[field] = value }
            #expect(throws: ShareError.self) { try open(w.write()) }
        }
    }

    @Test func invalidEphemeralPoint() throws {
        var w = writer()
        w.editHeader = { $0["ephemeral_public_key"] = (Data([0x04]) + Data(count: 64)).base64EncodedString() }
        #expect(throws: ShareError.malformedHeader("ephemeral_public_key")) { try open(w.write()) }
    }

    @Test func noncePrefixLength() throws {
        var header = writer()
        header.editHeader = { header in
            var manifest = header["manifest"] as! [String: Any]
            manifest["nonce_prefix"] = Data(count: 6).base64EncodedString()
            header["manifest"] = manifest
        }
        #expect(throws: ShareError.self) { try open(header.write()) }

        var item = writer()
        item.editManifest = { manifest in
            var items = manifest["items"] as! [[String: Any]]
            var original = items[0]["original"] as! [String: Any]
            original["nonce_prefix"] = Data(count: 8).base64EncodedString()
            items[0]["original"] = original
            manifest["items"] = items
        }
        #expect(throws: ShareError.self) { try open(item.write()) }
    }
}
