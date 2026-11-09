import CryptoKit
import Foundation
import Testing
@testable import PhotoVault

@Suite("Chunk math, AAD, identity, pairing file")
struct ShareFormatTests {
    private let mib: UInt64 = 1_048_576

    @Test func nonceIsPrefixThenBigEndianIndexThenLastFlag() throws {
        let prefix = Data([1, 2, 3, 4, 5, 6, 7])
        let last = try ChunkLayout.nonce(prefix: prefix, index: 0x0102_0304, isLast: true)
        #expect(last.withUnsafeBytes { Data($0) } == Data([1, 2, 3, 4, 5, 6, 7, 0x01, 0x02, 0x03, 0x04, 0x01]))
        let notLast = try ChunkLayout.nonce(prefix: prefix, index: 2, isLast: false)
        #expect(notLast.withUnsafeBytes { Data($0) } == Data([1, 2, 3, 4, 5, 6, 7, 0, 0, 0, 2, 0]))
    }

    @Test func nonceRejectsWrongPrefixLength() {
        #expect(throws: ShareError.self) { try ChunkLayout.nonce(prefix: Data(count: 6), index: 0, isLast: true) }
        #expect(throws: ShareError.self) { try ChunkLayout.nonce(prefix: Data(count: 8), index: 0, isLast: true) }
    }

    @Test func emptyPlaintextIsOneEmptyChunk() throws {
        let layout = try ChunkLayout(size: 0, length: 16)
        #expect(layout.chunkCount == 1)
        #expect(layout.plaintextLength(ofChunk: 0) == 0)
        #expect(layout.isLast(0))
    }

    @Test func chunkCountAndOffsets() throws {
        let exact = try ChunkLayout(size: mib, length: mib + 16)
        #expect(exact.chunkCount == 1)

        let oneOver = try ChunkLayout(size: mib + 1, length: mib + 1 + 32)
        #expect(oneOver.chunkCount == 2)
        #expect(oneOver.plaintextLength(ofChunk: 1) == 1)

        let fixture = try ChunkLayout(size: 2_621_440, length: 2_621_440 + 48)
        #expect(fixture.chunkCount == 3)
        #expect(fixture.ciphertextOffset(ofChunk: 0) == 0)
        #expect(fixture.ciphertextOffset(ofChunk: 1) == mib + 16)
        #expect(fixture.ciphertextOffset(ofChunk: 2) == 2 * (mib + 16))
        #expect(fixture.plaintextLength(ofChunk: 2) == 524_288)
        #expect(!fixture.isLast(1) && fixture.isLast(2))
        #expect(fixture.chunkIndex(forPlaintextOffset: mib - 1) == 0)
        #expect(fixture.chunkIndex(forPlaintextOffset: mib) == 1)
        #expect(fixture.chunkIndex(forPlaintextOffset: 2_621_439) == 2)
    }

    @Test func lengthMustEqualSizePlusTags() {
        #expect(throws: ShareError.blobLengthMismatch) { try ChunkLayout(size: 10, length: 10) }
        #expect(throws: ShareError.blobLengthMismatch) { try ChunkLayout(size: 10, length: 42) }
        #expect(throws: ShareError.blobLengthMismatch) { try ChunkLayout(size: 3 * mib, length: 3 * mib + 32) }
    }

    @Test func layoutArithmeticIsChecked() {
        #expect(throws: ShareError.blobLengthMismatch) { try ChunkLayout(size: .max, length: .max) }
        // n = 2^32 + 1 chunks, one more than a u32 index allows.
        let size = (UInt64(1) << 32) * mib + 1
        #expect(throws: ShareError.blobLengthMismatch) {
            try ChunkLayout(size: size, length: size + 16 * ((UInt64(1) << 32) + 1))
        }
    }

    @Test func blobAADIsItsID() throws {
        let ref = BlobRef(offset: 0, length: 26, noncePrefix: Data(count: 7), size: 10)
        let blob = try Blob(id: "7/thumb", ref: ref, blobAreaStart: 100, fileSize: 126)
        #expect(blob.aad == Data("7/thumb".utf8))
        #expect(blob.absoluteOffset == 100)
    }

    @Test func blobRangeMustLieInsideFile() {
        let ref = BlobRef(offset: 1, length: 26, noncePrefix: Data(count: 7), size: 10)
        #expect(throws: ShareError.blobOutOfBounds) {
            try Blob(id: "manifest", ref: ref, blobAreaStart: 100, fileSize: 126)
        }
        let huge = BlobRef(offset: .max, length: 16, noncePrefix: Data(count: 7), size: 0)
        #expect(throws: ShareError.blobOutOfBounds) {
            try Blob(id: "manifest", ref: huge, blobAreaStart: 100, fileSize: .max)
        }
    }

    // Expected values computed with OpenSSL from the spec's test scalar.
    private let fixturePublicKey = Data(hex: "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299")

    @Test func keyIDAndVerificationCode() throws {
        let key = try SoftwarePhoneKey.fixtureKey()
        #expect(key.publicKey == fixturePublicKey)
        #expect(key.keyID == "b18b86ce1389e46d")
        #expect(key.verificationCode == "B18B 86CE 1389 E46D E87A A4A5 131C E83C")
    }

    @Test func pairingFileEncoding() throws {
        let data = try PairingFile(publicKey: fixturePublicKey).encoded()
        let json = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(Set(json.keys) == ["format", "version", "label", "public_key", "key_id"])
        #expect(json["format"] as? String == "photovault-pair")
        #expect(json["version"] as? Int == 1)
        #expect(json["label"] as? String == "iPhone")
        #expect(json["key_id"] as? String == "b18b86ce1389e46d")
        let publicKey = try #require(Data(base64Encoded: json["public_key"] as? String ?? ""))
        #expect(publicKey == fixturePublicKey)
        #expect(publicKey.count == 65 && publicKey.first == 0x04)
    }
}
