import Foundation
import Testing
@testable import PhotoVault

/// Decrypts the file the Rust side writes (`share::tests::write_ios_fixture`).
/// Fails if the fixture is missing. Reads it from the source tree, which the
/// simulator can reach.
@Suite("Interop fixture from the Mac side")
struct InteropFixtureTests {
    static let fixtureURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .appendingPathComponent("Fixtures/fixture.pvshare")

    @Test
    func decryptsEveryByte() throws {
        let file = try ShareFile(url: Self.fixtureURL)
        #expect(file.header.keyID == "b18b86ce1389e46d")
        let share = try OpenShare(file: file, phoneKey: try SoftwarePhoneKey.fixtureKey())
        #expect(share.manifest.title == "Fixture")
        #expect(share.manifest.items.count == 2)

        let first = share.manifest.items[0]
        #expect(first.id == "1")
        #expect(first.name == "pattern.bin")
        #expect(first.kind == .photo)
        #expect(first.original.size == 2_621_440)
        #expect(first.original.layout.chunkCount == 3)
        let original = try share.decryptBlob(first.original)
        #expect(original.count == 2_621_440)
        #expect(original == Data.pattern(2_621_440))
        let thumb = try share.decryptBlob(try #require(first.thumb))
        #expect(thumb == Data(0 ..< 10))

        let second = share.manifest.items[1]
        #expect(second.id == "2")
        #expect(second.name == "empty.mov")
        #expect(second.kind == .video)
        #expect(second.thumb == nil)
        #expect(second.original.size == 0)
        #expect(second.original.layout.chunkCount == 1)
        #expect(try share.decryptBlob(second.original).isEmpty)
    }

    @Test
    func fixtureRejectsOtherKeys() throws {
        let file = try ShareFile(url: Self.fixtureURL)
        #expect(throws: ShareError.wrongRecipient) { try OpenShare(file: file, phoneKey: SoftwarePhoneKey()) }
    }
}
