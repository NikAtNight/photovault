import Foundation
import Testing
@testable import PhotoVault

@Suite("Share store: import")
struct ShareStoreTests {
    let phone = SoftwarePhoneKey()

    /// A fake Documents/Inbox with one share file in it, plus a destination folder.
    func makeFolders() throws -> (inbox: URL, source: URL, shares: URL) {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("import-\(UUID().uuidString)")
        let inbox = root.appendingPathComponent("Documents/Inbox", isDirectory: true)
        let shares = root.appendingPathComponent("Shares", isDirectory: true)
        try FileManager.default.createDirectory(at: inbox, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: shares, withIntermediateDirectories: true)
        let source = inbox.appendingPathComponent("PhotoVault-abcd.pvshare")
        let data = try ShareWriter(recipient: phone.publicKey, items: [
            .init(id: "1", name: "a.heic", kind: "photo", original: Data([1, 2, 3]), thumb: nil),
        ]).write()
        try data.write(to: source)
        return (inbox, source, shares)
    }

    func contents(_ dir: URL) throws -> [String] {
        try FileManager.default.contentsOfDirectory(atPath: dir.path).sorted()
    }

    @Test func successfulImportRemovesInboxCopy() throws {
        let (inbox, source, shares) = try makeFolders()
        let original = try Data(contentsOf: source)
        let stored = try ShareStore.importFile(at: source, publicKey: phone.publicKey, into: shares, inbox: inbox)
        #expect(!FileManager.default.fileExists(atPath: source.path))
        // Only the final file, no temporary left behind.
        #expect(try contents(shares) == [stored.url.lastPathComponent])
        #expect(stored.url.pathExtension == "pvshare")
        #expect(try Data(contentsOf: stored.url) == original)
        #expect(try stored.url.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup == true)
    }

    @Test func failedCopyKeepsInboxCopy() throws {
        let (inbox, source, shares) = try makeFolders()
        // A destination folder that doesn't exist makes the copy fail.
        let missing = shares.appendingPathComponent("missing", isDirectory: true)
        #expect(throws: (any Error).self) {
            try ShareStore.importFile(at: source, publicKey: phone.publicKey, into: missing, inbox: inbox)
        }
        #expect(FileManager.default.fileExists(atPath: source.path))
        #expect(try contents(shares).isEmpty)
    }

    @Test func wrongRecipientIsRemovedFromInbox() throws {
        let (inbox, source, shares) = try makeFolders()
        #expect(throws: ShareError.wrongRecipient) {
            try ShareStore.importFile(at: source, publicKey: SoftwarePhoneKey().publicKey, into: shares, inbox: inbox)
        }
        #expect(!FileManager.default.fileExists(atPath: source.path))
        #expect(try contents(shares).isEmpty)
    }

    @Test func unreadableHeaderKeepsInboxCopy() throws {
        let (inbox, source, shares) = try makeFolders()
        // No read permission makes ShareFile(url:) fail before it sees the header.
        try FileManager.default.setAttributes([.posixPermissions: 0o000], ofItemAtPath: source.path)
        defer { try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: source.path) }
        #expect(throws: CocoaError.self) {
            try ShareStore.importFile(at: source, publicKey: phone.publicKey, into: shares, inbox: inbox)
        }
        #expect(FileManager.default.fileExists(atPath: source.path))
        #expect(try contents(shares).isEmpty)
    }

    @Test func deleteAllEmptiesFolder() throws {
        let (inbox, source, shares) = try makeFolders()
        _ = try ShareStore.importFile(at: source, publicKey: phone.publicKey, into: shares, inbox: inbox)
        try Data([1]).write(to: shares.appendingPathComponent(".import-leftover"))
        try ShareStore.deleteAll(in: shares)
        #expect(try contents(shares).isEmpty)
    }

    @Test func deleteAllThrowsWhenFolderCantBeListed() throws {
        let (_, _, shares) = try makeFolders()
        #expect(throws: (any Error).self) {
            try ShareStore.deleteAll(in: shares.appendingPathComponent("missing", isDirectory: true))
        }
    }
}
