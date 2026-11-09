import Foundation

/// Imported `.pvshare` files in Application Support/Shares, protected with
/// NSFileProtectionComplete and excluded from backup. Files stay encrypted.
enum ShareStore {
    struct StoredShare: Identifiable, Hashable {
        let url: URL
        let imported: Date
        var id: String { url.lastPathComponent }
    }

    enum ImportError: Error, LocalizedError {
        case notPaired

        var errorDescription: String? {
            switch self {
            case .notPaired: "Pair this iPhone with your Mac before importing shares."
            }
        }
    }

    static func directory() throws -> URL {
        let support = try FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        var dir = support.appendingPathComponent("Shares", isDirectory: true)
        if !FileManager.default.fileExists(atPath: dir.path) {
            try FileManager.default.createDirectory(
                at: dir, withIntermediateDirectories: true,
                attributes: [.protectionKey: FileProtectionType.complete])
        }
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try dir.setResourceValues(values)
        return dir
    }

    static func list() -> [StoredShare] {
        guard let dir = try? directory(),
              let urls = try? FileManager.default.contentsOfDirectory(
                at: dir, includingPropertiesForKeys: [.creationDateKey], options: [.skipsHiddenFiles])
        else { return [] }
        return urls
            .filter { $0.pathExtension == "pvshare" }
            .map { StoredShare(url: $0, imported: (try? $0.resourceValues(forKeys: [.creationDateKey]))?.creationDate ?? .distantPast) }
            .sorted { $0.imported > $1.imported }
    }

    /// Validates the plaintext header, checks it's addressed to this phone,
    /// then copies the file in. Only ciphertext is copied; nothing is decrypted.
    @discardableResult
    static func importFile(at source: URL) throws -> StoredShare {
        try importFile(at: source, publicKey: KeyStore.storedPublicKey(), into: directory(), inbox: inboxDirectory())
    }

    /// The Documents/Inbox copy of `source` is deleted once the file is stored,
    /// or when the file itself is rejected. A failed read or copy keeps it.
    static func importFile(at source: URL, publicKey: Data?, into dir: URL, inbox: URL?) throws -> StoredShare {
        let scoped = source.startAccessingSecurityScopedResource()
        defer { if scoped { source.stopAccessingSecurityScopedResource() } }
        guard let publicKey else { throw ImportError.notPaired }
        do {
            let header = try ShareFile(url: source).header
            guard header.keyID == PublicKeyIdentity.keyID(publicKey) else { throw ShareError.wrongRecipient }
        } catch let error as ShareError {
            // These mean the file can never be imported: it isn't a share, its
            // header is damaged or truncated, it needs a newer app, or it's for
            // another iPhone. Don't leave it in the backed-up Inbox. Open, read,
            // and permission failures from ShareFile(url:) aren't ShareErrors,
            // so they keep the file for another try.
            switch error {
            case .notAShareFile, .headerTooLarge, .malformedHeader, .unsupportedVersion,
                 .blobOutOfBounds, .wrongRecipient:
                removeIfInInbox(source, inbox: inbox)
            default:
                break
            }
            throw error
        }

        // Copy to a hidden temporary name, protect it, then rename into place,
        // so a partial copy never shows up as a share.
        var temporary = dir.appendingPathComponent(".import-\(UUID().uuidString)")
        let now = Date()
        let destination: URL
        do {
            try FileManager.default.copyItem(at: source, to: temporary)
            try FileManager.default.setAttributes(
                [.protectionKey: FileProtectionType.complete, .creationDate: now], ofItemAtPath: temporary.path)
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            try temporary.setResourceValues(values)
            var candidate: URL
            repeat {
                candidate = dir.appendingPathComponent("PhotoVault-\(randomHex(4)).pvshare")
            } while FileManager.default.fileExists(atPath: candidate.path)
            try FileManager.default.moveItem(at: temporary, to: candidate)
            destination = candidate
        } catch {
            try? FileManager.default.removeItem(at: temporary)
            throw error
        }
        removeIfInInbox(source, inbox: inbox)
        return StoredShare(url: destination, imported: now)
    }

    static func delete(_ share: StoredShare) throws {
        try FileManager.default.removeItem(at: share.url)
    }

    static func deleteAll() throws {
        try deleteAll(in: directory())
    }

    /// Removes everything in `dir`, including leftover temporary copies.
    /// Throws if the folder can't be listed or any file stays behind.
    static func deleteAll(in dir: URL) throws {
        var firstError: Error?
        for url in try FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil) {
            do {
                try FileManager.default.removeItem(at: url)
            } catch {
                firstError = firstError ?? error
            }
        }
        if let firstError { throw firstError }
    }

    /// Files opened from AirDrop or Files arrive in Documents/Inbox, which is
    /// backed up.
    private static func inboxDirectory() -> URL? {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first?
            .appendingPathComponent("Inbox", isDirectory: true)
    }

    private static func removeIfInInbox(_ url: URL, inbox: URL?) {
        guard let inbox else { return }
        if url.standardizedFileURL.path.hasPrefix(inbox.standardizedFileURL.path + "/") {
            try? FileManager.default.removeItem(at: url)
        }
    }

    private static func randomHex(_ bytes: Int) -> String {
        (0 ..< bytes).map { _ in String(format: "%02x", UInt8.random(in: .min ... .max)) }.joined()
    }
}
