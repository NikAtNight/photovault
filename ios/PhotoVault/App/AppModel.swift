import Foundation
import LocalAuthentication
import Observation
import UIKit

/// Everything that exists only while unlocked. Dropping it forgets the
/// LAContext, the phone key handle, every content key, and every decoded image.
@MainActor
@Observable
final class UnlockedSession {
    @ObservationIgnored let context: LAContext
    var phoneKey: PhoneKey?
    @ObservationIgnored let thumbnails = NSCache<NSString, UIImage>()
    /// Every share opened in this session, including ones a reload replaced.
    @ObservationIgnored let openShares = OpenShareRegistry()

    init(context: LAContext, phoneKey: PhoneKey?) {
        self.context = context
        self.phoneKey = phoneKey
        thumbnails.countLimit = 300
    }

    func end() {
        openShares.close()
        thumbnails.removeAllObjects()
        phoneKey = nil
        context.invalidate()
    }
}

/// Tracks the shares one session opened, so ending the session revokes the
/// ones a view, thumbnail task, or video loader still holds. Entries are weak:
/// a share nobody holds goes away with its key.
final class OpenShareRegistry: @unchecked Sendable {
    private struct Entry { weak var share: OpenShare?; let url: URL }
    private let lock = NSLock()
    /// Only touched under `lock`.
    private var entries: [Entry] = []
    private var deleted: Set<URL> = []
    private var closed = false

    /// Adds `share`, opened from `url`. Revokes it right away if the session
    /// already ended or the album at `url` was deleted.
    func add(_ share: OpenShare, url: URL) {
        lock.withLock {
            if closed || deleted.contains(url) {
                share.revoke()
                return
            }
            entries.removeAll { $0.share == nil }
            entries.append(Entry(share: share, url: url))
        }
    }

    /// Revokes every share opened from `url`, including copies a view kept
    /// across a reload, and any opened from it later.
    func revoke(url: URL) {
        lock.withLock {
            deleted.insert(url)
            for entry in entries where entry.url == url { entry.share?.revoke() }
            entries.removeAll { $0.url == url }
        }
    }

    /// Revokes every share added so far. The session goes on.
    func revokeAll() {
        lock.withLock {
            for entry in entries { entry.share?.revoke() }
            entries = []
        }
    }

    /// Revokes every share, now and any added later.
    func close() {
        lock.withLock { closed = true }
        revokeAll()
    }
}

struct Album: Identifiable {
    enum Content {
        case ready(OpenShare)
        case failed(String)
    }

    let stored: ShareStore.StoredShare
    let content: Content
    var id: String { stored.id }
}

@MainActor
@Observable
final class AppModel {
    enum Phase: Equatable {
        case locked
        case unlocked
        case reenrollRequired
    }

    private(set) var phase: Phase = .locked
    private(set) var session: UnlockedSession?
    private(set) var albums: [Album] = []
    private(set) var isAuthenticating = false
    var lockMessage: String?
    /// One-line message about the last import, shown as an alert.
    var notice: String?

    /// Auto-prompt for Face ID once each time the app locks.
    private var autoPromptArmed = true
    /// Bumped by every lock. An unlock that started under an older value is stale.
    private var unlockGeneration = 0
    /// The context of the unlock in progress, so lock() can invalidate it.
    private var pendingContext: LAContext?
    /// The album load in progress. Internal so tests can await it.
    private(set) var albumLoad: Task<Void, Never>?

    private let authenticate: @MainActor (LAContext) async throws -> Void
    private let loadKey: @MainActor (LAContext) throws -> PhoneKey?
    private let listShares: @Sendable () -> [ShareStore.StoredShare]

    init(authenticate: @escaping @MainActor (LAContext) async throws -> Void = { try await KeyStore.authenticate($0) },
         loadKey: @escaping @MainActor (LAContext) throws -> PhoneKey? = { try KeyStore.loadKey(context: $0) },
         listShares: @escaping @Sendable () -> [ShareStore.StoredShare] = { ShareStore.list() }) {
        self.authenticate = authenticate
        self.loadKey = loadKey
        self.listShares = listShares
    }

    var isPaired: Bool { session?.phoneKey != nil }
    /// Keeps the pairing screen up after the first key is made, until the
    /// user has sent the pairing file and taps Done.
    private(set) var isFinishingPairing = false

    // MARK: Lock and unlock

    func sceneBecameActive() {
        guard phase == .locked, autoPromptArmed, !isAuthenticating else { return }
        autoPromptArmed = false
        Task { await unlock() }
    }

    /// The Face ID sheet itself makes the scene inactive, so an unlock in
    /// progress is left alone.
    func sceneBecameInactive() {
        guard !isAuthenticating else { return }
        lock()
    }

    /// Always locks. An unlock in progress becomes stale and stays locked,
    /// even if Face ID already passed.
    func sceneEnteredBackground() {
        lock()
    }

    func lock() {
        unlockGeneration += 1
        pendingContext?.invalidate()
        pendingContext = nil
        dropAlbums()
        session?.end()
        session = nil
        isFinishingPairing = false
        if phase == .unlocked { phase = .locked }
        autoPromptArmed = true
    }

    func unlock() async {
        guard !isAuthenticating else { return }
        isAuthenticating = true
        defer { isAuthenticating = false }
        lockMessage = nil
        let generation = unlockGeneration
        // One fresh context per unlock session, reused for every unwrap in it.
        let context = KeyStore.makeContext()
        pendingContext = context
        defer { if pendingContext === context { pendingContext = nil } }
        do {
            try await authenticate(context)
            // The app locked or went to the background while Face ID ran.
            guard generation == unlockGeneration else {
                context.invalidate()
                return
            }
            let key = try loadKey(context)
            session = UnlockedSession(context: context, phoneKey: key)
            phase = .unlocked
            reloadAlbums()
        } catch where generation != unlockGeneration {
            context.invalidate()
        } catch KeyStoreError.keyInvalidated {
            context.invalidate()
            phase = .reenrollRequired
        } catch let error as LAError where error.code == .userCancel || error.code == .systemCancel || error.code == .appCancel {
            context.invalidate()
        } catch let error as LAError where error.code == .biometryLockout {
            context.invalidate()
            lockMessage = "Face ID is locked after too many tries. Lock and unlock your iPhone with its passcode, then try again."
        } catch {
            context.invalidate()
            lockMessage = error.localizedDescription
        }
    }

    // MARK: Pairing

    func createPairingKey() throws {
        guard let session else { return }
        session.phoneKey = try KeyStore.createKey(context: session.context)
        isFinishingPairing = true
        reloadAlbums()
    }

    func finishPairing() {
        isFinishingPairing = false
    }

    /// Deletes every imported share, then the key they can't be opened without.
    /// If a share can't be deleted, the key stays so the user can try again.
    func resetPairing() {
        do {
            try ShareStore.deleteAll()
        } catch {
            notice = "Couldn't delete every album, so pairing wasn't reset. Try again. \(error.localizedDescription)"
            reloadAlbums() // show only the albums still on disk
            return
        }
        KeyStore.delete()
        session?.phoneKey = nil
        session?.openShares.revokeAll()
        session?.thumbnails.removeAllObjects()
        dropAlbums()
        if phase == .reenrollRequired {
            phase = .locked
            autoPromptArmed = false
            Task { await unlock() }
        }
    }

    // MARK: Albums

    /// Opens every share off the main actor, then publishes the result only
    /// if the same session is still unlocked. The shares it replaces stay
    /// usable, so a playing video keeps going, until the session ends.
    func reloadAlbums() {
        guard let session, let key = session.phoneKey else {
            dropAlbums()
            return
        }
        albumLoad?.cancel()
        let listShares = listShares
        let registry = session.openShares
        albumLoad = Task {
            let worker = Task.detached(priority: .userInitiated) {
                Self.openAll(listShares(), key: key, registry: registry)
            }
            let opened = await withTaskCancellationHandler {
                await worker.value
            } onCancel: {
                worker.cancel()
            }
            guard !Task.isCancelled, self.session === session else {
                Self.revoke(opened)
                return
            }
            // An album deleted while this load ran must not come back.
            let deleted = opened.filter { !FileManager.default.fileExists(atPath: $0.stored.url.path) }
            Self.revoke(deleted)
            albums = opened.filter { album in !deleted.contains { $0.id == album.id } }
        }
    }

    /// Cancels any load in progress and forgets every content key.
    private func dropAlbums() {
        albumLoad?.cancel()
        albumLoad = nil
        Self.revoke(albums)
        albums = []
    }

    private nonisolated static func revoke(_ albums: [Album]) {
        for album in albums {
            if case .ready(let share) = album.content { share.revoke() }
        }
    }

    /// Stops between opens once cancelled, and revokes what it already opened.
    private nonisolated static func openAll(_ shares: [ShareStore.StoredShare], key: PhoneKey,
                                            registry: OpenShareRegistry) -> [Album] {
        var albums: [Album] = []
        for stored in shares {
            if Task.isCancelled { break }
            albums.append(open(stored, key: key, registry: registry))
        }
        if Task.isCancelled {
            revoke(albums)
            return []
        }
        return albums
    }

    private nonisolated static func open(_ stored: ShareStore.StoredShare, key: PhoneKey,
                                         registry: OpenShareRegistry) -> Album {
        do {
            let share = try OpenShare(file: ShareFile(url: stored.url), phoneKey: key)
            registry.add(share, url: stored.url)
            return Album(stored: stored, content: .ready(share))
        } catch {
            return Album(stored: stored, content: .failed(error.localizedDescription))
        }
    }

    func delete(_ album: Album) {
        do {
            try ShareStore.delete(album.stored)
            session?.openShares.revoke(url: album.stored.url)
            Self.revoke([album] + albums.filter { $0.id == album.id })
            albums.removeAll { $0.id == album.id }
        } catch {
            notice = "Couldn't delete the album: \(error.localizedDescription)"
        }
    }

    /// Handles files from AirDrop, Files, or the import button. The copy needs
    /// no Face ID because only the plaintext header is read.
    func importFiles(_ urls: [URL]) {
        var imported = 0
        var failures: [String] = []
        for url in urls {
            do {
                try ShareStore.importFile(at: url)
                imported += 1
            } catch {
                failures.append(error.localizedDescription)
            }
        }
        if imported > 0, session?.phoneKey != nil { reloadAlbums() }
        if let failure = failures.first {
            notice = failures.count == 1 ? failure : "\(failures.count) files weren't imported. \(failure)"
        } else if imported > 0, phase != .unlocked {
            notice = imported == 1 ? "Album imported. Unlock to view it." : "\(imported) albums imported. Unlock to view them."
        }
    }
}
