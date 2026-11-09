import Foundation
import LocalAuthentication
import Security
import Testing
@testable import PhotoVault

/// Holds the injected Face ID call open until the test lets it finish.
@MainActor
final class AuthGate {
    private(set) var contexts: [LAContext] = []
    private var pending: CheckedContinuation<Void, Error>?
    private var started: CheckedContinuation<Void, Never>?

    func authenticate(_ context: LAContext) async throws {
        contexts.append(context)
        started?.resume()
        started = nil
        try await withCheckedThrowingContinuation { pending = $0 }
    }

    func waitUntilStarted() async {
        guard contexts.isEmpty else { return }
        await withCheckedContinuation { started = $0 }
    }

    func pass() {
        pending?.resume()
        pending = nil
    }

    func fail(_ error: Error) {
        pending?.resume(throwing: error)
        pending = nil
    }
}

@MainActor
@Suite("App model: lock and unlock")
struct AppModelTests {
    let phone = SoftwarePhoneKey()

    @Test func faceIDSheetDoesNotCancelUnlock() async {
        let gate = AuthGate()
        let phone = phone
        let model = AppModel(authenticate: gate.authenticate, loadKey: { _ in phone }, listShares: { [] })
        let unlocking = Task { await model.unlock() }
        await gate.waitUntilStarted()
        model.sceneBecameInactive()
        gate.pass()
        await unlocking.value
        #expect(model.phase == .unlocked)
        #expect(model.isPaired)
    }

    @Test func backgroundedDuringUnlockStaysLocked() async {
        let gate = AuthGate()
        var loads = 0
        let phone = phone
        let model = AppModel(authenticate: gate.authenticate, loadKey: { _ in loads += 1; return phone },
                             listShares: { [] })
        let unlocking = Task { await model.unlock() }
        await gate.waitUntilStarted()
        model.sceneBecameInactive()
        model.sceneEnteredBackground()
        // Face ID had already passed when the app went to the background.
        gate.pass()
        await unlocking.value
        #expect(model.phase == .locked)
        #expect(model.session == nil)
        #expect(!model.isAuthenticating)
        #expect(loads == 0)
    }

    @Test func staleUnlockIsRejected() async {
        let gate = AuthGate()
        var loads = 0
        let phone = phone
        let model = AppModel(authenticate: gate.authenticate, loadKey: { _ in loads += 1; return phone },
                             listShares: { [] })
        let unlocking = Task { await model.unlock() }
        await gate.waitUntilStarted()
        model.lock()
        // lock() invalidated the context, so Face ID reports a cancel.
        gate.fail(LAError(.appCancel))
        await unlocking.value
        #expect(model.phase == .locked)
        #expect(model.session == nil)
        #expect(model.lockMessage == nil)
        #expect(loads == 0)

        // A new attempt after the lock still works.
        let retry = Task { await model.unlock() }
        while gate.contexts.count < 2 { await Task.yield() }
        gate.pass()
        await retry.value
        #expect(model.phase == .unlocked)
    }

    @Test func keychainReadErrorIsNotUnpaired() async {
        let model = AppModel(authenticate: { _ in },
                             loadKey: { _ in throw KeyStoreError.keychain(errSecInteractionNotAllowed) },
                             listShares: { [] })
        await model.unlock()
        // Unlocked without a key would show Create Pairing Key.
        #expect(model.phase == .locked)
        #expect(model.session == nil)
        #expect(model.lockMessage == KeyStoreError.keychain(errSecInteractionNotAllowed).localizedDescription)
    }

    @Test func unlockPublishesAlbums() async throws {
        let stored = try storedShare(for: phone)
        let phone = phone
        let model = AppModel(authenticate: { _ in }, loadKey: { _ in phone }, listShares: { [stored] })
        await model.unlock()
        await (try #require(model.albumLoad)).value
        #expect(model.albums.count == 1)
        guard case .ready(let share) = model.albums.first?.content else {
            Issue.record("album didn't open")
            return
        }
        #expect(share.manifest.title == "Test Album")
    }

    @Test func loadFinishingAfterLockIsDiscarded() async throws {
        let stored = try storedShare(for: phone)
        let phone = phone
        let gate = DispatchSemaphore(value: 0)
        let model = AppModel(authenticate: { _ in }, loadKey: { _ in phone },
                             listShares: { gate.wait(); return [stored] })
        await model.unlock()
        let load = try #require(model.albumLoad)
        model.lock()
        gate.signal()
        await load.value
        #expect(model.albums.isEmpty)
        #expect(model.session == nil)
    }

    @Test func lockRevokesOpenShares() async throws {
        let stored = try storedShare(for: phone)
        let phone = phone
        let model = AppModel(authenticate: { _ in }, loadKey: { _ in phone }, listShares: { [stored] })
        await model.unlock()
        await (try #require(model.albumLoad)).value
        guard case .ready(let share) = model.albums.first?.content else {
            Issue.record("album didn't open")
            return
        }
        let blob = share.manifest.items[0].original
        #expect(try share.decryptBlob(blob) == Data([1, 2, 3]))
        model.lock()
        // A view still holding the share can't decrypt any more.
        #expect(throws: ShareError.keyUnavailable) { try share.decryptBlob(blob) }
    }

    @Test func shareReplacedByReloadIsRevokedOnLock() async throws {
        let stored = try storedShare(for: phone)
        let phone = phone
        let model = AppModel(authenticate: { _ in }, loadKey: { _ in phone }, listShares: { [stored] })
        await model.unlock()
        await (try #require(model.albumLoad)).value
        guard case .ready(let old) = model.albums.first?.content else {
            Issue.record("album didn't open")
            return
        }
        model.reloadAlbums()
        await (try #require(model.albumLoad)).value
        guard case .ready(let new) = model.albums.first?.content else {
            Issue.record("album didn't reopen")
            return
        }
        #expect(old !== new)
        let blob = old.manifest.items[0].original
        // A reload alone leaves the old share working, so a playing video goes on.
        #expect(try old.decryptBlob(blob) == Data([1, 2, 3]))
        model.lock()
        #expect(throws: ShareError.keyUnavailable) { try old.decryptBlob(blob) }
    }

    @Test func deleteRevokesCopiesKeptAcrossReload() async throws {
        let stored = try storedShare(for: phone)
        let phone = phone
        let model = AppModel(authenticate: { _ in }, loadKey: { _ in phone }, listShares: { [stored] })
        await model.unlock()
        await (try #require(model.albumLoad)).value
        guard case .ready(let old) = model.albums.first?.content else {
            Issue.record("album didn't open")
            return
        }
        model.reloadAlbums()
        await (try #require(model.albumLoad)).value
        let current = try #require(model.albums.first)
        let blob = old.manifest.items[0].original
        model.delete(current)
        #expect(model.albums.isEmpty)
        #expect(throws: ShareError.keyUnavailable) { try old.decryptBlob(blob) }
    }

    @Test func registryRevokesSharesOpenedAfterDelete() async throws {
        let stored = try storedShare(for: phone)
        let phone = phone
        let model = AppModel(authenticate: { _ in }, loadKey: { _ in phone }, listShares: { [stored] })
        await model.unlock()
        await (try #require(model.albumLoad)).value
        guard case .ready(let share) = model.albums.first?.content else {
            Issue.record("album didn't open")
            return
        }
        // A reload racing a delete registers its copy after the delete.
        let registry = OpenShareRegistry()
        registry.revoke(url: stored.url)
        registry.add(share, url: stored.url)
        #expect(throws: ShareError.keyUnavailable) { try share.decryptBlob(share.manifest.items[0].original) }
    }

    @Test func deleteDuringReloadDoesNotBringAlbumBack() async throws {
        let stored = try storedShare(for: phone)
        let phone = phone
        // The first load runs straight through. The second waits for the test.
        // Starting at 0 keeps libdispatch from trapping when the semaphore is freed.
        let gate = DispatchSemaphore(value: 0)
        gate.signal()
        let model = AppModel(authenticate: { _ in }, loadKey: { _ in phone },
                             listShares: { gate.wait(); return [stored] })
        await model.unlock()
        await (try #require(model.albumLoad)).value
        let album = try #require(model.albums.first)
        guard case .ready(let share) = album.content else {
            Issue.record("album didn't open")
            return
        }
        model.reloadAlbums()
        let reload = try #require(model.albumLoad)
        model.delete(album)
        #expect(model.albums.isEmpty)
        #expect(throws: ShareError.keyUnavailable) { try share.decryptBlob(share.manifest.items[0].original) }
        gate.signal()
        await reload.value
        #expect(model.albums.isEmpty)
    }

    private func storedShare(for key: PhoneKey) throws -> ShareStore.StoredShare {
        let data = try ShareWriter(recipient: key.publicKey, items: [
            .init(id: "1", name: "a.heic", kind: "photo", original: Data([1, 2, 3]), thumb: nil),
        ]).write()
        return ShareStore.StoredShare(url: try temporaryShare(data), imported: Date())
    }
}
