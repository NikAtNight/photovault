import CryptoKit
import Foundation
import LocalAuthentication
import Security

enum KeyStoreError: Error, LocalizedError {
    case noFaceID(String)
    case keyInvalidated
    case secureEnclaveUnavailable
    case keychain(OSStatus)

    var errorDescription: String? {
        switch self {
        case .noFaceID(let message): message
        case .keyInvalidated:
            "Face ID changed on this iPhone, so the pairing key no longer works. Pair this iPhone with your Mac again, then send your albums again."
        case .secureEnclaveUnavailable: "This device has no Secure Enclave, so PhotoVault can't create a key."
        case .keychain(let status): "The keychain couldn't reach the pairing key (error \(status)). Try again."
        }
    }
}

/// The Secure Enclave key, used through an LAContext that already passed Face ID.
struct SecureEnclavePhoneKey: PhoneKey {
    let key: SecureEnclave.P256.KeyAgreement.PrivateKey
    var publicKey: Data { key.publicKey.x963Representation }

    func sharedSecret(with ephemeral: P256.KeyAgreement.PublicKey) throws -> SharedSecret {
        do {
            return try key.sharedSecretFromKeyAgreement(with: ephemeral)
        } catch {
            throw ShareError.keyUnavailable
        }
    }
}

#if DEBUG && targetEnvironment(simulator)
/// The simulator has no Secure Enclave. Debug simulator builds only; this type
/// does not exist in device builds or release builds.
struct SimulatorSoftwarePhoneKey: PhoneKey {
    let key: P256.KeyAgreement.PrivateKey
    var publicKey: Data { key.publicKey.x963Representation }

    func sharedSecret(with ephemeral: P256.KeyAgreement.PublicKey) throws -> SharedSecret {
        try key.sharedSecretFromKeyAgreement(with: ephemeral)
    }
}
#endif

/// Face ID checks and the keychain items that hold the pairing key.
enum KeyStore {
    private static let service = "com.talix.photovault.ios.pairing"
    private enum Account: String {
        /// Secure Enclave key blob (dataRepresentation). Only this device's SE can use it.
        case privateKey = "private-key"
        /// Public key, so imports can check key_id without Face ID.
        case publicKey = "public-key"
        /// Face ID enrollment state hash at pairing time.
        case biometryState = "biometry-state"
    }

    static let unlockReason = "Unlock your shared albums"

    /// A fresh context with no passcode fallback. Never sets
    /// touchIDAuthenticationAllowableReuseDuration.
    static func makeContext() -> LAContext {
        let context = LAContext()
        context.localizedFallbackTitle = ""
        return context
    }

    /// Fails unless the device has Face ID hardware with a face enrolled.
    /// `.biometryCurrentSet` alone would also accept Touch ID or Optic ID.
    static func requireFaceID(_ context: LAContext) throws {
        var error: NSError?
        let canEvaluate = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        guard context.biometryType == .faceID else {
            throw KeyStoreError.noFaceID("PhotoVault unlocks with Face ID only, and this iPhone doesn't have Face ID.")
        }
        guard canEvaluate else {
            switch LAError.Code(rawValue: error?.code ?? 0) {
            case .biometryNotEnrolled:
                throw KeyStoreError.noFaceID("Set up Face ID in Settings to use PhotoVault.")
            case .biometryLockout:
                throw KeyStoreError.noFaceID("Face ID is locked after too many tries. Lock and unlock your iPhone with its passcode, then try again.")
            case .passcodeNotSet:
                throw KeyStoreError.noFaceID("Set a device passcode and Face ID in Settings to use PhotoVault.")
            default:
                throw KeyStoreError.noFaceID("Face ID isn't available right now.")
            }
        }
    }

    /// Runs the Face ID prompt on `context`. Biometrics only, no passcode.
    /// Main actor, so the caller can keep `context` and invalidate it on lock
    /// while the prompt is up.
    @MainActor
    static func authenticate(_ context: LAContext) async throws {
        try requireFaceID(context)
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: unlockReason) { success, error in
                if success {
                    continuation.resume()
                } else {
                    continuation.resume(throwing: error ?? LAError(.authenticationFailed))
                }
            }
        }
    }

    /// nil only when no key is stored. A keychain failure throws, so it
    /// never looks like an unpaired phone.
    static func storedPublicKey() throws -> Data? {
        try read(.publicKey)
    }

    /// The simulator reports a Secure Enclave but can't evaluate the Face ID
    /// access control a key needs, so Debug simulator builds use the software
    /// stand-in. Device builds always use the Secure Enclave.
    private static var usesSecureEnclave: Bool {
        #if DEBUG && targetEnvironment(simulator)
        false
        #else
        SecureEnclave.isAvailable
        #endif
    }

    /// Creates the pairing key. Call with an LAContext that passed Face ID.
    static func createKey(context: LAContext) throws -> PhoneKey {
        try requireFaceID(context)
        delete()
        let phoneKey: PhoneKey
        let privateBlob: Data
        if usesSecureEnclave {
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                compactRepresentable: false,
                accessControl: try accessControl(),
                authenticationContext: context)
            phoneKey = SecureEnclavePhoneKey(key: key)
            privateBlob = key.dataRepresentation
        } else {
            #if DEBUG && targetEnvironment(simulator)
            let key = P256.KeyAgreement.PrivateKey(compactRepresentable: false)
            phoneKey = SimulatorSoftwarePhoneKey(key: key)
            privateBlob = key.rawRepresentation
            #else
            throw KeyStoreError.secureEnclaveUnavailable
            #endif
        }
        try write(privateBlob, .privateKey)
        try write(phoneKey.publicKey, .publicKey)
        if let state = context.domainState.biometry.stateHash {
            try write(state, .biometryState)
        }
        return phoneKey
    }

    /// Loads the pairing key bound to an LAContext that passed Face ID, and
    /// checks that Face ID enrollment hasn't changed since pairing. Returns nil
    /// only when no key is stored. Any other keychain failure throws, so it
    /// never looks like an unpaired phone.
    static func loadKey(context: LAContext) throws -> PhoneKey? {
        guard let privateBlob = try read(.privateKey), let publicKey = try read(.publicKey) else { return nil }
        if let saved = try read(.biometryState), let current = context.domainState.biometry.stateHash,
           saved != current {
            throw KeyStoreError.keyInvalidated
        }
        let phoneKey: PhoneKey
        if usesSecureEnclave {
            do {
                let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                    dataRepresentation: privateBlob, authenticationContext: context)
                phoneKey = SecureEnclavePhoneKey(key: key)
            } catch {
                throw KeyStoreError.keyInvalidated
            }
        } else {
            #if DEBUG && targetEnvironment(simulator)
            phoneKey = SimulatorSoftwarePhoneKey(key: try P256.KeyAgreement.PrivateKey(rawRepresentation: privateBlob))
            #else
            throw KeyStoreError.secureEnclaveUnavailable
            #endif
        }
        guard phoneKey.publicKey == publicKey else { throw KeyStoreError.keyInvalidated }
        // A key agreement with our own public key proves the key still works.
        // After a Face ID enrollment change the Secure Enclave refuses it.
        do {
            _ = try phoneKey.sharedSecret(with: P256.KeyAgreement.PublicKey(x963Representation: publicKey))
        } catch {
            throw KeyStoreError.keyInvalidated
        }
        return phoneKey
    }

    static func delete() {
        for account in [Account.privateKey, .publicKey, .biometryState] {
            SecItemDelete(baseQuery(account) as CFDictionary)
        }
    }

    // MARK: Keychain

    private static func accessControl() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet], &error)
        else { throw error!.takeRetainedValue() as Error }
        return access
    }

    private static func baseQuery(_ account: Account) -> [CFString: Any] {
        [kSecClass: kSecClassGenericPassword,
         kSecAttrService: service,
         kSecAttrAccount: account.rawValue,
         kSecAttrSynchronizable: false]
    }

    private static func write(_ data: Data, _ account: Account) throws {
        SecItemDelete(baseQuery(account) as CFDictionary)
        var query = baseQuery(account)
        query[kSecValueData] = data
        query[kSecAttrAccessible] = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeyStoreError.keychain(status) }
    }

    /// nil only for errSecItemNotFound. Every other failure throws.
    private static func read(_ account: Account) throws -> Data? {
        var query = baseQuery(account)
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else { throw KeyStoreError.keychain(status) }
        return data
    }
}
