import SwiftUI

struct PairingView: View {
    /// True on first run, when there's no key yet and no album list behind it.
    let onboarding: Bool

    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var error: String?
    @State private var confirmReset = false
    @State private var pairingFileURL: URL?

    var body: some View {
        List {
            if let key = model.session?.phoneKey {
                pairedSections(key)
            } else {
                Section {
                    Text("PhotoVault creates a key in this iPhone's Secure Enclave. The key never leaves the iPhone, and every use needs Face ID. You then send its public half to your Mac once.")
                    Button("Create Pairing Key") {
                        do { try model.createPairingKey() } catch { self.error = error.localizedDescription }
                    }
                }
            }
            if let error {
                Section { Text(error).foregroundStyle(.red) }
            }
        }
        .navigationTitle("Pairing")
        .toolbar {
            if !onboarding {
                ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
            }
        }
        .confirmationDialog("Reset pairing?", isPresented: $confirmReset, titleVisibility: .visible) {
            Button("Reset Pairing", role: .destructive) {
                model.resetPairing()
                dismiss()
            }
        } message: {
            Text("This deletes the key and every album on this iPhone, because they can't be opened without it. Your Mac keeps its library. You'll need to pair again.")
        }
    }

    @ViewBuilder
    private func pairedSections(_ key: PhoneKey) -> some View {
        Section {
            Text("1. Send the pairing file to your Mac with AirDrop.\n2. On your Mac, open PhotoVault Settings, then Your iPhone, then Pair iPhone, and choose the file.\n3. Check that the Mac shows the same verification code.")
        }
        Section("Verification code") {
            Text(key.verificationCode)
                .font(.system(.title3, design: .monospaced).weight(.semibold))
                .textSelection(.disabled)
                .frame(maxWidth: .infinity, alignment: .center)
                .padding(.vertical, 4)
            LabeledContent("Key ID") {
                Text(key.keyID).font(.system(.body, design: .monospaced))
            }
        }
        Section {
            if let url = pairingFileURL {
                ShareLink(item: url) {
                    Label("Send Pairing File", systemImage: "square.and.arrow.up")
                }
            }
            if onboarding {
                Button("Done") { model.finishPairing() }
            }
        }
        .task(id: key.keyID) { pairingFileURL = writePairingFile(key) }
        Section {
            Button("Reset Pairing", role: .destructive) { confirmReset = true }
        } footer: {
            Text("Use this if you get a new Mac or think the key was misused.")
        }
    }

    /// The pairing file holds only the public key, so a temporary file is fine.
    private func writePairingFile(_ key: PhoneKey) -> URL? {
        do {
            let dir = FileManager.default.temporaryDirectory.appendingPathComponent("Pairing", isDirectory: true)
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            let url = dir.appendingPathComponent(PairingFile.fileName)
            try PairingFile(publicKey: key.publicKey).encoded().write(to: url, options: .atomic)
            return url
        } catch {
            self.error = "Couldn't make the pairing file: \(error.localizedDescription)"
            return nil
        }
    }
}
