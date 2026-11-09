import SwiftUI

struct RootView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.scenePhase) private var scenePhase
    @Environment(ScreenCapture.self) private var capture

    var body: some View {
        @Bindable var model = model
        ZStack {
            switch model.phase {
            case .locked:
                LockView()
            case .reenrollRequired:
                ReenrollView()
            case .unlocked:
                if model.isPaired && !model.isFinishingPairing {
                    AlbumListView()
                } else {
                    NavigationStack { PairingView(onboarding: true) }
                }
            }
        }
        .privacyCovered()
        .onChange(of: scenePhase, initial: true) { _, phase in
            switch phase {
            case .active:
                capture.refresh()
                model.sceneBecameActive()
            case .inactive:
                model.sceneBecameInactive()
            case .background:
                model.sceneEnteredBackground()
            @unknown default:
                model.sceneEnteredBackground()
            }
        }
        .alert("PhotoVault", isPresented: Binding(
            get: { model.notice != nil }, set: { if !$0 { model.notice = nil } }
        )) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(model.notice ?? "")
        }
    }
}

extension View {
    /// Blanks the view in the app switcher and while the screen is captured.
    /// Full-screen covers sit above the root view, so they apply it too.
    func privacyCovered() -> some View { modifier(PrivacyCovered()) }
}

private struct PrivacyCovered: ViewModifier {
    @Environment(\.scenePhase) private var scenePhase
    @Environment(ScreenCapture.self) private var capture

    func body(content: Content) -> some View {
        content.overlay {
            if scenePhase != .active || capture.isCaptured {
                PrivacyCover(captured: capture.isCaptured && scenePhase == .active)
                    .transition(.identity)
            }
        }
    }
}

struct PrivacyCover: View {
    let captured: Bool

    var body: some View {
        ZStack {
            Color(.systemBackground).ignoresSafeArea()
            VStack(spacing: 12) {
                Image(systemName: captured ? "eye.slash" : "lock.fill")
                    .font(.system(size: 40, weight: .regular))
                    .foregroundStyle(.secondary)
                if captured {
                    Text("Hidden while the screen is being recorded or mirrored.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 40)
                }
            }
        }
    }
}

struct LockView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        VStack(spacing: 20) {
            Spacer()
            Image(systemName: "lock.shield")
                .font(.system(size: 56, weight: .light))
                .foregroundStyle(.tint)
            Text("PhotoVault")
                .font(.largeTitle.bold())
            Text("Your shared albums are locked.")
                .foregroundStyle(.secondary)
            if let message = model.lockMessage {
                Text(message)
                    .font(.callout)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
            }
            Spacer()
            Button {
                Task { await model.unlock() }
            } label: {
                Label("Unlock with Face ID", systemImage: "faceid")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(model.isAuthenticating)
            .padding(.horizontal, 24)
            .padding(.bottom, 32)
        }
    }
}

struct ReenrollView: View {
    @Environment(AppModel.self) private var model
    @State private var confirmReset = false

    var body: some View {
        ContentUnavailableView {
            Label("Pair again", systemImage: "faceid")
        } description: {
            Text(KeyStoreError.keyInvalidated.localizedDescription)
            if let message = model.lockMessage {
                Text(message).foregroundStyle(.red)
            }
        } actions: {
            Button("Try Again") {
                Task { await model.unlock() }
            }
            .buttonStyle(.borderedProminent)
            .disabled(model.isAuthenticating)
            Button("Pair Again", role: .destructive) { confirmReset = true }
                .disabled(model.isAuthenticating)
        }
        .confirmationDialog("Reset pairing?", isPresented: $confirmReset, titleVisibility: .visible) {
            Button("Reset Pairing", role: .destructive) { model.resetPairing() }
        } message: {
            Text("This deletes the key and every album on this iPhone, because they can't be opened without it. Your Mac keeps its library. You'll need to pair again.")
        }
    }
}
