import SwiftUI
import UniformTypeIdentifiers

extension UTType {
    /// Declared in Info.plist (UTExportedTypeDeclarations).
    static let photoVaultShare = UTType(exportedAs: "com.talix.photovault.share")
}

@main
struct PhotoVaultApp: App {
    @State private var model = AppModel()
    @State private var capture = ScreenCapture()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(model)
                .environment(capture)
                .onOpenURL { url in
                    guard url.isFileURL else { return }
                    model.importFiles([url])
                }
        }
    }
}
