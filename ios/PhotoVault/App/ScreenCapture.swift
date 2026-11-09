import Observation
import UIKit

/// Tracks UIScreen.isCaptured (screen recording, mirroring, AirPlay) through
/// the captured-change notification.
@MainActor
@Observable
final class ScreenCapture {
    private(set) var isCaptured = false
    @ObservationIgnored private var observer: NSObjectProtocol?

    init() {
        refresh()
        observer = NotificationCenter.default.addObserver(
            forName: UIScreen.capturedDidChangeNotification, object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.refresh() }
        }
    }

    func refresh() {
        isCaptured = UIApplication.shared.connectedScenes
            .compactMap { ($0 as? UIWindowScene)?.screen }
            .contains { $0.isCaptured }
    }
}
