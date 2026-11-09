import AVKit
import SwiftUI

/// Full-screen paging viewer. There are no share, save, or copy actions.
struct MediaViewer: View {
    let share: OpenShare
    @State private var index: Int
    @State private var showChrome = true
    @Environment(\.dismiss) private var dismiss

    init(share: OpenShare, startIndex: Int) {
        self.share = share
        _index = State(initialValue: startIndex)
    }

    private var items: [ManifestItem] { share.manifest.items }

    var body: some View {
        TabView(selection: $index) {
            ForEach(Array(items.enumerated()), id: \.element.id) { offset, item in
                Group {
                    switch item.kind {
                    case .photo: PhotoPage(share: share, item: item, onTap: { showChrome.toggle() })
                    case .video: VideoPage(share: share, item: item, isCurrent: offset == index)
                    }
                }
                .tag(offset)
            }
        }
        .tabViewStyle(.page(indexDisplayMode: .never))
        .background(Color.black.ignoresSafeArea())
        .ignoresSafeArea()
        .overlay(alignment: .top) {
            if showChrome {
                HStack {
                    Button {
                        dismiss()
                    } label: {
                        Image(systemName: "xmark")
                            .font(.body.weight(.semibold))
                            .frame(width: 36, height: 36)
                    }
                    .buttonStyle(.glass)
                    .accessibilityLabel("Close")
                    Spacer()
                    VStack(alignment: .trailing, spacing: 2) {
                        Text(items[index].name).font(.subheadline.weight(.semibold))
                        if let taken = items[index].taken {
                            Text(taken.formatted(date: .abbreviated, time: .shortened)).font(.caption)
                        }
                        Text("\(index + 1) of \(items.count)").font(.caption).foregroundStyle(.secondary)
                    }
                    .foregroundStyle(.white)
                    .shadow(radius: 3)
                }
                .padding(.horizontal)
            }
        }
        .statusBarHidden(!showChrome)
        .privacyCovered()
    }
}

struct PhotoPage: View {
    let share: OpenShare
    let item: ManifestItem
    let onTap: () -> Void

    @Environment(AppModel.self) private var model
    @State private var image: UIImage?
    @State private var failed = false

    var body: some View {
        ZStack {
            Color.black
            if let image {
                ZoomableImage(image: image, onSingleTap: onTap)
            } else if failed {
                Label("This photo can't be shown.", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.white.opacity(0.8))
            } else {
                ProgressView().tint(.white)
            }
        }
        .task(id: item.id) { await load() }
        .onDisappear { image = nil }
    }

    private func load() async {
        guard image == nil, let session = model.session else { return }
        let decoded = await ImageDecoding.decrypt(
            item.original, in: share, limit: ImageDecoding.maxPhotoBytes, maxPixels: 4096)
        // The page may have gone, or the app may have locked, while decrypting.
        guard !Task.isCancelled, model.session === session else { return }
        if let decoded { image = decoded } else { failed = true }
    }
}

/// UIScrollView-backed pinch zoom with double-tap to zoom.
struct ZoomableImage: UIViewRepresentable {
    let image: UIImage
    let onSingleTap: () -> Void

    func makeUIView(context: Context) -> ZoomScrollView {
        let view = ZoomScrollView()
        view.onSingleTap = onSingleTap
        view.setImage(image)
        return view
    }

    func updateUIView(_ view: ZoomScrollView, context: Context) {
        view.onSingleTap = onSingleTap
        if view.imageView.image !== image { view.setImage(image) }
    }
}

final class ZoomScrollView: UIScrollView, UIScrollViewDelegate {
    let imageView = UIImageView()
    var onSingleTap: (() -> Void)?

    override init(frame: CGRect) {
        super.init(frame: frame)
        delegate = self
        minimumZoomScale = 1
        maximumZoomScale = 5
        showsVerticalScrollIndicator = false
        showsHorizontalScrollIndicator = false
        contentInsetAdjustmentBehavior = .never
        imageView.contentMode = .scaleAspectFit
        addSubview(imageView)
        let double = UITapGestureRecognizer(target: self, action: #selector(doubleTapped(_:)))
        double.numberOfTapsRequired = 2
        addGestureRecognizer(double)
        let single = UITapGestureRecognizer(target: self, action: #selector(singleTapped))
        single.require(toFail: double)
        addGestureRecognizer(single)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is not used") }

    func setImage(_ image: UIImage) {
        imageView.image = image
        zoomScale = 1
        setNeedsLayout()
    }

    override func layoutSubviews() {
        super.layoutSubviews()
        guard zoomScale == 1 else { return }
        imageView.frame = bounds
        contentSize = bounds.size
    }

    func viewForZooming(in scrollView: UIScrollView) -> UIView? { imageView }

    @objc private func doubleTapped(_ gesture: UITapGestureRecognizer) {
        if zoomScale > 1 {
            setZoomScale(1, animated: true)
        } else {
            let point = gesture.location(in: imageView)
            let size = CGSize(width: bounds.width / 2.5, height: bounds.height / 2.5)
            zoom(to: CGRect(x: point.x - size.width / 2, y: point.y - size.height / 2,
                            width: size.width, height: size.height), animated: true)
        }
    }

    @objc private func singleTapped() { onSingleTap?() }
}

struct VideoPage: View {
    let share: OpenShare
    let item: ManifestItem
    let isCurrent: Bool

    @State private var player: AVPlayer?
    @State private var loader: EncryptedAssetLoader?

    var body: some View {
        ZStack {
            Color.black
            if item.original.size == 0 {
                Label("This video is empty.", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.white.opacity(0.8))
            } else if let player {
                PlayerController(player: player)
            } else {
                ProgressView().tint(.white)
            }
        }
        .onChange(of: isCurrent, initial: true) { _, current in
            if current { start() } else { stop() }
        }
        .onDisappear { stop() }
    }

    private func start() {
        guard player == nil, item.original.size > 0 else { return }
        let loader = EncryptedAssetLoader(share: share, blob: item.original, fileName: item.name)
        let player = AVPlayer(playerItem: AVPlayerItem(asset: loader.makeAsset()))
        // No AirPlay streaming to another screen.
        player.allowsExternalPlayback = false
        self.loader = loader
        self.player = player
    }

    private func stop() {
        player?.pause()
        player?.replaceCurrentItem(with: nil)
        player = nil
        loader = nil
    }
}

/// AVPlayerViewController with picture in picture, Now Playing, and external
/// playback turned off, so video never shows outside the app.
struct PlayerController: UIViewControllerRepresentable {
    let player: AVPlayer

    func makeUIViewController(context: Context) -> AVPlayerViewController {
        let controller = AVPlayerViewController()
        controller.allowsPictureInPicturePlayback = false
        controller.canStartPictureInPictureAutomaticallyFromInline = false
        controller.updatesNowPlayingInfoCenter = false
        controller.player = player
        return controller
    }

    func updateUIViewController(_ controller: AVPlayerViewController, context: Context) {
        if controller.player !== player { controller.player = player }
    }
}
