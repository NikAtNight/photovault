import SwiftUI

struct AlbumGridView: View {
    let share: OpenShare

    @State private var viewerStart: ViewerStart?

    struct ViewerStart: Identifiable {
        let index: Int
        var id: Int { index }
    }

    private let columns = [GridItem(.adaptive(minimum: 96, maximum: 160), spacing: 2)]

    var body: some View {
        ScrollView {
            LazyVGrid(columns: columns, spacing: 2) {
                ForEach(Array(share.manifest.items.enumerated()), id: \.element.id) { index, item in
                    Button {
                        viewerStart = ViewerStart(index: index)
                    } label: {
                        ThumbnailCell(share: share, item: item)
                    }
                    .buttonStyle(.plain)
                }
            }
        }
        .navigationTitle(share.manifest.title.isEmpty ? "Untitled" : share.manifest.title)
        .navigationBarTitleDisplayMode(.inline)
        .fullScreenCover(item: $viewerStart) { start in
            MediaViewer(share: share, startIndex: start.index)
        }
    }
}

struct ThumbnailCell: View {
    let share: OpenShare
    let item: ManifestItem

    @Environment(AppModel.self) private var model
    @State private var image: UIImage?

    nonisolated private static let maxThumbBytes: UInt64 = 8 * 1_048_576

    var body: some View {
        Color(.secondarySystemBackground)
            .aspectRatio(1, contentMode: .fit)
            .overlay {
                if let image {
                    Image(uiImage: image)
                        .resizable()
                        .scaledToFill()
                } else {
                    Image(systemName: item.kind == .video ? "video" : "photo")
                        .font(.title2)
                        .foregroundStyle(.tertiary)
                }
            }
            .overlay(alignment: .bottomLeading) {
                if item.kind == .video {
                    Image(systemName: "play.fill")
                        .font(.caption)
                        .foregroundStyle(.white)
                        .shadow(radius: 2)
                        .padding(6)
                }
            }
            .clipped()
            .contentShape(Rectangle())
            .accessibilityLabel(item.name)
            .task(id: item.id) { await load() }
    }

    private var cacheKey: NSString { "\(share.file.url.lastPathComponent)/\(item.id)" as NSString }

    private func load() async {
        guard let thumb = item.thumb, let session = model.session else { return }
        if let cached = session.thumbnails.object(forKey: cacheKey) {
            image = cached
            return
        }
        let decoded = await ImageDecoding.decrypt(thumb, in: share, limit: Self.maxThumbBytes, maxPixels: 480)
        // The cell may have gone, or the app may have locked, while decrypting.
        guard let decoded, !Task.isCancelled, model.session === session else { return }
        session.thumbnails.setObject(decoded, forKey: cacheKey)
        image = decoded
    }
}
