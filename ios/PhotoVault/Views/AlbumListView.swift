import SwiftUI

struct AlbumListView: View {
    @Environment(AppModel.self) private var model
    @State private var showImporter = false
    @State private var showPairing = false
    @State private var pendingDelete: Album?

    var body: some View {
        NavigationStack {
            Group {
                if model.albums.isEmpty {
                    ContentUnavailableView {
                        Label("No Shared Albums", systemImage: "photo.on.rectangle.angled")
                    } description: {
                        Text("On your Mac, send an album to this iPhone, then AirDrop the file here or open it from Files.")
                    } actions: {
                        Button("Import from Files") { showImporter = true }
                    }
                } else {
                    List {
                        ForEach(model.albums) { album in
                            row(album)
                                .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                                    Button("Delete", systemImage: "trash", role: .destructive) {
                                        pendingDelete = album
                                    }
                                }
                        }
                    }
                }
            }
            .navigationTitle("Albums")
            .navigationDestination(for: String.self) { id in
                if let album = model.albums.first(where: { $0.id == id }), case .ready(let share) = album.content {
                    AlbumGridView(share: share)
                }
            }
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Lock", systemImage: "lock") { model.lock() }
                }
                ToolbarItemGroup(placement: .topBarTrailing) {
                    Button("Import", systemImage: "square.and.arrow.down") { showImporter = true }
                    Button("Pairing", systemImage: "iphone.and.arrow.forward") { showPairing = true }
                }
            }
            .fileImporter(isPresented: $showImporter, allowedContentTypes: [.photoVaultShare],
                          allowsMultipleSelection: true) { result in
                switch result {
                case .success(let urls): model.importFiles(urls)
                case .failure(let error): model.notice = error.localizedDescription
                }
            }
            .sheet(isPresented: $showPairing) {
                NavigationStack { PairingView(onboarding: false) }
            }
            .alert("Delete this album?", isPresented: Binding(
                get: { pendingDelete != nil }, set: { if !$0 { pendingDelete = nil } }
            ), presenting: pendingDelete) { album in
                Button("Delete", role: .destructive) { model.delete(album) }
                Button("Cancel", role: .cancel) {}
            } message: { _ in
                Text("The album is removed from this iPhone. Your Mac library isn't affected.")
            }
        }
    }

    @ViewBuilder
    private func row(_ album: Album) -> some View {
        switch album.content {
        case .ready(let share):
            NavigationLink(value: album.id) {
                VStack(alignment: .leading, spacing: 3) {
                    Text(share.manifest.title.isEmpty ? "Untitled" : share.manifest.title)
                        .font(.headline)
                    Text("\(share.manifest.items.count) \(share.manifest.items.count == 1 ? "item" : "items") · Imported \(album.stored.imported.formatted(date: .abbreviated, time: .omitted))")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                .padding(.vertical, 2)
            }
        case .failed(let message):
            VStack(alignment: .leading, spacing: 3) {
                Label("Can't open this album", systemImage: "exclamationmark.triangle")
                    .font(.headline)
                Text(message)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                Text("Imported \(album.stored.imported.formatted(date: .abbreviated, time: .omitted))")
                    .font(.footnote)
                    .foregroundStyle(.tertiary)
            }
            .padding(.vertical, 2)
        }
    }
}
