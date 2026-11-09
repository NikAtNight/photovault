import AVFoundation
import UniformTypeIdentifiers

/// Serves an encrypted video to AVPlayer through a custom URL scheme. Each
/// byte range request decrypts only the chunks it overlaps. Nothing is
/// written to disk; at most one decrypted chunk is kept for reuse.
final class EncryptedAssetLoader: NSObject, AVAssetResourceLoaderDelegate, @unchecked Sendable {
    static let scheme = "pvshare-media"

    private let share: OpenShare
    private let blob: Blob
    private let contentType: String
    /// AVFoundation calls the delegate here.
    private let delegateQueue = DispatchQueue(label: "com.talix.photovault.video.delegate")
    /// Decryption runs here, so cancellations aren't stuck behind it.
    private let workQueue = DispatchQueue(label: "com.talix.photovault.video.work")
    /// Only touched on workQueue.
    private var cached: (index: UInt64, data: Data)?

    init(share: OpenShare, blob: Blob, fileName: String) {
        self.share = share
        self.blob = blob
        let ext = (fileName as NSString).pathExtension
        contentType = UTType(filenameExtension: ext, conformingTo: .movie)?.identifier ?? UTType.quickTimeMovie.identifier
    }

    func makeAsset() -> AVURLAsset {
        let asset = AVURLAsset(url: URL(string: "\(Self.scheme)://media/\(UUID().uuidString)")!)
        asset.resourceLoader.setDelegate(self, queue: delegateQueue)
        return asset
    }

    func resourceLoader(_ resourceLoader: AVAssetResourceLoader,
                        shouldWaitForLoadingOfRequestedResource loadingRequest: AVAssetResourceLoadingRequest) -> Bool {
        guard loadingRequest.request.url?.scheme == Self.scheme else { return false }
        workQueue.async { [self] in serve(loadingRequest) }
        return true
    }

    private func serve(_ request: AVAssetResourceLoadingRequest) {
        if request.isCancelled { return }
        if let info = request.contentInformationRequest {
            info.contentType = contentType
            info.contentLength = Int64(blob.size)
            info.isByteRangeAccessSupported = true
        }
        guard let dataRequest = request.dataRequest else {
            request.finishLoading()
            return
        }
        let size = blob.size
        let start = UInt64(max(0, dataRequest.currentOffset))
        let requestedEnd = dataRequest.requestsAllDataToEndOfResource
            ? size
            : UInt64(max(0, dataRequest.requestedOffset)) + UInt64(max(0, dataRequest.requestedLength))
        let end = min(requestedEnd, size)
        var position = start
        do {
            while position < end {
                if request.isCancelled { return }
                let index = position / ShareFormat.chunkSize
                let chunkEnd = min(end, (index + 1) * ShareFormat.chunkSize)
                let data = try share.plaintext(blob, offset: position, count: chunkEnd - position) { try chunk($0) }
                dataRequest.respond(with: data)
                position = chunkEnd
            }
            request.finishLoading()
        } catch {
            request.finishLoading(with: error)
        }
    }

    private func chunk(_ index: UInt64) throws -> Data {
        // The cached plaintext outlives the key, so check it before reuse.
        if share.isRevoked {
            cached = nil
            throw ShareError.keyUnavailable
        }
        if let cached, cached.index == index { return cached.data }
        let data = try share.decryptChunk(blob, index: index)
        cached = (index, data)
        return data
    }
}
