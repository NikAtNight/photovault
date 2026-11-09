import ImageIO
import UIKit

/// Decodes decrypted image bytes in memory with ImageIO. Nothing touches disk.
enum ImageDecoding {
    /// Photos larger than this are refused rather than risk running out of memory.
    static let maxPhotoBytes: UInt64 = 256 * 1_048_576

    /// Decrypts and decodes an image off the main actor. Cancelling the
    /// calling task cancels the work between chunks.
    static func decrypt(_ blob: Blob, in share: OpenShare, limit: UInt64, maxPixels: Int) async -> UIImage? {
        let work = Task.detached(priority: .userInitiated) { () -> UIImage? in
            guard let data = try? share.decryptBlob(blob, limit: limit) else { return nil }
            return image(from: data, maxPixels: maxPixels)
        }
        return await withTaskCancellationHandler { await work.value } onCancel: { work.cancel() }
    }

    /// Decodes and downsamples so the longest side is at most `maxPixels`.
    static func image(from data: Data, maxPixels: Int) -> UIImage? {
        let sourceOptions = [kCGImageSourceShouldCache: false] as CFDictionary
        guard let source = CGImageSourceCreateWithData(data as CFData, sourceOptions),
              CGImageSourceGetCount(source) > 0
        else { return nil }
        let options = [
            kCGImageSourceCreateThumbnailFromImageAlways: true,
            kCGImageSourceCreateThumbnailWithTransform: true,
            kCGImageSourceShouldCacheImmediately: true,
            kCGImageSourceThumbnailMaxPixelSize: maxPixels,
        ] as CFDictionary
        guard let cgImage = CGImageSourceCreateThumbnailAtIndex(source, 0, options) else { return nil }
        return UIImage(cgImage: cgImage)
    }
}
