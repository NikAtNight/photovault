# App icon

The September 2026 replacement uses a photo frame and keyhole on a blue glass
tile. The source is `app-icon.png`, created with the built-in imagegen tool.
It has transparent margins. Tauri generates the platform assets in
`src-tauri/icons` with `npm run tauri -- icon app-icon.png`.

## Generation prompt

Use case: logo-brand. Create one finished macOS desktop application icon for PhotoVault, a private photo library. Asset: square 1024 by 1024 PNG with genuine transparent alpha outside the icon. Design a beautifully restrained rounded-square glass tile, front-on orthographic, with generous macOS icon margins roughly 10% on each edge. Inside: a single luminous frosted-glass photograph frame, a simple mountain silhouette and small sun; integrate a tiny elegant keyhole into the lower photo border to imply privacy. Strong simple silhouette readable at 32 pixels. Soft dimensional edges and subtle material highlights, premium desktop-app craftsmanship, calm sophisticated color, clear contrast on both light and dark desktop backgrounds. Keep the composition centered and the artwork large within the tile. No text, letters, watermark, desktop screenshot, extra icons, checkerboard drawn into image, busy detail, oversized padlock, or ornamental flourishes. Deliver only the standalone production icon, not a presentation board.

The generated source is 1254 by 1254 pixels with alpha. Tauri resamples it for
each platform rather than relying on the requested generation dimensions.

## Verification

Inspected the generated 32px and 128px icons. The build-ID test and release
build passed. The bundle's `icon.icns` matches the generated asset, and both
the built and installed bundles pass strict code-signature verification.
The previous Applications copy was retained before installing the new bundle.
No application logic changed; the full backend suite was not rerun.
