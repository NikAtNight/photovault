# PhotoVault for iPhone

A read-only viewer for albums sent from PhotoVault on the Mac. The Mac encrypts
an album to this iPhone's key and you move the `.pvshare` file over with
AirDrop or Files. The app opens it with Face ID. It has no network code, no
sync, and no way to save or share media out of the app.

The file format is defined in [docs/iphone-sharing.md](../docs/iphone-sharing.md).
Change the Mac and iPhone sides together.

## Requirements

- Xcode 27 or later, iOS 26 SDK.
- XcodeGen (`brew install xcodegen`). The Xcode project is generated from
  `project.yml` and isn't checked in.
- An iPhone with Face ID, a device passcode, and at least one enrolled face.
  The app refuses Touch ID and passcode-only devices.

## Open and build

```sh
cd ios
xcodegen generate
open PhotoVault.xcodeproj
```

Run the tests on a simulator:

```sh
xcodebuild test -project PhotoVault.xcodeproj -scheme PhotoVault \
  -destination 'platform=iOS Simulator,name=iPhone 17' -collect-test-diagnostics never
```

The interop test reads `PhotoVaultTests/Fixtures/fixture.pvshare`, which the
Rust test `share::tests::write_ios_fixture` writes. It fails if the file is
missing.

## Install on a real iPhone

1. Connect the iPhone by cable and unlock it. Trust the Mac if asked.
2. On the iPhone, turn on Settings > Privacy & Security > Developer Mode and
   restart when asked.
3. In Xcode, sign in under Settings > Accounts with an Apple ID on team
   `2TG5HP8NSV`. The project already sets that team with automatic signing
   and bundle id `com.talix.photovault.ios`.
4. Pick the iPhone as the run destination and press Run. Xcode registers the
   device and makes a provisioning profile.
5. If iOS says the developer isn't trusted, go to Settings > General > VPN &
   Device Management and trust the developer profile.

From the command line, once the device is registered:

```sh
xcodebuild -project PhotoVault.xcodeproj -scheme PhotoVault \
  -destination 'platform=iOS,name=<your iPhone>' -allowProvisioningUpdates build
```

## Pairing

1. Open the app and unlock with Face ID.
2. Tap Create Pairing Key. The app makes a P-256 key in the Secure Enclave.
   The private key can't leave the chip and every use needs Face ID.
3. The screen shows a verification code (8 groups of 4 hex characters) and the
   key ID. Tap Send Pairing File and AirDrop `iPhone.pvpair` to your Mac.
4. Open the file in PhotoVault on the Mac. Check that the Mac shows the same
   verification code before you confirm. A swapped pairing file would show a
   different code.

Reset Pairing (from the pairing button on the album list) deletes the key and
every album on the phone, since those albums can't be opened without the key.

## Importing albums

On the Mac, send an album or a selection to the paired iPhone. You get a file
named `PhotoVault-<hex>.pvshare`. Move it to the phone in any of these ways:

- AirDrop it to the iPhone. The phone offers to open it in PhotoVault.
- Save it to Files, then tap it, or use the Import button in the app.

The app reads only the plaintext header on import, so it works while locked.
It refuses a file addressed to a different key. Accepted files are copied to
Application Support with complete file protection and excluded from backup.
The copy iOS leaves in Documents/Inbox is deleted once the album is stored, or
when the file is refused. If the copy fails, for example on a full disk, the
Inbox file stays. The album list shows the
decrypted title, never the file name.

## Face ID changes

The key is created with `.biometryCurrentSet`. Adding a face, removing a face,
or resetting Face ID makes the Secure Enclave refuse the key for good. The app
notices this at unlock, says so, and offers Try Again and Pair Again. Pairing again deletes
the old albums. Pair with the Mac again and resend the albums you want.

Turning off the device passcode deletes the key outright. Once a passcode and
Face ID are back, the app shows the pairing screen. Albums sent to the old key
show as "Can't open this album" and can be swiped away.

## Privacy behavior

- The app locks on launch and whenever it leaves the foreground, including
  for Control Center or the app switcher. Locking drops the Face ID session,
  every content key, and every decoded image from memory.
- The screen is blank in the app switcher and while the screen is recorded,
  mirrored, or sent over AirPlay.
- Video plays from memory through a custom URL scheme that decrypts only the
  chunks a byte range needs. Picture in Picture, Now Playing, and external
  playback are off. Nothing is written to temporary files.
- Screenshots can't be blocked on iOS. Neither can someone photographing the
  screen.

## Simulator notes

The simulator has no Secure Enclave. Debug simulator builds fall back to a
software key stored in the simulator keychain. That code is compiled only
under `#if DEBUG && targetEnvironment(simulator)` and doesn't exist in device
builds. To unlock in the simulator, turn on Features > Face ID > Enrolled and
use Matching Face when the prompt appears.

## Layout

- `PhotoVault/Crypto`: format parsing, chunk decryption, and the key store.
- `PhotoVault/Storage`: imported share files on disk.
- `PhotoVault/App`: app entry point, lock state, screen capture tracking.
- `PhotoVault/Views`: SwiftUI screens, the zoomable photo view, and the video
  resource loader.
- `PhotoVaultTests`: chunk math, tamper checks, pairing file, interop fixture.
  `Support/TestSupport.swift` has the test-only software key and a share
  writer.
