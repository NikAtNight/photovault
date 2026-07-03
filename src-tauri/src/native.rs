// macOS-native integration: Keychain-backed Touch ID unlock, screen-capture
// protection, and locking the vault when the system sleeps or the screen locks.
#![cfg(target_os = "macos")]

use std::ffi::c_void;
use std::ptr::NonNull;

use block2::RcBlock;
use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::{CFString, CFStringRef};
use objc2::msg_send;
use objc2::rc::Retained;
use objc2::runtime::{AnyClass, AnyObject, Bool};
use objc2_app_kit::{NSWindow, NSWindowSharingType, NSWorkspace};
use objc2_foundation::{NSNotification, NSString};

// ------------------------------------------------------------- window/UI ---

/// Exclude (or re-include) the window from screenshots and screen sharing.
/// NSWindow is main-thread-only, so the actual call hops threads.
pub fn set_screen_protect(window: &tauri::WebviewWindow, protect: bool) {
    let Ok(ptr) = window.ns_window() else { return };
    let addr = ptr as usize;
    let _ = window.run_on_main_thread(move || {
        let win = addr as *mut NSWindow;
        if win.is_null() {
            return;
        }
        unsafe {
            (*win).setSharingType(if protect {
                NSWindowSharingType::None
            } else {
                NSWindowSharingType::ReadOnly
            });
        }
    });
}

/// Fire `callback` when the screen locks or the machine goes to sleep.
/// Must be called from the main thread (Tauri setup) so notifications are
/// delivered on the main run loop. Observer tokens are intentionally leaked —
/// they have to live for the whole app lifetime.
pub fn register_lock_observers<F: Fn() + Clone + 'static>(callback: F) {
    unsafe {
        let cb = callback.clone();
        let block = RcBlock::new(move |_: NonNull<NSNotification>| cb());
        let center = objc2_foundation::NSDistributedNotificationCenter::defaultCenter();
        let name = NSString::from_str("com.apple.screenIsLocked");
        std::mem::forget(center.addObserverForName_object_queue_usingBlock(
            Some(&name),
            None,
            None,
            &block,
        ));

        let block = RcBlock::new(move |_: NonNull<NSNotification>| callback());
        let workspace = NSWorkspace::sharedWorkspace();
        let wcenter = workspace.notificationCenter();
        let name = NSString::from_str("NSWorkspaceWillSleepNotification");
        std::mem::forget(wcenter.addObserverForName_object_queue_usingBlock(
            Some(&name),
            None,
            None,
            &block,
        ));
    }
}

// --------------------------------------------------------------- Touch ID ---
//
// The master key is stored as a login-keychain generic password (encrypted at
// rest by the keychain, released only to this app), and reads are gated by an
// app-level LocalAuthentication biometric prompt. This works for locally
// built, ad-hoc-signed apps — the SEP-backed data-protection keychain requires
// Apple-issued signing entitlements.

const KEYCHAIN_SERVICE: &str = "com.talix.photovault";
const KEYCHAIN_ACCOUNT: &str = "vault-master-key";

type OSStatus = i32;

#[link(name = "Security", kind = "framework")]
extern "C" {
    static kSecClass: CFStringRef;
    static kSecClassGenericPassword: CFStringRef;
    static kSecAttrService: CFStringRef;
    static kSecAttrAccount: CFStringRef;
    static kSecValueData: CFStringRef;
    static kSecReturnData: CFStringRef;
    static kSecMatchLimit: CFStringRef;
    static kSecMatchLimitOne: CFStringRef;

    fn SecItemAdd(attributes: *const c_void, result: *mut *const c_void) -> OSStatus;
    fn SecItemCopyMatching(query: *const c_void, result: *mut *const c_void) -> OSStatus;
    fn SecItemDelete(query: *const c_void) -> OSStatus;
}

/// Base keychain query identifying our one item, plus any extra pairs.
fn item_query(extra: Vec<(CFString, CFType)>) -> CFDictionary<CFString, CFType> {
    unsafe {
        let mut pairs: Vec<(CFString, CFType)> = vec![
            (
                CFString::wrap_under_get_rule(kSecClass),
                CFString::wrap_under_get_rule(kSecClassGenericPassword).as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrService),
                CFString::new(KEYCHAIN_SERVICE).as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrAccount),
                CFString::new(KEYCHAIN_ACCOUNT).as_CFType(),
            ),
        ];
        pairs.extend(extra);
        CFDictionary::from_CFType_pairs(&pairs)
    }
}

pub fn keychain_store_master(key: &[u8]) -> Result<(), String> {
    keychain_delete_master();
    unsafe {
        let dict = item_query(vec![(
            CFString::wrap_under_get_rule(kSecValueData),
            CFData::from_buffer(key).as_CFType(),
        )]);
        match SecItemAdd(
            dict.as_concrete_TypeRef() as *const c_void,
            std::ptr::null_mut(),
        ) {
            0 => Ok(()),
            s => Err(format!("Keychain error {s}.")),
        }
    }
}

pub fn keychain_read_master() -> Result<Vec<u8>, String> {
    unsafe {
        let dict = item_query(vec![
            (
                CFString::wrap_under_get_rule(kSecReturnData),
                CFBoolean::true_value().as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecMatchLimit),
                CFString::wrap_under_get_rule(kSecMatchLimitOne).as_CFType(),
            ),
        ]);
        let mut result: *const c_void = std::ptr::null();
        match SecItemCopyMatching(dict.as_concrete_TypeRef() as *const c_void, &mut result) {
            0 if !result.is_null() => {
                let data = CFData::wrap_under_create_rule(result as _);
                Ok(data.bytes().to_vec())
            }
            -25300 => Err("No Touch ID key found — re-enable Touch ID in Settings.".into()),
            -128 => Err("cancelled".into()),
            s => Err(format!("Keychain error {s}.")),
        }
    }
}

pub fn keychain_delete_master() {
    unsafe {
        let dict = item_query(Vec::new());
        let _ = SecItemDelete(dict.as_concrete_TypeRef() as *const c_void);
    }
}

/// True when biometric auth (Touch ID / Apple Watch) can be evaluated.
pub fn biometrics_available() -> bool {
    unsafe {
        let Some(cls) = AnyClass::get(c"LAContext") else {
            return false;
        };
        let ctx: Retained<AnyObject> = msg_send![cls, new];
        // LAPolicyDeviceOwnerAuthenticationWithBiometrics = 1
        let ok: Bool = msg_send![
            &*ctx,
            canEvaluatePolicy: 1isize,
            error: std::ptr::null_mut::<*mut AnyObject>()
        ];
        ok.as_bool()
    }
}

/// Show the system biometric prompt and block until the user responds.
pub fn authenticate_biometric(reason: &str) -> Result<(), String> {
    let (tx, rx) = std::sync::mpsc::channel::<bool>();
    unsafe {
        let cls = AnyClass::get(c"LAContext").ok_or("Touch ID is unavailable.")?;
        let ctx: Retained<AnyObject> = msg_send![cls, new];
        let ns_reason = NSString::from_str(reason);
        let block = RcBlock::new(move |ok: Bool, _err: *mut AnyObject| {
            let _ = tx.send(ok.as_bool());
        });
        let _: () = msg_send![
            &*ctx,
            evaluatePolicy: 1isize,
            localizedReason: &*ns_reason,
            reply: &*block
        ];
        // ctx stays alive in this scope until the reply arrives.
        match rx.recv() {
            Ok(true) => Ok(()),
            _ => Err("Touch ID authentication was cancelled.".into()),
        }
    }
}
