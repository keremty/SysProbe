#![allow(non_snake_case)]

use serde::Serialize;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use winapi::ctypes::c_void;
use winapi::shared::guiddef::GUID;
use winapi::shared::minwindef::DWORD;
use winapi::shared::winerror::{
    CERT_E_UNTRUSTEDROOT, CRYPT_E_SECURITY_SETTINGS, ERROR_SUCCESS, TRUST_E_BAD_DIGEST,
    TRUST_E_EXPLICIT_DISTRUST, TRUST_E_NOSIGNATURE, TRUST_E_SUBJECT_NOT_TRUSTED,
};
use winapi::um::wincrypt::{
    CertCloseStore, CertFreeCertificateContext, CertGetNameStringW, CryptQueryObject,
    CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY,
    CERT_QUERY_OBJECT_FILE, HCERTSTORE, PCCERT_CONTEXT,
};
use winapi::um::softpub::WINTRUST_ACTION_GENERIC_VERIFY_V2;
use winapi::um::wintrust::{
    WinVerifyTrust, WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL,
    WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_IGNORE, WTD_UI_NONE,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SignatureStatus {
    Valid,
    Unsigned,
    Invalid,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignatureInfo {
    pub status: SignatureStatus,
    pub signer: Option<String>,
    pub is_microsoft: Option<bool>,
    pub error: Option<u32>,
}

pub fn verify_signature(path: &str) -> SignatureInfo {
    if path.is_empty() {
        return SignatureInfo {
            status: SignatureStatus::Error,
            signer: None,
            is_microsoft: None,
            error: None,
        };
    }

    let wide = to_wide(path);
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as DWORD,
        pcwszFilePath: wide.as_ptr(),
        hFile: std::ptr::null_mut(),
        pgKnownSubject: std::ptr::null_mut(),
    };

    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as DWORD,
        pPolicyCallbackData: std::ptr::null_mut(),
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        u: unsafe { std::mem::zeroed() },
        dwStateAction: WTD_STATEACTION_IGNORE,
        hWVTStateData: std::ptr::null_mut(),
        pwszURLReference: std::ptr::null_mut(),
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        dwUIContext: 0,
        pSignatureSettings: std::ptr::null_mut(),
    };

    unsafe {
        *data.u.pFile_mut() = &mut file_info;
    }

    let mut action: GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let status = unsafe {
        WinVerifyTrust(
            std::ptr::null_mut(),
            &mut action as *mut _,
            &mut data as *mut _ as *mut c_void,
        )
    };

    let mut info = SignatureInfo {
        status: SignatureStatus::Error,
        signer: None,
        is_microsoft: None,
        error: Some(status as u32),
    };

    if status == ERROR_SUCCESS as i32 {
        info.status = SignatureStatus::Valid;
        let signer = extract_signer_name(path);
        info.is_microsoft = signer
            .as_ref()
            .map(|s| s.to_ascii_lowercase().contains("microsoft"));
        info.signer = signer;
        info.error = None;
        return info;
    }

    match status {
        s if s == TRUST_E_NOSIGNATURE => {
            info.status = SignatureStatus::Unsigned;
        }
        s if s == TRUST_E_BAD_DIGEST
            || s == TRUST_E_EXPLICIT_DISTRUST
            || s == TRUST_E_SUBJECT_NOT_TRUSTED
            || s == CERT_E_UNTRUSTEDROOT
            || s == CRYPT_E_SECURITY_SETTINGS =>
        {
            info.status = SignatureStatus::Invalid;
        }
        _ => {
            info.status = SignatureStatus::Error;
        }
    }

    info
}

fn extract_signer_name(path: &str) -> Option<String> {
    let wide = to_wide(path);
    let mut store: HCERTSTORE = std::ptr::null_mut();
    let mut context: PCCERT_CONTEXT = std::ptr::null_mut();
    let mut encoding: DWORD = 0;
    let mut content: DWORD = 0;
    let mut format: DWORD = 0;

    let ok = unsafe {
        CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            wide.as_ptr() as *const c_void,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            &mut encoding as *mut DWORD,
            &mut content as *mut DWORD,
            &mut format as *mut DWORD,
            &mut store as *mut HCERTSTORE,
            std::ptr::null_mut(),
            &mut context as *mut PCCERT_CONTEXT as *mut *const c_void,
        )
    };

    if ok == 0 || context.is_null() {
        return None;
    }

    let mut buf = [0u16; 256];
    let len = unsafe {
        CertGetNameStringW(
            context,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            std::ptr::null_mut(),
            buf.as_mut_ptr(),
            buf.len() as DWORD,
        )
    };

    unsafe {
        CertFreeCertificateContext(context);
        if !store.is_null() {
            CertCloseStore(store, 0);
        }
    }

    if len <= 1 {
        return None;
    }

    Some(String::from_utf16_lossy(&buf[..(len as usize - 1)]))
}

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}
