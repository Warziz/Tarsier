use std::{env};

use windows::Win32::System::Pipes::{CreatePipe};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation};
use windows::Win32::Security::{SECURITY_ATTRIBUTES};
use windows::Win32::System::Threading::{CreateProcessA, PROCESS_INFORMATION, STARTF_USESHOWWINDOW, STARTF_USESTDHANDLES, STARTUPINFOA};
use windows::core::{PSTR};

struct Handle {
    h_std_in_read: HANDLE,
    h_std_in_write: HANDLE,
    h_std_out_read: HANDLE,
    h_std_out_write: HANDLE,
}



fn get_args() -> String {

    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("[-] Programme path is required");
    }

    let path: String = args[1].clone();

    path
}

fn create_pipe() -> Handle {

    let mut h_std_in_r: HANDLE = HANDLE(std::ptr::null_mut());
    let mut h_std_in_w: HANDLE = HANDLE(std::ptr::null_mut());
    let mut h_std_out_r: HANDLE = HANDLE(std::ptr::null_mut());
    let mut h_std_out_w: HANDLE = HANDLE(std::ptr::null_mut());


    let security_attr: SECURITY_ATTRIBUTES = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: true.into(),
    };

    let sa = Some(&security_attr as *const SECURITY_ATTRIBUTES);

    let result = unsafe {CreatePipe(&mut h_std_in_r, &mut h_std_in_w, sa, 0) };
    match result {
        Ok(()) => {
            println!("[+] Successfully creating STDIN pipe");
            println!("[*] HANDLE hreadpipe: {:?}", h_std_in_r);
            println!("[*] HANDLE hwritepipe: {:?}", h_std_in_w);
        },
        Err(e) => println!("[-] Error while creating pipe: {e}") ,
    }

    let result = unsafe {
        SetHandleInformation(h_std_in_w, 0,HANDLE_FLAG_INHERIT)
    };
    match result {
        Ok(()) => println!("[+] Change HANDLE FLAGS"),
        Err(e) => println!("[-] Failed to change HANDLE FLAGS {e}"),
    }

    let result = unsafe {CreatePipe(&mut h_std_out_r, &mut h_std_out_w, sa, 0) };
    match result {
        Ok(()) => {
            println!("[+] Successfully creating STDOUT pipe");
            println!("[*] HANDLE hreadpipe: {:?}", h_std_out_r);
            println!("[*] HANDLE hwritepipe: {:?}", h_std_out_w);
        },
        Err(e) => println!("[-] Error while creating pipe: {e}") ,
    }

    let result = unsafe {
        SetHandleInformation(h_std_out_r, 0,HANDLE_FLAG_INHERIT)
    };
    match result {
        Ok(()) => println!("[+] Change HANDLE FLAGS"),
        Err(e) => println!("[-] Failed to change HANDLE FLAGS {e}"),
    }


    let my_handle = Handle {
        h_std_in_read: h_std_in_r,
        h_std_in_write: h_std_in_w,
        h_std_out_read: h_std_out_r,
        h_std_out_write: h_std_out_w,
    };

    my_handle

}


fn main() {
    
    //let path: String = get_args();
    
    // get handle of hStdInput / hStdOuput
    let my_handle = create_pipe();

    // fill startup info
    let reserved = PSTR::null();

    let si: STARTUPINFOA = STARTUPINFOA { 
        cb: std::mem::size_of::<STARTUPINFOA>() as u32, 
        lpReserved: reserved,
        dwFlags: STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW, 
        hStdInput: my_handle.h_std_in_write, 
        hStdOutput: my_handle.h_std_out_read, 
        hStdError: my_handle.h_std_out_read,
        ..Default::default()
    };

    let mut pi: PROCESS_INFORMATION = PROCESS_INFORMATION {..Default::default()};

}


