use std::{env,ptr,thread,time::Duration};
use std::ffi::{CString, NulError, c_void};

use windows::Win32::System::Pipes::{CreatePipe};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation};
use windows::Win32::Security::{SECURITY_ATTRIBUTES};
use windows::Win32::System::Threading::{CREATE_NEW_CONSOLE, CreateProcessA, NORMAL_PRIORITY_CLASS, PROCESS_INFORMATION, STARTF_USESHOWWINDOW, STARTF_USESTDHANDLES, STARTUPINFOA};
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows::Win32::System::IO::{OVERLAPPED};
use windows::core::{PSTR,PCSTR};

struct Handle {
    h_std_in_read: HANDLE,
    h_std_in_write: HANDLE,
    h_std_out_read: HANDLE,
    h_std_out_write: HANDLE,
    security_attr: SECURITY_ATTRIBUTES,
}



fn get_args() -> Result<CString,NulError> {

    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("[-] Programme path is required");
    }

    let result = CString::new(args[1].clone());
    match result {
        Ok(path) => Ok(path),
        Err(e) => Err(e),
    }

}

fn create_pipe() -> Handle {

    let mut h_std_in_r: HANDLE = HANDLE(ptr::null_mut());
    let mut h_std_in_w: HANDLE = HANDLE(ptr::null_mut());
    let mut h_std_out_r: HANDLE = HANDLE(ptr::null_mut());
    let mut h_std_out_w: HANDLE = HANDLE(ptr::null_mut());


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
        security_attr: security_attr,
    };

    my_handle

}


fn main() {
    
    // get path to executable
    let result  = get_args().unwrap();
    let path = result.as_ptr() as *mut u8;
    let cmd_line: PSTR = PSTR::from_raw(path); 

    println!("path: {:?}", result);

    // get handle of hStdInput / hStdOuput
    let my_handle = create_pipe();

    // fill startup info
    let reserved = PSTR::null();

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
    let mut pi: PROCESS_INFORMATION = PROCESS_INFORMATION {..Default::default()};
    let app_name = PCSTR::null();
    let env: *const c_void = ptr::null();
    let curr_directory = PCSTR::null();
    let sa = Some(&my_handle.security_attr as *const SECURITY_ATTRIBUTES);


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
            &mut pi)
    };

    // close unuse handle
    match result {
        Ok(()) => {
            println!("[+] Process create Successfully !");
            let _ = unsafe {CloseHandle(my_handle.h_std_in_read)};
            let _ = unsafe {CloseHandle(my_handle.h_std_out_write)};
            thread::sleep(Duration::from_secs(2));
        },
        Err(e) => println!("[-] Process creation failed: {e}"), 
    };

    let buffer: [u8;15] = [0x61,0x62,0x63,0x61,0x62,0x63,0x61,0x62,0x63,0x61,0x62,0x63,0x61,0x62,0x63];
    let mut byte_written: u32= 0;
    let mut overlapped = OVERLAPPED{..Default::default()};

    let result = unsafe {
        //lpnumberofbytewritten w/o coercion, lpoverlapped w/ coercion
        WriteFile(my_handle.h_std_in_write, Some(&buffer), Some(&mut byte_written as *mut u32), Some(&mut overlapped)) 
    };

    match result {
        Ok(()) => println!("[+] Successfully write 14 bytes into process:{:?}", byte_written),
        Err(e) => println!("[-] Error while writing in process: {e}"),
    };

    let mut buffer_out:[u8;512] = [0;512];
    let mut byte_read: u32 = 0;

    let result = unsafe { 
        ReadFile(my_handle.h_std_out_read, Some(&mut buffer_out),Some(&mut byte_read), Some(&mut overlapped))
    };
    
    match result {
        Ok(_) => {
            println!("[+] Bytes recieved: {:?}",byte_read);
            let data = String::from_utf8_lossy(&buffer_out);
            println!("[*] STDOUT: {:?}",data);

        },
        Err(e) => println!("[-] Error while recieved: {e}")
    }

    unsafe {
    
        let _ = CloseHandle(my_handle.h_std_in_write);
        let _ = CloseHandle(my_handle.h_std_out_read);
    };
    

}


