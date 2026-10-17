use std::{env,ptr,thread,time::Duration};
use std::ffi::{CString, NulError, c_void};

use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Memory::{MEM_COMMIT,MEM_PRIVATE, MEMORY_BASIC_INFORMATION, PAGE_GUARD, PAGE_NOACCESS, VirtualQueryEx};
use windows::Win32::System::Pipes::{CreatePipe};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation};
use windows::Win32::Security::{SECURITY_ATTRIBUTES};
use windows::Win32::System::Threading::{CREATE_NEW_CONSOLE, CreateProcessA, NORMAL_PRIORITY_CLASS, PROCESS_INFORMATION, STARTF_USESHOWWINDOW, STARTF_USESTDHANDLES, STARTUPINFOA};
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows::Win32::System::IO::{OVERLAPPED};
use windows::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
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

fn find_offset(ns_handle: HANDLE){
    
    let mut system_info: SYSTEM_INFO = SYSTEM_INFO {..Default::default()};
    unsafe { GetSystemInfo(&mut system_info);}

    let mut memory_info: MEMORY_BASIC_INFORMATION = MEMORY_BASIC_INFORMATION {..Default::default()};
    let start_address = system_info.lpMinimumApplicationAddress as *const c_void;
    let memory_info_size: usize = size_of::<MEMORY_BASIC_INFORMATION>();
    let mut addr: usize = start_address as usize;
    let mut read_memory_buffer = vec![0u8;4096];
    let mut bytes_read :usize = 0;
    let mut current_addr: usize;

    loop {

        let result  = unsafe {
            VirtualQueryEx(ns_handle, Some(addr as *const c_void), &mut memory_info, memory_info_size)
        };

        // verify VirtualQueryEx not failed
        if result == 0 {
            println!("[-] Failed to get VirtualMemory Region size equal: {result}");
            break;
        }

        // save current addr for read memory
        current_addr = addr;
        // prepare addr for next iteration
        addr += memory_info.RegionSize;
        // println!("[*] Next region base address: {:#x}", addr);
        if addr >= system_info.lpMaximumApplicationAddress as usize {
            break;
        }

        // search for correct memory region
        // Verify is memory is commited
        if memory_info.State != MEM_COMMIT {
            continue;
        }
        // Verify if memory region is no_acces or is a page guard
        if memory_info.Protect.contains(PAGE_GUARD) || memory_info.Protect.contains(PAGE_NOACCESS) {
            continue;
        }
        // Verify if region MEM_PRIVATE
        if memory_info.Type != MEM_PRIVATE {
            continue;
        }


        println!("[*] Reading @ {:#x}, Region size: {:?}",addr,memory_info.RegionSize);
        
        let result = unsafe {
            ReadProcessMemory(ns_handle,
                current_addr as *const c_void,
                read_memory_buffer.as_mut_ptr() as *mut c_void,
                read_memory_buffer.len(), 
                Some(&mut bytes_read))
        };

        match result {
            Ok(_) => println!("[+] Successfully reading @ {:#x}, length {:?}",addr,bytes_read),
            Err(e) => println!("[-] Failed to read process memory: {e}, bytes read {:?}", bytes_read),
        }

    }

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

    // send bytes pattern
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
            // let data = String::from_utf8_lossy(&buffer_out);
            // println!("[*] STDOUT: {:?}",data);

        },
        Err(e) => println!("[-] Error while recieved: {e}")
    }

    let ns_handle : HANDLE = pi.hProcess;
    find_offset(ns_handle);

    unsafe {
    
        let _ = CloseHandle(my_handle.h_std_in_write);
        let _ = CloseHandle(my_handle.h_std_out_read);
    };
    

}


