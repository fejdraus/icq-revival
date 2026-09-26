//! `host dumpstacks <pid>`: prints the call stack of every thread of another
//! (32-bit) process, and which thread owns the loader lock. Used on a hung test
//! host from outside, so nothing in the hung process has to cooperate.

use std::ffi::c_void;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows_sys::Win32::System::Threading::{
    GetThreadDescription, OpenProcess, OpenThread, PROCESS_ALL_ACCESS, ResumeThread, SuspendThread,
    THREAD_ALL_ACCESS,
};

#[repr(C)]
struct ProcessBasicInformation {
    exit_status: i32,
    peb: u32,
    affinity: u32,
    base_priority: i32,
    pid: u32,
    parent: u32,
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryInformationProcess(
        h: HANDLE,
        class: u32,
        info: *mut c_void,
        len: u32,
        ret: *mut u32,
    ) -> i32;
}

fn read_u32(process: HANDLE, addr: u32) -> Option<u32> {
    let mut v = 0u32;
    let ok = unsafe {
        ReadProcessMemory(
            process,
            addr as usize as *const c_void,
            (&mut v as *mut u32).cast(),
            4,
            null_mut(),
        )
    };
    (ok != 0).then_some(v)
}

fn symbol(process: HANDLE, addr: u64) -> String {
    unsafe {
        let mut buf = [0u8; size_of::<SYMBOL_INFO>() + 512];
        let info = buf.as_mut_ptr() as *mut SYMBOL_INFO;
        (*info).SizeOfStruct = size_of::<SYMBOL_INFO>() as u32;
        (*info).MaxNameLen = 500;
        let mut disp = 0u64;
        let mut module: IMAGEHLP_MODULE64 = std::mem::zeroed();
        module.SizeOfStruct = size_of::<IMAGEHLP_MODULE64>() as u32;
        let modname = if SymGetModuleInfo64(process, addr, &mut module) != 0 {
            let n = module.ModuleName.iter().position(|&c| c == 0).unwrap_or(0);
            String::from_utf8_lossy(
                &module.ModuleName[..n]
                    .iter()
                    .map(|&c| c as u8)
                    .collect::<Vec<_>>(),
            )
            .into_owned()
        } else {
            "?".into()
        };
        let mut s = if SymFromAddr(process, addr, &mut disp, info) != 0 {
            let name = std::slice::from_raw_parts(
                (*info).Name.as_ptr() as *const u8,
                (*info).NameLen as usize,
            );
            format!("{modname}!{}+{disp:#x}", String::from_utf8_lossy(name))
        } else {
            format!("{modname}+{:#x}", addr.wrapping_sub(module.BaseOfImage))
        };
        let mut line: IMAGEHLP_LINE64 = std::mem::zeroed();
        line.SizeOfStruct = size_of::<IMAGEHLP_LINE64>() as u32;
        let mut d32 = 0u32;
        if SymGetLineFromAddr64(process, addr, &mut d32, &mut line) != 0 && !line.FileName.is_null()
        {
            let f = std::ffi::CStr::from_ptr(line.FileName as *const i8).to_string_lossy();
            let short: String = f
                .rsplit(['\\', '/'])
                .take(2)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join("/");
            s.push_str(&format!("  [{short}:{}]", line.LineNumber));
        }
        s
    }
}

pub fn dump(pid: u32, sympath: &str) {
    unsafe {
        let process = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
        assert!(!process.is_null(), "OpenProcess {pid} failed");
        SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
        let sp: Vec<u8> = sympath.bytes().chain(Some(0)).collect();
        SymInitialize(process, sp.as_ptr(), 1);

        // Loader lock: PEB+0xA0 -> RTL_CRITICAL_SECTION, OwningThread at +0xC.
        let mut pbi: ProcessBasicInformation = std::mem::zeroed();
        NtQueryInformationProcess(
            process,
            0,
            (&mut pbi as *mut ProcessBasicInformation).cast(),
            size_of::<ProcessBasicInformation>() as u32,
            null_mut(),
        );
        let lock = read_u32(process, pbi.peb + 0xA0).unwrap_or(0);
        let lock_count = read_u32(process, lock + 4).unwrap_or(0) as i32;
        let recursion = read_u32(process, lock + 8).unwrap_or(0);
        let owner = read_u32(process, lock + 0xC).unwrap_or(0);
        println!(
            "=== process {pid}: loader lock at {lock:#x}, owner thread {owner} (recursion {recursion}, lock count {lock_count})"
        );

        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        let mut te: THREADENTRY32 = std::mem::zeroed();
        te.dwSize = size_of::<THREADENTRY32>() as u32;
        let mut more = Thread32First(snap, &mut te) != 0;
        while more {
            if te.th32OwnerProcessID == pid {
                dump_thread(process, te.th32ThreadID, owner);
            }
            more = Thread32Next(snap, &mut te) != 0;
        }
        CloseHandle(snap);
        SymCleanup(process);
        CloseHandle(process);
    }
}

unsafe fn dump_thread(process: HANDLE, tid: u32, loader_owner: u32) {
    unsafe {
        let thread = OpenThread(THREAD_ALL_ACCESS, 0, tid);
        if thread.is_null() {
            println!("--- thread {tid}: cannot open");
            return;
        }
        let mut desc: *mut u16 = null_mut();
        let mut name = String::new();
        if GetThreadDescription(thread, &mut desc) >= 0 && !desc.is_null() {
            let n = (0..).take_while(|&i| *desc.add(i) != 0).count();
            name = String::from_utf16_lossy(std::slice::from_raw_parts(desc, n));
        }
        SuspendThread(thread);
        let mut ctx: CONTEXT = std::mem::zeroed();
        ctx.ContextFlags = CONTEXT_FULL_X86;
        GetThreadContext(thread, &mut ctx);
        let mut frame: STACKFRAME64 = std::mem::zeroed();
        frame.AddrPC.Offset = ctx.Eip as u64;
        frame.AddrPC.Mode = AddrModeFlat;
        frame.AddrFrame.Offset = ctx.Ebp as u64;
        frame.AddrFrame.Mode = AddrModeFlat;
        frame.AddrStack.Offset = ctx.Esp as u64;
        frame.AddrStack.Mode = AddrModeFlat;
        let mark = if tid == loader_owner {
            "  <== OWNS THE LOADER LOCK"
        } else {
            ""
        };
        println!("--- thread {tid} {name:?}{mark}");
        for _ in 0..60 {
            if StackWalk64(
                0x014c,
                process,
                thread,
                &mut frame,
                (&mut ctx as *mut CONTEXT).cast(),
                None,
                Some(SymFunctionTableAccess64),
                Some(SymGetModuleBase64),
                None,
            ) == 0
                || frame.AddrPC.Offset == 0
            {
                break;
            }
            println!(
                "    {:08x} {}",
                frame.AddrPC.Offset,
                symbol(process, frame.AddrPC.Offset)
            );
        }
        ResumeThread(thread);
        CloseHandle(thread);
    }
}
