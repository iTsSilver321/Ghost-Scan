use std::ffi::{CStr, CString};
use std::os::raw::{c_char};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

#[repr(C)]
pub struct PortResult {
    port: u16,
    is_open: bool,
    banner: *mut c_char, // Null-terminated string or NULL
}

// SAFETY: We are transferring ownership of the pointer between threads.
// We created it with CString::into_raw, so it's a unique pointer effectively.
unsafe impl Send for PortResult {}
unsafe impl Sync for PortResult {}

#[repr(C)]
pub struct ScanResultArgs {
    results: *mut PortResult,
    len: usize,
}

#[no_mangle]
pub unsafe extern "C" fn scan_target(
    target_ip: *const c_char,
    ports: *const u16,
    ports_len: usize,
    threads: usize,
    timeout_ms: u64,
) -> *mut ScanResultArgs {
    let c_str = unsafe { CStr::from_ptr(target_ip) };
    let target = match c_str.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return std::ptr::null_mut(),
    };

    let ports_slice = unsafe { std::slice::from_raw_parts(ports, ports_len) };
    let ports_vec = ports_slice.to_vec();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let results = rt.block_on(async {
        run_scan(target, ports_vec, threads, timeout_ms).await
    });

    let mut c_results = Vec::with_capacity(results.len());
    for res in results {
        c_results.push(res);
    }
    
    let results_ptr = c_results.as_mut_ptr();
    let results_len = c_results.len();
    std::mem::forget(c_results); 

    let args = Box::new(ScanResultArgs {
        results: results_ptr,
        len: results_len,
    });

    Box::into_raw(args)
}

#[no_mangle]
pub unsafe extern "C" fn free_scan_results(ptr: *mut ScanResultArgs) {
    if ptr.is_null() {
        return;
    }
    
    let args = Box::from_raw(ptr);
    let vec = Vec::from_raw_parts(args.results, args.len, args.len);
    
    for res in vec {
        if !res.banner.is_null() {
            let _ = CString::from_raw(res.banner);
        }
    }
}

async fn run_scan(target: String, ports: Vec<u16>, threads: usize, timeout_val: u64) -> Vec<PortResult> {
    // Use a much larger semaphore or just rely on OS limits. 
    // Threads argument now controls max concurrent scans.
    let semaphore = Arc::new(Semaphore::new(threads));
    let mut handles = Vec::new();
    let target = Arc::new(target);

    for port in ports {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let target_clone = target.clone();
        
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            let addr = format!("{}:{}", target_clone, port);
            
            let connect_res = timeout(Duration::from_millis(timeout_val), TcpStream::connect(&addr)).await;
            
            match connect_res {
                Ok(Ok(mut stream)) => {
                    let banner_str = grab_banner_async(&mut stream, 500).await;
                    
                    let banner_ptr = match CString::new(banner_str) {
                        Ok(s) => s.into_raw(),
                        Err(_) => std::ptr::null_mut(),
                    };

                    Some(PortResult {
                        port,
                        is_open: true,
                        banner: banner_ptr,
                    })
                },
                _ => None
            }
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        if let Ok(Some(res)) = handle.await {
            results.push(res);
        }
    }
    
    results
}

async fn grab_banner_async(stream: &mut TcpStream, timeout_ms: u64) -> String {
    let mut buf = [0u8; 1024];
    
    // Check if data is already available or wait briefly (passive)
    let read_res = timeout(Duration::from_millis(timeout_ms), stream.read(&mut buf)).await;
    
    if let Ok(Ok(n)) = read_res {
        if n > 0 {
            return String::from_utf8_lossy(&buf[..n]).trim().to_string();
        }
    }
    
    // Send probe (Active)
    if stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n").await.is_err() {
        return "Unknown".to_string();
    }
    
    // Read again with timeout
    let read_res = timeout(Duration::from_millis(timeout_ms), stream.read(&mut buf)).await;
    if let Ok(Ok(n)) = read_res {
        if n > 0 {
            return String::from_utf8_lossy(&buf[..n]).trim().to_string();
        }
    }
    
    "Unknown".to_string()
}
