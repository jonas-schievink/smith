use std::ptr::write_volatile;
use std::process;
use std::fmt::Display;

/// Sets all bytes in the given byte slice to 0.
///
/// Uses volatile operations to ensure that the write isn't elided.
pub fn clear_slice_securely(slice: &mut [u8]) {
    let mut ptr = slice.as_mut_ptr();
    for _ in 0..slice.len() {
        unsafe {
            write_volatile(ptr, 0);
            ptr = ptr.offset(1);
        }
    }
}

/// If the given `Result` is an `Err`, logs the error using `error!()`. Always returns the original
/// result.
pub fn log_if_err<T, E: Display>(res: Result<T, E>) -> Result<T, E> {
    res.map_err(|e| {
        error!("{}", e);
        e
    })
}

/// Prints an error and exits with return code 1 if the given `Result` is an `Err`, returns the
/// `Ok` value otherwise.
pub fn unwrap_or_exit<T, E: Display>(res: Result<T, E>) -> T {
    match res {
        Ok(t) => t,
        Err(e) => {
            error!("{}", e);
            process::exit(1);
        }
    }
}

#[test]
fn clear_slice() {
    let mut data = [1,2,3,4,5,6,0,0,0,1];
    clear_slice_securely(&mut data);
    assert_eq!(data, [0,0,0,0,0,0,0,0,0,0]);

    let mut data = [1,2,3,4,5,6,0,0,0,1];
    clear_slice_securely(&mut data[..9]);
    assert_eq!(data, [0,0,0,0,0,0,0,0,0,1]);

    let mut data = [1,2,3,4,5,6,0,0,0,1];
    clear_slice_securely(&mut data[1..]);
    assert_eq!(data, [1,0,0,0,0,0,0,0,0,0]);
}
