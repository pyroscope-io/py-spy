//! py-spy: a sampling profiler for python programs
//!
//! This crate lets you use py-spy as a rust library, and gather stack traces from
//! your python process programmatically.
//!
//! # Example:
//!
//! ```rust,no_run
//! fn print_python_stacks(pid: py_spy::Pid) -> Result<(), failure::Error> {
//!     // Create a new PythonSpy object with the default config options
//!     let config = py_spy::Config::default();
//!     let mut process = py_spy::PythonSpy::new(pid, &config)?;
//!
//!     // get stack traces for each thread in the process
//!     let traces = process.get_stack_traces()?;
//!
//!     // Print out the python stack for each thread
//!     for trace in traces {
//!         println!("Thread {:#X} ({})", trace.thread_id, trace.status_str());
//!         for frame in &trace.frames {
//!             println!("\t {} ({}:{})", frame.name, frame.filename, frame.line);
//!         }
//!     }
//!     Ok(())
//! }
//! ```

#[macro_use]
extern crate clap;
#[macro_use]
extern crate failure;
extern crate goblin;
#[macro_use]
extern crate lazy_static;
extern crate libc;
#[macro_use]
extern crate log;
#[cfg(unwind)]
extern crate lru;
extern crate memmap;
extern crate proc_maps;
extern crate regex;
#[cfg(windows)]
extern crate winapi;
extern crate cpp_demangle;
extern crate rand;
extern crate rand_distr;
extern crate remoteprocess;

pub mod config;
pub mod binary_parser;
#[cfg(unwind)]
mod cython;
#[cfg(unwind)]
mod native_stack_trace;
mod python_bindings;
mod python_interpreters;
mod python_spy;
mod python_data_access;
mod python_threading;
pub mod sampler;
mod stack_trace;
pub mod timer;
mod utils;
mod version;

pub use python_spy::PythonSpy;
pub use config::Config;
pub use stack_trace::StackTrace;
pub use stack_trace::Frame;
pub use remoteprocess::Pid;


use std::collections::HashMap;
use std::sync::Mutex;
use std::slice;

lazy_static! {
    static ref HASHMAP: Mutex<HashMap<Pid, PythonSpy>> =
    {
        let h = HashMap::new();
        Mutex::new(h)
    };
}

fn copy_error(err_ptr: *mut u8, err_len: i32, err_str: String) -> i32 {
    let slice = err_str.as_bytes();
    let l = slice.len();
    if l as i32 > err_len {
        return copy_error(err_ptr, err_len, "buffer is too small".to_string());
    }
    let target = unsafe { slice::from_raw_parts_mut(err_ptr, l as usize) };
    target.clone_from_slice(slice);
    -(l as i32)
}

#[no_mangle]
pub extern "C" fn pyspy_init(pid: Pid, err_ptr: *mut u8, err_len: i32) -> i32 {
    let config = config::Config::default();
    match PythonSpy::new(pid, &config) {
        Ok(getter) => {
            let mut map = HASHMAP.lock().unwrap(); // get()
            map.insert(pid, getter);
            1
        }
        Err(err) => {
            copy_error(err_ptr, err_len, err.to_string())
        }
    }
}

#[no_mangle]
pub extern "C" fn pyspy_cleanup(pid: Pid, err_ptr: *mut u8, err_len: i32) -> i32 {
    let mut map = HASHMAP.lock().unwrap(); // get()
    map.remove(&pid);
    1
}

#[no_mangle]
pub extern "C" fn pyspy_snapshot(pid: Pid, ptr: *mut u8, len: i32, err_ptr: *mut u8, err_len: i32) -> i32 {
    let mut map = HASHMAP.lock().unwrap(); // get()
    match map.get_mut(&pid) {
        Some(getter) => {
            let mut res = 0;
            let trace_res = getter.get_stack_traces();
            match trace_res {
                Ok(trace) => {
                    let mut string_list = vec![];
                    for thread in trace.iter() {
                        if thread.active {
                            for frame in &thread.frames {
                                let filename = match &frame.short_filename { Some(f) => &f, None => &frame.filename };
                                if frame.line != 0 {
                                    string_list.insert(0, format!("{} - {}:{}", filename, frame.name, frame.line));
                                } else {
                                    string_list.insert(0, format!("{} - {}", filename, frame.name));
                                }
                            }
                            break
                        }
                    }
                    let joined = string_list.join(";");
                    let joined_slice = joined.as_bytes();
                    let l = joined_slice.len();

                    if len < (l as i32) {
                        res = copy_error(err_ptr, err_len, "buffer is too small".to_string());
                    } else {
                        let slice = unsafe { slice::from_raw_parts_mut(ptr, l as usize) };
                        slice.clone_from_slice(joined_slice);
                        res = l as i32
                    }
                }
                Err(err) => {
                    res = copy_error(err_ptr, err_len, err.to_string());
                }
            }
            res
        }
        None => copy_error(err_ptr, err_len, "could not find spy for this pid".to_string())
    }
}
