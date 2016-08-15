#![feature(libc)]
#![allow(unused_variables)]
extern crate getopts;
extern crate libc;
#[macro_use] extern crate mdo;
extern crate nix;
extern crate users;
extern crate pam;
extern crate mnt;
#[macro_use] extern crate nom;
extern crate syslog;

use libc::{c_char, c_int};
use nix::sys::quota::{quota, quotactl_set};
use pam::{constants, module}; // https://tozny.github.io/rust-pam/pam/module/index.html
use pam::constants::*;
use syslog::{Facility,Severity};

#[no_mangle]
pub extern fn pam_sm_open_session(pamh: &module::PamHandleT, flags: PamFlag,
                                  argc: c_int, argv: *mut *const c_char
) -> PamResultCode {
    use mdo::result::{bind,ret};
    use users::os::unix::UserExt;
    use mnt::get_mount;

    let args = unsafe { translate_args(argc, argv) };


    (mdo! {
        username =<< module::get_user(pamh, None)
            .map_err(|e| (e, "Failed to get username"));

        user =<< users::get_user_by_name(&username)
            .ok_or((PAM_USER_UNKNOWN, "Unknown user"));

        () =<< if user.uid() < 1000 { Err((PAM_SUCCESS, "")) } else { Ok(()) };


        quota =<< parse_args(args)
            .map_err(|s| (PAM_SESSION_ERR, &*format!("Failed to parse {}", s)));


        home_opt =<< get_mount(user.home_dir())
            .or(Err((PAM_SESSION_ERR, "Couldn't get the homedir's mountpoint")));

        home =<< home_opt
            .ok_or((PAM_SESSION_ERR, "Couldn't get the homedir's mountpoint"));

        () =<< quotactl_set(quota::USRQUOTA,
                            &home.file,
                            user.uid() as i32,
                            &quota)
            .or(Err((PAM_SESSION_ERR, "Failed to set quota")));

        ret Ok(PAM_SUCCESS)
    }).unwrap_or_else(|(e, msg)|
                      if e != PAM_SUCCESS {
                          mdo! {
                              writer =<< syslog::unix(Facility::LOG_AUTH);
                              result =<< writer.send_3164(Severity::LOG_ALERT, &format!("pam_setquota: {}", msg));
                              ret Ok(result)
                          };
                          e
                      } else { e }
    )
}


fn parse_args(args: Vec<String>) -> Result<quota::Dqblk, String> {
    use nom::{alpha,digit};
    use std::{i32,str};

    let quota0 = quota::Dqblk {
        bhardlimit: 0,
        bsoftlimit: 0,
        curspace:   0,
        ihardlimit: 0,
        isoftlimit: 0,
        curinodes:  0,
        btime:      0,
        itime:      0,
        valid:      quota::QuotaValidFlags::empty()
    };

    named!(arg,
           chain!(tag: alpha ~
                  char!('=') ~
                  v1: digit  ~
                  char!(',') ~
                  v2: digit,
                  || {
                      use mdo::option::{bind,ret};
                      mdo! {
                          s1 =<< str::from_utf8(v1).ok();
                          i1 =<< i32::from_str_radix(s1, 10).ok();

                          s2 =<< str::from_utf8(v2).ok();
                          i2 =<< i32::from_str_radix(s2, 10).ok();
                          ret Some(tag, i1, i2)
                      }
                  }
           )
    );
    Ok(quota0)
//    let apply_arg = |q: quota::Dqblk, s: String| {
//        match arg(s) {
//            Done(
//
//        }
//    };
//
//    args.fold(defaults, |ret, s| { ret bind apply_arg s });
}

#[no_mangle]
pub extern fn pam_sm_close_session(pamh: *mut module::PamHandleT, flags: PamFlag,
                                   argc: c_int, argv: *const *const c_char
                                   ) -> PamResultCode {
    constants::PAM_SUCCESS
}


unsafe fn translate_args(argc: c_int, argv: *mut *const c_char) -> Vec<String> {
    use std::ffi;
    let v = Vec::<*const c_char>::from_raw_parts(argv, argc as usize, argc as usize);
    v.into_iter().filter_map(|arg| {
        let bytes = ffi::CStr::from_ptr(arg).to_bytes();
        String::from_utf8(bytes.to_vec()).ok()
    }).collect()
}
