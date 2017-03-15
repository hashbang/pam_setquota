#![feature(alloc_system,libc)]
#![allow(unused_variables)] // Unused parameters from the PAM API
extern crate alloc_system;  // Save space by using malloc rather than jemalloc
extern crate libc;
extern crate nix;
extern crate users;
extern crate pam;
extern crate mnt;
#[macro_use]
extern crate nom;
extern crate syslog;

use libc::{c_char, c_int};
use pam::module; // https://tozny.github.io/rust-pam/pam/module/index.html
use pam::constants::*;
use syslog::{Facility, Severity};
use std::borrow::Cow;
use nix::sys::quota::quota;


#[no_mangle]
pub extern "C" fn pam_sm_open_session(pamh: &module::PamHandleT,
                                      flags: PamFlag,
                                      argc: c_int,
                                      argv: *mut *const c_char)
                                      -> PamResultCode {

    let args = unsafe { translate_args(argc, argv) };

    let log_err_and_return = |(e, msg): (PamResultCode, Cow<str>)| -> PamResultCode {
        if e != PAM_SUCCESS {
            // We cheerfully ignore errors in logging to syslog,
            // since there is nothing we can do about it.
            let _ = syslog::unix(Facility::LOG_AUTH).and_then(|writer| {
                writer.send_3164(Severity::LOG_ALERT, &format!("pam_setquota: {}", msg))
            });
        };

        e
    };

    //  if something triggers an error, it has an associated pam::constant value
    //  and processing stop (we go to .unwrap_or_else() and log the error)
    open_session(pamh, flags, args).unwrap_or_else(log_err_and_return)
}

pub fn open_session(pamh: &module::PamHandleT,
                    flags: PamFlag,
                    args: Vec<String>)
                    -> Result<PamResultCode, (PamResultCode, Cow<str>)> {
    use users::os::unix::UserExt;
    use mnt::get_mount;
    use nix::sys::quota::quotactl_set;

    // Get the username from PAM
    let username = module::get_user(pamh, None).map_err(|e| (e, Cow::from("")))?;

    // Get the user object from the passwd db
    let user =
        users::get_user_by_name(&username).ok_or((PAM_USER_UNKNOWN, Cow::from("Unknown user")))?;

    // If this is a system user (uid < 1000), bail out early with PAM_SUCCESS
    if user.uid() < 1000 {
        return Err((PAM_SUCCESS, Cow::from("")));
    }

    // Parse the module's arguments.
    // It is done late to avoid erroring out if the user has uid < 1000
    let quota = parse_args(&args)
        .map_err(|s| (PAM_SESSION_ERR, Cow::from(format!("Failed to parse {}", s))))?;

    // Get the user's homedir mountpoint.
    // Somehow, this requires unwrapping twice (yay for silly APIs!)
    let home = get_mount(user.home_dir())
        .map_err(|_| (PAM_SESSION_ERR, Cow::from("Couldn't get the homedir's mountpoint")))?
        .ok_or((PAM_SESSION_ERR, Cow::from("Couldn't get the homedir's mountpoint")))?;

    // Perform the actual quotactl(2) call
    quotactl_set(quota::USRQUOTA,
                            &home.file,
                            user.uid() as i32,
                            &quota)
            .or(Err((PAM_SESSION_ERR, Cow::from("Failed to set quota"))))?;

    Ok(PAM_SUCCESS)
}

// parse_args returns either a quota::Dqblk struct
//  or the string that failed to parse.
fn parse_args<'a>(args: &'a Vec<String>) -> Result<quota::Dqblk, Cow<'a, str>> {
    use nom::{alpha, digit};
    use nix::sys::quota::quota::{QuotaValidFlags, QIF_BLIMITS, QIF_ILIMITS};

    // The default quota value
    // It isn't quota::Dqblk::default() directly because
    //  the documentation doesn't state what the default value is.
    let quota0 = quota::Dqblk { valid: QuotaValidFlags::empty(), ..quota::Dqblk::default() };

    // A parser (and converter) for “([a-z]+)=([0-9])+,([0-9])+”
    named!(int64<&str, u64>, map_res!(digit, |s| u64::from_str_radix(s, 10)));
    named!(arg<&str, (&str, u64, u64)>,
           chain!(tag: alpha ~ tag_s!("=") ~ i1: int64 ~ tag_s!(",") ~ i2: int64,
                  || (tag, i1, i2)
           )
    );


    // We fold over the arguments, updating the quota value as we go.
    // Again, the Result<> is used to error-out early.
    args.iter().fold(Ok(quota0), |res, s| -> Result<quota::Dqblk, Cow<'a, str>> {
        use nom::IResult::Done;

        let quota0 = res?;

        let parse = match arg(s) {
            Done(_, o) => Ok(o),
            _ => Err(Cow::from(s.as_str())),
        }?;

        let (type_, soft, hard) = parse;

        match type_ {
            "blocks" => {
                Ok(quota::Dqblk {
                    bsoftlimit: soft,
                    bhardlimit: hard,
                    valid: quota0.valid | QIF_BLIMITS,
                    ..quota0
                })
            }
            "inodes" => {
                Ok(quota::Dqblk {
                    isoftlimit: soft,
                    ihardlimit: hard,
                    valid: quota0.valid | QIF_ILIMITS,
                    ..quota0
                })
            }
            _ => Err(Cow::from(s.as_str())),
        }
    })
}

#[no_mangle]
// Closing the session involves no special work.
pub extern "C" fn pam_sm_close_session(pamh: *mut module::PamHandleT,
                                       flags: PamFlag,
                                       argc: c_int,
                                       argv: *const *const c_char)
                                       -> PamResultCode {
    PAM_SUCCESS
}


// Arcane magic to turn (argc,argv) into a Vec<String>.
// Please set your syntax coloring to octarine.
unsafe fn translate_args(argc: c_int, argv: *mut *const c_char) -> Vec<String> {
    use std::ffi;
    let v = Vec::<*const c_char>::from_raw_parts(argv, argc as usize, argc as usize);
    v.into_iter()
        .filter_map(|arg| {
            let bytes = ffi::CStr::from_ptr(arg).to_bytes();
            String::from_utf8(bytes.to_vec()).ok()
        })
        .collect()
}
