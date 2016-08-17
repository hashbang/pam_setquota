#![feature(libc, convert)]
#![allow(unused_variables)]
extern crate libc;
#[macro_use] extern crate mdo;
extern crate nix;
extern crate users;
extern crate pam;
extern crate mnt;
#[macro_use] extern crate nom;
extern crate syslog;

use libc::{c_char, c_int};
use pam::module; // https://tozny.github.io/rust-pam/pam/module/index.html
use pam::constants::*;
use syslog::{Facility,Severity};
use std::borrow::Cow;
use nix::sys::quota::quota;


#[no_mangle]
pub extern fn pam_sm_open_session(pamh: &module::PamHandleT, flags: PamFlag,
                                  argc: c_int, argv: *mut *const c_char
) -> PamResultCode {
    use mdo::result::{bind,ret};
    use users::os::unix::UserExt;
    use mnt::get_mount;
    use nix::sys::quota::quotactl_set;

    let args = unsafe { translate_args(argc, argv) };

    // We use the Result<_, pam::constant> monad:
    //  if something triggers an error, it has an associated pam::constant value
    //  and processing stop (we go to .unwrap_or_else() and log the error)
    (mdo! {
        // Get the username from PAM
        username =<< module::get_user(pamh, None)
            .map_err(|e| (e, Cow::from("Failed to get username")));

        // Get the user object from the passwd db
        user =<< users::get_user_by_name(&username)
            .ok_or((PAM_USER_UNKNOWN, Cow::from("Unknown user")));

        // If this is a system user (uid < 1000), bail out early with PAM_SUCCESS
        () =<< if user.uid() < 1000 { Err((PAM_SUCCESS, Cow::from(""))) } else { Ok(()) };


        // Parse the module's arguments.
        // It is done late to avoid erroring out if the user has uid < 1000
        quota =<< parse_args(&args)
            .map_err(|s| (PAM_SESSION_ERR, Cow::from(format!("Failed to parse {}", s))));


        // Get the user's homedir mountpoint.
        // Somehow, this requires unwrapping twice (yay for silly APIs!)
        home_opt =<< get_mount(user.home_dir())
            .or(Err((PAM_SESSION_ERR, Cow::from("Couldn't get the homedir's mountpoint"))));

        home =<< home_opt
            .ok_or((PAM_SESSION_ERR, Cow::from("Couldn't get the homedir's mountpoint")));


        // Perform the actual quotactl(2) call
        () =<< quotactl_set(quota::USRQUOTA,
                            &home.file,
                            user.uid() as i32,
                            &quota)
            .or(Err((PAM_SESSION_ERR, Cow::from("Failed to set quota"))));

        ret Ok(PAM_SUCCESS)
    }).unwrap_or_else(|(e, msg)|
                      if e != PAM_SUCCESS {
                          // We cheerfully ignore errors in logging to syslog,
                          // since there is nothing we can do about it.
                          mdo! {
                              writer =<< syslog::unix(Facility::LOG_AUTH);
                              result =<< writer.send_3164(Severity::LOG_ALERT, &format!("pam_setquota: {}", msg));
                              ret Ok(result)
                          };
                          e
                      } else { e }
    )
}


// parse_args returns either a quota::Dqblk struct
//  or the string that failed to parse.
fn parse_args<'a>(args: &'a Vec<String>) -> Result<quota::Dqblk, Cow<'a, str> > {
    use nom::{alpha,digit};
    use std::str;
    use nix::sys::quota::quota::{QuotaValidFlags,QIF_BLIMITS,QIF_ILIMITS};

    // The default quota value
    // It isn't quota::Dqblk::default() directly because
    //  the documentation doesn't state what the default value is.
    let quota0 = quota::Dqblk {
        valid: QuotaValidFlags::empty(),
        .. quota::Dqblk::default()
    };

    // A parser (and converter) for “([a-z]+)=([0-9])+,([0-9])+”
    named!(arg<&[u8], Option<(&[u8], u64, u64)> >,
           chain!(tag: alpha ~
                  char!('=') ~
                  v1: digit  ~
                  char!(',') ~
                  v2: digit,
                  || {
                      use mdo::option::{bind,ret};
                      mdo! {
                          s1 =<< str::from_utf8(v1).ok();
                          i1 =<< u64::from_str_radix(s1, 10).ok();

                          s2 =<< str::from_utf8(v2).ok();
                          i2 =<< u64::from_str_radix(s2, 10).ok();
                          ret Some((tag, i1, i2))
                      }
                  }
           )
    );

    // We fold over the arguments, updating the quota value as we go.
    // Again, the Result<> monad is used to error-out early.
    args.iter().fold(Ok(quota0),
              |res, s| {
                  use mdo::result::{bind,ret};
                  use nom::IResult::Done;
                  mdo! {
                      quota0 =<< res;
                      // TODO: This is horrible; check why parse cannot be deconstructed
                      parse =<< match arg(s.as_bytes()) {
                          Done(_, o) => o.ok_or(Cow::from(s.as_str())),
                          _ => Err(Cow::from(s.as_str()))
                      };
                      ret match parse.0 {
                          b"blocks" => Ok(quota::Dqblk {
                              bsoftlimit: parse.1,
                              bhardlimit: parse.2,
                              valid:      quota0.valid | QIF_BLIMITS,
                              .. quota0
                          }),
                          b"inodes" => Ok(quota::Dqblk {
                              isoftlimit: parse.1,
                              ihardlimit: parse.2,
                              valid:      quota0.valid | QIF_ILIMITS,
                              .. quota0
                          }),
                          _ => Err(Cow::from(s.as_str()))
                      }
                  }
              }
    )
}

#[no_mangle]
// Closing the session involves no special work.
pub extern fn pam_sm_close_session(pamh: *mut module::PamHandleT, flags: PamFlag,
                                   argc: c_int, argv: *const *const c_char
                                   ) -> PamResultCode {
    PAM_SUCCESS
}


// Arcane magic to turn (argc,argv) into a Vec<String>.
// Please set your syntax coloring to octarine.
unsafe fn translate_args(argc: c_int, argv: *mut *const c_char) -> Vec<String> {
    use std::ffi;
    let v = Vec::<*const c_char>::from_raw_parts(argv, argc as usize, argc as usize);
    v.into_iter().filter_map(|arg| {
        let bytes = ffi::CStr::from_ptr(arg).to_bytes();
        String::from_utf8(bytes.to_vec()).ok()
    }).collect()
}
