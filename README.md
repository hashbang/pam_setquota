PAM `setquota` module
=====================

This module sets disk quota when a session begins.

This makes quotas usable with central user databases, such as LDAP.


Usage
-----

`pam_setquota` applies a specific disk quota to users (with uid >= 1000).

Limits can be passed to `pam_setquota.so` through the PAM configuration.
They take the form `type=soft,hard`, where:
- `type` is either `blocks` or `inodes`:
  - `blocks` limits the space usage, expressed in bytes;
  - `inodes` limits the number of filesystem objects (file, folder, ...)
- `soft` (resp. `hard`) is the decimal value of the soft limit.

See `quotactl(2)` for further information.


Missing features (TODOs)
------------------------

Compared to the original C version, we miss the following functionality:

- [ ] configurable uid ranges;
- [ ] configurable directory;
- [ ] `override` flag.


Example
-------

	session    required     /lib/security/pam_setquota.so blocks=19000,20000 inodes=3000,4000


Licence and credits
-------------------

Released under the ISC license, © Keller Fuchs <kellerfuchs@hashbang.sh>

Inspired by the C version of `pam_setquota`.

Special thanks go to @geal for his `nom` and `syslog` crates,
and his supportive rubber-ducking.
