//! Darwin errno -> Linux errno. Values 1..=34 coincide except 11 (EDEADLK on
//! Darwin, EAGAIN on Linux); everything above differs.

pub const EPERM: i64 = 1;
pub const ENOENT: i64 = 2;
pub const EBADF: i64 = 9;
pub const EAGAIN: i64 = 11;
pub const ENOMEM: i64 = 12;
pub const EFAULT: i64 = 14;
pub const EINVAL: i64 = 22;
pub const ENOTTY: i64 = 25;
pub const ERANGE: i64 = 34;
pub const ENOSYS: i64 = 38;
pub const ENODEV: i64 = 19;

pub fn from_host(e: i32) -> i64 {
    use libc::*;
    (match e {
        EDEADLK => 35,
        EAGAIN => 11,
        EINPROGRESS => 115,
        EALREADY => 114,
        ENOTSOCK => 88,
        EDESTADDRREQ => 89,
        EMSGSIZE => 90,
        EPROTOTYPE => 91,
        ENOPROTOOPT => 92,
        EPROTONOSUPPORT => 93,
        ESOCKTNOSUPPORT => 94,
        ENOTSUP | EOPNOTSUPP => 95,
        EPFNOSUPPORT => 96,
        EAFNOSUPPORT => 97,
        EADDRINUSE => 98,
        EADDRNOTAVAIL => 99,
        ENETDOWN => 100,
        ENETUNREACH => 101,
        ENETRESET => 102,
        ECONNABORTED => 103,
        ECONNRESET => 104,
        ENOBUFS => 105,
        EISCONN => 106,
        ENOTCONN => 107,
        ESHUTDOWN => 108,
        ETOOMANYREFS => 109,
        ETIMEDOUT => 110,
        ECONNREFUSED => 111,
        ELOOP => 40,
        ENAMETOOLONG => 36,
        EHOSTDOWN => 112,
        EHOSTUNREACH => 113,
        ENOTEMPTY => 39,
        EUSERS => 87,
        EDQUOT => 122,
        ESTALE => 116,
        ENOLCK => 37,
        ENOSYS => 38,
        EOVERFLOW => 75,
        ECANCELED => 125,
        EIDRM => 43,
        ENOMSG => 42,
        EILSEQ => 84,
        EBADMSG => 74,
        ENODATA => 61,
        ETIME => 62,
        EPROTO => 71,
        ENOTRECOVERABLE => 131,
        EOWNERDEAD => 130,
        e if (1..=34).contains(&e) => e,
        _ => 5, // EIO
    }) as i64
}

/// `-errno` of the last host error, as a Linux syscall return value.
pub fn last() -> i64 {
    -from_host(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO))
}

#[cfg(test)]
mod tests {
    #[test]
    fn mapping() {
        assert_eq!(super::from_host(libc::EAGAIN), 11);
        assert_eq!(super::from_host(libc::ENOENT), 2);
        assert_eq!(super::from_host(libc::ENOSYS), 38);
        assert_eq!(super::from_host(libc::ETIMEDOUT), 110);
    }
}
