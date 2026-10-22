//! End-to-end: run the x86-64 Linux binaries from tests/guest/bin through
//! `xrun` and check their output and exit status. Expected output of the
//! benchmark comes from the same C source compiled natively for arm64 macOS.

use std::path::PathBuf;
use std::process::{Command, Output};

fn guest(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/guest").join(name)
}

fn xrun(args: &[&str]) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_xrun"));
    c.arg("--clear-env").arg(guest(&format!("bin/{}", args[0]))).args(&args[1..]);
    c.output().expect("failed to start xrun")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn hello_raw_syscalls() {
    let o = xrun(&["hello_asm"]);
    assert_eq!(stdout(&o), "Hello from raw x86-64 syscalls!\n");
    assert_eq!(o.status.code(), Some(0));
}

#[test]
fn hello_musl_static() {
    let o = xrun(&["hello"]);
    assert_eq!(stdout(&o), "Hello, world!\n");
    assert_eq!(o.status.code(), Some(0));
}

#[test]
fn hello_static_pie() {
    let o = xrun(&["hello_pie"]);
    assert_eq!(stdout(&o), "Hello, world!\n");
    assert_eq!(o.status.code(), Some(0));
}

#[test]
fn exit_code() {
    assert_eq!(xrun(&["exit42"]).status.code(), Some(42));
}

#[test]
fn argv_envp_auxv() {
    let o = Command::new(env!("CARGO_BIN_EXE_xrun"))
        .arg(guest("bin/args"))
        .args(["one", "two words"])
        .env_clear()
        .env("XRUN_TEST", "yes")
        .output()
        .unwrap();
    assert_eq!(stdout(&o), "argc=3\nargv[1]=one\nargv[2]=two words\nXRUN_TEST=yes\npagesz=4096\nstack aligned=1\n");
    assert_eq!(o.status.code(), Some(3));
}

#[test]
fn bench_matches_native() {
    let o = xrun(&["bench"]);
    let want = std::fs::read_to_string(guest("expected/bench.out")).unwrap();
    assert_eq!(stdout(&o), want);
    assert_eq!(o.status.code(), Some(0));
}

#[test]
fn invalid_opcode_is_sigill() {
    let o = xrun(&["ud2"]);
    assert_eq!(o.status.code(), Some(128 + libc_sig::SIGILL));
    assert!(String::from_utf8_lossy(&o.stderr).contains("invalid opcode"));
}

#[test]
fn null_write_is_sigsegv() {
    let o = xrun(&["segv"]);
    assert_eq!(o.status.code(), Some(128 + libc_sig::SIGSEGV));
    assert!(String::from_utf8_lossy(&o.stderr).contains("0x0000000000000000"));
}

#[test]
fn missing_file() {
    let o = Command::new(env!("CARGO_BIN_EXE_xrun")).arg("/nonexistent").output().unwrap();
    assert_eq!(o.status.code(), Some(127));
}

mod libc_sig {
    pub const SIGILL: i32 = 4;
    pub const SIGSEGV: i32 = 11;
}
