#[cfg(feature = "log_debug")]
use core::fmt::Write;
#[cfg(feature = "log_debug")]
use ledger_device_sdk::testing::debug_print;

#[cfg(feature = "log_debug")]
#[allow(clippy::upper_case_acronyms)]
pub struct DBG;

#[cfg(feature = "log_debug")]
impl Write for DBG {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        use arrayvec::ArrayString;
        // Dunno why the copy is required, might be some pic issue as this is going straight to
        // assembly.
        for c in s.chars() {
            let mut qq = ArrayString::<1>::new();
            qq.push(c);
            debug_print(qq.as_str());
        }
        Ok(())
    }
}

#[cfg(feature = "log_debug")]
macro_rules! _log {
    (target: $target:expr, $lvl:expr, $fmt:literal $($arg:tt)*) => ({
        use core::fmt::Write;
        let _ = core::write!($crate::log::DBG, concat!("{}:{}: ", $fmt, "\r\n"), core::file!(), core::line!() $($arg)*);
    });
    ($lvl:expr, $fmt:literal $($arg:tt)*) => (log!(target: __log_module_path!(), $lvl, $fmt $($arg)*))
}

#[cfg(feature = "log_debug")]
pub(crate) use _log as log;

#[cfg(feature = "log_debug")]
macro_rules! _debug {
    ($fmt:literal $($arg:tt)*) => ({use $crate::log::log; log!("DEBUG", $fmt $($arg)*)})
}

#[cfg(not(feature = "log_debug"))]
macro_rules! _debug {
    ($fmt:literal $($arg:tt)*) => {{}};
}

pub(crate) use _debug as debug;

#[cfg(feature = "log_debug")]
macro_rules! _info {
    ($fmt:literal $($arg:tt)*) => ({use $crate::log::log; log!("INFO", $fmt $($arg)*)})
}

#[cfg(not(feature = "log_debug"))]
macro_rules! _info {
    ($fmt:literal $($arg:tt)*) => {{}};
}

pub(crate) use _info as info;

#[cfg(feature = "log_debug")]
macro_rules! _error {
    ($fmt:literal $($arg:tt)*) => ({use $crate::log::log; log!("ERROR", $fmt $($arg)*)})
}

#[cfg(not(feature = "log_debug"))]
macro_rules! _error {
    ($fmt:literal $($arg:tt)*) => {{}};
}

pub(crate) use _error as error;
