#![allow(unused_imports)]

#[cfg(feature = "debug")]
pub(crate) mod log_impl {
    pub(crate) use ledger_device_sdk::log::{debug, error, info, trace, warn};
}

// NOTE: remove this when SDK fixes unused variable/imports warnings in log macros
#[cfg(not(feature = "debug"))]
pub(crate) mod log_impl {
    macro_rules! _dummy {
        ($fmt:literal $($arg:tt)*) => {{
            let _ = format_args!($fmt $($arg)*);
        }};
    }

    pub(crate) use _dummy as error;
    pub(crate) use _dummy as warn;
    pub(crate) use _dummy as info;
    pub(crate) use _dummy as debug;
    pub(crate) use _dummy as trace;
}

pub(crate) use log_impl::*;
