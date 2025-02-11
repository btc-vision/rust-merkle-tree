#![deny(clippy::all)]

#[macro_use]
extern crate napi_derive;

use env_logger::Builder;
use log::LevelFilter;
use std::panic;
use std::sync::Once;

mod application;
mod domain;
mod interfaces;

static INIT: Once = Once::new();

/// Safe initializer for the Rust side, hooking a panic logger.
/// We only call `INIT.call_once(...)` to ensure it’s done once.
#[napi]
pub fn safe_init_rust() {
    INIT.call_once(|| {
        panic::set_hook(Box::new(|e| {
            log::error!("Uncaught panic: {}", e);
        }));

        Builder::new().filter_level(LevelFilter::Error).init();
    });
}
