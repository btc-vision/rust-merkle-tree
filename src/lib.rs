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

#[napi]
pub fn safe_init_rust() {
  INIT.call_once(|| {
    panic::set_hook(Box::new(|e| {
      log::error!("{}", e);
    }));

    Builder::new()
      .filter_level(LevelFilter::Error) // Set log level here
      .init();
  });
}
