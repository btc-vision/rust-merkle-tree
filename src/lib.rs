#![deny(clippy::all)]

#[macro_use]
extern crate napi_derive;

use std::panic;

use itertools::Itertools;

mod application;
mod domain;
mod interfaces;

#[napi]
pub fn init() {
  panic::set_hook(Box::new(|_| {}));
}
