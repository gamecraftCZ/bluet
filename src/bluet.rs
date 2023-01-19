use env_logger;
use log::info;

#[macro_use]
extern crate lazy_static;

mod common;
mod parser;
mod consts;

// BlueT command line utility
fn main() {
    env_logger::init();

    info!("Logger setup done.");

    println!("Hello, world!");
    println!("TODO me!");
}
