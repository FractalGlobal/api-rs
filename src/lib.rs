//! Fractal Global Credits API.

// #![forbid(missing_docs, warnings)]
#![deny(deprecated, improper_ctypes, non_shorthand_field_patterns, overflowing_literals,
    plugin_as_library, private_no_mangle_fns, private_no_mangle_statics, stable_features,
    unconditional_recursion, unknown_lints, unused, unused_allocation, unused_attributes,
    unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(missing_docs, trivial_casts, trivial_numeric_casts, unused, unused_extern_crates,
    unused_import_braces, unused_qualifications, unused_results, variant_size_differences)]

extern crate hyper;
extern crate chrono;
extern crate rustc_serialize;
extern crate fractal_dto as dto;
extern crate fractal_utils as utils;

pub mod error;
pub mod types;
pub mod oauth;
pub mod v1;

pub use v1::Client;
