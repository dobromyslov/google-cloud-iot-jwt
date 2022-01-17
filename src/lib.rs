#![cfg_attr(not(test), no_std)]

mod jwt_es256;

pub use jwt_es256::create_google_jwt_es256;
pub use jwt_es256::JWT_ES256_MAX_LENGTH;

#[cfg(test)]
mod readme_example_test;
