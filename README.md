# google-cloud-iot-jwt
[![crates.io](https://img.shields.io/crates/v/google-cloud-iot-jwt.svg)](https://crates.io/crates/google-cloud-iot-jwt)
> Rust implementation of the [Google Cloud IOT Core JWT](https://cloud.google.com/iot/docs/how-tos/credentials/jwts) 
for embedded no_std heapless (no alloc) devices.

## Features
* [ES256 JWT signature](https://cloud.google.com/iot/docs/how-tos/credentials/jwts) - implements Elliptic Curves ES256 
signature as it needs less computational resources for generation,
and it's shorter than RSA RS256 signature.
* `no_std` compliant - the library and all its dependencies are [no_std](https://docs.rust-embedded.org/book/intro/no-std.html) compatible and can be freely used for Rust 
embedded applications.
* `heapless` (without `alloc`) compliant - the library and all its dependencies do not require heap memory allocation.
All calculations are preformed using stack fixed-size variables. Special thanks to 
[heapless](https://github.com/japaric/heapless) and [ufmt](https://github.com/japaric/ufmt) contributors.
* [RustCrypto](https://github.com/RustCrypto) - the library uses high quality cryptographic algorithms written in pure 
Rust.
* Low flash memory footprint - takes only 49.7 KB. See details below.

## Install

https://crates.io/crates/google-cloud-iot-jwt

```toml
# Cargo.toml
[dependencies]
google-cloud-iot-jwt = "0.1.1"
```

## Usage

1. Get the Google Cloud project name from the [console dashboard](https://console.cloud.google.com/home/dashboard).
2. Generate private key for ES256 signature in PEM sec1 format.
3. Get current unix timestamp in seconds (use Real-Time Clock hardware, NTP client, etc). The timestamp is +-10 minutes 
tolerant.
5. Create a JWT ES256 using the project name, the private key and the timestamp.
6. Use with Google Cloud IOT Core.

### Generate Elliptic Curve keys

Excerpts from the [official Google IOT Core documentation](https://cloud.google.com/iot/docs/how-tos/credentials/keys#generating_an_elliptic_curve_keys).

You can use the following commands to generate a P-256 Elliptic Curve key pair:
```
openssl ecparam -genkey -name prime256v1 -noout -out ec_private.pem
openssl ec -in ec_private.pem -pubout -out ec_public.pem
```

These commands create the following public/private key pair:
* `ec_private.pem`: The private key in sec1 PEM-string format that must be securely stored on the device and used to 
sign the authentication JWT.
* `ec_public.pem`: The public key that must be stored in Cloud IoT Core and used to verify the signature of the 
authentication JWT.

Open the `ec_private.pem` and use its contents to create a JWT.

### Generate ES256 JWT

```rust
#[cfg(test)]
mod test {
    use google_cloud_iot_jwt::create_google_jwt_es256;
    use google_cloud_iot_jwt::JWT_ES256_MAX_LENGTH;

    #[test]
    fn print_jwt() {
        // Project name from the Google Cloud Dashboard
        let project = "your_google_cloud_project_name";

        // Caution: Do not place the Private Key into your sources.
        // Flash it into your device separately and then load in your code from the flash or whatever else.
        let private_key = "\
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIDMvJjBfq3YVCHHeJj8pbsGITyhoHjkwg9o+3pLZkAAWoAoGCCqGSM49
AwEHoUQDQgAE5JHMOhIYK0AwPmvWXpRz2tU4OaC9A2+j8wTPDYmDLT1C3hV5ZeWr
iuPXSxsC6gVceKszCX/sJkcgQVXVkE3nOg==
-----END EC PRIVATE KEY-----
";
        // Get current Unix timestamp in seconds (e.g. Real Timer Clock, NTP client, etc)
        let timestamp = 1642293084;

        // Create JWT
        let jwt = create_google_jwt_es256(
            project,
            private_key,
            timestamp
        ).unwrap();

        println!("JWT = {}", jwt);
        println!("Actual JWT length = {}", jwt.len());
        println!("Max possible JWT length = {}", JWT_ES256_MAX_LENGTH);
    }
}
```

The generated JWT is valid
* since the specified `timestamp + 10 minutes` (Google time skew parameter) and
* till the specified `timestamp + 24 hours + 10 minutes`, 

thus you can store the JWT in the memory and use for 24 hours.

## Firmware size optimizations

Reached limits of your MCU flash size? No problem.

Set `opt-level = "z"` and reduce firmware size up to ~50% of the original.
```toml
# Cargo.toml

# See https://docs.rust-embedded.org/book/unsorted/speed-vs-size.html

[profile.dev.package.google-cloud-iot-jwt]
opt-level = "z"

# or even set z-level for all packages to optimize your debug firmware size
# [profile.dev.package."*"]
# opt-level = "z"

[profile.release]
opt-level = "z"
lto = true
panic = "abort"
debug = true
```


## Flash memory footprint
Tested in a firmware for [STM32F3Discovery](https://docs.rust-embedded.org/discovery/f3discovery/index.html):
* Build target `thumbv7em-none-eabihf`
* Release profile
    * opt-level = "z"
    * lto = true
    * panic = "abort"
    * debug = true

Compilation with google_cloud_iot_jwt::create_google_jwt_es256;
```
section               size        addr
.text                46132   0x8000194
.rodata               8580   0x800b5c8
Total = 54712 bytes
```

Compilation without google_cloud_iot_jwt::create_google_jwt_es256;
```
section               size        addr
.text                 3388   0x8000194
.rodata                432   0x8000ed0
Total = 3820 bytes
```

Flash memory footprint = 54712 - 3820 = 50892 bytes (49.7 KB)

## License

MIT (c) 2022 Viacheslav Dobromyslov <<viacheslav@dobromyslov.ru>>
