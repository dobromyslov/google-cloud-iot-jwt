#![cfg_attr(not(test), no_std)]

#[cfg(test)]
mod test {
    use crate::create_google_jwt_es256;
    use crate::JWT_ES256_MAX_LENGTH;

    #[test]
    fn print_jwt() {
        // Project name from the Google Cloud Dashboard
        let project = "your_google_cloud_project_name";

        // Caution: Do not place the Private Key into your sources.
        // Flash it into your device separately and then load in your code from the flash or
        // whatever else.
        // But it's ok do all simple for testing and rapid prototyping:)
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
        let jwt= create_google_jwt_es256(
            project,
            private_key,
            timestamp
        ).unwrap();

        println!("JWT = {}", jwt);
        println!("Actual JWT length = {}", jwt.len());
        println!("Max possible JWT length = {}", JWT_ES256_MAX_LENGTH);
    }
}
