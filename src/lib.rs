use anyhow::ensure;

pub struct SecretKey<'a> {
    buffer: &'a [u8],
}

impl<'a> TryFrom<&'a [u8]> for SecretKey<'a> {
    type Error = anyhow::Error;

    fn try_from(buffer: &'a [u8]) -> Result<Self, Self::Error> {
        let num_bytes = buffer.len();
        ensure!(
            num_bytes <= 255,
            "secret key length of {num_bytes} is too large"
        );
        Ok(Self { buffer })
    }
}

/*
 * This function should return a cipher text for a given key and plaintext
 *
 */
pub fn encode(key: SecretKey, plaintext: Vec<u8>) -> Vec<u8> {
    let mut ciphertext = Vec::new();
    ciphertext
}

/*
 * This function should return a plaintext for a given key and ciphertext
 *
 */
pub fn decode(key: SecretKey, ciphertext: Vec<u8>) -> Vec<u8> {
    let mut plaintext = Vec::new();
    plaintext
}
