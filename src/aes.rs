use crate::encrypted_data::{AesEncryptedData, AesEncryptedDataOwned};

pub struct AesKey {
    pub key: [u8; 32],
    pub iv: [u8; 16],
}

impl AesKey {
    pub fn from_str(key: &str) -> AesKey {
        let mut key_48 = Vec::new();

        while key_48.len() < 48 {
            key_48.extend_from_slice(key.as_bytes());
        }

        if key_48.len() > 48 {
            key_48.truncate(48);
        }

        AesKey::new(&key_48)
    }
    pub fn new(key: &[u8]) -> AesKey {
        if key.len() != 48 {
            panic!("AesKey: key must be 48 bytes");
        }

        let mut aes_key = AesKey {
            key: [0; 32],
            iv: [0; 16],
        };
        aes_key.key.copy_from_slice(&key[..32]);
        aes_key.iv.copy_from_slice(&key[32..]);
        aes_key
    }

    pub fn get_cipher(&self) -> libaes::Cipher {
        libaes::Cipher::new_256(&self.key)
    }

    pub fn encrypt(&self, data: &[u8]) -> AesEncryptedDataOwned {
        let cipher = self.get_cipher();
        AesEncryptedDataOwned::new(cipher.cbc_encrypt(&self.iv, data))
    }

    pub fn decrypt(&self, data: &impl AesEncryptedData) -> Result<AesDecryptedData, String> {
        let cipher = self.get_cipher();

        let data_slice = data.as_slice();

        let result = std::panic::catch_unwind(|| cipher.cbc_decrypt(&self.iv, data_slice));
        match result {
            Ok(result) => {
                if result.is_empty() {
                    return Err("AesKey: decryption failed: empty result".to_string());
                }

                Ok(AesDecryptedData::new(result))
            }
            Err(err) => Err(format!("AesKey: decryption failed: {:?}", err)),
        }
    }
}

pub struct AesDecryptedData {
    data: Vec<u8>,
}

impl AesDecryptedData {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    pub fn into_string(self) -> String {
        String::from_utf8(self.data).unwrap()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

#[cfg(test)]
mod test {

    use crate::aes::AesEncryptedDataOwned;

    use super::AesKey;

    #[test]
    pub fn encrypt() {
        let my_key = b"This is the key!This is the key!This is 16 bytes";

        let plaintext = b"My Phrase";
        let key = AesKey::new(my_key);

        // Encryption
        let encrypted = key.encrypt(plaintext);

        // Decryption
        let decrypted = key.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted.into_bytes(), plaintext);
    }

    #[test]
    pub fn encrypt_with_error() {
        let my_key = b"This is the key!This is the key!This is 16 bytes";

        let plaintext = b"My Phrase";
        let key = AesKey::new(my_key);

        // Encryption
        let encrypted = key.encrypt(plaintext);

        let slice_encrypted = encrypted.as_slice()[..3].to_vec();

        // Decryption
        let decrypted = key.decrypt(&AesEncryptedDataOwned::new(slice_encrypted));

        assert!(decrypted.is_err());
    }

    #[test]
    pub fn encrypt_two_times_the_same_result() {
        let my_key = b"This is the key!This is the key!This is 16 bytes";

        let plaintext = b"My Phrase";
        let key = AesKey::new(my_key);

        // Encryption
        let encrypted1 = key.encrypt(plaintext);

        let encrypted2 = key.encrypt(plaintext);

        assert_eq!(encrypted1.as_base_64(), encrypted2.as_base_64());
    }
}
