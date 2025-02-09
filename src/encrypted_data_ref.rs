use crate::encrypted_data::{AesEncryptedData, AesEncryptedDataOwned};

pub struct AesEncryptedDataRef<'s> {
    data: &'s [u8],
}

impl<'s> AesEncryptedDataRef<'s> {
    pub fn new(data: &'s [u8]) -> Self {
        Self { data }
    }

    pub fn to_vec(self) -> Vec<u8> {
        self.data.to_vec()
    }

    pub fn to_owned(self) -> AesEncryptedDataOwned {
        AesEncryptedDataOwned::new(self.data.to_vec())
    }

    pub fn as_base_64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(&self.data)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

impl AesEncryptedData for AesEncryptedDataRef<'_> {
    fn as_slice(&self) -> &[u8] {
        &self.data
    }
}
