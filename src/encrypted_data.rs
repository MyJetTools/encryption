pub trait AesEncryptedData {
    fn as_slice(&self) -> &[u8];
}

pub struct AesEncryptedDataOwned {
    data: Vec<u8>,
}

impl AesEncryptedDataOwned {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn from_base_64(base64: &str) -> Result<Self, String> {
        use base64::Engine;
        let data = base64::engine::general_purpose::STANDARD.decode(base64.as_bytes());

        match data {
            Ok(data) => Ok(Self { data }),
            Err(err) => Err(format!("Can not decode base64: {}", err)),
        }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    pub fn as_base_64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(&self.data)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

impl AesEncryptedData for AesEncryptedDataOwned {
    fn as_slice(&self) -> &[u8] {
        &self.data
    }
}
