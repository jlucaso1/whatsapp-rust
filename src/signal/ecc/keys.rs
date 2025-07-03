pub const DJB_TYPE: u8 = 0x05;

// Corresponds to ECPublicKeyable
pub trait EcPublicKey: Send + Sync {
    fn serialize(&self) -> Vec<u8>;
    fn q_type(&self) -> u8;
    fn public_key(&self) -> [u8; 32];
}

// Corresponds to ECPrivateKeyable
pub trait EcPrivateKey: Send + Sync {
    fn serialize(&self) -> [u8; 32];
    fn q_type(&self) -> u8;
}

// Corresponds to DjbECPublicKey
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DjbEcPublicKey {
    public_key: [u8; 32],
}

impl DjbEcPublicKey {
    pub fn new(public_key: [u8; 32]) -> Self {
        Self { public_key }
    }
}

impl EcPublicKey for DjbEcPublicKey {
    fn serialize(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(33);
        v.push(DJB_TYPE);
        v.extend_from_slice(&self.public_key);
        v
    }

    fn q_type(&self) -> u8 {
        DJB_TYPE
    }

    fn public_key(&self) -> [u8; 32] {
        self.public_key
    }
}

// Corresponds to DjbECPrivateKey
#[derive(Clone)]
pub struct DjbEcPrivateKey {
    private_key: [u8; 32],
}

impl DjbEcPrivateKey {
    pub fn new(private_key: [u8; 32]) -> Self {
        Self { private_key }
    }
}

impl EcPrivateKey for DjbEcPrivateKey {
    fn serialize(&self) -> [u8; 32] {
        self.private_key
    }

    fn q_type(&self) -> u8 {
        DJB_TYPE
    }
}
