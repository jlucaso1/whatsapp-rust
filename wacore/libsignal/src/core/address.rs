use std::fmt;

use uuid::Uuid;

#[derive(Clone, Copy, Hash, PartialEq, Eq, derive_more::TryFrom)]
#[try_from(repr)]
#[repr(u8)]
pub enum ServiceIdKind {
    Aci,
    Pni,
}

impl From<ServiceIdKind> for u8 {
    fn from(value: ServiceIdKind) -> Self {
        value as u8
    }
}

impl fmt::Display for ServiceIdKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceIdKind::Aci => f.write_str("ACI"),
            ServiceIdKind::Pni => f.write_str("PNI"),
        }
    }
}

impl fmt::Debug for ServiceIdKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WrongKindOfServiceIdError {
    pub expected: ServiceIdKind,
    pub actual: ServiceIdKind,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SpecificServiceId<const RAW_KIND: u8>(Uuid);

impl<const KIND: u8> SpecificServiceId<KIND> {
    #[inline]
    pub const fn from_uuid_bytes(bytes: [u8; 16]) -> Self {
        Self::from_uuid(uuid::Uuid::from_bytes(bytes))
    }

    #[inline]
    const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl<const KIND: u8> std::hash::Hash for SpecificServiceId<KIND> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(self.0.as_bytes());
    }
}

impl<const KIND: u8> SpecificServiceId<KIND>
where
    ServiceId: From<Self>,
    Self: TryFrom<ServiceId>,
{
    #[inline]
    pub fn service_id_binary(&self) -> Vec<u8> {
        ServiceId::from(*self).service_id_binary()
    }

    #[inline]
    pub fn service_id_fixed_width_binary(&self) -> ServiceIdFixedWidthBinaryBytes {
        ServiceId::from(*self).service_id_fixed_width_binary()
    }

    pub fn service_id_string(&self) -> String {
        ServiceId::from(*self).service_id_string()
    }

    #[inline]
    pub fn parse_from_service_id_binary(bytes: &[u8]) -> Option<Self> {
        ServiceId::parse_from_service_id_binary(bytes)?
            .try_into()
            .ok()
    }

    #[inline]
    pub fn parse_from_service_id_fixed_width_binary(
        bytes: &ServiceIdFixedWidthBinaryBytes,
    ) -> Option<Self> {
        ServiceId::parse_from_service_id_fixed_width_binary(bytes)?
            .try_into()
            .ok()
    }

    pub fn parse_from_service_id_string(input: &str) -> Option<Self> {
        ServiceId::parse_from_service_id_string(input)?
            .try_into()
            .ok()
    }
}

impl<const KIND: u8> From<Uuid> for SpecificServiceId<KIND> {
    #[inline]
    fn from(value: Uuid) -> Self {
        Self::from_uuid(value)
    }
}

impl<const KIND: u8> From<SpecificServiceId<KIND>> for Uuid {
    #[inline]
    fn from(value: SpecificServiceId<KIND>) -> Self {
        value.0
    }
}

impl<const KIND: u8> fmt::Debug for SpecificServiceId<KIND>
where
    ServiceId: From<Self>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        ServiceId::from(*self).fmt(f)
    }
}

pub type Aci = SpecificServiceId<{ ServiceIdKind::Aci as u8 }>;

pub type Pni = SpecificServiceId<{ ServiceIdKind::Pni as u8 }>;

pub type ServiceIdFixedWidthBinaryBytes = [u8; 17];

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, derive_more::From)]
pub enum ServiceId {
    Aci(Aci),
    Pni(Pni),
}

impl ServiceId {
    #[inline]
    pub fn kind(&self) -> ServiceIdKind {
        match self {
            ServiceId::Aci(_) => ServiceIdKind::Aci,
            ServiceId::Pni(_) => ServiceIdKind::Pni,
        }
    }

    #[inline]
    pub fn service_id_binary(&self) -> Vec<u8> {
        if let Self::Aci(aci) = self {
            aci.0.as_bytes().to_vec()
        } else {
            self.service_id_fixed_width_binary().to_vec()
        }
    }

    #[inline]
    pub fn service_id_fixed_width_binary(&self) -> ServiceIdFixedWidthBinaryBytes {
        let mut result = [0; 17];
        result[0] = self.kind().into();
        result[1..].copy_from_slice(self.raw_uuid().as_bytes());
        result
    }

    pub fn service_id_string(&self) -> String {
        if let Self::Aci(aci) = self {
            aci.0.to_string()
        } else {
            format!("{}:{}", self.kind(), self.raw_uuid())
        }
    }

    #[inline]
    pub fn parse_from_service_id_binary(bytes: &[u8]) -> Option<Self> {
        match bytes.len() {
            16 => Some(Self::Aci(Uuid::from_slice(bytes).ok()?.into())),
            17 => {
                let result = Self::parse_from_service_id_fixed_width_binary(
                    bytes.try_into().expect("already measured"),
                )?;
                if result.kind() == ServiceIdKind::Aci {
                    None
                } else {
                    Some(result)
                }
            }
            _ => None,
        }
    }

    #[inline]
    pub fn parse_from_service_id_fixed_width_binary(
        bytes: &ServiceIdFixedWidthBinaryBytes,
    ) -> Option<Self> {
        let uuid = Uuid::from_slice(&bytes[1..]).ok()?;
        match ServiceIdKind::try_from(bytes[0]).ok()? {
            ServiceIdKind::Aci => Some(Self::Aci(uuid.into())),
            ServiceIdKind::Pni => Some(Self::Pni(uuid.into())),
        }
    }

    pub fn parse_from_service_id_string(input: &str) -> Option<Self> {
        fn try_parse_hyphenated(input: &str) -> Option<Uuid> {
            if input.len() != uuid::fmt::Hyphenated::LENGTH {
                return None;
            }
            Uuid::try_parse(input).ok()
        }

        if let Some(uuid_string) = input.strip_prefix("PNI:") {
            let uuid = try_parse_hyphenated(uuid_string)?;
            Some(Self::Pni(uuid.into()))
        } else {
            let uuid = try_parse_hyphenated(input)?;
            Some(Self::Aci(uuid.into()))
        }
    }

    #[inline]
    pub fn raw_uuid(self) -> Uuid {
        match self {
            ServiceId::Aci(aci) => aci.into(),
            ServiceId::Pni(pni) => pni.into(),
        }
    }

    pub fn to_protocol_address(&self, device_id: DeviceId) -> ProtocolAddress {
        ProtocolAddress::new(self.service_id_string(), device_id)
    }
}

impl fmt::Debug for ServiceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{}:{}>", self.kind(), self.raw_uuid())
    }
}

impl<const KIND: u8> TryFrom<ServiceId> for SpecificServiceId<KIND> {
    type Error = WrongKindOfServiceIdError;

    #[inline]
    fn try_from(value: ServiceId) -> Result<Self, Self::Error> {
        if u8::from(value.kind()) == KIND {
            Ok(value.raw_uuid().into())
        } else {
            Err(WrongKindOfServiceIdError {
                expected: KIND
                    .try_into()
                    .expect("invalid kind, not covered in ServiceIdKind"),
                actual: value.kind(),
            })
        }
    }
}

impl<const KIND: u8> PartialEq<ServiceId> for SpecificServiceId<KIND>
where
    ServiceId: From<SpecificServiceId<KIND>>,
{
    fn eq(&self, other: &ServiceId) -> bool {
        ServiceId::from(*self) == *other
    }
}

impl<const KIND: u8> PartialEq<SpecificServiceId<KIND>> for ServiceId
where
    ServiceId: From<SpecificServiceId<KIND>>,
{
    fn eq(&self, other: &SpecificServiceId<KIND>) -> bool {
        *self == ServiceId::from(*other)
    }
}

#[derive(
    Copy, Clone, Debug, Hash, Eq, PartialEq, PartialOrd, Ord, derive_more::From, derive_more::Into,
)]
pub struct DeviceId(u32);

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct ProtocolAddress {
    name: String,
    device_id: DeviceId,
}

impl ProtocolAddress {
    pub fn new(name: String, device_id: DeviceId) -> Self {
        ProtocolAddress { name, device_id }
    }

    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[inline]
    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }
}

impl fmt::Display for ProtocolAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}", self.name, self.device_id)
    }
}
