pub type Result<T> = std::result::Result<T, Error>;

pub enum Error{
    InvalidMessageType(u8),
    InvalidArchitectureType(u8),
}


#[derive(Debug, Default)]
pub struct Pxe{
    pub client_id: [u8; 16],
    pub arch: ClientArch,
    pub version: (u8, u8, u8),
}

#[derive(Debug, PartialEq)]
pub enum ClientArch{
    IntelX86,
    NECPC98,
    EFIItanium,
    DECAlpha,
    ArcX86,
    IntelLeanClient,
    EFIIA32,
    EFIBC,
    EFIXscale,
    EFIX8664,
    Unknown,
}

impl Default for ClientArch{
    fn default() -> Self {
        Self::Unknown
    }
}

impl From<u16> for ClientArch{
    fn from(value: u16) -> Self {
        match value {
            0 => Self::IntelX86,
            1 => Self::NECPC98,
            2 => Self::EFIItanium,
            3 => Self::DECAlpha,
            4 => Self::ArcX86,
            5 => Self::IntelLeanClient,
            6 => Self::EFIIA32,
            7 => Self::EFIBC,
            8 => Self::EFIXscale,
            9 => Self::EFIX8664,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Options<'a> {
    MessageType(MessageType),
    ClientIdentifier(u8, [u8; 6]),
    ParameterRequestList([u8; 50]),
    MaxDhcpMessageSize(u16),
    RequestedIPAddr([u8; 4]),
    HostName(&'a str)
}

#[derive(Clone, Copy, Debug)]
pub enum MessageType {
    Discover    = 1,
    Offer       = 2,
    Request     = 3,
    Decline     = 4,
    Ack         = 5,
    Nak         = 6,
    Release     = 7,
    Inform      = 8,
}

impl TryFrom<u8> for MessageType {
    type Error = Error;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            1 => { Ok(Self::Discover) },
            2 => { Ok(Self::Offer) },
            3 => { Ok(Self::Request) },
            4 => { Ok(Self::Decline) },
            5 => { Ok(Self::Ack) },
            6 => { Ok(Self::Nak) },
            7 => { Ok(Self::Release) },
            8 => { Ok(Self::Inform) },
            t => { Err(Error::InvalidMessageType(t))}
        }
    }
}