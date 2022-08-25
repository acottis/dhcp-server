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
    SubnetMask([u8; 4]),
    HostName(&'a str),
    RequestedIPAddr([u8; 4]),
    LeaseTime(u32),       
    MessageType(MessageType), 
    ServerIP([u8;4]),     
    ParameterRequestList([u8; 50]),
    MaxDhcpMessageSize(u16),
    ClientIdentifier(u8, [u8; 6]),
    TftpServer(&'a str), 
    BootFile(&'a str),
    ClientSystemArch(u16),
    ClientNetInterfaceIdent((u8,u8)),
    ClientMachineIdent(u8),
    TftpServerIP([u8; 4]),
    End,
}

impl Options<'_>{
    fn opcode(&self) -> u8{
        match self {
            Self::SubnetMask(_) => 1,
            Self::HostName(_) => 12,
            Self::RequestedIPAddr(_) => 50,
            Self::LeaseTime(_) => 51,     
            Self::MessageType(_) => 53, 
            Self::ServerIP(_) => 54,        
            Self::ParameterRequestList(_) => 55,
            Self::MaxDhcpMessageSize(_) => 57,
            Self::ClientIdentifier(_, _) => 61,
            Self::TftpServer(_) => 66,      
            Self::BootFile(_) => 67,      
            Self::ClientSystemArch(_) => 93,   
            Self::ClientNetInterfaceIdent(_) => 94,   
            Self::ClientMachineIdent(_) => 97,  
            Self::TftpServerIP(_) => 150,   
            Self::End => 255,
        }
    }
} 


impl Serialise for Options<'_>{
    fn serialise(&self, tmp_buf: &mut [u8; 100]) -> usize {
        tmp_buf[0] = self.opcode();
        match self {
            Self::MessageType(msg) => {
                let len: usize = 3;
                tmp_buf[1] = len as u8 - 2;
                tmp_buf[2] = *msg as u8;
                len
            },
            Self::ServerIP(addr) => {
                let len: usize = 6;
                tmp_buf[1] = len as u8 - 2;
                tmp_buf[2..6].copy_from_slice(addr);
                len
            },
            Self::TftpServer(addr) => {
                let len: usize = addr.len() + 2;
                tmp_buf[1] = addr.len() as u8;
                tmp_buf[2..2+addr.len()].copy_from_slice(addr.as_bytes());
                len
            },
            Self::BootFile(file_path) => {
                let len: usize = file_path.len() + 2;
                tmp_buf[1] = file_path.len() as u8;
                tmp_buf[2..2+file_path.len()].copy_from_slice(file_path.as_bytes());
                len
            },
            Self::LeaseTime(time) => {
                let len: usize = 6;
                tmp_buf[1] = len as u8 - 2;
                tmp_buf[2] = (time >> 24) as u8;
                tmp_buf[3] = (time >> 16) as u8;
                tmp_buf[4] = (time >> 8) as u8;
                tmp_buf[5] = *time as u8;
                len
            },
            Self::SubnetMask(addr) => {
                let len: usize = 6;
                tmp_buf[1] = len as u8 - 2;
                tmp_buf[2..6].copy_from_slice(addr);
                len
            },
            Self::ClientIdentifier(i, j) => {0},
            Self::ParameterRequestList(e) => {0},
            Self::MaxDhcpMessageSize(e) => {0},
            Self::RequestedIPAddr(e) => {0},
            Self::HostName(e) => {0},
            Self::ClientSystemArch(num) => {
                let len: usize = 4;
                tmp_buf[1] = len as u8 - 2;
                tmp_buf[2] = (num << 8) as u8;
                tmp_buf[3] = *num as u8;
                len
            },
            Self::ClientNetInterfaceIdent((major, minor)) => {
                let len: usize = 5;
                tmp_buf[1] = len as u8 - 2;
                tmp_buf[2] = 1;
                tmp_buf[3] = *major;
                tmp_buf[4] = *minor;
                len
            },
            Self::ClientMachineIdent(num) => {
                let len: usize = 19;
                tmp_buf[1] = len as u8 - 2;
                tmp_buf[2] = *num;
                len
            },
            Self::TftpServerIP(addr) => {
                let len: usize = 6;
                tmp_buf[1] = len as u8 - 2;
                tmp_buf[2..6].copy_from_slice(addr);
                len
            },
            Self::End => { 1 },
        }
    }
}

pub trait Serialise{
    fn serialise(&self, tmp_buf: &mut [u8; 100]) -> usize;
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