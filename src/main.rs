use std::net::UdpSocket;

/// DHCP Magic number to signal this is a DHCP packet
static DHCP_MAGIC: [u8; 4] = [99, 130, 83, 99];

fn main(){
 
    let socket = UdpSocket::bind("0.0.0.0:67").unwrap();

    let mut buf = [0; 1500];

    loop {
        let (len, src) = socket.recv_from(&mut buf).unwrap();
        println!("Received {len} byte(s) from {src:?}");
        let now = unsafe { core::arch::x86_64::_rdtsc()}; 
        let dhcp = DHCP::parse(&buf, len);
        println!("Cycles: {}", unsafe{ core::arch::x86_64::_rdtsc() } - now);
        println!("{dhcp:?}");
    }    
}

#[allow(dead_code)]
#[derive(Debug)]
struct DHCP<'a>{
    op: u8,
    htype: u8,
    hlen: u8,
    hops: u8,
    xid: [u8;4],
    secs: [u8; 2],
    flags: [u8; 2],
    ciaddr: [u8; 4], 
    yiaddr: [u8; 4],
    siaddr: [u8; 4], 
    giaddr: [u8; 4], 
    chaddr: [u8; 16],
    sname: [u8; 64],
    file: [u8; 128],
    magic: [u8; 4],
    options: [Option<DhcpOption<'a>>; 10],
}

impl<'a> DHCP<'a>{
    fn parse(payload: &'a [u8; 1500], len: usize) -> Option<Self> {
        
        // Not a valid DHCP request
        if len < 240 {
            return None
        }

        let mut xid: [u8; 4] = [0; 4];
        let mut secs: [u8; 2] = [0; 2];
        let mut flags: [u8; 2] = [0; 2];
        let mut ciaddr: [u8; 4] = [0; 4];
        let mut yiaddr: [u8; 4] = [0; 4];
        let mut siaddr: [u8; 4] = [0; 4];
        let mut giaddr: [u8; 4] = [0; 4];
        let mut chaddr: [u8; 16] = [0; 16];
        let mut sname: [u8; 64] = [0; 64];
        let mut file: [u8; 128] = [0; 128];
        let mut magic: [u8; 4] = [0; 4];

        let op = payload[0];
        let htype = payload[1];
        let hlen = payload[2];
        let hops = payload[3];
        xid.copy_from_slice(&payload[4..8]);
        secs.copy_from_slice(&payload[8..10]);
        flags.copy_from_slice(&payload[10..12]);
        ciaddr.copy_from_slice(&payload[12..16]);
        yiaddr.copy_from_slice(&payload[16..20]);
        siaddr.copy_from_slice(&payload[20..24]);
        giaddr.copy_from_slice(&payload[24..28]);
        chaddr.copy_from_slice(&payload[28..44]);
        sname.copy_from_slice(&payload[44..108]);
        file.copy_from_slice(&payload[108..236]);
        magic.copy_from_slice(&payload[236..240]);

        // Not a valid DHCP request
        if magic != DHCP_MAGIC { return None }

        let mut options_counter = 0;
        let mut options: [Option<DhcpOption>; 10] = [None; 10];
        let mut options_ptr = 240;
        loop {
            if options_ptr >= len { break }
            
            let res: (Option<DhcpOption>, usize) = match &payload[options_ptr] {
                // Host name
                12 => {
                    let len: usize = payload[options_ptr+1] as usize; 
                    
                    if let Ok(hostname) = core::str::from_utf8(&payload[options_ptr+2..options_ptr + 2 + len]){
                        (
                            Some(DhcpOption::HostName(hostname)),
                            len
                        )
                    }else{
                        return None
                    }
                }
                // Requested IP Address
                50 => {
                    let mut ip_addr: [u8; 4] = [0u8; 4];
                    ip_addr.copy_from_slice(&payload[options_ptr+2..options_ptr+6]);
                    (
                        Some(DhcpOption::RequestedIPAddr(ip_addr)),
                        payload[options_ptr+1] as usize
                    )
                },
                // DHCP Message Type
                53 => { 
                    if let Some(msg_type) = payload[options_ptr+2].try_into().ok(){
                        (
                            Some(DhcpOption::MessageType(msg_type)),
                            payload[options_ptr+1] as usize
                        )
                    }else{
                        return None
                    }
                },
                // DHCP Requested Parameters
                55 =>{
                    let len: usize = payload[options_ptr+1] as usize;
                    let mut params = [0u8; 50];
                    for (i, param) in payload[options_ptr+2 .. options_ptr+2+len].iter().enumerate(){
                        params[i] = *param;
                    } 
                    (
                        Some(DhcpOption::ParameterRequestList(params)), 
                        len
                    )
                },
                // Maximum DHCP Message Size
                57 => {
                    let len: usize = payload[options_ptr+1] as usize;
                    // Think this should only ever be 2 length
                    if len != 2 { return None }
                    let sz: u16 = (payload[options_ptr+2] as u16) << 8 | payload[options_ptr+3] as u16;
                    (
                        Some(DhcpOption::MaxDhcpMessageSize(sz)),
                        len
                    )
                },
                // Client Identifier (MAC)
                61 => {
                    let hardware_type = payload[options_ptr+2];
                    let mut client_mac :[u8; 6] = [0u8;6];
                    client_mac.copy_from_slice(&payload[options_ptr+3..options_ptr+9]);
                    (
                        Some(DhcpOption::ClientIdentifier(hardware_type, client_mac)),
                        payload[options_ptr+1] as usize,
                    )
                },
                // End option
                255 => { break }
                unknown => { 
                    println!("We do not handle option {unknown}");
                    (None, payload[options_ptr+1] as usize)
                },
            };
            // Add the parsed option
            options[options_counter] = res.0;
            // Increment the number of parsed options
            options_counter = options_counter+1;
            // Array increment + options len + 1 as options len doesnt count itself
            options_ptr = options_ptr + 1 + res.1 + 1;
        }

        Some( Self {
            op,
            htype,
            hlen,
            hops,
            xid,
            secs,
            flags,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr,
            sname,
            file,
            magic,
            options,
        })
    }
}

#[derive(Clone, Copy, Debug)]
enum DhcpOption<'a> {
    MessageType(MessageType),
    ClientIdentifier(u8, [u8; 6]),
    ParameterRequestList([u8; 50]),
    MaxDhcpMessageSize(u16),
    RequestedIPAddr([u8; 4]),
    HostName(&'a str)
}

#[derive(Clone, Copy, Debug)]
enum MessageType {
    Discover    = 1,
    Offer       = 2,
    Request     = 3,
    Ack         = 4,
    Nak         = 5,
    Decline     = 6,
    Release     = 7,
    Inform      = 8,
}

impl TryFrom<u8> for MessageType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => { Ok(Self::Discover) },
            2 => { Ok(Self::Offer) },
            3 => { Ok(Self::Request) },
            4 => { Ok(Self::Decline) },
            5 => { Ok(Self::Ack) },
            6 => { Ok(Self::Nak) },
            7 => { Ok(Self::Release) },
            8 => { Ok(Self::Inform) },
            e => { 
                println!("We do not handle MessageType: {e} yet");
                Err(())
            }
        }
    }
}

// #[macro_export]
// macro_rules! consume {
//     (&$buf:expr, $typ:ty) => {{
//         println!("{}", core::mem::size_of::<$typ>());
//         [0u8; 1]
//     }}
// }