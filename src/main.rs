use std::net::UdpSocket;

mod types;
use types::*;

/// DHCP Magic number to signal this is a DHCP packet
const DHCP_MAGIC: [u8; 4] = [99, 130, 83, 99];
/// The IP we bind to
const BIND_ADDR: &str = "192.168.10.1:67";
/// The size we give our empty buffers by default, code should truncate to correct size
const BUFFER_SIZE: usize = 1500; 
/// Our advertised IP Address in Packets
const SERVER_IP: [u8; 4] = [192, 168, 10, 1];
/// Our advertised IP Address in Packets
const SUBNET_MASK: [u8; 4] = [255, 255, 255, 0];
/// TFTP Server
const TFTP_ADDR: &str = "192.168.10.1";
/// TFTP Boot file
const TFTP_BOOT_FILE: &str = "stage0.flat";
/// Addresses Offered
const LEASE_TIME: u32 = 86400;
/// Addresses Offered
static mut LEASE_POOL: [([u8; 4], [u8; 6]); 4] = [
    ([192, 168, 10, 101], [0u8; 6]),
    ([192, 168, 10, 102], [0u8; 6]),
    ([192, 168, 10, 103], [0u8; 6]),
    ([192, 168, 10, 104], [0u8; 6]),
];

fn main(){
 
    let socket = UdpSocket::bind(BIND_ADDR).expect("Cannot bind");
    socket.set_broadcast(true).expect("Cannot set broadcast");

    let mut buf = [0; BUFFER_SIZE];

    loop {
        let (len, src) = socket.recv_from(&mut buf).unwrap();
        println!("Received {len} byte(s) from {src:?}");
        let now = unsafe { core::arch::x86_64::_rdtsc()}; 
        let dhcp = DHCP::parse(&buf, len);
        println!("Cycles: {}", unsafe{ core::arch::x86_64::_rdtsc() - now } );
        
        if let Some(dhcp) = dhcp {
            if dhcp.op != 1 {
                continue
            }
            //println!("{dhcp:?}");
            let mut buf = [0u8; BUFFER_SIZE];
            match dhcp.msg_type {
                // If request -> Lets acknowledge
                Some(MessageType::Request) => {
                    let len = dhcp.ack(&mut buf);
                    socket.send_to(&buf[0..len], "255.255.255.255:68").unwrap();
                }
                // If Discover -> Do Something
                Some(MessageType::Discover) => {
                    println!("Found DHCP Discover");
                    let len = dhcp.offer(&mut buf);
                    socket.send_to(&buf[0..len], "255.255.255.255:68").unwrap();
                }
                // If Inform -> Do Something
                Some(MessageType::Inform) => {
                    todo!("Not implemented inform yet");
                }
                _ => {todo!("We dont handle this yet")}
            };
        }
    }    
}

/// This struct holds all the state of a DHCP packet
/// 
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
    chaddr: [u8; 6],
    sname: [u8; 64],
    file: [u8; 128],
    magic: [u8; 4],
    msg_type: Option<MessageType>,
    options: [Option<Options<'a>>; 20],
    pxe_config: Pxe
}

impl<'a> DHCP<'a>{
    /// Read an incoming packet and parse out DHCP information if it is a DHCP packet
    /// 
    fn parse(payload: &'a [u8; BUFFER_SIZE], packet_len: usize) -> Option<Self> {
        // Not a valid DHCP request
        if packet_len < 240 {
            return None
        }
        let mut xid: [u8; 4] = [0; 4];
        let mut secs: [u8; 2] = [0; 2];
        let mut flags: [u8; 2] = [0; 2];
        let mut ciaddr: [u8; 4] = [0; 4];
        let mut yiaddr: [u8; 4] = [0; 4];
        let mut siaddr: [u8; 4] = [0; 4];
        let mut giaddr: [u8; 4] = [0; 4];
        let mut chaddr: [u8; 6] = [0; 6];
        let mut sname: [u8; 64] = [0; 64];
        let mut file: [u8; 128] = [0; 128];
        let mut magic: [u8; 4] = [0; 4];
        let mut msg_type = None;

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
        chaddr.copy_from_slice(&payload[28..34]);
        sname.copy_from_slice(&payload[44..108]);
        file.copy_from_slice(&payload[108..236]);
        magic.copy_from_slice(&payload[236..240]);

        // Not a valid DHCP request
        if magic != DHCP_MAGIC { return None }

        let mut pxe_config: Pxe = Default::default();

        let mut options_counter = 0;
        let mut options: [Option<Options>; 20] = [None; 20];
        let mut options_ptr = 240;
        loop {
            // If the PTR exceeds the len of the UDP Data break
            if options_ptr > packet_len { break }

            // End Option, break loop
            if payload[options_ptr] == 255 { break } 
            
            // Not enough space to have length in the option
            if options_ptr + 1 > packet_len { break }
            // Bounds check on Options Len

            let len = payload[options_ptr+1] as usize;
            if len > packet_len - options_ptr {
                println!("Option len is greater than packet");
                return None 
            }

            let res: Option<Options> = match &payload[options_ptr] {
                // Host name
                12 => {           
                    if let Ok(hostname) = 
                        core::str::from_utf8(&payload[options_ptr+2..options_ptr + 2 + len]){
                        Some(Options::HostName(hostname))
                    }else{
                        return None
                    }
                }
                // Requested IP Address
                50 => {
                    let mut ip_addr: [u8; 4] = [0u8; 4];
                    ip_addr.copy_from_slice(&payload[options_ptr+2..options_ptr+6]);
                    Some(Options::RequestedIPAddr(ip_addr))
                },
                // DHCP Message Type
                53 => { 
                    if let Some(m_type) = payload[options_ptr+2].try_into().ok(){
                        msg_type = Some(m_type);
                        Some(Options::MessageType(m_type))
                    }else{
                        return None
                    }
                },
                // DHCP Requested Parameters
                55 =>{
                    let mut params = [0u8; 50];
                    for (i, param) in payload[options_ptr+2 .. options_ptr+2+len].iter().enumerate(){
                        params[i] = *param;
                    } 
                    Some(Options::ParameterRequestList(params))
                },
                // Maximum DHCP Message Size
                57 => {
                    // Think this should only ever be 2 length
                    if len != 2 { return None }
                    let sz: u16 = (payload[options_ptr+2] as u16) << 8 | payload[options_ptr+3] as u16;
                    Some(Options::MaxDhcpMessageSize(sz))
                },
                // DHCP Server Identifier | Pfft we ignore this
                54 => { None }
                // Vendor class ID | Pfft we ignore this
                60 => { None }
                // Client Identifier (MAC)
                61 => {
                    let hardware_type = payload[options_ptr+2];
                    let mut client_mac: [u8; 6] = [0u8;6];
                    client_mac.copy_from_slice(&payload[options_ptr+3..options_ptr+9]);
    
                    Some(Options::ClientIdentifier(hardware_type, client_mac))
                },
                // Client System Arch (For PXE)
                93 => {
                    // Client ID is 16 bytes out of 17 of length
                    let arch_num: u16 = (payload[options_ptr+2] as u16) << 8 | payload[options_ptr+3] as u16; 
                    pxe_config.arch = arch_num.into();

                    None
                }   
                // Client Identifier (For PXE)
                94 => {
                    // Client ID is 16 bytes out of 17 of length
                    pxe_config.version = (
                        payload[options_ptr+2],
                        payload[options_ptr+3],
                        payload[options_ptr+4],
                    );
                    None
                }   
                // Client Identifier (For PXE)
                97 => {
                    // Client ID is 16 bytes out of 17 of length
                    pxe_config.client_id.copy_from_slice(&payload[options_ptr+2..options_ptr+2+len-1]);
                    None
                }
                unknown => { 
                    println!("We do not handle option {unknown}");
                    None
                },
            };
            // Add the parsed option
            if res.is_some(){
                options[options_counter] = res;
                // Increment the number of parsed options
                options_counter = options_counter+1;
            }
            // Options PTR increment and increment by len of DHCP Option + 1 as options len doesnt count itself
            options_ptr = options_ptr + 1 + payload[options_ptr+1] as usize + 1;
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
            msg_type,
            options,
            pxe_config,
        })
    }
    /// Creates an ACK response based on a DHCP Request
    fn ack(&self, buf: &mut [u8;BUFFER_SIZE]) -> usize {

        // Set the basic defaults
        self.baseline(buf);

        let options: &[Options] = &[
            Options::MessageType(MessageType::Ack),
            Options::ServerIP(SERVER_IP),
            Options::SubnetMask(SUBNET_MASK),
            Options::LeaseTime(LEASE_TIME), // 1 day
            Options::TftpServer(TFTP_ADDR),
            Options::BootFile(TFTP_BOOT_FILE),
            Options::End,
        ];

        // Start at 240 (After the magic bytes)
        let mut option_ptr = 240;
        // For every option we want
        for opt in options {
            // Allocate a buffer we can pass down to default evil rust!
            let mut tmp_buf = [0u8; 100];
            // Take the length so we can dynamically push on our option
            let len = opt.serialise(&mut tmp_buf);
            // Copy the option serialised into the UDP data
            buf[option_ptr .. option_ptr + len].copy_from_slice(&tmp_buf[..len]);
            // Increment the UDP data len
            option_ptr = option_ptr + len;
        }

        option_ptr
    }
    /// Creates an Offer response based on a DHCP Discover
    fn offer(&self, buf: &mut [u8;BUFFER_SIZE]) -> usize {

        // Set the basic defaults
        self.baseline(buf);
        
        let options: &[Options] = if self.pxe_config.arch == ClientArch::Unknown {
            &[
                Options::MessageType(MessageType::Offer),
                Options::ServerIP(SERVER_IP),
                Options::SubnetMask(SUBNET_MASK),
                Options::LeaseTime(LEASE_TIME), // 1 day
                Options::TftpServer(TFTP_ADDR),
                Options::BootFile(TFTP_BOOT_FILE),
                Options::End,
            ]
        }else{
            &[
                Options::MessageType(MessageType::Offer),
                Options::ServerIP(SERVER_IP),
                Options::SubnetMask(SUBNET_MASK),
                Options::LeaseTime(LEASE_TIME), // 1 day
                Options::TftpServer(TFTP_ADDR),
                Options::BootFile(TFTP_BOOT_FILE),
                Options::End,
                // &[93, 2, 0, 0], // PXE Client Arch
                // &[94, 3, 1, 2, 1], // PXE Version
                // &[97, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], // PXE Guid
            ]
        };

        // Start at 240 (After the magic bytes)
        let mut option_ptr = 240;
        // For every option we want
        for opt in options {
            // Allocate a buffer we can pass down to default evil rust!
            let mut tmp_buf = [0u8; 100];
            // Take the length so we can dynamically push on our option
            let len = opt.serialise(&mut tmp_buf);
            // Copy the option serialised into the UDP data
            buf[option_ptr .. option_ptr + len].copy_from_slice(&tmp_buf[..len]);
            // Increment the UDP data len
            option_ptr = option_ptr + len;
        }

        option_ptr
    }
    /// Manages our pool of IP addresses
    fn get_addr_from_pool(&self) -> Option<[u8; 4]> {
        for (ip, mac) in unsafe { &mut LEASE_POOL }{      
            if *mac == self.chaddr{
                return Some(*ip);
            }
        }
        for (ip, mac) in unsafe { &mut LEASE_POOL }{      
            if mac == &[0u8; 6]{
                *mac = self.chaddr;
                return Some(*ip);
            }
        }
        // Could not find a valid IP
        None
    }

    fn baseline(&self, buf: &mut [u8; BUFFER_SIZE]) {
        let ip_offered = self.get_addr_from_pool().expect("No available IPs");

        buf[0] = 0x2; // op
        buf[1] = 0x1; // hytpe
        buf[2] = 0x6; // hlen
        buf[3] = 0x0; // hops
        buf[4..8].copy_from_slice(&self.xid); // Client ID
        buf[8..10].copy_from_slice(&[0u8; 2]); // Seconds
        buf[10..12].copy_from_slice(&[0u8; 2]); // Bootp flags
        buf[12..16].copy_from_slice(&[0u8; 4]); // Client IP
        buf[16..20].copy_from_slice(&ip_offered); // Yiaddr
        buf[20..24].copy_from_slice(&[0u8; 4]); // Our Server IP
        buf[24..28].copy_from_slice(&[0u8; 4]); // Relay IP
        buf[28..34].copy_from_slice(&self.chaddr); // Requester MAC
        buf[44..108].copy_from_slice(&[0u8; 64]); // Unused
        buf[108..236].copy_from_slice(&[0u8; 128]); // Unused
        buf[236..240].copy_from_slice(&DHCP_MAGIC); // DHCP Magic bytes
    }
}