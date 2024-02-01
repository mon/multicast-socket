use std::collections::{HashMap, HashSet};
use std::ffi::{c_int, CStr};
use std::io;
use std::iter::FromIterator;
use std::mem;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::windows::prelude::*;
use std::ptr;
use std::str::FromStr;

use socket2::{Domain, Protocol, Socket, Type};

use windows::core::{GUID, PSTR};
use windows::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
use windows::Win32::NetworkManagement::IpHelper::{GetAdaptersInfo, IP_ADAPTER_INFO};
use windows::Win32::Networking::WinSock::{
    self as sock, CMSGHDR, IN_ADDR, IN_ADDR_0, IN_PKTINFO, IPPROTO_IP, IP_PKTINFO, LPFN_WSARECVMSG,
    LPFN_WSASENDMSG, LPWSAOVERLAPPED_COMPLETION_ROUTINE, SIO_GET_EXTENSION_FUNCTION_POINTER,
    SOCKADDR, SOCKET, WSABUF, WSAID_WSARECVMSG, WSAMSG,
};
use windows::Win32::System::IO::OVERLAPPED;

// missing in windows-rs for some reason
const WSAID_WSASENDMSG: GUID = GUID::from_u128(0xa441e712_754f_43ca_84a7_0dee44cf606d);

fn last_error() -> io::Error {
    io::Error::from_raw_os_error(unsafe { sock::WSAGetLastError().0 })
}

unsafe fn setsockopt<T>(socket: RawSocket, opt: c_int, val: c_int, payload: T) -> io::Result<()>
where
    T: Copy,
{
    let payload = &payload as *const T as *const u8;
    let payload = std::slice::from_raw_parts(payload, mem::size_of::<T>());
    if sock::setsockopt(SOCKET(socket as _), opt, val, Some(payload)) == 0 {
        Ok(())
    } else {
        Err(last_error())
    }
}

type WSARecvMsgExtension = unsafe extern "system" fn(
    s: SOCKET,
    lpmsg: *mut WSAMSG,
    lpdwnumberofbytesrecvd: *mut u32,
    lpoverlapped: *mut OVERLAPPED,
    lpcompletionroutine: LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) -> i32;

fn locate_wsarecvmsg(socket: RawSocket) -> io::Result<WSARecvMsgExtension> {
    let mut fn_pointer: usize = 0;
    let mut byte_len: u32 = 0;

    let r = unsafe {
        sock::WSAIoctl(
            SOCKET(socket as _),
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            Some(&WSAID_WSARECVMSG as *const _ as *const _),
            mem::size_of_val(&WSAID_WSARECVMSG) as u32,
            Some(&mut fn_pointer as *const _ as *mut _),
            mem::size_of_val(&fn_pointer) as u32,
            &mut byte_len,
            None,
            None,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }

    if mem::size_of::<LPFN_WSARECVMSG>() != byte_len as _ {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Locating fn pointer to WSARecvMsg returned different expected bytes",
        ));
    }
    let cast_to_fn: LPFN_WSARECVMSG = unsafe { mem::transmute(fn_pointer) };

    match cast_to_fn {
        None => Err(io::Error::new(
            io::ErrorKind::Other,
            "WSARecvMsg extension not foud",
        )),
        Some(extension) => Ok(extension),
    }
}

type WSASendMsgExtension = unsafe extern "system" fn(
    s: SOCKET,
    lpMsg: *const WSAMSG,
    dwFlags: u32,
    lpNumberOfBytesSent: *mut u32,
    lpOverlapped: *mut OVERLAPPED,
    lpCompletionRoutine: LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) -> i32;

fn locate_wsasendmsg(socket: RawSocket) -> io::Result<WSASendMsgExtension> {
    let mut fn_pointer: usize = 0;
    let mut byte_len: u32 = 0;

    let r = unsafe {
        sock::WSAIoctl(
            SOCKET(socket as _),
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            Some(&WSAID_WSASENDMSG as *const _ as *const _),
            mem::size_of_val(&WSAID_WSASENDMSG) as u32,
            Some(&mut fn_pointer as *const _ as *mut _),
            mem::size_of_val(&fn_pointer) as u32,
            &mut byte_len,
            None,
            None,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }

    if mem::size_of::<LPFN_WSASENDMSG>() != byte_len as _ {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Locating fn pointer to WSASendMsg returned different expected bytes",
        ));
    }
    let cast_to_fn: LPFN_WSASENDMSG = unsafe { mem::transmute(fn_pointer) };

    match cast_to_fn {
        None => Err(io::Error::new(
            io::ErrorKind::Other,
            "WSASendMsg extension not foud",
        )),
        Some(extension) => Ok(extension),
    }
}

fn set_pktinfo(socket: RawSocket, payload: bool) -> io::Result<()> {
    unsafe { setsockopt(socket, IPPROTO_IP.0, IP_PKTINFO, payload as c_int) }
}

fn create_on_interfaces(
    options: crate::MulticastOptions,
    interfaces: Vec<Ipv4Addr>,
    multicast_address: SocketAddrV4,
) -> io::Result<MulticastSocket> {
    let socket = Socket::new(Domain::ipv4(), Type::dgram(), Some(Protocol::udp()))?;
    socket.set_read_timeout(options.read_timeout)?;
    socket.set_multicast_loop_v4(options.loopback)?;
    socket.set_reuse_address(true)?;

    // enable fetching interface information and locate the extension function
    set_pktinfo(socket.as_raw_socket(), true)?;
    let wsarecvmsg: WSARecvMsgExtension = locate_wsarecvmsg(socket.as_raw_socket())?;
    let wsasendmsg: WSASendMsgExtension = locate_wsasendmsg(socket.as_raw_socket())?;

    // Join multicast listeners on every interface passed
    for interface in &interfaces {
        socket.join_multicast_v4(multicast_address.ip(), interface)?;
    }

    // On Windows, unlike all Unix variants, it is improper to bind to the multicast address
    // see https://msdn.microsoft.com/en-us/library/windows/desktop/ms737550(v=vs.85).aspx
    socket.bind(&SocketAddr::new(options.bind_address.into(), multicast_address.port()).into())?;

    let interfaces = build_address_table(HashSet::from_iter(interfaces))?;

    Ok(MulticastSocket {
        socket,
        wsarecvmsg,
        wsasendmsg,
        interfaces,
        multicast_address,
        buffer_size: options.buffer_size,
    })
}

fn build_address_table(interfaces: HashSet<Ipv4Addr>) -> io::Result<HashMap<u32, Ipv4Addr>> {
    let mut size = 0u32;
    let r = unsafe { GetAdaptersInfo(None, &mut size) };
    if r != ERROR_BUFFER_OVERFLOW.0 {
        return Err(io::Error::last_os_error());
    }

    let mut buffer =
        vec![0; mem::size_of::<IP_ADAPTER_INFO>() * interfaces.len() * (size as usize)];
    let mut adapter_info = buffer.as_mut_ptr() as *mut IP_ADAPTER_INFO;
    let mut size = buffer.len() as u32;
    let r = unsafe { GetAdaptersInfo(Some(adapter_info), &mut size) };

    if r != 0 {
        return Err(io::Error::last_os_error());
    }

    let mut table = HashMap::with_capacity(interfaces.len());
    loop {
        if adapter_info.is_null() {
            break;
        }

        let current: IP_ADAPTER_INFO = unsafe { *adapter_info };
        let ip_address =
            unsafe { CStr::from_ptr(current.IpAddressList.IpAddress.String.as_ptr() as *const i8) }
                .to_str();
        let ip_address = match ip_address {
            Ok(i) => Ipv4Addr::from_str(i),
            _ => {
                continue;
            }
        };
        let ip_address = match ip_address {
            Ok(i) => i,
            _ => {
                continue;
            }
        };

        if interfaces.contains(&ip_address) {
            table.insert(current.Index, ip_address);
        }

        adapter_info = current.Next;
    }

    Ok(table)
}

pub struct MulticastSocket {
    socket: socket2::Socket,
    wsarecvmsg: WSARecvMsgExtension,
    wsasendmsg: WSASendMsgExtension,
    interfaces: HashMap<u32, Ipv4Addr>,
    multicast_address: SocketAddrV4,
    buffer_size: usize,
}

#[derive(Debug, Clone)]
pub enum Interface {
    Default,
    Ip(Ipv4Addr),
    Index(u32),
}

#[derive(Debug, Clone)]
pub struct Message {
    pub data: Vec<u8>,
    pub origin_address: SocketAddrV4,
    pub interface: Interface,
}

const CMSG_HEADER_SIZE: usize = mem::size_of::<CMSGHDR>();
const PKTINFO_DATA_SIZE: usize = mem::size_of::<IN_PKTINFO>();
const CONTROL_PKTINFO_BUFFER_SIZE: usize = CMSG_HEADER_SIZE + PKTINFO_DATA_SIZE;

pub fn all_ipv4_interfaces() -> io::Result<Vec<Ipv4Addr>> {
    let interfaces = get_if_addrs::get_if_addrs()?
        .into_iter()
        .filter_map(|i| match i.ip() {
            std::net::IpAddr::V4(v4) => Some(v4),
            _ => None,
        })
        .collect();
    Ok(interfaces)
}

impl MulticastSocket {
    pub fn all_interfaces(multicast_address: SocketAddrV4) -> io::Result<Self> {
        let interfaces = all_ipv4_interfaces()?;
        create_on_interfaces(Default::default(), interfaces, multicast_address)
    }

    pub fn with_options(
        multicast_address: SocketAddrV4,
        interfaces: Vec<Ipv4Addr>,
        options: crate::MulticastOptions,
    ) -> io::Result<Self> {
        create_on_interfaces(options, interfaces, multicast_address)
    }
}

impl MulticastSocket {
    pub fn receive(&self) -> io::Result<Message> {
        let mut data_buffer = vec![0; self.buffer_size];
        let mut data = WSABUF {
            buf: PSTR(data_buffer.as_mut_ptr()),
            len: data_buffer.len() as u32,
        };

        let mut control_buffer = [0; CONTROL_PKTINFO_BUFFER_SIZE];
        let control = WSABUF {
            buf: PSTR(control_buffer.as_mut_ptr()),
            len: control_buffer.len() as u32,
        };

        let mut origin_address: SOCKADDR = unsafe { mem::zeroed() };
        let mut wsa_msg = WSAMSG {
            name: &mut origin_address,
            namelen: mem::size_of_val(&origin_address) as i32,
            lpBuffers: &mut data,
            Control: control,
            dwBufferCount: 1,
            dwFlags: 0,
        };

        let mut read_bytes = 0;
        let r = {
            unsafe {
                (self.wsarecvmsg)(
                    SOCKET(self.socket.as_raw_socket() as _),
                    &mut wsa_msg,
                    &mut read_bytes,
                    ptr::null_mut(),
                    None,
                )
            }
        };

        if r != 0 {
            return Err(io::Error::last_os_error());
        }

        let origin_address = unsafe {
            socket2::SockAddr::from_raw_parts(
                &origin_address as *const _ as *const _,
                mem::size_of_val(&origin_address) as i32,
            )
        }
        .as_std();

        let origin_address = match origin_address {
            Some(SocketAddr::V4(v4)) => v4,
            _ => SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
        };

        let mut interface = Interface::Default;
        // Ensures that the control buffer is the size of the CSMG_HEADER + the pkinto data
        if control.len as usize == CONTROL_PKTINFO_BUFFER_SIZE {
            let cmsg_header: CMSGHDR =
                unsafe { ptr::read_unaligned(control.buf.as_ptr() as *const _) }; // TODO fix clippy warning without breaking the code
            if cmsg_header.cmsg_level == IPPROTO_IP.0 && cmsg_header.cmsg_type == IP_PKTINFO {
                let interface_info: IN_PKTINFO = unsafe {
                    ptr::read_unaligned(control.buf.as_ptr().add(CMSG_HEADER_SIZE) as *const _)
                }; // TODO fix clippy warning without breaking the code
                interface = Interface::Index(interface_info.ipi_ifindex);
            };
        };

        Ok(Message {
            data: data_buffer[0..read_bytes as _].to_vec(),
            origin_address,
            interface,
        })
    }

    pub fn send(&self, buf: &[u8], interface: &Interface) -> io::Result<usize> {
        let pkt_info = match interface {
            Interface::Default => None,
            Interface::Ip(address) => Some(IN_PKTINFO {
                ipi_addr: IN_ADDR {
                    S_un: to_s_addr(address),
                },
                ipi_ifindex: 0,
            }),
            Interface::Index(index) => self.interfaces.get(index).map(|address| IN_PKTINFO {
                ipi_addr: IN_ADDR {
                    S_un: to_s_addr(address),
                },
                ipi_ifindex: *index,
            }),
        };

        let mut data = WSABUF {
            buf: PSTR(buf.as_ptr() as *mut _),
            len: buf.len() as u32,
        };

        let mut control_buffer = [0; CONTROL_PKTINFO_BUFFER_SIZE];
        let control = if let Some(pkt_info) = pkt_info {
            let hdr = CMSGHDR {
                cmsg_len: CONTROL_PKTINFO_BUFFER_SIZE,
                cmsg_level: IPPROTO_IP.0,
                cmsg_type: IP_PKTINFO,
            };
            unsafe {
                ptr::copy(
                    &hdr as *const _ as *const _,
                    control_buffer.as_mut_ptr(),
                    CMSG_HEADER_SIZE,
                );
                ptr::copy(
                    &pkt_info as *const _ as *const _,
                    control_buffer.as_mut_ptr().add(CMSG_HEADER_SIZE),
                    PKTINFO_DATA_SIZE,
                )
            };
            WSABUF {
                buf: PSTR(control_buffer.as_mut_ptr()),
                len: control_buffer.len() as _,
            }
        } else {
            WSABUF {
                buf: PSTR([].as_mut_ptr()),
                len: 0,
            }
        };

        let destination = socket2::SockAddr::from(self.multicast_address);
        let destination_address = destination.as_ptr();
        let mut wsa_msg = WSAMSG {
            name: destination_address as *mut _,
            namelen: destination.len(),
            lpBuffers: &mut data,
            Control: control,
            dwBufferCount: 1,
            dwFlags: 0,
        };

        println!("{wsa_msg:?}");

        let mut sent_bytes = 0;
        let r = unsafe {
            (self.wsasendmsg)(
                SOCKET(self.socket.as_raw_socket() as _),
                &mut wsa_msg,
                0,
                &mut sent_bytes,
                ptr::null_mut(),
                None,
            )
        };
        if r != 0 {
            println!("fail here");
            return Err(io::Error::last_os_error());
        }

        Ok(sent_bytes as _)
    }

    pub fn broadcast(&self, buf: &[u8]) -> io::Result<()> {
        for interface in self.interfaces.values() {
            println!("{interface:?}");
            self.send(buf, &Interface::Ip(*interface))?;
        }
        Ok(())
    }
}

fn to_s_addr(addr: &Ipv4Addr) -> IN_ADDR_0 {
    let octets = addr.octets();
    let res = u32::from_ne_bytes(octets);
    let mut new_addr: IN_ADDR_0 = Default::default();
    new_addr.S_addr = res;
    new_addr
}
