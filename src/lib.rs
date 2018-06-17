// Copyright 2017 Ethan Welker et al.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Provides Cidr and Inet support for [`postgres`][1].
//!
//! Unlike several other names of this pattern, this is not affiliated
//! with or supported by the [author][2] of [`postgres`][1].
//!
//! Please see the `examples/` folder in the crate root for a simple example.
//!
//! [1]: https://crates.io/crates/postgres
//! [2]: https://github.com/sfackler
#![doc(html_root_url = "https://docs.rs/postgres-inet/0.15.0")]
#![warn(missing_docs)]

#[cfg(feature = "ipnetwork")]
extern crate ipnetwork;

#[macro_use]
extern crate postgres;

extern crate byteorder;

mod tests;

use postgres::types::{self, FromSql, IsNull, ToSql, Type};
use std::error::Error;
use std::fmt;
use std::net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::ParseIntError;
use std::str::FromStr;

const IPV4_NETMASK_FULL: u8 = 32;
const IPV4_ADDRESS_FAMILY: u8 = 2; // Should be AF_INET; See Issue #1
const IPV4_ADDRESS_SIZE: u8 = 4;

const IPV6_NETMASK_FULL: u8 = 128;
// AF_INET + 1, not AF_INET6; see postgres src/include/utils/inet.h
const IPV6_ADDRESS_FAMILY: u8 = 3;
const IPV6_ADDRESS_SIZE: u8 = 16;

#[derive(Copy, Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
/// An IP address with a netmask.
pub struct MaskedIpAddr {
    addr: IpAddr,
    mask: u8,
}

impl MaskedIpAddr {
    /// Creates a new `MaskedIpAddr` from components.
    ///
    /// # Panics
    ///
    /// Panics if the netmask is greater than 32 for an [IPv4 address], or is
    /// greater than 128 for an [IPv6 address].
    ///
    /// [IPv4 address]: https://doc.rust-lang.org/std/net/enum.IpAddr.html#variant.V4
    /// [IPv6 address]: https://doc.rust-lang.org/std/net/enum.IpAddr.html#variant.V6
    ///
    /// # Examples
    ///
    /// To represent an address:
    ///
    /// ```rust
    /// # use postgres_inet::MaskedIpAddr;
    /// # use std::net::Ipv4Addr;
    /// let ip = Ipv4Addr::new(192, 0, 2, 142);
    /// MaskedIpAddr::new(ip, 32);
    /// ```
    ///
    /// To represent a network:
    ///
    /// ```rust
    /// # use postgres_inet::MaskedIpAddr;
    /// # use std::net::Ipv6Addr;
    /// let network = Ipv6Addr::new(0x2001, 0x0DB8, 0, 0, 0, 0, 0, 0);
    /// MaskedIpAddr::new(network, 32);
    /// ```
    pub fn new<I: Into<IpAddr>>(addr: I, mask: u8) -> MaskedIpAddr {
        let addr = addr.into();

        if match addr {
            IpAddr::V4(_) => mask > IPV4_NETMASK_FULL,
            IpAddr::V6(_) => mask > IPV6_NETMASK_FULL,
        } {
            panic!("Mask {} too big for {:?}!", mask, addr);
        }

        MaskedIpAddr { addr, mask }
    }

    /// Returns [`true`] for the special 'unspecified' address.
    ///
    /// See the documentation for [`Ipv4Addr::is_unspecified`][IPv4] and
    /// [`Ipv6Addr::is_unspecified`][IPv6] for more details.
    ///
    /// [`true`]: https://doc.rust-lang.org/std/primitive.bool.html
    /// [IPv4]: https://doc.rust-lang.org/std/net/struct.Ipv4Addr.html#method.is_unspecified
    /// [IPv6]: https://doc.rust-lang.org/std/net/struct.Ipv6Addr.html#method.is_unspecified
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use postgres_inet::MaskedIpAddr;
    /// # use std::net::{Ipv4Addr, Ipv6Addr};
    /// assert!(MaskedIpAddr::new(Ipv4Addr::new(0, 0, 0, 0), 32).is_unspecified());
    /// assert!(MaskedIpAddr::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 128).is_unspecified());
    /// ```
    pub fn is_unspecified(&self) -> bool {
        self.addr.is_unspecified()
    }

    /// Returns [`true`] if this is a loopback address.
    ///
    /// See the documentation for [`Ipv4Addr::is_loopback`][IPv4] and
    /// [`Ipv6Addr::is_loopback`][IPv6] for more details.
    ///
    /// [`true`]: https://doc.rust-lang.org/std/primitive.bool.html
    /// [IPv4]: https://doc.rust-lang.org/std/net/struct.Ipv4Addr.html#method.is_loopback
    /// [IPv6]: https://doc.rust-lang.org/std/net/struct.Ipv6Addr.html#method.is_loopback
    ///
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use postgres_inet::MaskedIpAddr;
    /// # use std::net::{Ipv4Addr, Ipv6Addr};
    /// assert!(MaskedIpAddr::new(Ipv4Addr::new(127, 0, 0, 1), 32).is_loopback());
    /// assert!(MaskedIpAddr::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 128).is_loopback());
    /// ```
    pub fn is_loopback(&self) -> bool {
        self.addr.is_loopback()
    }

    /// Returns [`true`] if this is a multicast address.
    ///
    /// See the documentation for [`Ipv4Addr::is_multicast`][IPv4] and
    /// [`Ipv6Addr::is_multicast`][IPv6] for more details.
    ///
    /// [`true`]: https://doc.rust-lang.org/std/primitive.bool.html
    /// [IPv4]: https://doc.rust-lang.org/std/net/struct.Ipv4Addr.html#method.is_multicast
    /// [IPv6]: https://doc.rust-lang.org/std/net/struct.Ipv6Addr.html#method.is_multicast
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use postgres_inet::MaskedIpAddr;
    /// # use std::net::{Ipv4Addr, Ipv6Addr};
    /// assert!(MaskedIpAddr::new(Ipv4Addr::new(224, 254, 0, 0), 32).is_multicast());
    /// assert!(MaskedIpAddr::new(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 128).is_multicast());
    /// ```
    pub fn is_multicast(&self) -> bool {
        self.addr.is_multicast()
    }

    /// Returns [`true`] if this address is an [IPv4 address], and [`false`] otherwise.
    ///
    /// [`true`]: https://doc.rust-lang.org/std/primitive.bool.html
    /// [`false`]: https://doc.rust-lang.org/std/primitive.bool.html
    /// [IPv4 address]: https://doc.rust-lang.org/std/net/enum.IpAddr.html#variant.V4
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use postgres_inet::MaskedIpAddr;
    /// # use std::net::{Ipv4Addr, Ipv6Addr};
    /// assert!(MaskedIpAddr::new(Ipv4Addr::new(203, 0, 113, 6), 32).is_ipv4());
    /// assert!(!MaskedIpAddr::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 128).is_ipv4());
    /// ```
    pub fn is_ipv4(&self) -> bool {
        self.addr.is_ipv4()
    }

    /// Returns [`true`] if this address is an [IPv6 address], and [`false`] otherwise.
    ///
    /// [`true`]: https://doc.rust-lang.org/std/primitive.bool.html
    /// [`false`]: https://doc.rust-lang.org/std/primitive.bool.html
    /// [IPv4 address]: https://doc.rust-lang.org/std/net/enum.IpAddr.html#variant.V6
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use postgres_inet::MaskedIpAddr;
    /// # use std::net::{Ipv4Addr, Ipv6Addr};
    /// assert!(!MaskedIpAddr::new(Ipv4Addr::new(203, 0, 113, 6), 32).is_ipv6());
    /// assert!(MaskedIpAddr::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 128).is_ipv6());
    /// ```
    pub fn is_ipv6(&self) -> bool {
        self.addr.is_ipv6()
    }

    /// Returns the contained [IP address].
    ///
    /// [IP address]: https://doc.rust-lang.org/std/net/enum.IpAddr.html
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use postgres_inet::MaskedIpAddr;
    /// # use std::net::{Ipv4Addr, Ipv6Addr};
    /// let ip = Ipv4Addr::new(192, 0, 2, 142);
    /// assert_eq!(MaskedIpAddr::new(ip, 32).address(), ip);
    /// let network = Ipv6Addr::new(0x2001, 0x0DB8, 0, 0, 0, 0, 0, 0);
    /// assert_eq!(MaskedIpAddr::new(network, 32).address(), network);
    /// ```
    pub fn address(&self) -> IpAddr {
        self.addr
    }

    /// Returns the contained netmask.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use postgres_inet::MaskedIpAddr;
    /// # use std::net::{Ipv4Addr, Ipv6Addr};
    /// assert_eq!(MaskedIpAddr::new(Ipv4Addr::new(192, 0, 2, 142), 32).netmask(), 32);
    /// assert_eq!(MaskedIpAddr::new(Ipv6Addr::new(0x2001, 0x0DB8, 0, 0, 0, 0, 0, 0), 64).netmask(), 64);
    /// ```
    pub fn netmask(&self) -> u8 {
        self.mask
    }

    /// Consumes the `MaskedIpAddr`, returning the IP address and netmask.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use postgres_inet::MaskedIpAddr;
    /// # use std::net::Ipv4Addr;
    /// let network = Ipv4Addr::new(198, 51, 100, 0);
    /// assert_eq!(MaskedIpAddr::new(network, 24).into_inner(), (network.into(), 24));
    /// ```
    pub fn into_inner(self) -> (IpAddr, u8) {
        (self.addr, self.mask)
    }
}

impl From<Ipv4Addr> for MaskedIpAddr {
    fn from(ipv4: Ipv4Addr) -> MaskedIpAddr {
        MaskedIpAddr {
            addr: IpAddr::V4(ipv4),
            mask: IPV4_NETMASK_FULL,
        }
    }
}

impl From<Ipv6Addr> for MaskedIpAddr {
    fn from(ipv6: Ipv6Addr) -> MaskedIpAddr {
        MaskedIpAddr {
            addr: IpAddr::V6(ipv6),
            mask: IPV6_NETMASK_FULL,
        }
    }
}

impl From<IpAddr> for MaskedIpAddr {
    fn from(ip: IpAddr) -> MaskedIpAddr {
        MaskedIpAddr {
            mask: match ip {
                IpAddr::V4(_) => IPV4_NETMASK_FULL,
                IpAddr::V6(_) => IPV6_NETMASK_FULL,
            },
            addr: ip,
        }
    }
}

impl From<MaskedIpAddr> for IpAddr {
    fn from(mip: MaskedIpAddr) -> IpAddr {
        mip.addr
    }
}

impl From<[u8; 4]> for MaskedIpAddr {
    fn from(octets: [u8; 4]) -> MaskedIpAddr {
        IpAddr::from(octets).into()
    }
}

impl From<[u8; 16]> for MaskedIpAddr {
    fn from(octets: [u8; 16]) -> MaskedIpAddr {
        IpAddr::from(octets).into()
    }
}

impl From<[u16; 8]> for MaskedIpAddr {
    fn from(segments: [u16; 8]) -> MaskedIpAddr {
        IpAddr::from(segments).into()
    }
}

#[cfg(feature = "ipnetwork")]
impl From<ipnetwork::IpNetwork> for MaskedIpAddr {
    fn from(ipnetwork: ipnetwork::IpNetwork) -> MaskedIpAddr {
        MaskedIpAddr::new(ipnetwork.ip(), ipnetwork.prefix())
    }
}

#[cfg(feature = "ipnetwork")]
impl From<MaskedIpAddr> for ipnetwork::IpNetwork {
    fn from(mip: MaskedIpAddr) -> ipnetwork::IpNetwork {
        // this conversion will never fail
        ipnetwork::IpNetwork::new(mip.address(), mip.netmask()).unwrap()
    }
}

impl fmt::Display for MaskedIpAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.addr {
            IpAddr::V4(ipv4) => match self.mask {
                IPV4_NETMASK_FULL => ipv4.fmt(f),
                _ => write!(f, "{}/{}", ipv4, self.mask),
            },
            IpAddr::V6(ipv6) => match self.mask {
                IPV6_NETMASK_FULL => ipv6.fmt(f),
                _ => write!(f, "{}/{}", ipv6, self.mask),
            },
        }
    }
}

impl fmt::Debug for MaskedIpAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.mask)
    }
}

impl FromSql for MaskedIpAddr {
    fn from_sql(_: &Type, raw: &[u8]) -> Result<Self, Box<Error + 'static + Sync + Send>> {
        // The address family is at raw[0], as AF_INET for ipv4 or (AF_INET + 1)
        // for ipv6.  It's unneeded, as `nb` at raw[3] tells us the version just as
        // well. A bool of the `cidr`ness is at raw[2]. It's also unneeded, as it
        // doesn't affect our codepath in any way whatsoever.

        Ok(MaskedIpAddr {
            addr: match raw[3] {
                IPV4_ADDRESS_SIZE => IpAddr::V4(Ipv4Addr::new(raw[4], raw[5], raw[6], raw[7])),
                IPV6_ADDRESS_SIZE => {
                    // The IPv6 is sent in network byte order, so we need to convert it to the host
                    // order.
                    use byteorder::{NetworkEndian, ReadBytesExt};
                    use std::io::Read;

                    let mut raw = raw;
                    raw.read_exact(&mut [0u8; 4])?; // throw away the first four bytes
                    IpAddr::V6(Ipv6Addr::new(
                        raw.read_u16::<NetworkEndian>()?,
                        raw.read_u16::<NetworkEndian>()?,
                        raw.read_u16::<NetworkEndian>()?,
                        raw.read_u16::<NetworkEndian>()?,
                        raw.read_u16::<NetworkEndian>()?,
                        raw.read_u16::<NetworkEndian>()?,
                        raw.read_u16::<NetworkEndian>()?,
                        raw.read_u16::<NetworkEndian>()?,
                    ))
                }
                _ => panic!("Unknown Internet Protocol Version!"),
            },
            mask: raw[1],
        })
    }

    fn accepts(ty: &Type) -> bool {
        match *ty {
            types::CIDR | types::INET => true,
            _ => false,
        }
    }
}

impl ToSql for MaskedIpAddr {
    fn to_sql(&self, ty: &Type, w: &mut Vec<u8>) -> Result<IsNull, Box<Error + Sync + Send>> {
        // We're relying on the optimizer to clean this up.

        w.push(match self.addr {
            // Address Family
            IpAddr::V4(_) => IPV4_ADDRESS_FAMILY,
            IpAddr::V6(_) => IPV6_ADDRESS_FAMILY,
        });
        w.push(self.mask); // Subnet mask
        w.push(match *ty {
            // cidr
            types::CIDR => true as u8,
            types::INET => false as u8,
            _ => unreachable!(),
        });
        w.push(match self.addr {
            IpAddr::V4(_) => IPV4_ADDRESS_SIZE,
            IpAddr::V6(_) => IPV6_ADDRESS_SIZE,
        });
        match self.addr {
            // Luckily, ipv6.octets() outputs in Network Byte Order.
            IpAddr::V4(ipv4) => w.extend_from_slice(&ipv4.octets()),
            IpAddr::V6(ipv6) => w.extend_from_slice(&ipv6.octets()),
        };

        Ok(IsNull::No)
    }

    accepts!(types::CIDR, types::INET);
    to_sql_checked!();
}

/// An error which can be returned when parsing a [`MaskedIpAddr`].
///
/// [`MaskedIpAddr`]: struct.MaskedIpAddr.html
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MaskedIpAddrParseError {
    /// An error occured in parsing the IP address
    Address(AddrParseError),
    /// An error occured in parsing the netmask
    Netmask(ParseIntError),
    /// An error occured elsewhere in parsing
    Format
}

impl fmt::Display for MaskedIpAddrParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            MaskedIpAddrParseError::Address(ref e) => e.fmt(f),
            MaskedIpAddrParseError::Netmask(ref e) => e.fmt(f),
            MaskedIpAddrParseError::Format => f.write_str(self.description()),
        }
    }
}

impl Error for MaskedIpAddrParseError {
    fn description(&self) -> &str {
        "invalid IP address/netmask syntax"
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            MaskedIpAddrParseError::Address(ref err) => Some(err),
            MaskedIpAddrParseError::Netmask(ref err) => Some(err),
            MaskedIpAddrParseError::Format => None,
        }
    }
}

impl From<AddrParseError> for MaskedIpAddrParseError {
    fn from(from: AddrParseError) -> MaskedIpAddrParseError {
        MaskedIpAddrParseError::Address(from)
    }
}

impl From<ParseIntError> for MaskedIpAddrParseError {
    fn from(from: ParseIntError) -> MaskedIpAddrParseError {
        MaskedIpAddrParseError::Netmask(from)
    }
}

impl FromStr for MaskedIpAddr {
    type Err = MaskedIpAddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('/').collect();
        match parts.len() {
            1 => Ok(IpAddr::from_str(parts[0])?.into()),
            2 => Ok(MaskedIpAddr::new(IpAddr::from_str(parts[0])?, parts[1].parse()?)),
            _ => Err(MaskedIpAddrParseError::Format)
        }
    }
}

