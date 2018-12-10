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

#![cfg(test)]
#![allow(unused_results)]

use super::*;
use postgres::{Connection, TlsMode};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn _db() -> Connection {
    let conn = Connection::connect("postgres://postgres@localhost", TlsMode::None).unwrap();
    conn.execute(
        "CREATE TEMPORARY TABLE foo (id SERIAL PRIMARY KEY, cidr CIDR, inet INET)",
        &[],
    )
    .unwrap();
    conn
}

fn _new_full_ipv4() -> (MaskedIpAddr, IpAddr, u8) {
    let expected = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0));
    let cidr = IPV4_CIDR_FULL;

    (MaskedIpAddr::new(expected, cidr), expected, cidr)
}

fn _new_full_ipv6() -> (MaskedIpAddr, IpAddr, u8) {
    let expected = IpAddr::V6(Ipv6Addr::new(0x2001, 0xDB8, 0, 0, 0, 0, 0, 0));
    let cidr = IPV6_CIDR_FULL;

    (MaskedIpAddr::new(expected, cidr), expected, cidr)
}

fn _new_masked_ipv4() -> (MaskedIpAddr, IpAddr, u8) {
    let expected = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0));
    let cidr = 24;

    (MaskedIpAddr::new(expected, cidr), expected, cidr)
}

fn _new_masked_ipv6() -> (MaskedIpAddr, IpAddr, u8) {
    let expected = IpAddr::V6(Ipv6Addr::new(0x2001, 0xDB8, 0, 0, 0, 0, 0, 0));
    let cidr = 48;

    (MaskedIpAddr::new(expected, cidr), expected, cidr)
}

#[test]
fn new_full_ipv4() {
    let (mip, expected, cidr) = _new_full_ipv4();
    assert_eq!(mip.addr, expected);
    assert_eq!(mip.cidr, cidr);
}

#[test]
fn new_full_ipv6() {
    let (mip, expected, cidr) = _new_full_ipv6();
    assert_eq!(mip.addr, expected);
    assert_eq!(mip.cidr, cidr);
}

#[test]
fn new_masked_ipv4() {
    let (mip, expected, cidr) = _new_masked_ipv4();
    assert_eq!(mip.addr, expected);
    assert_eq!(mip.cidr, cidr);
}

#[test]
fn new_masked_ipv6() {
    let (mip, expected, cidr) = _new_masked_ipv6();
    assert_eq!(mip.addr, expected);
    assert_eq!(mip.cidr, cidr);
}

#[test]
#[should_panic]
fn new_overfull_ipv4() {
    MaskedIpAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 0x7F);
}

#[test]
#[should_panic]
fn new_overfull_ipv6() {
    MaskedIpAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xDB8, 0, 0, 0, 0, 0, 0)),
        0xFF,
    );
}

#[test]
fn is_unspec_ipv4() {
    let mip = MaskedIpAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), IPV4_CIDR_FULL);
    assert!(mip.is_unspecified());
}

#[test]
fn is_unspec_ipv6() {
    let mip = MaskedIpAddr::new(
        IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
        IPV6_CIDR_FULL,
    );
    assert!(mip.is_unspecified());
}

#[test]
fn is_unspec_ipv4_false() {
    let (mip, _, _) = _new_full_ipv4();
    assert!(!mip.is_unspecified());
}

#[test]
fn is_unspec_ipv6_false() {
    let (mip, _, _) = _new_full_ipv6();
    assert!(!mip.is_unspecified());
}

#[test]
fn is_loop_ipv4() {
    let mip = MaskedIpAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), IPV4_CIDR_FULL);
    assert!(mip.is_loopback());
}

#[test]
fn is_loop_ipv6() {
    let mip = MaskedIpAddr::new(
        IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
        IPV6_CIDR_FULL,
    );
    assert!(mip.is_loopback());
}

#[test]
fn is_loop_ipv4_false() {
    let (mip, _, _) = _new_full_ipv4();
    assert!(!mip.is_loopback());
}

#[test]
fn is_loop_ipv6_false() {
    let (mip, _, _) = _new_full_ipv6();
    assert!(!mip.is_loopback());
}

#[test]
fn is_multi_ipv4() {
    let mip = MaskedIpAddr::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 0)), IPV4_CIDR_FULL);
    assert!(mip.is_multicast());
}

#[test]
fn is_multi_ipv6() {
    let mip = MaskedIpAddr::new(
        IpAddr::V6(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0)),
        IPV6_CIDR_FULL,
    );
    assert!(mip.is_multicast());
}

#[test]
fn is_multi_ipv4_false() {
    let (mip, _, _) = _new_full_ipv4();
    assert!(!mip.is_multicast());
}

#[test]
fn is_multi_ipv6_false() {
    let (mip, _, _) = _new_full_ipv6();
    assert!(!mip.is_multicast());
}

#[test]
fn is_ipv4_ipv4() {
    let (mip, _, _) = _new_full_ipv4();
    assert!(mip.is_ipv4());
}

#[test]
fn is_ipv4_ipv6() {
    let (mip, _, _) = _new_full_ipv6();
    assert!(!mip.is_ipv4());
}

#[test]
fn is_ipv6_ipv4() {
    let (mip, _, _) = _new_full_ipv4();
    assert!(!mip.is_ipv6());
}

#[test]
fn is_ipv6_ipv6() {
    let (mip, _, _) = _new_full_ipv6();
    assert!(mip.is_ipv6());
}

#[test]
fn address_ipv4() {
    let (mip, expected, _) = _new_full_ipv4();
    assert_eq!(mip.address(), expected);
}

#[test]
fn address_ipv6() {
    let (mip, expected, _) = _new_full_ipv6();
    assert_eq!(mip.address(), expected);
}

#[test]
fn cidr_ipv4() {
    let (mip, _, cidr) = _new_full_ipv4();
    assert_eq!(mip.cidr(), cidr);
}

#[test]
fn cidr_ipv6() {
    let (mip, _, cidr) = _new_full_ipv6();
    assert_eq!(mip.cidr(), cidr);
}

#[test]
#[allow(deprecated)]
fn netmask_ipv4() {
    let (mip, _, cidr) = _new_full_ipv4();
    assert_eq!(mip.netmask(), cidr);
}

#[test]
#[allow(deprecated)]
fn netmask_ipv6() {
    let (mip, _, cidr) = _new_full_ipv6();
    assert_eq!(mip.netmask(), cidr);
}

#[test]
fn subnet_mask_v4() {
    let (mip, _, _) = _new_masked_ipv4();
    assert_eq!(mip.subnet_mask(), 0xffffff00);
}

#[test]
fn subnet_mask_v6() {
    let (mip, _, _) = _new_masked_ipv6();
    assert_eq!(mip.subnet_mask(), 0xffffffffffff00000000000000000000);
}

#[test]
fn into_inner_ipv4() {
    let (mip, expected, cidr) = _new_full_ipv4();
    assert_eq!(mip.into_inner(), (expected, cidr));
}

#[test]
fn into_inner_ipv6() {
    let (mip, expected, cidr) = _new_full_ipv6();
    assert_eq!(mip.into_inner(), (expected, cidr));
}

#[test]
fn new_from_ipv4() {
    let ipv4 = Ipv4Addr::new(198, 51, 100, 255);
    let cidr = IPV4_CIDR_FULL;

    assert_eq!(
        MaskedIpAddr::new(ipv4, cidr).into_inner(),
        (ipv4.into(), cidr)
    );
}

#[test]
fn from_ipv4_to_mip() {
    let ipv4 = Ipv4Addr::new(198, 51, 100, 255);
    assert_eq!(
        MaskedIpAddr::from(ipv4).into_inner(),
        (ipv4.into(), IPV4_CIDR_FULL)
    );
}

#[test]
fn new_from_ipv6() {
    let ipv6 = Ipv6Addr::new(0x2001, 0xDB8, 0, 0, 0, 0, 0, 0);
    let cidr = IPV6_CIDR_FULL;

    assert_eq!(
        MaskedIpAddr::new(ipv6, cidr).into_inner(),
        (ipv6.into(), cidr)
    );
}

#[test]
fn from_ipv6_to_mip() {
    let ipv6 = Ipv6Addr::new(0x2001, 0xDB8, 0, 0, 0, 0, 0, 0);
    assert_eq!(
        MaskedIpAddr::from(ipv6).into_inner(),
        (ipv6.into(), IPV6_CIDR_FULL)
    );
}

#[test]
fn new_from_ip() {
    let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 128));
    let cidr = IPV4_CIDR_FULL;

    assert_eq!(MaskedIpAddr::new(ip, cidr).into_inner(), (ip, cidr));
}

#[test]
fn from_ip_to_mip() {
    let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xDB8, 0, 0, 0, 0, 0, 0));
    assert_eq!(MaskedIpAddr::from(ip).into_inner(), (ip, IPV6_CIDR_FULL));
}

#[test]
#[cfg(feature = "ipnetwork")]
fn from_ipnetwork_to_mip_ipv4() {
    let (mip, ip, cidr) = _new_full_ipv4();
    let ipn = ipnetwork::IpNetwork::new(ip, cidr).unwrap();

    assert_eq!(mip, MaskedIpAddr::from(ipn));
}

#[test]
#[cfg(feature = "ipnetwork")]
fn from_ipnetwork_to_mip_ipv6() {
    let (mip, ip, cidr) = _new_full_ipv6();
    let ipn = ipnetwork::IpNetwork::new(ip, cidr).unwrap();

    assert_eq!(mip, MaskedIpAddr::from(ipn));
}

#[test]
#[cfg(feature = "ipnetwork")]
fn from_mip_to_ipnetwork_ipv4() {
    let (mip, expected, cidr) = _new_full_ipv4();
    let ipn = ipnetwork::IpNetwork::from(mip);

    assert_eq!(ipn.ip(), expected);
    assert_eq!(ipn.prefix(), cidr);
}

#[test]
#[cfg(feature = "ipnetwork")]
fn from_mip_to_ipnetwork_ipv6() {
    let (mip, expected, cidr) = _new_full_ipv6();
    let ipn = ipnetwork::IpNetwork::from(mip);

    assert_eq!(ipn.ip(), expected);
    assert_eq!(ipn.prefix(), cidr);
}

#[test]
fn display_omit_netmask_when_full_ipv4() {
    let (mip, expected, _) = _new_full_ipv4();
    assert_eq!(format!("{}", mip), format!("{}", expected));
}

#[test]
fn display_omit_netmask_when_full_ipv6() {
    let (mip, expected, _) = _new_full_ipv6();
    assert_eq!(format!("{}", mip), format!("{}", expected));
}

#[test]
fn display_with_netmask_when_masked_ipv4() {
    let (mip, expected, cidr) = _new_masked_ipv4();
    assert_eq!(format!("{}", mip), format!("{}/{}", expected, cidr));
}

#[test]
fn display_with_netmask_when_masked_ipv6() {
    let (mip, expected, cidr) = _new_masked_ipv6();
    assert_eq!(format!("{}", mip), format!("{}/{}", expected, cidr));
}

#[test]
fn debug_with_netmask_when_full_ipv4() {
    let (mip, expected, cidr) = _new_full_ipv4();
    assert_eq!(format!("{:?}", mip), format!("{}/{}", expected, cidr));
}

#[test]
fn debug_with_netmask_when_full_ipv6() {
    let (mip, expected, cidr) = _new_full_ipv6();
    assert_eq!(format!("{:?}", mip), format!("{}/{}", expected, cidr));
}

#[test]
fn debug_with_netmask_when_masked_ipv4() {
    let (mip, expected, cidr) = _new_masked_ipv4();
    assert_eq!(format!("{:?}", mip), format!("{}/{}", expected, cidr));
}

#[test]
fn debug_with_netmask_when_masked_ipv6() {
    let (mip, expected, cidr) = _new_masked_ipv6();
    assert_eq!(format!("{:?}", mip), format!("{}/{}", expected, cidr));
}

#[test]
fn from_string_to_full_ipv4() {
    let (expected, addr, _) = _new_full_ipv4();
    assert_eq!(addr.to_string().parse::<MaskedIpAddr>().unwrap(), expected);
}

#[test]
fn from_string_to_full_ipv6() {
    let (expected, addr, _) = _new_full_ipv6();
    assert_eq!(addr.to_string().parse::<MaskedIpAddr>().unwrap(), expected);
}

#[test]
fn from_string_to_masked_ipv4() {
    let (expected, addr, cidr) = _new_masked_ipv4();
    assert_eq!(
        format!("{}/{}", addr, cidr)
            .parse::<MaskedIpAddr>()
            .unwrap(),
        expected
    );
}

#[test]
fn from_string_to_masked_ipv6() {
    let (expected, addr, cidr) = _new_masked_ipv6();
    assert_eq!(
        format!("{}/{}", addr, cidr)
            .parse::<MaskedIpAddr>()
            .unwrap(),
        expected
    );
}

#[test]
fn cidr_insert_full_ipv4() {
    let (mip, _, _) = _new_full_ipv4();
    _db()
        .execute("INSERT INTO foo (cidr) VALUES ($1)", &[&mip])
        .unwrap();
}

#[test]
fn cidr_insert_full_ipv6() {
    let (mip, _, _) = _new_full_ipv6();
    _db()
        .execute("INSERT INTO foo (cidr) VALUES ($1)", &[&mip])
        .unwrap();
}

#[test]
fn cidr_insert_masked_ipv4() {
    let (mip, _, _) = _new_masked_ipv4();
    _db()
        .execute("INSERT INTO foo (cidr) VALUES ($1)", &[&mip])
        .unwrap();
}

#[test]
fn cidr_insert_masked_ipv6() {
    let (mip, _, _) = _new_masked_ipv6();
    _db()
        .execute("INSERT INTO foo (cidr) VALUES ($1)", &[&mip])
        .unwrap();
}

#[test]
fn inet_insert_full_ipv4() {
    let (mip, _, _) = _new_full_ipv4();
    _db()
        .execute("INSERT INTO foo (inet) VALUES ($1)", &[&mip])
        .unwrap();
}

#[test]
fn inet_insert_full_ipv6() {
    let (mip, _, _) = _new_full_ipv6();
    _db()
        .execute("INSERT INTO foo (inet) VALUES ($1)", &[&mip])
        .unwrap();
}

#[test]
fn inet_insert_masked_ipv4() {
    let (mip, _, _) = _new_masked_ipv4();
    _db()
        .execute("INSERT INTO foo (inet) VALUES ($1)", &[&mip])
        .unwrap();
}

#[test]
fn inet_insert_masked_ipv6() {
    let (mip, _, _) = _new_masked_ipv6();
    _db()
        .execute("INSERT INTO foo (inet) VALUES ($1)", &[&mip])
        .unwrap();
}

#[test]
fn cidr_insert_and_select_full_ipv4() {
    let db = _db();
    let (mip, _, _) = _new_full_ipv4();

    db.execute("INSERT INTO foo (cidr) VALUES ($1)", &[&mip])
        .unwrap();

    let mip_b = db
        .query("SELECT cidr FROM foo LIMIT 1", &[])
        .unwrap()
        .get(0)
        .get(0);
    assert_eq!(mip, mip_b);
}

#[test]
fn cidr_insert_and_select_full_ipv6() {
    let db = _db();
    let (mip, _, _) = _new_full_ipv6();

    db.execute("INSERT INTO foo (cidr) VALUES ($1)", &[&mip])
        .unwrap();

    let mip_b = db
        .query("SELECT cidr FROM foo LIMIT 1", &[])
        .unwrap()
        .get(0)
        .get(0);
    assert_eq!(mip, mip_b);
}

#[test]
fn cidr_insert_and_select_masked_ipv4() {
    let db = _db();
    let (mip, _, _) = _new_masked_ipv4();

    db.execute("INSERT INTO foo (cidr) VALUES ($1)", &[&mip])
        .unwrap();

    let mip_b = db
        .query("SELECT cidr FROM foo LIMIT 1", &[])
        .unwrap()
        .get(0)
        .get(0);
    assert_eq!(mip, mip_b);
}

#[test]
fn cidr_insert_and_select_masked_ipv6() {
    let db = _db();
    let (mip, _, _) = _new_masked_ipv6();

    db.execute("INSERT INTO foo (cidr) VALUES ($1)", &[&mip])
        .unwrap();

    let mip_b = db
        .query("SELECT cidr FROM foo LIMIT 1", &[])
        .unwrap()
        .get(0)
        .get(0);
    assert_eq!(mip, mip_b);
}

#[test]
fn inet_insert_and_select_full_ipv4() {
    let db = _db();
    let (mip, _, _) = _new_full_ipv4();

    db.execute("INSERT INTO foo (inet) VALUES ($1)", &[&mip])
        .unwrap();

    let mip_b = db
        .query("SELECT inet FROM foo LIMIT 1", &[])
        .unwrap()
        .get(0)
        .get(0);
    assert_eq!(mip, mip_b);
}

#[test]
fn inet_insert_and_select_full_ipv6() {
    let db = _db();
    let (mip, _, _) = _new_full_ipv6();

    db.execute("INSERT INTO foo (inet) VALUES ($1)", &[&mip])
        .unwrap();

    let mip_b = db
        .query("SELECT inet FROM foo LIMIT 1", &[])
        .unwrap()
        .get(0)
        .get(0);
    assert_eq!(mip, mip_b);
}

#[test]
fn inet_insert_and_select_masked_ipv4() {
    let db = _db();
    let (mip, _, _) = _new_masked_ipv4();

    db.execute("INSERT INTO foo (inet) VALUES ($1)", &[&mip])
        .unwrap();

    let mip_b = db
        .query("SELECT inet FROM foo LIMIT 1", &[])
        .unwrap()
        .get(0)
        .get(0);
    assert_eq!(mip, mip_b);
}

#[test]
fn inet_insert_and_select_masked_ipv6() {
    let db = _db();
    let (mip, _, _) = _new_masked_ipv6();

    db.execute("INSERT INTO foo (inet) VALUES ($1)", &[&mip])
        .unwrap();

    let mip_b = db
        .query("SELECT inet FROM foo LIMIT 1", &[])
        .unwrap()
        .get(0)
        .get(0);
    assert_eq!(mip, mip_b);
}

#[test]
fn masked_ip_send() {
    fn assert_send<T: Send>() {}
    assert_send::<MaskedIpAddr>();
}

#[test]
fn masked_ip_sync() {
    fn assert_sync<T: Send>() {}
    assert_sync::<MaskedIpAddr>();
}
