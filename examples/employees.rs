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

extern crate postgres;
extern crate postgres_inet;

use postgres::{Connection, TlsMode};
use postgres_inet::MaskedIpAddr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

struct Employee {
    name: String,
    network: MaskedIpAddr,
    workstation: IpAddr,
}

fn main() {
    let employees = vec![
        Employee {
            name: String::from("John Smith"),
            network: MaskedIpAddr::new(Ipv4Addr::new(10, 0, 0, 0), 8),
            workstation: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)),
        },
        Employee {
            name: String::from("Jane Doe"),
            network: MaskedIpAddr::new(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7),
            workstation: IpAddr::V6(Ipv6Addr::new(0x2001, 0x0DB8, 0, 0, 0, 0, 0, 0xC513)),
        },
    ];
    let conn = Connection::connect("postgres://postgres@localhost", TlsMode::None).unwrap();

    conn.execute(
        "CREATE TABLE employees (
            id SERIAL PRIMARY KEY,
            name VARCHAR NOT NULL,
            network CIDR NOT NULL,
            workstation INET NOT NULL
        )",
        &[],
    ).unwrap();

    for employee in employees {
        let workstation: MaskedIpAddr = From::from(employee.workstation);
        conn.execute(
            "INSERT INTO employees (name, network, workstation) VALUES ($1, $2, $3)",
            &[&employee.name, &employee.network, &workstation],
        ).unwrap();
    }

    for row in &conn.query("SELECT name, network, workstation FROM employees", &[])
        .unwrap()
    {
        let workstation: MaskedIpAddr = row.get(2);
        let employee = Employee {
            name: row.get(0),
            network: row.get(1),
            workstation: From::from(workstation),
        };

        println!(
            "{} manages {} from {}",
            employee.name, employee.network, employee.workstation
        );
    }
    conn.execute("DROP TABLE employees", &[]).unwrap();
}
