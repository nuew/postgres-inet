# postgres-inet
[![Build Status](https://travis-ci.org/nuew/postgres-inet.svg?branch=master)](https://travis-ci.org/nuew/postgres-inet)
[![Docs.rs](https://docs.rs/postgres-inet/badge.svg)](https://docs.rs/postgres-inet/)
[![Crates.io](https://img.shields.io/crates/v/postgres-inet.svg)](https://crates.io/crates/postgres-inet)
[![License](https://img.shields.io/crates/l/postgres-inet.svg)]()

Provides [`cidr` and `inet`][1] support for rust's [`postgres`].

This crate is not affiliated with or supported by the author of [`postgres`].

## Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
postgres = "0.15"
postgres-inet = "0.15"
```

This crate will have the same major and minor version numbers as the supported
version of [`postgres`]. The `patch` version number will be incremented by
one for each release within that version. Unless required by an upstream
change, this crate's API is guaranteed stable.

## Usage

Please see the `examples/` folder in the crate root for a simple example.

[1]: https://www.postgresql.org/docs/current/static/datatype-net-types.html
[`postgres`]: https://crates.io/crates/postgres
