# postgres-inet
[![Build Status](https://travis-ci.org/nuew/postgres-inet.svg?branch=master)](https://travis-ci.org/nuew/postgres-inet)
[![Docs.rs](https://docs.rs/postgres-inet/badge.svg)](https://docs.rs/postgres-inet/)
[![Crates.io](https://img.shields.io/crates/v/postgres-inet.svg)](https://crates.io/crates/postgres-inet)
[![License](https://img.shields.io/crates/l/postgres-inet.svg)]()

Provides Cidr and Inet support for [`postgres`][1].

Unlike several other names of this pattern, this is not affiliated with or
supported by the [author][2] of [`postgres`][1].

## Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
postgres-inet = "0.1"
```

## Usage

Please see the `examples/` folder in the crate root for a simple example.

[1]: https://crates.io/crates/postgres
[2]: https://github.com/sfackler
