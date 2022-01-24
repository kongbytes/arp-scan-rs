#!/bin/bash

# RELEASE UTILITY
# This script helps with the release process on Github (musl & glibc builds for Linux)

mkdir -p ./builds
rm -rf ./builds/*

CLI_VERSION=$(/usr/bin/cat Cargo.toml | egrep "version = (.*)" | egrep -o --color=never "([0-9]+\.?){3}" | head -n 1)
echo "Releasing v$CLI_VERSION for GNU & musl targets"

# Build a 'musl' release for Linux x86_64
cargo build --release --target=x86_64-unknown-linux-musl --locked
cp -p ./target/x86_64-unknown-linux-musl/release/arp-scan ./builds/arp-scan-v$CLI_VERSION-x86_64-unknown-linux-musl
./builds/arp-scan-v$CLI_VERSION-x86_64-unknown-linux-musl --version

# Build a 'glibc' (GNU) release for Linux x86_64
cargo build --release --target=x86_64-unknown-linux-gnu --locked
cp -p ./target/x86_64-unknown-linux-gnu/release/arp-scan ./builds/arp-scan-v$CLI_VERSION-x86_64-unknown-linux-glibc
./builds/arp-scan-v$CLI_VERSION-x86_64-unknown-linux-glibc --version

# Build the deb archive
mkdir -p ./builds/arp-scan-rs_$CLI_VERSION-1_amd64/DEBIAN
echo "Package: arp-scan-rs" > ./builds/arp-scan-rs_$CLI_VERSION-1_amd64/DEBIAN/control
echo "Version: 0.13.0" >> ./builds/arp-scan-rs_$CLI_VERSION-1_amd64/DEBIAN/control
echo "Architecture: all" >> ./builds/arp-scan-rs_$CLI_VERSION-1_amd64/DEBIAN/control
echo "Maintainer: Saluki" >> ./builds/arp-scan-rs_$CLI_VERSION-1_amd64/DEBIAN/control
echo "Description: Minimalist ARP scan written in Rust" >> ./builds/arp-scan-rs_$CLI_VERSION-1_amd64/DEBIAN/control
mkdir -p ./builds/arp-scan-rs_$CLI_VERSION-1_amd64/usr/local/bin
cp ./builds/arp-scan-v$CLI_VERSION-x86_64-unknown-linux-glibc ./builds/arp-scan-rs_$CLI_VERSION-1_amd64/usr/local/bin/arp-scan
(cd ./builds && dpkg-deb --build --root-owner-group arp-scan-rs_0.13.0-1_amd64)

echo "Update the README instructions for v$CLI_VERSION"
echo " ✓ Publish on crates.io"
echo " ✓ Release on Github with Git tag v$CLI_VERSION"
