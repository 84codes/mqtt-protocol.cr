# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `from_io(io)` on each packet type, such as `Connect.from_io(io)`. It reads
  the whole packet, fixed header included. (#22)

### Changed

- `from_io(io)` on a packet type now raises `Error::PacketDecode` if the
  packet has another type. Before, it returned any packet type. (#22)


## [0.3.1] - 2026-07-28

### Fixed

- Make sure verions in shard.yml is the same as release tag.


## [0.3.0] - 2025-11-14

### Added

- Setting for and validation of max payload size.
- Add MQTT 3.1 support.


