# Zippy

A library for working with various types of archives. It provides a more object-oriented way to work with archives and retrieve their data and metadata, all in once place. Same code should work with every supported format.

## Preface

Files are fully stored in memory, so opening very large archives may be limited. Not all compression and encryption algorithms are supported. Most of them are implemented by third-party libraries, which can complicate installation. The project is in active development but with some limitations.

## Supported Formats

### ZIP

Archives with this format can be created, opened, and edited. Supports ZIP64 format (read-only) and ZipCrypto encryption (weak protection).

### RAR

Archives with this format can only be read due to licensing restrictions. Functionality is under development.

## Plans

Future support for the following formats is planned:

- tar
- gz
- 7z

Possible formats for future support:

- a, ar
- iso
- bz2
- apk
- msi
- dmg
- pak

### License

This code is distributed under the MIT License. You can use it for your purposes.
