# project-net
This is a TCPIP implementation of the cryptographic protocol implemented in [proj_crypto](https://github.com/tblah/project-crypto).

This project is licenced under GPL version 3 or later as published by the [Free Software Foundation](https://fsf.org)

**Please do not use this for anything important. The cryptography in proj_crypto has not been reviewed by a professional**

[The documentation generated by cargo-doc](https://tblah.github.io/project-net/)

Building (you may need to install libsodium):
```
cargo build
```

Testing:
```
cargo test
```

To generate your own documentation:

```
cargo doc 
```

For a description of the cryptographic design and for usage examples, see the cargo documentation for proj_crypto. 
