# A totally insecure SSH agent in Rust

**Use at your own risk.**

Only supports RSA keys. Not very configurable. But it *will* lazily ask you to
unlock your private keys, while not pulling in half a desktop environment.

## Installation

Requires `pinentry` to work. After you've installed that, installing `smith` is
as simple as cloning this repo and running

    cargo install
