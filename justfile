_default:
  @just --list

crawl network="bitcoin":
    cargo run --release -- -n {{network}}

fmt:
  cargo +nightly fmt

check:
  cargo +nightly fmt -- --check
  cargo +nightly clippy -- -D warnings
  cargo +nightly check --all-features

# TODO(@luisschwab): add testnet3
# Options: bitcoin, signet, testnet4, regtest, lockfile
delete item="data":
  just _delete-{{item}}

_delete-bitcoin:
  rm -rf output/bitcoin

_delete-signet:
  rm -rf output/signet

_delete-testnet4:
  rm -rf output/testnet4

_delete-regtest:
  rm -rf output/signet

_delete-lockfile:
  rm -f Cargo.lock