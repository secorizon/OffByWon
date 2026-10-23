# Quinn QUIC fuzzing target

This is a deliberately small QUIC v1 server for exercising
`examples/quic_initial_fuzzer.py`. It uses Quinn and rustls, negotiates the
fuzzer's default `hq-29` ALPN, and listens on UDP port 4433 by default.

The server persists a self-signed certificate in `state/`, limits incomplete
connections, and applies a 10-second idle timeout so one-flight fuzz cases do
not accumulate indefinitely. A completed QUIC connection gets a bounded
bidirectional echo service that is used by the built-in probe.

```console
cargo build --release --locked
./target/release/offbywon-quic-server serve
./target/release/offbywon-quic-server probe
```

For the user service, install `offbywon-quic.service` under
`~/.config/systemd/user/`, reload the user manager, and enable the service.

From the OffByWon checkout, validate the actual handcrafted Initial packet:

```console
python3 examples/quic_initial_fuzzer.py \
  -s <server-ip> -p 4433 --dry-run --timeout 2
```

Configuration is available through the environment variables shown by
`offbywon-quic-server --help`.
