
# `attested-tls-proxy`

This is a work-in-progress crate designed to be an alternative to [`cvm-reverse-proxy`](https://github.com/flashbots/cvm-reverse-proxy).

It offers two components:
- a proxy server, which accepts TLS connections from a proxy client, sends an attestation and then forwards traffic to a target CVM service.
- a proxy client, which accepts connections from elsewhere, connects to and verifies the attestation from the proxy server, and then forwards traffic to it over TLS.

Unlike `cvm-reverse-proxy`, this uses post-handshake remote-attested TLS, meaning regular CA-signed TLS certificates can be used.

However attestation generation and verification is not yet implemented - there is a trait provided and mock attestation for testing purposes.

This shares some code with [ameba23/attested-channels](https://github.com/ameba23/attested-channels) and may eventually be merged with that crate.

