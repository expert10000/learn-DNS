# Roadmap

This roadmap outlines a practical, staged build-out for the DNS Security Protocol Lab.

## Phase 0: Starter (done)
- Docker Compose topology with segmented networks
- Authoritative BIND9 for `example.test`
- Unbound resolver with DNSSEC validation and ACLs
- Trusted and untrusted client containers
- Starter docs

## Phase 1: Core DNSSEC Validation
- Add a validation test matrix (expected `AD` flag, `SERVFAIL`, and `REFUSED` cases)
- Document how to verify DNSSEC with `dig +dnssec +multi`
- Add a small script to run checks from trusted and untrusted clients

## Phase 2: Negative Scenarios
- Introduce a deliberately broken signature zone and show `SERVFAIL`
- Demonstrate DNSSEC stripping and how Unbound mitigates it
- Add a misconfigured DS record example and expected behavior

## Phase 3: Policy & Hardening
- Add response rate limiting (RRL) at authoritative
- Enable query logging and show sample analysis
- Document QNAME minimization effects and visibility

## Phase 4: Delegation & Child Zones
- Add a child zone (`lab.example.test`) with its own keys
- Demonstrate DS submission and validation chain
- Automate key rollovers (KSK/ZSK) with documented steps

## Phase 5: Monitoring & Observability
- Add lightweight metrics (stats output) for BIND and Unbound
- Provide example dashboards or log parsing notes
- Add a troubleshooting guide

## Stretch Goals
- Add DNS-over-TLS (DoT) on the resolver
- Add DNS-over-HTTPS (DoH) using a sidecar proxy
- Add query replay tests and latency benchmarks
- Package a CI job that runs the validation matrix

## Backlog / Ideas
- Multi-authoritative setup for failover testing
- ACL segmentation for multiple trusted clients
- Optional external forwarding to public resolvers
- Expanded zone files with AAAA, MX, TXT, CAA records

## Contribution Notes
- Keep changes minimal and reproducible
- Prefer scripts over large manual sequences
- Document expected outputs for every test
