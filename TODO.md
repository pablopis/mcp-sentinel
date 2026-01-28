# MCP Sentinel - TODO

## Completed

- [x] Project hygiene improvements (2026-01-28)
  - [x] Create PLANNING.md
  - [x] Create TODO.md
  - [x] Refactor gateway.py into smaller modules (hitl.py, policy.py)
  - [x] Add pyproject.toml
  - [x] Create test suite (35 tests passing)
  - [x] Modernize type hints (Optional → X | None)

## Backlog

### v0.2 - Enhanced Configurability
- [ ] Multiple policy profiles (development, staging, production)

### v0.3 - Enterprise Features
- [x] Circuit Breaker: Rate limiting and infinite loop detection
- [x] Human-in-the-Loop: Approval workflow for critical actions

### v0.4 - Scalability & Connectivity
- [ ] HTTP/SSE Transport Layer: Gateway as HTTP proxy for remote MCP servers
- [ ] Metrics Endpoint: Prometheus-compatible metrics (requests, blocks, latency)
- [ ] OPA (Open Policy Agent) Integration for complex rules

### v1.0 - Full Platform
- [ ] Web-based Audit Logging Dashboard
- [ ] Multi-tenancy support
- [ ] Policy library marketplace
- [ ] Integration with SIEM tools

## Discovered During Work

- [x] Regex operator bug: uppercasing broke regex special sequences like \s → \S
