# CaseHawk

Secure digital evidence management and investigation platform for authorized law-enforcement teams. Preserve, organize, correlate, and audit digital evidence.

> **Status:** Operational MVP for authorized testing/pilot use. **Not certified for live police evidence until an independent security, legal, and operational review is completed.**

## What is CaseHawk?

CaseHawk is being built as a secure workspace for authorized investigators to manage digital case evidence without losing provenance.

### MVP

- Case creation and listing
- Evidence upload with a 100 MB per-file limit
- SHA-256 evidence hashing
- Private evidence-object storage with restrictive file permissions
- Evidence metadata and case relationships
- Case-linked investigation indicator storage (IP/domain/URL/hash observations)
- Tamper-evident append-only audit events
- Bearer-token API protection
- PostgreSQL persistence
- Docker Compose deployment

## API

Health check:

`GET /healthz`

Create a case:

`POST /api/v1/cases`

```json
{"case_number":"NP-2026-0001","title":"Example case","description":"Authorized test case"}
```

Upload evidence:

`POST /api/v1/cases/{case_id}/evidence`

Use multipart field `file`.

List evidence:

`GET /api/v1/cases/{case_id}/evidence`

Protected endpoints require:

`Authorization: Bearer <access_token>`

## Run locally

```bash
export CASEHAWK_API_TOKEN="replace-with-a-long-random-token"
docker compose up --build
```

Then:

```bash
curl http://localhost:8080/healthz
```

## Lawful investigation workflow

CaseHawk records observed indicators with their source, timestamp, classification, provider and confidence so investigators can preserve context around an IP, domain, URL or file hash. It does **not** attempt to bypass VPNs, proxies, Tor, or other anonymity services. Where additional subscriber or source information is legally obtainable, investigators should use the applicable provider/legal process and preserve the resulting records as evidence.

## Security direction

Before any real-world deployment, CaseHawk needs proper identity and access management, TLS, key management, encrypted storage/backups, immutable audit storage, evidence export verification, retention controls, rate limiting, security review, and jurisdiction-specific legal/compliance review.

CaseHawk is intended only for lawful, authorized investigations and evidence handling.

## Roadmap

- [x] Investigator authentication and RBAC
- [x] Tamper-evident chained audit log
- [x] Evidence download with hash re-verification
- [x] Case timeline
- [ ] Entity/evidence relationship graph
- [ ] Secure report export
- [x] Web dashboard
- [x] Automated tests and CI
- [ ] Security threat model and independent review

## License

MIT
