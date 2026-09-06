# Security Monitoring Changes

This version removes the visible attack simulator and makes the security workflow event-driven.

## Operator workflow

1. The normal `/dispatch/` page contains no attack controls.
2. A POST submission containing the user's own crafted test payload is accepted by the dispatch endpoint.
3. The application stores the submitted string as a live rendering record.
4. The security pipeline automatically records telemetry, extracts and normalizes IOCs, enriches them with the local intelligence store, calculates risk, and evaluates Sigma rules.
5. An incident appears at `/soc/` with request telemetry, payload evidence, IOCs, enrichment, score rationale, and Sigma YAML.
6. The analyst clicks `TAKE ACTION`.
7. The exact active payload record linked to the incident is deleted from the database.
8. The incident and event retain the captured payload as forensic evidence.
9. The dispatch page no longer renders the unexpected media effect for any session.

## Important implementation detail

The submitted payload is stored and inspected as data. It is not inserted into the template as executable HTML/JavaScript. The visible media effect is driven by the presence of the active database record. This keeps the demonstration harmless while still showing the full detection and response lifecycle.

## Main routes

- `/dispatch/` - normal application page; GET renders it, POST accepts submitted content.
- `/soc/` - administrator-only SOC console.
- `/soc/incident/<id>/contain/` - administrator-only response action.

There is no visible `Launch Attack`, `Controlled Attack Vector Simulator`, payload input field, or simulation control on the application page.
