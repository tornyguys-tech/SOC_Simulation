# ThreatLens Corrective Implementation Specification

## Objective

Correct the existing `SOC_Simulation` repository so ThreatLens detects the **real suspicious request** entering the normal TornSpy application, creates a real security event/incident, displays the actual evidence in the SOC, and lets the analyst contain that exact application record.

**Do not build or retain an attack simulator.**

## Hard Requirements

- NO `Controlled Attack Vector Simulator`
- NO attack launcher
- NO `Launch Attack` button
- NO malicious-payload input field
- NO special testing/lab/simulation page
- NO `Security Lab`, `Testing Lab`, `Safe Room`, `Attack Playground`, `Demo Attack`, or `Training Mode` UI
- The operator submits their own crafted payload externally through the normal application path.
- ThreatLens automatically detects the resulting request.
- The SOC shows details from the actual request/event.
- `TAKE ACTION` removes the exact malicious application database entry.
- The forensic incident remains after containment.
- All SOC counts and values are dynamic, never fake/static.

---

## 1. Use the Real Application Record

The existing TornSpy application has:

```text
SurveillanceRequest
```

This must be the authoritative live application record associated with a detected malicious request.

Do not create a separate synthetic `SecurityLabPayload` as the source of truth.

If the old `SecurityLabPayload` model is retained temporarily for migration compatibility, it must not control the live malicious state.

The desired relationship is:

```text
Incoming HTTP request
        ↓
Normal application processing
        ↓
SurveillanceRequest
        ↓
SecurityEvent
        ↓
SecurityIncident
```

The security records must directly reference the exact `SurveillanceRequest`.

---

## 2. Eliminate Fuzzy Request Matching

Do NOT reconnect security events to application requests later by searching for payload text, for example:

```python
SurveillanceRequest.objects.filter(
    faction_id=extracted_payload
)
```

That is unreliable.

Instead, retain the exact object/primary key when the normal view creates it:

```python
surveillance_request = SurveillanceRequest.objects.create(...)
```

Then associate that exact object with the security event/incident.

A suitable relationship is:

```python
application_request = models.ForeignKey(
    SurveillanceRequest,
    null=True,
    blank=True,
    on_delete=models.SET_NULL,
)
```

Use a suitable field name/related name consistent with the existing project.

---

## 3. Automatic Detection of the Actual HTTP Request

ThreatLens must inspect the actual Django request.

Inspect relevant sources including:

- `request.GET`
- `request.POST`
- `request.body`
- query-string values
- submitted form values
- request path
- relevant headers
- User-Agent
- source IP / forwarded client metadata

Do not depend on a parameter literally named `payload`.

A suspicious value must be detectable regardless of which normal application parameter carries it.

The detector must run automatically.

There must be no security UI involved in initiating detection.

---

## 4. Detection Pipeline

Implement:

```text
REAL HTTP REQUEST
       ↓
Collect request data
       ↓
Normalize/decode for inspection
       ↓
Threat signature detection
       ↓
     suspicious?
      /           NO         YES
    ↓           ↓
normal flow  SecurityEvent
                ↓
          IOC extraction
                ↓
            Normalize
                ↓
            Enrichment
                ↓
           Risk scoring
                ↓
         Sigma evaluation
                ↓
        SecurityIncident
                ↓
             SOC
```

The incident must be generated because a real request triggered detection, not because a demo button was pressed.

---

## 5. Safe Inspection

Submitted content must be inspected as data.

Do not execute arbitrary JavaScript.

Do not implement:

- cookie theft
- credential theft
- keylogging
- token theft
- attacker callbacks
- command execution
- destructive behavior

The controlled visible effect may be driven by application state, but arbitrary submitted JavaScript must never be executed.

---

## 6. Normalization Before Detection

Safely normalize common encodings before signature matching:

- URL encoding
- HTML entities
- common escaped representations
- case variations
- relevant repeated encoding where appropriate

Example conceptual flow:

```text
raw request
   ↓
decode/normalize
   ↓
inspect normalized representation
```

Normalization is for analysis only.

Never execute the normalized value.

---

## 7. XSS Detection

The detector should recognize suspicious characteristics including:

- `<script`
- HTML event handlers such as `onerror=`
- HTML event handlers such as `onload=`
- `javascript:`
- `vbscript:`
- suspicious SVG event handlers
- iframe/object/embed injection
- suspicious executable data URI patterns
- other clearly suspicious HTML/JavaScript execution indicators

Detection should work against common encoded representations.

Return structured evidence, for example:

```python
{
    "detected": True,
    "attack_type": "stored_xss",
    "confidence": 0.96,
    "matches": [
        {
            "rule": "html_event_handler",
            "pattern": "onerror="
        }
    ]
}
```

The exact schema can differ, but the result must identify the evidence that actually triggered detection.

---

## 8. Correct Event/Application Ordering

If middleware executes before the normal view creates `SurveillanceRequest`, store the detection context on the request object:

```python
request.threat_detection = detection_result
```

Then, after the normal application view creates the `SurveillanceRequest`, associate that exact record with the detection.

Do not attempt to rediscover the record from payload contents.

The final result must be:

```text
SecurityEvent.application_request
        ↓
exact SurveillanceRequest primary key
```

---

## 9. SecurityEvent

Create a real security event from the incoming request.

Suggested information:

```text
event_type
timestamp
source_ip
http_method
request_path
query_string
user_agent
request_headers
request_body
matched_signatures
application_request
raw_event
```

The event must contain actual values from the triggering request.

---

## 10. IOC Extraction

Run IOC extraction against the actual SecurityEvent.

Potential types:

```text
IP
DOMAIN
URL
HASH
USER_AGENT
PAYLOAD_PATTERN
```

Only create indicators actually present in the event.

If one IOC exists, show one.

If four exist, show four.

If no IOC of a type exists, do not fabricate it.

Never display permanent values such as `6 indicators` simply because this is a presentation.

---

## 11. IOC Normalization

Normalize extracted indicators before storage/deduplication.

Examples:

```text
domain → lowercase
hash → canonical hexadecimal representation
IP → canonical representation
URL → normalized host/scheme where appropriate
```

Avoid duplicate indicators caused only by encoding/case differences.

---

## 12. IOC Enrichment

Enrichment must operate on actual extracted indicators.

A deterministic local threat-intelligence dataset is acceptable for the project.

For an unknown indicator:

```text
Reputation: Unknown
```

Do not fabricate malicious reputation.

The enrichment displayed in the SOC must correspond to the actual IOC.

---

## 13. Dynamic Risk Scoring

Calculate risk from the actual event.

Example factors:

```text
XSS signature matched       +50
Known suspicious IOC        +30
Repeated suspicious events  +10
Suspicious User-Agent       +10
```

Cap at 100.

Store/display:

```text
risk_score
risk_reasons
```

Do not hard-code one permanent score.

---

## 14. Real Sigma Evaluation

Sigma must evaluate the actual normalized security event.

Example rule:

```yaml
title: Stored XSS Detection
status: experimental
logsource:
  category: webserver
detection:
  selection:
    event_type: stored_xss
  condition: selection
level: high
```

Implementation must:

1. load the rule
2. parse YAML
3. evaluate the actual event
4. return MATCHED or NOT MATCHED
5. associate the result with the incident

Do not show `MATCHED` for every incident.

---

## 15. Automatic Incident Creation

When the request is detected:

```text
SecurityEvent
    ↓
IOC extraction
    ↓
Normalization
    ↓
Enrichment
    ↓
Risk scoring
    ↓
Sigma
    ↓
SecurityIncident
```

The incident should reference both:

```text
SecurityEvent
SurveillanceRequest
```

where applicable.

Suggested incident information:

```text
incident_id
title
attack_type
severity
confidence
status
source_ip
endpoint
risk_score
matched_sigma_rule
created_at
```

---

## 16. SOC Must Display Actual Evidence

The SOC page must show data from the newly created incident.

### Incident

```text
Incident ID
Title
Attack Type
Severity
Confidence
Status
Created At
```

### Request

```text
Source IP
HTTP Method
Endpoint
User-Agent
Timestamp
```

### Application Record

Show the exact:

```text
SurveillanceRequest ID
```

This is the record that `TAKE ACTION` will target.

### Evidence

Show the actual suspicious request/evidence.

### Indicators

Show only indicators extracted from that incident.

### Enrichment

Show enrichment for those indicators.

### Detection

Show:

```text
matched signatures
Sigma rule
Sigma result
```

### Risk

Show:

```text
score
risk reasons
```

### Timeline

Use actual timestamps for:

```text
request received
detection
IOC extraction
enrichment
Sigma evaluation
incident creation
response
containment
```

---

## 17. Remove Static SOC Data

Search the project for hard-coded live SOC values.

Remove values such as:

```text
6 indicators
3 incidents
87 risk score
12 events
```

unless calculated from current database state.

All counts must be dynamic.

Examples:

```python
SecurityIncident.objects.count()
IOC.objects.count()
```

The UI must never pretend that an incident contains indicators that do not exist.

---

## 18. Live SOC Refresh

Keep the existing polling approach if suitable.

Expected behavior:

```text
SOC already open
       ↓
Operator submits payload externally
       ↓
ThreatLens detects request
       ↓
Incident automatically created
       ↓
SOC polling discovers new incident
       ↓
Actual incident appears
```

No attack button is required.

No manual incident creation is required.

---

## 19. TAKE ACTION

`TAKE ACTION` is the analyst's response step.

It must be:

- authenticated
- authorized
- POST
- CSRF protected

When clicked:

```text
TAKE ACTION
      ↓
validate incident
      ↓
retrieve exact SurveillanceRequest
      ↓
delete/remove exact record
      ↓
record response
      ↓
verify deletion
      ↓
mark incident CONTAINED
```

The response service must operate on the exact application record referenced by the incident.

---

## 20. Do NOT Broadly Delete Records

Remove any logic that searches the entire database for vaguely suspicious requests and deletes multiple records.

Do NOT do:

```text
find all suspicious requests
        ↓
delete all matching requests
```

Only the exact application record associated with the incident may be removed.

Example:

```text
Incident #42
    ↓
SurveillanceRequest #1837
    ↓
TAKE ACTION
    ↓
delete #1837
```

Unrelated requests must remain untouched.

---

## 21. Preserve Forensic Evidence

When the live application record is removed, preserve the security investigation.

Keep:

```text
original payload/evidence
source IP
User-Agent
endpoint
timestamp
matched signatures
IOC data
enrichment
risk score
Sigma result
application record ID
```

Therefore:

```text
LIVE APPLICATION RECORD
        ↓
TAKE ACTION
        ↓
removed

SECURITY INCIDENT
        ↓
remains for investigation
```

---

## 22. Containment Verification

After the response action:

```text
Does associated SurveillanceRequest still exist?
        |
        +-- NO → containment verified
        |
        +-- YES → containment failed
```

Only mark:

```text
CONTAINED
```

after successful verification.

Record:

```text
Action: Delete malicious request
Result: SUCCESS
Record: SurveillanceRequest #<id>
Verification: PASSED
```

---

## 23. Database-Driven Shared Effect

If the affected page renders a harmless demonstration effect based on the malicious application record, the state must be shared server-side.

Do not use:

- localStorage
- browser-only variables
- session-only state
- per-user cookies

Desired behavior:

```text
SurveillanceRequest #1837 exists
        ↓
affected page renders associated controlled effect
```

After `TAKE ACTION`:

```text
SurveillanceRequest #1837 deleted
        ↓
affected page no longer has the database state
        ↓
effect disappears
```

This must work across separate browser sessions.

---

## 24. No Security UI on the Victim Side

The normal application must remain normal.

Do not expose attack-related controls to ordinary users.

The only special interface should be the authorized SOC/investigation interface.

---

## 25. Tests

Add/update tests for:

### Detection

- benign request → no incident
- suspicious request → detection
- encoded suspicious input → detection
- event-handler signatures → detection
- script signatures → detection

### Linking

- event links to exact SurveillanceRequest
- no fuzzy payload lookup
- unrelated requests remain unrelated

### IOC

- actual IP extraction
- actual domain extraction
- actual URL extraction
- actual hash extraction
- normalization/deduplication

### Sigma

- matching event → MATCHED
- nonmatching event → NOT MATCHED

### Response

- TAKE ACTION deletes only associated SurveillanceRequest
- unrelated records remain
- action is idempotent
- incident remains after deletion
- containment verification occurs

### End-to-End

```text
external crafted request
    ↓
normal application endpoint
    ↓
SurveillanceRequest
    ↓
automatic detection
    ↓
SecurityEvent
    ↓
IOC extraction
    ↓
normalization
    ↓
enrichment
    ↓
risk score
    ↓
Sigma
    ↓
SecurityIncident
    ↓
SOC
    ↓
TAKE ACTION
    ↓
exact SurveillanceRequest deleted
    ↓
containment verified
```

---

# Manual Demonstration Acceptance Test

## 1. Normal State

Open the normal application.

There is no:

- attack simulator
- attack launcher
- payload field
- lab UI

Open `/soc/`.

It should show actual current state.

## 2. External Attack

Using an external browser/client, submit your own crafted payload through the normal application request path.

The application should not have a special control for this.

## 3. Automatic Detection

ThreatLens detects the request automatically.

It creates:

```text
SecurityEvent
IOC records
SecurityIncident
```

## 4. SOC

The SOC displays:

```text
actual source
actual endpoint
actual request
actual evidence
actual IOCs
actual enrichment
actual risk score
actual Sigma result
```

## 5. Response

The analyst clicks:

```text
TAKE ACTION
```

## 6. Containment

The exact malicious `SurveillanceRequest` is deleted.

The system verifies it is gone.

Incident becomes:

```text
CONTAINED
```

## 7. Verification

Refresh the affected page.

The controlled database-driven effect is gone.

The forensic incident remains visible in the SOC.

---

# Definition of Done

- [ ] No attack simulator
- [ ] No attack launcher
- [ ] No payload input field
- [ ] No lab/testing UI
- [ ] Operator submits their own payload externally
- [ ] Normal application receives the request
- [ ] ThreatLens inspects the real request
- [ ] Suspicious input is detected automatically
- [ ] Detection evidence is recorded
- [ ] SecurityEvent is created
- [ ] SecurityEvent links to exact SurveillanceRequest
- [ ] IOC extraction uses actual event data
- [ ] IOC normalization is real
- [ ] IOC enrichment is real
- [ ] Risk scoring is dynamic
- [ ] Sigma evaluation is real
- [ ] SecurityIncident is created automatically
- [ ] SOC displays actual evidence
- [ ] SOC counts are dynamic
- [ ] TAKE ACTION targets exact application record
- [ ] No unrelated records are deleted
- [ ] Malicious active record is removed
- [ ] Containment is verified
- [ ] Forensic evidence remains
- [ ] Database-driven effect disappears
- [ ] Existing TornSpy functionality remains operational

# Final Architecture

```text
                 OPERATOR
                    |
                    | own crafted request
                    v
          NORMAL TORNSpy ENDPOINT
                    |
                    v
          SurveillanceRequest
                    |
                    v
          ThreatLens Detection
                    |
                    v
             SecurityEvent
                    |
                    v
             IOC Extraction
                    |
                    v
               Normalize
                    |
                    v
               Enrichment
                    |
                    v
              Risk Scoring
                    |
                    v
             Sigma Matching
                    |
                    v
           SecurityIncident
                    |
                    v
                SOC PAGE
                    |
                    | analyst
                    v
              TAKE ACTION
                    |
                    v
       DELETE EXACT SurveillanceRequest
                    |
                    v
          VERIFY CONTAINMENT
                    |
             +------+------+
             |             |
             v             v
        LIVE EFFECT     FORENSIC
           STOPS         EVIDENCE
                         REMAINS
```

## Core Principle

**Detect the real application event.**

**Associate the security incident with the exact application record.**

**Show the actual evidence in the SOC.**

**Contain only that exact record.**

**Never replace the real attack flow with a simulator.**
