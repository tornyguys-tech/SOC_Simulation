# ThreatLens: Real Client IP Fix for Render Deployment

## Objective

Fix the SOC dashboard so that it displays the **real client IP address** instead of `127.0.0.1` when the application is deployed behind Render's reverse proxy.

The application must correctly identify the originating client IP from trusted proxy headers while avoiding unsafe blind trust of arbitrary client-supplied headers.

---

## 1. Why `127.0.0.1` Appears

The Django application is not receiving the browser's TCP connection directly.

The request path is approximately:

```text
Browser
   |
   v
Render / proxy infrastructure
   |
   v
Gunicorn
   |
   v
Django
```

Django therefore sees the proxy/server connection as the immediate peer.

In local development this commonly results in:

```text
127.0.0.1
```

The original client address is normally carried through proxy headers such as:

```text
X-Forwarded-For
```

---

# 2. Create One Authoritative Client-IP Function

Do not calculate client IP independently in multiple places.

Create one reusable helper, for example:

```text
security_monitoring/utils.py
```

or an appropriate existing utility module.

Use one function:

```python
get_client_ip(request)
```

Every security event, incident, audit record, and SOC display should ultimately use this helper.

---

# 3. Trusted Proxy Handling

The implementation must distinguish between:

```text
DIRECT CLIENT
```

and:

```text
TRUSTED REVERSE PROXY
```

Do not blindly trust an arbitrary `X-Forwarded-For` value from an untrusted direct client.

Recommended logic:

```text
request
  |
  +--> trusted deployment proxy?
  |       |
  |       +--> yes → process X-Forwarded-For
  |
  +--> no → use REMOTE_ADDR
```

For the Render deployment, configure the application according to the deployment's trusted proxy behavior.

Do not allow a normal internet client to freely choose the IP shown in the SOC.

---

# 4. X-Forwarded-For Parsing

When the trusted proxy supplies:

```text
X-Forwarded-For: client-ip, proxy-ip, proxy-ip
```

parse the address list correctly.

Do not blindly use an arbitrary value without considering the trusted proxy chain.

At minimum:

```python
forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
```

Then:

```text
split on comma
strip whitespace
validate each candidate as an IP
```

The selected address must represent the original client according to the configured trusted proxy chain.

---

# 5. Validate the IP

Use Python's standard library:

```python
import ipaddress
```

Validate candidates before storing them.

Example conceptual implementation:

```python
def is_valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
```

Do not store malformed header contents as an IP address.

---

# 6. Fallback Logic

If the trusted forwarding header is missing or invalid:

```text
X-Forwarded-For unavailable
        |
        v
REMOTE_ADDR
```

Example:

```python
request.META.get("REMOTE_ADDR")
```

This means local development may correctly show:

```text
127.0.0.1
```

while the deployed application should show the actual client IP when the proxy supplies it.

That is expected.

---

# 7. Do Not Use the Wrong Headers

Do not treat arbitrary headers such as:

```text
X-Real-IP
Client-IP
True-Client-IP
```

as authoritative unless the deployment architecture explicitly guarantees that the header is supplied by a trusted proxy.

The implementation should have one documented trusted source.

---

# 8. Store the Real IP at Event Creation

When a suspicious request is detected:

```python
source_ip = get_client_ip(request)
```

Store that value directly on:

```text
SecurityEvent
```

Do not calculate it later from the browser or from the SOC page.

The event becomes the authoritative forensic record.

---

# 9. Propagate IP Through the Pipeline

The same source IP should flow through:

```text
HTTP Request
      ↓
get_client_ip()
      ↓
SecurityEvent.source_ip
      ↓
SecurityIncident.source_ip
      ↓
SOC dashboard
```

Do not recalculate it independently in:

- detector
- IOC extractor
- incident service
- SOC view
- template

The event/incident should contain the captured value.

---

# 10. Existing Incidents

Do not rewrite historical incident IP addresses unless the original request metadata is available.

Existing records containing:

```text
127.0.0.1
```

may legitimately represent previously captured local/proxy addresses.

The fix should apply to newly captured events.

---

# 11. Render Deployment Configuration

Review the production settings and make sure the application is proxy-aware.

Do not disable security features simply to make the IP appear correct.

Do not use:

```python
SECURE_PROXY_SSL_HEADER
```

as an IP solution. That setting concerns HTTPS scheme detection, not client-IP extraction.

The IP solution should remain in the dedicated client-IP helper.

---

# 12. Logging

For debugging, temporarily log:

```text
REMOTE_ADDR
X-Forwarded-For
resolved client IP
```

Example:

```text
REMOTE_ADDR=127.0.0.1
X_FORWARDED_FOR=<forwarded chain>
RESOLVED_CLIENT_IP=<resolved value>
```

Do not log sensitive request bodies unnecessarily.

Once verified, reduce logging to normal production levels.

---

# 13. SOC Display

The SOC should display:

```text
Source IP
```

from:

```text
SecurityIncident.source_ip
```

which originates from:

```text
SecurityEvent.source_ip
```

It must not display:

```text
request.META["REMOTE_ADDR"]
```

directly in the template.

The template should never contain IP-resolution logic.

---

# 14. IPv4 and IPv6

Support both:

```text
IPv4
IPv6
```

using:

```python
ipaddress.ip_address()
```

Do not assume every client address is IPv4.

---

# 15. Testing

Add tests for:

### Local request

```text
REMOTE_ADDR=127.0.0.1
X-Forwarded-For absent
→ 127.0.0.1
```

### Forwarded request

```text
REMOTE_ADDR=127.0.0.1
X-Forwarded-For=<valid client IP>
→ resolved client IP
```

### Multiple forwarded addresses

Test the configured trusted-proxy chain and verify that the correct original client is selected.

### Invalid header

```text
X-Forwarded-For=not-an-ip
→ fallback to REMOTE_ADDR
```

### IPv6

Verify valid IPv6 addresses are accepted.

### Incident propagation

Verify:

```text
resolved client IP
    ↓
SecurityEvent.source_ip
    ↓
SecurityIncident.source_ip
    ↓
SOC
```

---

# 16. Important Security Requirement

Do not solve the problem by simply doing:

```python
client_ip = request.META.get("HTTP_X_FORWARDED_FOR", request.META.get("REMOTE_ADDR"))
```

without considering trusted proxies.

That makes the application vulnerable to clients spoofing the displayed source IP.

The implementation must know which proxy layer it trusts.

---

# 17. Expected Production Result

After deployment:

```text
Browser
   ↓
Render proxy
   ↓
Django
```

Django may still see:

```text
REMOTE_ADDR = 127.0.0.1
```

but the resolved client address should come from the trusted forwarding metadata.

SOC should then show:

```text
Source IP
<actual originating client IP>
```

instead of:

```text
Source IP
127.0.0.1
```

---

# 18. Verification Procedure

After deploying the change:

1. Open the public application from your normal browser.
2. Trigger a request that creates a SecurityEvent.
3. Open the resulting SOC incident.
4. Check `Source IP`.
5. Compare it with the public client IP observed from a trusted external service or your network information.
6. Confirm the event and incident contain the same resolved address.
7. Confirm no arbitrary `X-Forwarded-For` value supplied by an untrusted client can spoof the SOC value.

---

# Definition of Done

- [ ] One authoritative `get_client_ip(request)` helper exists.
- [ ] Render/proxy forwarding is handled.
- [ ] Trusted proxy behavior is explicitly configured.
- [ ] `X-Forwarded-For` is safely parsed.
- [ ] IPs are validated.
- [ ] IPv4 and IPv6 are supported.
- [ ] Invalid forwarding headers fall back safely.
- [ ] SecurityEvent stores the resolved client IP.
- [ ] SecurityIncident inherits the event's resolved IP.
- [ ] SOC displays the incident's stored IP.
- [ ] Templates contain no IP-resolution logic.
- [ ] Historical data is not falsely rewritten.
- [ ] Tests cover forwarded, local, invalid, multiple-address, and IPv6 cases.
- [ ] Spoofing an untrusted forwarding header does not allow arbitrary IP attribution.

## Final Data Flow

```text
REAL CLIENT
    ↓
TRUSTED PROXY
    ↓
X-Forwarded-For
    ↓
get_client_ip(request)
    ↓
SecurityEvent.source_ip
    ↓
SecurityIncident.source_ip
    ↓
SOC Source IP
```
