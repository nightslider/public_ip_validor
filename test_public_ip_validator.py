"""Offline unit tests for the pure logic in public_ip_validator.py.

Run: python3 -m unittest -v
"""

import ipaddress
import io
import json
import unittest
from unittest.mock import patch

import public_ip_validator as piv


class AddressClassTests(unittest.TestCase):
    def _status(self, s):
        return piv.check_address_class(ipaddress.ip_address(s)).status

    def test_cgnat_fails(self):
        self.assertEqual(self._status("100.64.0.1"), piv.FAIL)
        self.assertEqual(self._status("100.127.255.254"), piv.FAIL)

    def test_cgnat_boundary_passes(self):
        self.assertEqual(self._status("100.128.0.1"), piv.PASS)

    def test_rfc1918_fails(self):
        for s in ("10.1.2.3", "172.16.5.5", "192.168.0.10"):
            self.assertEqual(self._status(s), piv.FAIL, s)

    def test_documentation_range_fails(self):
        self.assertEqual(self._status("203.0.113.9"), piv.FAIL)

    def test_loopback_and_linklocal_fail(self):
        self.assertEqual(self._status("127.0.0.1"), piv.FAIL)
        self.assertEqual(self._status("169.254.1.1"), piv.FAIL)

    def test_public_v4_passes(self):
        self.assertEqual(self._status("8.8.8.8"), piv.PASS)

    def test_public_v6_passes(self):
        self.assertEqual(self._status("2606:4700:4700::1111"), piv.PASS)

    def test_ula_v6_fails(self):
        self.assertEqual(self._status("fd12:3456::1"), piv.FAIL)


class HostingClassificationTests(unittest.TestCase):
    def test_cloud_providers_flagged(self):
        for name in ("AMAZON-AES, US", "DIGITALOCEAN-ASN, US",
                     "MICROSOFT-CORP-MSN-AS-BLOCK, US", "GOOGLE, US",
                     "HETZNER-AS, DE", "OVH, FR"):
            self.assertTrue(piv.classify_asn(name), name)

    def test_isps_not_flagged(self):
        for name in ("COMCAST-7922, US", "TEAM-CYMRU, US",
                     "ORANGE, FR", "DTAG, DE"):
            self.assertEqual(piv.classify_asn(name), [], name)

    def test_google_fiber_exception(self):
        self.assertEqual(piv.classify_asn("GOOGLE-FIBER, US"), [])


class ConsistencyTests(unittest.TestCase):
    def test_agreement_passes_when_matching_candidate(self):
        echo = {"a": "1.2.3.4", "b": "1.2.3.4", "c": None}
        chk = piv.check_consistency(echo, "1.2.3.4")
        self.assertEqual(chk.status, piv.PASS)

    def test_disagreement_fails(self):
        echo = {"a": "1.2.3.4", "b": "5.6.7.8"}
        chk = piv.check_consistency(echo, "1.2.3.4")
        self.assertEqual(chk.status, piv.FAIL)

    def test_candidate_mismatch_warns(self):
        echo = {"a": "1.2.3.4", "b": "1.2.3.4"}
        chk = piv.check_consistency(echo, "9.9.9.9")
        self.assertEqual(chk.status, piv.WARN)

    def test_too_few_providers_warns(self):
        echo = {"a": "1.2.3.4", "b": None}
        chk = piv.check_consistency(echo, "1.2.3.4")
        self.assertEqual(chk.status, piv.WARN)


class SubnetAndGatewayTests(unittest.TestCase):
    def _status(self, ip, subnet_mask, gateway):
        return piv.check_subnet_and_gateway(
            ipaddress.ip_address(ip), subnet_mask, gateway).status

    def test_valid_configuration_passes(self):
        self.assertEqual(self._status("134.215.239.227", "255.255.0.0", "134.215.0.1"), piv.PASS)

    def test_cidr_prefix_is_accepted(self):
        self.assertEqual(self._status("8.8.8.8", "24", "8.8.8.1"), piv.PASS)

    def test_invalid_mask_fails(self):
        self.assertEqual(self._status("8.8.8.8", "255.0.255.0", "8.8.8.1"), piv.FAIL)

    def test_gateway_outside_subnet_fails(self):
        self.assertEqual(self._status("8.8.8.8", "255.255.255.0", "8.8.9.1"), piv.FAIL)

    def test_gateway_must_differ_from_host(self):
        self.assertEqual(self._status("8.8.8.8", "255.255.255.0", "8.8.8.8"), piv.FAIL)

    def test_gateway_network_address_fails(self):
        self.assertEqual(self._status("8.8.8.8", "255.255.255.0", "8.8.8.0"), piv.FAIL)

    def test_gateway_broadcast_address_fails(self):
        self.assertEqual(self._status("8.8.8.8", "255.255.255.0", "8.8.8.255"), piv.FAIL)

    def test_network_address_fails(self):
        self.assertEqual(self._status("8.8.8.0", "255.255.255.0", "8.8.8.1"), piv.FAIL)

    def test_broadcast_address_fails(self):
        self.assertEqual(self._status("8.8.8.255", "255.255.255.0", "8.8.8.1"), piv.FAIL)


class VerdictTests(unittest.TestCase):
    def test_any_fail_fails_overall(self):
        checks = [piv.Check("a", piv.PASS), piv.Check("b", piv.FAIL)]
        status, _ = piv.overall_verdict(checks)
        self.assertEqual(status, piv.FAIL)

    def test_warn_is_inconclusive(self):
        checks = [piv.Check("a", piv.PASS), piv.Check("b", piv.WARN)]
        status, _ = piv.overall_verdict(checks)
        self.assertEqual(status, piv.WARN)

    def test_all_pass_is_valid(self):
        checks = [piv.Check("a", piv.PASS), piv.Check("b", piv.PASS)]
        status, _ = piv.overall_verdict(checks)
        self.assertEqual(status, piv.PASS)


class ExplicitAddressTests(unittest.TestCase):
    def test_explicit_address_skips_echo_checks(self):
        asn_info = piv.AsnInfo(asn=15169, as_name="Example ISP", prefix="8.8.8.0/24")
        with patch.object(piv, "fetch_public_ips") as fetch, \
             patch.object(piv, "lookup_asn", return_value=asn_info), \
             patch("sys.stdout", new_callable=io.StringIO) as stdout:
            exit_code = piv.main(["--json", "8.8.8.8"])

        report = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        fetch.assert_not_called()
        self.assertEqual(
            [check["name"] for check in report["checks"]],
            ["2. Not private / CGNAT / reserved", "3. ASN ownership (ISP vs cloud/hosting)",
             "4. Routability"],
        )


if __name__ == "__main__":
    unittest.main()
