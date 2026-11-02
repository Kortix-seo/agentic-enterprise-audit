"""Tests for audit.py. Run with: python -m unittest discover -s tests"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import audit  # noqa: E402


def severities(result):
    return [f["severity"] for f in result["findings"]]


class AuditTests(unittest.TestCase):
    def test_omitted_grants_are_none_and_tools_default_to_all(self):
        result = audit.audit({"agents": {"a": {"prompt": "x"}}})
        row = result["agents"][0]
        self.assertEqual(row["grants"]["skills"], "none")
        self.assertEqual(row["grants"]["secrets"], "none")
        self.assertEqual(row["grants"]["tools"], "all (default)")
        self.assertEqual(row["permission"], "allow (default)")

    def test_secrets_all_is_high(self):
        result = audit.audit({"agents": {"a": {"prompt": "x", "secrets": "all"}}})
        self.assertIn("high", severities(result))

    def test_tight_agent_has_no_high_findings(self):
        doc = {"agents": {"a": {
            "prompt": "x",
            "mode": "subagent",
            "permission": {"bash": "ask"},
            "tools": ["read"],
            "secrets": "none",
            "kortix_permissions": ["project.read"],
        }}}
        result = audit.audit(doc)
        self.assertEqual(result["score"], 0)

    def test_deprecated_keys_are_reported(self):
        result = audit.audit({"kortix_version": 3, "sandboxes": [], "agents": {}})
        where = [f["where"] for f in result["findings"]]
        self.assertIn("kortix_version", where)
        self.assertIn("sandboxes", where)

    def test_default_agent_must_exist(self):
        result = audit.audit({"default_agent": "ghost", "agents": {}})
        self.assertIn("high", severities(result))

    def test_agent_without_prompt_is_medium(self):
        result = audit.audit({"agents": {"a": {"tools": ["read"]}}})
        self.assertIn("medium", severities(result))

    def test_permission_map_is_summarised(self):
        result = audit.audit({"agents": {"a": {
            "prompt": "x", "permission": {"bash": "ask", "edit": "deny"}}}})
        self.assertEqual(result["agents"][0]["permission"], "ask: bash; deny: edit")

    def test_exclude_grant_is_rendered(self):
        result = audit.audit({"agents": {"a": {
            "prompt": "x", "tools": {"exclude": ["bash"]}}}})
        self.assertEqual(result["agents"][0]["grants"]["tools"], "all except bash")


if __name__ == "__main__":
    unittest.main()
