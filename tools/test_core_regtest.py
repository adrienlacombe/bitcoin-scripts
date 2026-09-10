"""Offline guards for the Core harness's serialization and rejection criteria."""

import unittest

from core_regtest import RPCError, compact_size, consensus_check, rejection_matches


class CoreHarnessTests(unittest.TestCase):
    def test_compact_size_boundaries(self):
        for value, expected in [(0, "00"), (252, "fc"), (253, "fdfd00"),
                                (65535, "fdffff"), (65536, "fe00000100"),
                                (2**32, "ff0000000001000000")]:
            self.assertEqual(compact_size(value).hex(), expected)
        with self.assertRaises(ValueError):
            compact_size(-1)

    def test_wrong_script_failure_does_not_satisfy_a_boundary(self):
        result = {"accepted": False, "reason": "TestBlockValidity failed: block-script-verify-flag-failed (Witness program hash mismatch), input 0 of abc"}
        self.assertTrue(rejection_matches(result, "taproot-commitment"))
        self.assertFalse(rejection_matches(result, "stack-size"))
        self.assertFalse(rejection_matches(result, None))

    def test_policy_failure_is_distinct_from_consensus_failure(self):
        result = {"allowed": False, "reject-reason": "bad-witness-nonstandard"}
        self.assertTrue(rejection_matches(result, "witness-stack-item-size", policy=True))
        self.assertFalse(rejection_matches(result, "push-size", policy=True))
        self.assertFalse(rejection_matches({"allowed": True}, "witness-stack-item-size", policy=True))

    def test_infrastructure_errors_are_not_consensus_rejections(self):
        class FailingNode:
            def __init__(self, code, message):
                self.error = RPCError({"code": code, "message": message})

            def tick(self):
                pass

            def rpc(self, method, *params):
                if method == "getblockcount":
                    return 102
                raise self.error

        for code, message in [(-22, "Transaction decode failed"), (-25, "TestBlockValidity failed: bad-txns-inputs-missingorspent"),
                              (-1, "Failed to make block.")]:
            with self.subTest(code=code, message=message), self.assertRaises(RPCError):
                consensus_check(FailingNode(code, message), "address", {"hex": "00"})
        accepted_error = FailingNode(-25, "TestBlockValidity failed: block-script-verify-flag-failed (Stack size limit exceeded), input 0 of abc")
        self.assertFalse(consensus_check(accepted_error, "address", {"hex": "00"})["accepted"])


if __name__ == "__main__":
    unittest.main()
