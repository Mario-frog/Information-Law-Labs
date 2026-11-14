import unittest
from ffs_lab5 import (generate_keys, Prover, Verifier, Cheater, run_rounds,
                      rand_unit, is_probable_prime)


class TestFFS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.n, cls.s, cls.v = generate_keys(128, 3)

    def test_prime(self):
        self.assertTrue(is_probable_prime(2**127 - 1))
        self.assertFalse(is_probable_prime(2**127 + 1))

    def test_key_relation(self):          # v_i * s_i^2 = 1 (mod n)
        for s, v in zip(self.s, self.v):
            self.assertEqual((v * s * s) % self.n, 1)

    def test_completeness(self):
        ok, passed = run_rounds(Prover(self.n, self.s), Verifier(self.n, self.v), 20)
        self.assertTrue(ok)
        self.assertEqual(passed, 20)

    def test_wrong_secret_rejected(self):
        wrong = [rand_unit(self.n) for _ in self.s]
        ok, _ = run_rounds(Prover(self.n, wrong), Verifier(self.n, self.v), 20)
        self.assertFalse(ok)

    def test_cheater_rejected_t20(self):
        ok, _ = run_rounds(Cheater(self.n, self.v), Verifier(self.n, self.v), 20)
        self.assertFalse(ok)

    def test_replay_x_rejected(self):
        ver, pr = Verifier(self.n, self.v), Prover(self.n, self.s)
        x = pr.commit()
        ver.challenge(x)
        with self.assertRaises(ValueError):
            ver.challenge(x)

    def test_tampered_response(self):
        pr, ver = Prover(self.n, self.s), Verifier(self.n, self.v)
        x = pr.commit()
        c = ver.challenge(x)
        y = pr.respond(c)
        self.assertTrue(ver.check(x, c, y))
        self.assertFalse(ver.check(x, c, (y + 1) % self.n))


if __name__ == "__main__":
    unittest.main(verbosity=2)
