"""Лабораторна робота №5. Протокол Feige-Fiat-Shamir (FFS).

Режими:
    python ffs_lab5.py demo   [--bits 512] [-k 3] [-t 20]   # чесний Prover
    python ffs_lab5.py attack [--trials 20000]              # самозванець без секретів
    python ffs_lab5.py leak                                 # повторне використання r

Використано криптографічно стійкий генератор (модуль secrets).
Секрети s_i у лог не записуються.
"""
import argparse
import logging
import secrets
from math import gcd

# ---------------------------------------------------------------- допоміжне
_SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Тест Міллера-Рабіна."""
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(bits: int, mod4: int = 3) -> int:
    """Просте число заданої довжини, p ≡ 3 (mod 4) (число Блюма)."""
    while True:
        c = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if c % 4 == mod4 and is_probable_prime(c):
            return c


def rand_unit(n: int) -> int:
    """Випадкове число 1 < x < n, взаємно просте з n."""
    while True:
        x = secrets.randbelow(n - 2) + 2
        if gcd(x, n) == 1:
            return x


def prod_pow(values, bits, n):
    """Добуток values[i]^bits[i] mod n."""
    res = 1
    for v, b in zip(values, bits):
        if b:
            res = (res * v) % n
    return res


# ------------------------------------------------------------- генерація ключів
def generate_keys(bits: int = 512, k: int = 3):
    """Повертає (n, s[], v[]); v_i = s_i^{-2} mod n. p, q знищуються."""
    p = gen_prime(bits)
    q = gen_prime(bits)
    while q == p:
        q = gen_prime(bits)
    n = p * q
    s = [rand_unit(n) for _ in range(k)]
    v = [pow(pow(si, 2, n), -1, n) for si in s]   # v_i = s_i^{-2} mod n
    return n, s, v


# --------------------------------------------------------------- учасники
class Prover:
    def __init__(self, n, s):
        self.n, self.s = n, s
        self._r = None

    def commit(self):
        """Крок 1: r випадкове, x = r^2 mod n."""
        self._r = rand_unit(self.n)
        return pow(self._r, 2, self.n)

    def respond(self, c):
        """Крок 3: y = r * prod(s_i^{c_i}) mod n."""
        y = (self._r * prod_pow(self.s, c, self.n)) % self.n
        self._r = None                      # r одноразове
        return y


class Verifier:
    def __init__(self, n, v):
        self.n, self.v = n, v
        self.seen_x = set()                 # захист від повтору x (replay)

    def challenge(self, x):
        if x in self.seen_x or x % self.n == 0:
            raise ValueError("повторне або нульове x - раунд відхилено")
        self.seen_x.add(x)
        return [secrets.randbelow(2) for _ in self.v]

    def check(self, x, c, y):
        """Крок 4: y^2 * prod(v_i^{c_i}) == x (mod n)."""
        if y % self.n == 0:
            return False
        return (pow(y, 2, self.n) * prod_pow(self.v, c, self.n)) % self.n == x % self.n


class Cheater:
    """Самозванець: не знає s_i, вгадує викличний вектор заздалегідь."""

    def __init__(self, n, v):
        self.n, self.v = n, v

    def commit(self):
        self.guess = [secrets.randbelow(2) for _ in self.v]
        self.y = rand_unit(self.n)
        # x підбирається так, щоб перевірка пройшла саме для guess
        self.x = (pow(self.y, 2, self.n) * prod_pow(self.v, self.guess, self.n)) % self.n
        return self.x

    def respond(self, c):
        return self.y if c == self.guess else rand_unit(self.n)


# ------------------------------------------------------------------ протокол
def run_rounds(prover, verifier, t, log=None):
    """t незалежних раундів. Повертає (прийнято?, кількість успішних раундів)."""
    ok_rounds = 0
    for i in range(1, t + 1):
        x = prover.commit()
        c = verifier.challenge(x)
        y = prover.respond(c)
        ok = verifier.check(x, c, y)
        if log:
            # у лог - лише відкриті значення (x, c, y); без s_i та r
            log.info("round=%02d c=%s x=%s... y=%s... result=%s",
                     i, "".join(map(str, c)), str(x)[:12], str(y)[:12], ok)
        if not ok:
            return False, ok_rounds
        ok_rounds += 1
    return True, ok_rounds


def setup_log(path="ffs_rounds.log"):
    log = logging.getLogger("ffs")
    log.setLevel(logging.INFO)
    log.handlers.clear()
    h = logging.FileHandler(path, mode="w", encoding="utf-8")
    h.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    log.addHandler(h)
    return log


# ------------------------------------------------------------------- режими
def demo(bits, k, t):
    n, s, v = generate_keys(bits, k)
    print(f"[KEYGEN] bits(p)=bits(q)={bits}, bits(n)={n.bit_length()}, k={k}, t={t}")
    print(f"[KEYGEN] n   = {str(n)[:40]}...")
    for i, vi in enumerate(v, 1):
        print(f"[KEYGEN] v_{i} = {str(vi)[:40]}...  (публічний)")
    print(f"[KEYGEN] gcd(s_i, n) = 1 для всіх i: {all(gcd(si, n) == 1 for si in s)}")
    print("[KEYGEN] секрети s_i не виводяться")
    log = setup_log()
    prover, verifier = Prover(n, s), Verifier(n, v)
    accepted, passed = run_rounds(prover, verifier, t, log)
    print(f"[PROTOCOL] чесний Prover: пройдено раундів {passed}/{t}, "
          f"автентифікація {'УСПІШНА' if accepted else 'ВІДХИЛЕНА'}")
    # хибний секрет
    wrong = [rand_unit(n) for _ in range(k)]
    accepted, passed = run_rounds(Prover(n, wrong), Verifier(n, v), t)
    print(f"[PROTOCOL] Prover з хибними s_i: пройдено {passed} раундів, "
          f"автентифікація {'УСПІШНА' if accepted else 'ВІДХИЛЕНА'}")
    # повтор x
    ver = Verifier(n, v)
    pr = Prover(n, s)
    x = pr.commit()
    ver.challenge(x)
    try:
        ver.challenge(x)
    except ValueError as e:
        print(f"[REPLAY] повтор x: {e}")
    print("[LOG] відкриті значення раундів збережено у ffs_rounds.log")


def attack(trials, bits=128):
    print(f"[ATTACK] самозванець без s_i, n={2*bits} біт, {trials} спроб на конфігурацію")
    print(f"{'k':>2} {'t':>2} {'успіхів':>8} {'емпірично':>11} {'теорія 2^-(k*t)':>16}")
    n, s, v = generate_keys(bits, 3)
    for k in (1, 2, 3):
        n, s, v = generate_keys(bits, k)
        for t in (1, 2, 3):
            hits = 0
            for _ in range(trials):
                if run_rounds(Cheater(n, v), Verifier(n, v), t)[0]:
                    hits += 1
            print(f"{k:>2} {t:>2} {hits:>8} {hits/trials:>11.5f} {2.0**-(k*t):>16.5f}")
    print("[ATTACK] для k=3, t=20 теоретична ймовірність: 2^-60 =", f"{2.0**-60:.2e}")


def leak():
    """Повторне використання r при k=1 розкриває секрет s."""
    n, s, v = generate_keys(128, 1)
    r = rand_unit(n)
    y0 = r % n                       # відповідь на c = 0
    y1 = (r * s[0]) % n              # відповідь на c = 1 з тим самим r
    recovered = (y1 * pow(y0, -1, n)) % n
    print("[LEAK] той самий r використано у двох раундах з c=0 та c=1")
    print(f"[LEAK] s відновлено: {recovered == s[0]}  (y1 / y0 mod n = s)")
    print("[LEAK] висновок: r має бути унікальним у кожному раунді")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["demo", "attack", "leak"])
    ap.add_argument("--bits", type=int, default=512)
    ap.add_argument("-k", type=int, default=3)
    ap.add_argument("-t", type=int, default=20)
    ap.add_argument("--trials", type=int, default=20000)
    a = ap.parse_args()
    if a.mode == "demo":
        demo(a.bits, a.k, a.t)
    elif a.mode == "attack":
        attack(a.trials)
    else:
        leak()
