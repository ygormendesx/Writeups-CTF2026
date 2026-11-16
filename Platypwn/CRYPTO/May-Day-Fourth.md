# May Day Fourth

**Platypwn 2026**

**Category:** Crypto  
**Challenge:** May Day Fourth


### Overview

The challenge exposes a small command-line service that authenticates commands with a reduced-round MD4 construction. Each connection gets a fresh 32-byte secret. The service reveals several randomly generated message and tag pairs, then accepts messages beginning with a known 24-byte prefix if their tag is valid.

The goal is to recover enough of the secret IV to authenticate a command beginning with `give me a flag!`.

The exploit uses the message verification endpoint to obtain tags for carefully modified observations:

```text
Known message and truncated tag
    → controlled change to MD4 word W10
    → enumerate a small set of possible valid tags
    → use accepted tags to recover the hidden IV words
    → compute a valid tag for the flag command
```

### Service and hash construction

The server generates a 32-byte key for each connection. Its first 16 bytes are used as four little-endian MD4 state words:

```text
IV = (A, B, C, D)
```

The first 24 bytes of every accepted command must equal `key[8:32]`. This reveals `C` and `D`, because they correspond to the first eight bytes of that prefix. The remaining unknown IV material is `A` and `B`, or 64 bits.

The server's `mdfour.py` performs only eight steps in each of MD4's three rounds, for 24 steps total. Observations are 55 bytes long, so they fit in one padded block. The server removes the first digest byte before returning the tag, leaving 15 bytes.

The third-round message-word order begins:

```text
W0, W8, W4, W12, W2, W10, W6, W14
```

The operation indices below are **zero-based**. Rounds 1 and 2 use indices `0–7` and `8–15`; round 3 uses `16–23`. In round 3, `W10` is its sixth word, at operation `21` (the 22nd operation overall). It is unused before then, so changing `W10` leaves the state through operation `20` unchanged.

For clarity, the solver names the successive updated words around this point:

| Solver name | MD4 register | State after operation |
| --- | --- | --- |
| `q23` | `B` | `19` |
| `q24` | `A` | `20` |
| `q25` | `D` | `21`, which uses `W10` |
| `q26` | `C` | `22` |
| `q27` | `B` | `23` |

These are intermediate register values **before feed-forward**. `A_out`, `B_out`, `C_out`, and `D_out` denote the four digest words after adding the initial IV.

### Recovering chosen valid tags

Let `q25` be the state word produced at step 21, and let `q26` be the word produced at step 22. Feed-forward gives:

```text
q25 = D_out - D  (mod 2^32)
q26 = C_out - C  (mod 2^32)
```

Operation `21` rotates left by 9 bits. To change `q25` to a chosen value `q25'`, adjust `W10` by the corresponding difference before the rotation:

```text
W10' = W10 + ROR9(q25') - ROR9(q25)  (mod 2^32)
```

For a concrete calculation, an earlier saved observation had `W10 = 0x7b745e36`, `q25 = 0xc73e02a0`, and `q26 = 0xa548f298`. For `k = 31`, setting `q25' = q25 XOR 0x80000000 = 0x473e02a0` gives `W10' = 0x7b345e36`. The script writes this little-endian word at message offset `40`. This saved observation was from a different connection; its tag cannot be reused for the final session. In the successful run, the first modified message (`k = 31`) produced an accepted tag after eight verification attempts. The transcript recorded the acceptance count, but not that tag's hex bytes.

Why are there only two candidates for `q26'`? Operation `22` computes `H(q25, q24, q23) = q25 XOR q24 XOR q23`. Flipping one bit of `q25` toggles exactly that bit of `H`, while `q24`, `q23`, and the message word stay fixed. Viewed as an integer before the 11-bit rotation, the input therefore changes by either `+2^k` or `-2^k`, depending on the original bit. Thus:

```text
q26' = ROL11(ROR11(q26) ± 2^k)
```

The final operation also has an enumerable set of possible output differences. For each modified message, the script constructs candidate 15-byte tags and submits them to the service. The server's response identifies the valid tag. Processing bits from 31 down to 0 yielded all 32 accepted modified-message pairs after **583 verification attempts**.

This use of the high bit follows a known differential property of MD4's XOR round. The chosen-message construction and candidate bounds here come from the challenge's reduced schedule and its verification oracle.

### Recovering the secret IV words

The accepted pairs reveal differences in the state after operations `21` and `22`. The sign of the change before the operation-22 rotation reveals one bit of `U = q24 XOR q23` for each `k < 31`. The sign cannot distinguish the top bit because `+2^31` and `-2^31` coincide modulo `2^32`. At operation `23`, the observed `B_out` difference restricts the XOR input containing `q24`. The solver enumerates the few uncertain carry choices in that rotated addition, intersects their consistent bit values, and thereby recovers 31 bits of `q24`. The successful run left one bit of `q24` and one bit of `U` to enumerate.

For each remaining candidate, the last MD4 step gives `q27`. Feed-forward then yields:

```text
B = B_out - q27  (mod 2^32)
A = A_out - q24   (mod 2^32)
```

Because the first digest byte was truncated, there are 256 possible values for the low byte of `A_out`. The script checks those possibilities against two independent observed message and tag pairs. The recovered hidden words were:

```text
A = d1ccb9fd
B = 6702b1da
```

### Forging the flag command

With the full IV recovered, the service's MD4 implementation can compute a valid truncated tag for any command with the known prefix. The forged command was:

```text
<known 24-byte prefix> || give me a flag!.
```

The service accepted it and returned the flag.

### Exploit flow

1. Open one connection and request two observations.
2. Recover `q25` and `q26` from the truncated tag and known `C` and `D`.
3. For each bit from 31 to 0, modify only `W10` and enumerate candidate tags.
4. Use the verification response to identify each valid tag.
5. Recover the remaining bits of `q24` and `U`, then calculate `A` and `B`.
6. Validate the recovered IV against both observations.
7. Compute the tag for `give me a flag!.` and submit it on the same connection.

### Complete exploit

The following is the Python solver used in the successful run. It implements the reduced MD4 locally, obtains two observations, tests candidate tags on the same connection, recovers the IV, and submits the forged command. Set `MAYDAY_HOST` and `MAYDAY_PORT` to the active challenge instance; the historical address in the default value may no longer be live.

```python
import os
import re
import socket
import struct

MASK = (1 << 32) - 1
K = (0, 0x5A827999, 0x6ED9EBA1)
ORDER = (
    tuple(range(16)),
    (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15),
    (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15),
)
SHIFTS = ((3, 7, 11, 19), (3, 5, 9, 13), (3, 9, 11, 15))

def rol(x, n):
    x &= MASK
    return ((x << n) | (x >> (32 - n))) & MASK

def ror(x, n):
    x &= MASK
    return ((x >> n) | (x << (32 - n))) & MASK

def mix(r, x, y, z):
    if r == 0:
        return ((x & y) | (~x & z)) & MASK
    if r == 1:
        return (x & y) | (x & z) | (y & z)
    return x ^ y ^ z

def md4(msg, iv, iterations=2):
    data = bytearray(msg)
    data.append(0x80)
    data.extend(b"\x00" * ((56 - len(data) % 64) % 64))
    data.extend(struct.pack("<Q", len(msg) * 8))
    state = list(iv)

    for off in range(0, len(data), 64):
        old = state[:]
        words = struct.unpack_from("<16I", data, off)
        a, b, c, d = state

        for rnd in range(3):
            for j in range(4 * iterations):
                word = words[ORDER[rnd][j]]
                shift = SHIFTS[rnd][j & 3]
                if j & 3 == 0:
                    a = rol(a + mix(rnd, b, c, d) + word + K[rnd], shift)
                elif j & 3 == 1:
                    d = rol(d + mix(rnd, a, b, c) + word + K[rnd], shift)
                elif j & 3 == 2:
                    c = rol(c + mix(rnd, d, a, b) + word + K[rnd], shift)
                else:
                    b = rol(b + mix(rnd, c, d, a) + word + K[rnd], shift)

        state = [
            (old[0] + a) & MASK,
            (old[1] + b) & MASK,
            (old[2] + c) & MASK,
            (old[3] + d) & MASK,
        ]

    return struct.pack("<4I", *state)

assert md4(
    b"abc",
    (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476),
    iterations=4,
).hex() == "a448017aaf21d8525fc10ae87aa6729d"

def possible_delta_b(delta_h):
    lo = delta_h & 0x1FFFF
    hi = delta_h >> 17
    return {
        ((lo << 15) + hi + carry_lo - (carry_hi << 15)) & MASK
        for carry_lo in (0, 1)
        for carry_hi in (0, 1)
    }

def expand(base, positions):
    for selection in range(1 << len(positions)):
        value = base
        for i, position in enumerate(positions):
            if selection >> i & 1:
                value |= 1 << position
        yield value

def make_candidates(msg, tag, q25, q26, bout, c, d, k,
                    known_mask, known_v):
    bit = 1 << k
    q25_new = q25 ^ bit
    w10 = struct.unpack_from("<I", msg, 40)[0]
    w10_new = (w10 + ror(q25_new, 9) - ror(q25, 9)) & MASK

    altered = bytearray(msg)
    struct.pack_into("<I", altered, 40, w10_new)

    r0 = q25 ^ q26
    tags = set()

    for sign in (1, -1):
        q26_new = rol(ror(q26, 11) + sign * bit, 11)
        mask = (q25_new ^ q25) ^ (q26_new ^ q26)
        fixed_h = (known_v ^ r0) & known_mask & mask
        free = [
            j for j in range(32)
            if (mask >> j & 1) and not (known_mask >> j & 1)
        ]
        if len(free) > 18:
            raise RuntimeError(f"Busca de candidatos ampla no bit {k}")

        for h in expand(fixed_h, free):
            delta_h = ((h ^ mask) - h) & MASK
            for delta_b in possible_delta_b(delta_h):
                b_new = (bout + delta_b) & MASK
                tags.add(
                    tag[:3] +
                    struct.pack(
                        "<III",
                        b_new,
                        (c + q26_new) & MASK,
                        (d + q25_new) & MASK,
                    )
                )

    return bytes(altered), sorted(tags)

def learn(k, new_tag, q25, q26, bout, c, d,
          known_mask, known_v, u_mask, u_value):
    bit = 1 << k
    b_new, c_new, d_new = struct.unpack("<III", new_tag[3:])
    q25_new = (d_new - d) & MASK
    q26_new = (c_new - c) & MASK

    if q25_new != (q25 ^ bit):
        raise RuntimeError(f"Estado D inconsistente no bit {k}")
   
    if k < 31:
        delta = (ror(q26_new, 11) - ror(q26, 11)) & MASK
        if delta == bit:
            input_bit = 0
        elif delta == (-bit) & MASK:
            input_bit = 1
        else:
            raise RuntimeError(f"Passo 22 inconsistente no bit {k}")
        u_value |= (input_bit ^ ((q25 >> k) & 1)) << k
        u_mask |= bit
   
    mask = (q25_new ^ q25) ^ (q26_new ^ q26)
    delta_b = (b_new - bout) & MASK
    r0 = q25 ^ q26
    positions = [j for j in range(32) if mask >> j & 1]

    fixed_ones = mask
    fixed_zeros = mask
    valid = 0

    for h in expand(0, positions):
        delta_h = ((h ^ mask) - h) & MASK
        if delta_b in possible_delta_b(delta_h):
            valid += 1
            fixed_ones &= h
            fixed_zeros &= (~h) & MASK

    if not valid:
        raise RuntimeError(f"Passo 23 inconsistente no bit {k}")

    new_mask = mask & (fixed_ones | fixed_zeros)
    new_v = (fixed_ones ^ (r0 & new_mask)) & new_mask

    if (known_v ^ new_v) & known_mask & new_mask:
        raise RuntimeError(f"Bits contraditórios de q24 no bit {k}")

    known_v = (known_v & (~new_mask & MASK)) | new_v
    known_mask |= new_mask
    return known_mask, known_v, u_mask, u_value

def recover_iv(msg, tag, msg2, tag2, c, d, q25, q26, bout,
               known_mask, known_v, u_mask, u_value):
    missing_v = [j for j in range(32) if not (known_mask >> j & 1)]
    missing_u = [j for j in range(32) if not (u_mask >> j & 1)]
    print(f"Bits finais a testar: q24={len(missing_v)}, U={len(missing_u)}",
          flush=True)

    if len(missing_v) + len(missing_u) > 12:
        raise RuntimeError("Restaram bits demais; envie a saída para ajustarmos")

    high_a = int.from_bytes(tag[:3], "little") << 8
    w14 = len(msg) * 8

    for v in expand(known_v, missing_v):
        for u in expand(u_value, missing_u):
            q23 = v ^ u
            q27 = rol(q23 + (q26 ^ q25 ^ v) + w14 + K[2], 15)
            b = (bout - q27) & MASK
            
            for low_a in range(256):
                a = ((high_a | low_a) - v) & MASK
                iv = (a, b, c, d)
                if md4(msg, iv)[1:] != tag:
                    continue
                if md4(msg2, iv)[1:] == tag2:
                    return iv

    raise RuntimeError("Nenhum IV validou as duas observações")

host = os.environ.get("MAYDAY_HOST", "10.83.15.149")
port = int(os.environ.get("MAYDAY_PORT", "1337"))

with socket.create_connection((host, port), timeout=15) as sock:
    sock.settimeout(30)
    pending = bytearray()

    def read_menu():
        while b"> " not in pending:
            part = sock.recv(8192)
            if not part:
                raise EOFError("A instância fechou a conexão")
            pending.extend(part)
        end = pending.index(b"> ") + 2
        reply = bytes(pending[:end])
        del pending[:end]
        return reply

    def observe():
        sock.sendall(b"1\n")
        reply = read_menu()
        matches = re.findall(
            rb"(?<![0-9a-f])[0-9a-f]{140}(?![0-9a-f])",
            reply,
        )
        if not matches:
            raise RuntimeError(f"Observação inesperada: {reply[:400]!r}")
        raw = bytes.fromhex(matches[-1].decode())
        return raw[:55], raw[55:]

    def test_tags(message, tags):
        tried = 0
        for off in range(0, len(tags), 32):
            batch = tags[off:off + 32]
            requests = b"".join(
                b"2\n" + (message + candidate).hex().encode() + b"\n"
                for candidate in batch
            )
            sock.sendall(requests)

            winner = None
            for candidate in batch:
                reply = read_menu()
                tried += 1
                if b"Command accepted." in reply:
                    winner = candidate
                elif b"Authentication failed." not in reply:
                    raise RuntimeError(f"Resposta inesperada: {reply[:400]!r}")

            if winner is not None:
                return winner, tried
        return None, tried

    read_menu()
    msg, tag = observe()
    msg2, tag2 = observe()

    if len(msg) != 55 or len(tag) != 15 or msg[:24] != msg2[:24]:
        raise RuntimeError("Formato das observações diferente do código analisado")

    c, d = struct.unpack_from("<II", msg)
    bout, cout, dout = struct.unpack("<III", tag[3:])
    q25 = (dout - d) & MASK
    q26 = (cout - c) & MASK

    known_mask = known_v = u_mask = u_value = attempts = 0

    for k in range(31, -1, -1):
        altered, candidates = make_candidates(
            msg, tag, q25, q26, bout, c, d, k,
            known_mask, known_v,
        )
        if attempts + len(candidates) >= 32000:
            raise RuntimeError("Limite de verificações próximo")

        accepted, used = test_tags(altered, candidates)
        attempts += used
        if accepted is None:
            raise RuntimeError(
                f"Nenhuma tag aceita no bit {k}; "
                f"{len(candidates)} candidatas testadas"
            )

        known_mask, known_v, u_mask, u_value = learn(
            k, accepted, q25, q26, bout, c, d,
            known_mask, known_v, u_mask, u_value,
        )
        print(
            f"bit {k:2}: tag aceita; "
            f"{attempts} verificações acumuladas",
            flush=True,
        )

    iv = recover_iv(
        msg, tag, msg2, tag2, c, d, q25, q26, bout,
        known_mask, known_v, u_mask, u_value,
    )
    print(f"64 bits recuperados: A={iv[0]:08x} B={iv[1]:08x}", flush=True)

    target = msg[:24] + b"give me a flag!."
    forged_tag = md4(target, iv)[1:]
    sock.sendall(b"2\n" + (target + forged_tag).hex().encode() + b"\n")
    result = read_menu().decode(errors="replace")
    print(result)

    if "PP{" not in result:
        raise RuntimeError("IV recuperado, mas a resposta final não contém a flag")
```

### Flag

```text
PP{d0_n07_m3ss_wi7h_c0mpr3ssi0n_func7i0ns::lOpQGytuXobY}
```

### Takeaway

The 15-byte tag still exposed three complete state words and most of the fourth. The fixed command prefix also disclosed half of the IV. By changing a message word used only in the final steps, the verification endpoint became a differential oracle for the hidden state. The reduced MD4 schedule made that final-round information sufficient to recover the remaining IV words and forge the required command.
