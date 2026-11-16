# Fishies

**Platypwn CTF**

**Category:** Web  
**Challenge:** Fish Pond

## Fishies Writeup

### Overview

Fish Pond lets users add ASCII fish and report them for review. Reporting a fish launches a Puppeteer browser with an administrator cookie and opens the fish page. The challenge combines a broken HTML escape routine, an unsafe recursive merge, and inherited Puppeteer launch options to read `/flag.txt`.

The exploit chain is:

```text
Fish markup injection
    → XSS in the administrator's browser
    → prototype pollution in the Node.js process
    → Puppeteer launches npm with attacker-controlled NODE_OPTIONS
    → Node.js reads /flag.txt and posts it back as a fish
```

### The XSS

The fish page places the submitted ASCII inside a `<pre>` element in a `<template>`. Its custom `escape()` function tries to replace `<` and `>`, but it edits the string while iterating with indices from the original string. A crafted sequence of tags escapes the `<pre>` and template and places a script in the document:

```text
<</pre x=<><</section x=<><</template x=<><<script x=<>
```

When a fish is reported, the bot visits its hash URL with the administrator cookie. The injected script can therefore call the admin-only fish data endpoint.

One detail matters: the escape routine also changes `>` characters inside JavaScript to `&gt;`. Character references are not decoded inside a script element, so arrow functions become invalid JavaScript (`=&gt;`). The payload uses regular `function` syntax and avoids literal angle brackets in the script body.

### Prototype pollution

The admin endpoint merges incoming fish data recursively:

```js
function combine(target, source) {
  if (!obj(target) || !obj(source)) return target;
  for (const key of Object.keys(source)) {
    if (obj(source[key])) {
      if (!target[key]) target[key] = {};
      combine(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
```

It does not reject `__proto__`. A JSON body containing that key makes `combine()` recurse into the target object's prototype. Since `fishData` is stored server-side, the pollution affects the Node.js process, not just the browser page.

### Turning pollution into code execution

The review handler launches Puppeteer with fixed Chrome arguments. However, Puppeteer also reads launch options such as `executablePath` and `env`. Those missing own properties can be resolved through the polluted `Object.prototype`.

The payload sets:

```json
{
  "__proto__": {
    "executablePath": "/usr/local/bin/npm",
    "env": {
      "PATH": "/usr/local/bin:/usr/bin:/bin",
      "HOME": "/tmp",
      "NODE_OPTIONS": "--import=data:text/javascript,..."
    }
  }
}
```

Using `node` directly as the executable did not work: Node treated Chrome's launch arguments as invalid Node options. The npm launcher runs a Node script first, then passes along its arguments. Node processes `NODE_OPTIONS` before that script, so the `--import` data URL executes before npm handles the Chrome arguments.

### Reading the flag

The imported module uses Node's filesystem API to read `/flag.txt`, then posts the value to the application's local fish API:

```js
import fs from 'node:fs';

const value = fs.readFileSync('/flag.txt', 'utf8').trim();

await fetch('http://127.0.0.1:80/api/fish', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({ascii: 'FLAG:' + value, fishData: {}})
});
```

The exploit uses two reviews. The first visits the XSS fish and applies the prototype pollution. The next review starts a new Puppeteer process, which launches npm with the inherited `executablePath` and environment. The imported module reads the flag and creates a fish containing it.

### Exploit flow

1. Submit a fish containing the crafted markup and JavaScript.
2. Report it; the administrator bot runs the script.
3. Use the admin PATCH route to pollute `Object.prototype` with `executablePath` and `env`.
4. Confirm the PATCH succeeded.
5. Report a fish again to start a new Puppeteer process.
6. npm starts Node with the `NODE_OPTIONS` data module.
7. The module reads `/flag.txt` and posts its contents as a fish.
8. Read the new fish from the page and submit the flag.

### Flag

```text
PP{h1jack1ng_th3_d3bugg3r_w1th_f1sh13s::enPnlILg5WTd}
```

### Takeaway

This challenge highlights how prototype pollution can turn seemingly harmless inherited properties into a critical security risk. Explicit configuration does not guarantee safety when security-sensitive components still trust properties inherited from mutable prototypes. The key lesson is to enforce strict property validation and prevent untrusted data from influencing process execution.
