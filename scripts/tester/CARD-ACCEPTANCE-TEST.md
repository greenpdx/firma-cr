# Firma CR — card acceptance test

A short, self-contained run-through to confirm **Firma CR works end-to-end on
your real BCCR Firma Digital card**: the card is read, you can sign documents,
and the signatures verify. No prior knowledge of the codebase needed.

Please work top to bottom and fill in the **Results** table at the end. Each step
says **PASS if …**; if something differs, copy the exact command + full output.

⏱️ ~30 minutes. You will enter your **card PIN** a few times — that's expected.

---

## 0. What you need

- Your **BCCR Firma Digital card** + its **PC/SC reader**, and **internet**.
- A Linux machine set up per the tester guide
  ([`README.md`](README.md), steps 1–4 = install deps → build → stack check →
  GUI). If those four steps already passed, you're ready.
- One sample **PDF** (e.g. `~/sample.pdf`) — any small PDF is fine.
- The **BCCR national CA root** saved as `~/bccr-chain.pem` (used to *verify*
  signatures). How to get it: see
  [`SECURITY-TEST-FLOW.md`](SECURITY-TEST-FLOW.md) → "Getting `~/bccr-chain.pem`".

Set up shell shortcuts (in the `scripts/tester` folder):
```sh
cd ~/firma-cr/scripts/tester && source ./env.sh   # defines $CLI_BIN, $AGENT_BIN
TSA="https://tsa.firmadigital.go.cr/tsa"           # BCCR timestamp service
CA="$HOME/bccr-chain.pem"
```

> Two ways to sign: the **GUI** (easiest — Part B) or the **command line**
> (Part C). Do **both** if you can; if short on time, the GUI (Part B) is the
> minimum.

---

## A. The card is readable (no PIN)

Insert the card, then:
```sh
pcsc_scan          # press Ctrl-C once you see the card's ATR
$CLI_BIN list      # should list a slot with a token present
$CLI_BIN info      # should print your certificate (your name / CN)
```
**PASS if** `list` shows a token and `info` prints your certificate details. No
PIN is asked here.

If this fails, stop — the rest depends on it. Note whether `pcsc_scan` saw the
card, and re-seat the card / `sudo systemctl restart pcscd` and retry.

---

## B. Sign a PDF in the GUI

Launch the app:
```sh
cd ~/firma-cr/gui && npm run tauri dev      # or open the installed "Firma CR" app
```
Then:
1. **Tarjeta** tab → your card, token, and certificate (your name) appear — **no
   PIN**.
2. **Firmar** tab → add `~/sample.pdf`, drag the signature box onto the page
   preview. Turn **on** the **sello de tiempo (TSA)** switch — it should already
   show `https://tsa.firmadigital.go.cr/tsa`. Click **Sign / Firmar** and enter
   your **PIN** once.
3. **Documento** tab → the signed PDF opens inline.
4. Check it independently:
   ```sh
   pdfsig ~/<the-signed-file>.pdf
   ```

**PASS if** the signed PDF is produced, opens in the **Documento** tab, and
`pdfsig` prints **`Signature is Valid`** (and shows a signing time / timestamp).

---

## C. Sign + verify from the command line

### C1 — PDF, basic
```sh
$CLI_BIN pdf -i ~/sample.pdf -o ~/test-basic.pdf --pin-prompt
$CLI_BIN verify pdf --in ~/test-basic.pdf --ca-file "$CA"
pdfsig ~/test-basic.pdf
```
**PASS if** our verify says the signature is OK **and** `pdfsig` says
`Signature is Valid` with `Total document signed`.

### C2 — PDF, with a timestamp (uses the live BCCR TSA)
```sh
$CLI_BIN pdf -i ~/sample.pdf -o ~/test-ts.pdf --profile T --tsa-url "$TSA" --pin-prompt
$CLI_BIN verify pdf --in ~/test-ts.pdf --ca-file "$CA" --json
```
**PASS if** signing succeeds and the verify output shows `"has_timestamp": true`
with a timestamp verdict of `"ok": true`.

### C3 — XML (XAdES), and check it in another tool
```sh
$CLI_BIN xml -i ~/sample.xml -o ~/test-signed.xml --pin-prompt
$CLI_BIN verify xml --in ~/test-signed.xml --ca-file "$CA"
```
Then open `~/test-signed.xml` in the **BCCR online validator**
(<https://firmadigital.go.cr> → "Validar") or another signature checker.
**PASS if** our verifier accepts it **and** the other tool also accepts it.
(Report the other tool's exact message either way.)

### C4 — a tampered file must be REJECTED
```sh
cp ~/test-basic.pdf ~/test-tampered.pdf
printf 'EXTRA' >> ~/test-tampered.pdf
$CLI_BIN verify pdf --in ~/test-tampered.pdf --ca-file "$CA" ; echo "exit=$?"
```
**PASS if** verify **rejects** it (says not valid, non-zero `exit=`). A signer
that accepts a modified file would be the real problem.

---

## D. Repeat-sign (don't re-insert the card)

Sign three times in a row without removing the card:
```sh
for n in 1 2 3; do $CLI_BIN pdf -i ~/sample.pdf -o ~/test-rep-$n.pdf --pin-prompt; done
```
**PASS if** all three succeed. (If the second or third fails with a card error,
note it — that's a regression we need to know about.)

---

## E. GUI controls (menu + Documento viewer)

Checks the recently-changed GUI chrome. Do these in the **GUI** with a signed PDF
open in the **Documento** tab (e.g. the one from step B). No card needed except
where a step signs.

- **E1 — ☰ menu (Exit):** click the **☰** button (top-left). A menu opens with
  **Configuración** and **Salir**. *Configuración* opens the settings dialog;
  *Salir* quits the app. Clicking elsewhere / pressing Esc closes the menu.
  **PASS if** the menu opens and **Salir** quits.
- **E2 — Documento viewer (no edit tools):** the PDF shows in our own viewer.
  **PASS if** it **scrolls** through all pages, **zoom** (− / + / **Ajustar**)
  works, the page indicator updates, and there are **no editing/annotation
  tools** anywhere.
- **E3 — Guardar (Save):** click **Guardar** → a native **Save** dialog appears;
  pick a path. **PASS if** the file is written there (open it to confirm).
- **E4 — Imprimir (Print):** click **Imprimir**. **PASS if** the PDF opens in the
  system's default PDF app (where you can print).
- **E5 — Cerrar (Close):** click **Cerrar**. **PASS if** the viewer clears back to
  the empty state and the app keeps running (it must **not** quit).

> If a button does nothing, open DevTools (F12) → Console and paste what shows
> when you click it — the app logs `[firma-cr] click: …` and any `‼ error:`.

---

## Results — please fill in and send back

| Step | What | PASS / FAIL | Notes (paste output on FAIL) |
|------|------|-------------|------------------------------|
| A    | card read (`list` / `info`, no PIN) | | |
| B    | GUI: sign PDF + `pdfsig` valid + timestamp | | |
| C1   | CLI: sign PDF + verify + `pdfsig` valid | | |
| C2   | CLI: timestamped PDF verifies (`has_timestamp`) | | |
| C3   | CLI: XAdES verifies in **our** tool **and** another tool | | |
| C4   | tampered PDF is **rejected** | | |
| D    | three signs in one session all succeed | | |
| E1   | ☰ menu opens; **Salir** quits | | |
| E2   | Documento viewer: scroll + zoom, **no edit tools** | | |
| E3   | **Guardar** writes via the native Save dialog | | |
| E4   | **Imprimir** opens the system PDF app | | |
| E5   | **Cerrar** clears the view (does not quit) | | |

Also send:
- The reader model and `pcsc_scan` ATR line.
- For any FAIL: the exact command and its **full** output (add `--json` to
  `verify` for machine-readable detail).
- For **C3**, the other validator's exact verdict text (this is the most useful
  single result — it confirms our signatures interoperate).

Thank you! 🙏

---

*Deeper security-regression checks (negative tests, driver fallback, multi-session,
and on-card data capture for open items) live in
[`SECURITY-TEST-FLOW.md`](SECURITY-TEST-FLOW.md) — run those if you have time.*
