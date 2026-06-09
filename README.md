# Firma CR

Open-source digital-signature toolkit for the Costa Rica BCCR *Firma Digital*
smart card — a Firmador / SCManager replacement. Works with **any** PKCS#11
module (the official Idopte driver, OpenSC, …).

## Crates
- **firma-cr-core** — ETSI signer (PAdES / CAdES / XAdES + verify), the local
  `/dyn` web-signing agent, and the `firma-cr` CLI.
- **firma-cr-card** — PKCS#11 client: load any driver, card info, login, read
  cert, sign, PKCS#15 discovery (`probe` feature).

Desktop GUI: the **firma-cr-gui** repo. License: GPL-3.0-or-later.
