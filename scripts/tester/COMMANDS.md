# Firma CR — tester commands (RPi, Debian 13 trixie, aarch64)

## 0. SSH + git + clone
```sh
sudo apt-get update -qq && sudo apt-get install -y git openssh-client
ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519
cat ~/.ssh/id_ed25519.pub          # add this to GitHub → Settings → SSH keys
ssh -o StrictHostKeyChecking=accept-new -T git@github.com   # expect "successfully authenticated"
git clone git@github.com:greenpdx/firma-cr.git          ~/firma-cr
git clone git@github.com:greenpdx/firma-cr-engine.git   ~/firma-cr-engine
git clone git@github.com:greenpdx/firma-cr-analysis.git ~/firma-cr-analysis
```

## 1. Dependencies
```sh
sudo apt-get update -qq
sudo apt-get install -y \
  build-essential pkg-config curl wget file ca-certificates git libssl-dev \
  pcscd libpcsclite-dev pcsc-tools libccid \
  libwebkit2gtk-4.1-dev libgtk-3-dev libsoup-3.0-dev librsvg2-dev libayatana-appindicator3-dev \
  poppler-utils nodejs npm
sudo systemctl enable --now pcscd
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal
source ~/.cargo/env
```

## 2. Build + install
```sh
# driver (closed)
cd ~/firma-cr-engine && cargo build --release -p firma-cr-pkcs11
sudo install -Dm755 target/release/libfirma_cr_pkcs11.so /usr/lib/firma-cr/libfirma_cr_pkcs11.so
# agent + CLI (open)
cd ~/firma-cr && cargo build --release -p firma-cr-core --features agent --bin firma-cr-agent --bin firma-cr
```

## 3. Stack check (insert the real card; no PIN)
```sh
systemctl is-active pcscd
pcsc_scan                          # Ctrl-C once you see the card ATR
~/firma-cr/target/release/firma-cr list    # expect a slot with a token
~/firma-cr/target/release/firma-cr info    # expect the card certificate (CN)
```

## 4. Run the GUI
```sh
sudo ss -ltnp | grep 41231 || true         # if SCManager/GAUDI holds :41231, stop it first
cd ~/firma-cr/gui && npm install
npm run tauri dev                           # opens "Firma CR — firmador" (first build slow)
# Test: Tarjeta = card info · Firmar = add PDF, place box, Sign, enter PIN · Documento = view
pdfsig ~/path/to/signed.pdf                 # expect "Signature is Valid"
```

### Build an installable .deb instead
```sh
cd ~/firma-cr/gui && npm run tauri build -- --bundles deb
# -> src-tauri/target/release/bundle/deb/*.deb   →   sudo apt install ./<file>.deb
```
