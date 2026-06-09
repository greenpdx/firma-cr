//! firma-cr-agent — Pi-native (aarch64) BCCR GAUDI web-signing agent.
//! Local `/dyn/<action>` HTTP API backed by the clean-room PKCS#11 driver
//! (loaded as a .so) and the PAdES/CMS/XAdES signer in this crate.
//! See `DESIGN.md`. Now a feature-gated module of `firma-cr-core`.

pub mod api;
pub mod dyn_request;
pub mod http;
pub mod session;
pub mod sign;
pub mod token;
