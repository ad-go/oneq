//! oneq client core: the post-quantum layer-2 mesh seen from a layer-3 device (Windows, macOS, Android, Linux).
//!
//! Wire-compatible with the Python `oneqnode` (`tunmesh-pq/v2`). Educational project, not independently audited.
pub mod client;
pub mod control;
pub mod engine;
pub mod ffi;
pub mod frag;
pub mod fuzzing;
#[cfg(target_os = "macos")]
pub mod menubar;
pub mod l3;
pub mod nat;
pub mod nativehost;
pub mod netstack;
pub mod peer;
pub mod portmap;
pub mod proxy;
pub mod relay;
pub mod relaysvc;
pub mod routes_os;
pub mod socks;
pub mod status;
pub mod svc;
#[cfg(windows)]
pub mod winsvc;
pub mod tls;
pub mod update;
pub mod ui;
pub mod wire;

pub use client::{create_tun, load_or_create_identity, prepare, run, run_port, Config, Prepared};
pub use status::{Snapshot, Status};
