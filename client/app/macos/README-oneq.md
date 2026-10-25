# oneq on macOS (source only, NOT built or tested)

There was no Mac available. What is prepared: the core builds as `liboneq_core.dylib` (`cargo build --release -p oneq-core
--target aarch64-apple-darwin` / `x86_64-apple-darwin`, tun-rs creates a `utun` device) and the sandbox is off in the
entitlements. What is missing and needs a Mac:

1. Copy `liboneq_core.dylib` into `Contents/Frameworks` of the app (an Xcode "Copy Files" phase) and sign it.
2. Creating a utun device needs root. Either start the app with `sudo`, or add a privileged helper (SMAppService
   daemon) that runs `oneq_prepare/oneq_run`; the UI then talks to it instead of loading the library itself.
3. Notarisation if the app is distributed outside the App Store.
