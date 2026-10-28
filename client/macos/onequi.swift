import Cocoa

// MARK: - FlippedView (top→bottom layout in scroll views)
class FlippedView: NSView { override var isFlipped: Bool { true } }

// MARK: - API
final class OneqAPI {
    var base: URL?
    init() {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let candidates = [
            home.appendingPathComponent(".config/oneq/ui.url"),
            URL(fileURLWithPath: "/Library/Application Support/oneq/ui.url"),
            home.appendingPathComponent("Library/Application Support/oneq/ui.url"),
        ]
        for f in candidates {
            if let s = try? String(contentsOf: f, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
               !s.isEmpty, let u = URL(string: s) { base = u; break }
        }
    }
    func get(_ path: String, _ cb: @escaping ([String:Any]?)->Void) {
        guard let b = base, let u = URL(string: path, relativeTo: b) else { cb(nil); return }
        URLSession.shared.dataTask(with: u) { d,_,_ in
            let j = d.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String:Any] }
            DispatchQueue.main.async { cb(j) }
        }.resume()
    }
    func post(_ path: String, _ body: [String:Any], _ cb: @escaping ([String:Any]?)->Void) {
        guard let b = base, let u = URL(string: path, relativeTo: b),
              let data = try? JSONSerialization.data(withJSONObject: body) else { cb(nil); return }
        var req = URLRequest(url: u); req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type"); req.httpBody = data
        URLSession.shared.dataTask(with: req) { d,_,_ in
            let j = d.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String:Any] }
            DispatchQueue.main.async { cb(j) }
        }.resume()
    }
}

func fmtBytes(_ b: Int) -> String {
    let u = ["B","KB","MB","GB"]; var v = Double(b); var i = 0
    while v >= 1024 && i < 3 { v /= 1024; i += 1 }
    return i == 0 ? "\(b) B" : String(format: "%.1f %@", v, u[i])
}

// MARK: - Settings model (mirrors Flutter Settings)
struct OSettings {
    var relays:       [String] = []
    var community:    String   = ""
    var user:         String   = ""
    var name:         String   = ""
    var caPem:        String   = ""
    var forceRelay:   Bool     = false
    var acceptRoutes: Bool     = false
    var exitNode:     String   = ""
    var startHidden:  Bool     = false
    var autoStart:    Bool     = false
    var updateCheck:  Bool     = true

    var relaysText: String {
        get { relays.joined(separator: "\n") }
        set { relays = newValue.components(separatedBy: "\n").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty } }
    }
    var configured: Bool { !relays.isEmpty && !community.isEmpty && !user.isEmpty }

    func toJSON() -> [String:Any] {
        let m: [String:Any] = ["relays": relays, "community": community, "user": user,
                                "name": name, "ca_pem": caPem, "force_relay": forceRelay,
                                "accept_routes": acceptRoutes, "exit_node": exitNode,
                                "start_hidden": startHidden, "auto_start": autoStart,
                                "update_check": updateCheck]
        return m
    }

    static func fromJSON(_ j: [String:Any]) -> OSettings {
        var s = OSettings()
        s.relays       = (j["relays"] as? [String]) ?? []
        s.community    = j["community"]    as? String ?? ""
        s.user         = j["user"]         as? String ?? ""
        s.name         = j["name"]         as? String ?? ""
        s.caPem        = j["ca_pem"]       as? String ?? ""
        s.forceRelay   = j["force_relay"]  as? Bool ?? false
        s.acceptRoutes = j["accept_routes"] as? Bool ?? false
        s.exitNode     = j["exit_node"]    as? String ?? ""
        s.startHidden  = j["start_hidden"] as? Bool ?? false
        s.autoStart    = j["auto_start"]   as? Bool ?? false
        s.updateCheck  = j["update_check"] as? Bool ?? true
        return s
    }
}

// MARK: - Shared state (controller)
final class OState {
    var settings   = OSettings()
    var password   = ""
    var active     = false
    var busy       = false
    var error: String?
    var snap: [String:Any]?
    var peers: [[String:Any]] { snap?["peers"] as? [[String:Any]] ?? [] }
    var updateMessage = ""
    var updateBusy  = false
}

// MARK: - Export / Import helpers
func buildExportJSON(state: OState, withPassword: Bool, withKey: Bool) -> String {
    var m: [String:Any] = ["format": "oneq-settings", "version": 1, "settings": state.settings.toJSON()]
    if withPassword && !state.password.isEmpty { m["password"] = state.password }
    if withKey {
        let kf = keyFilePath()
        if let key = try? String(contentsOfFile: kf, encoding: .utf8) { m["node_key"] = key.trimmingCharacters(in: .whitespacesAndNewlines) }
    }
    if let data = try? JSONSerialization.data(withJSONObject: m, options: [.prettyPrinted]),
       let s = String(data: data, encoding: .utf8) { return s }
    return "{}"
}

func importJSON(_ text: String, state: OState) throws -> String {
    guard let data = text.data(using: .utf8),
          let obj = try? JSONSerialization.jsonObject(with: data) as? [String:Any] else { throw NSError(domain: "import", code: 1, userInfo: [NSLocalizedDescriptionKey: "Not a JSON file."]) }
    guard obj["format"] as? String == "oneq-settings" else { throw NSError(domain: "import", code: 2, userInfo: [NSLocalizedDescriptionKey: "Not a oneq settings file."]) }
    guard let sv = obj["version"] as? Int, sv == 1 else { throw NSError(domain: "import", code: 3, userInfo: [NSLocalizedDescriptionKey: "Unsupported settings version."]) }
    guard let sj = obj["settings"] as? [String:Any] else { throw NSError(domain: "import", code: 4, userInfo: [NSLocalizedDescriptionKey: "Missing settings."]) }
    state.settings = OSettings.fromJSON(sj)
    var parts = ["settings"]
    if let pw = obj["password"] as? String, !pw.isEmpty { state.password = pw; parts.append("password (in memory only)") }
    if let key = obj["node_key"] as? String, !key.isEmpty {
        let kf = keyFilePath()
        let dir = (kf as NSString).deletingLastPathComponent
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        let bakPath = kf + ".bak"
        if FileManager.default.fileExists(atPath: kf) { try? FileManager.default.moveItem(atPath: kf, toPath: bakPath) }
        try? (key + "\n").write(toFile: kf, atomically: true, encoding: .utf8)
        parts.append("node key (old kept as client.key.bak)")
    }
    return "Imported: \(parts.joined(separator: ", "))."
}

func keyFilePath() -> String {
    let home = FileManager.default.homeDirectoryForCurrentUser.path
    return "\(home)/.config/oneq/client.key"
}

// MARK: - Settings panel (SettingsPage equivalent)
final class SettingsVC: NSViewController {
    let api: OneqAPI
    let state: OState
    var onChanged: (() -> Void)?

    // connection fields
    let relaysField   = NSTextView(); let communityField = NSTextField()
    let userField     = NSTextField(); let passwordField  = NSSecureTextField()
    let nameField     = NSTextField(); let caField        = NSTextView()
    let forceRelayChk = NSButton();   let acceptRoutesChk = NSButton()
    let exitNodePop   = NSPopUpButton()
    let startHiddenChk = NSButton();  let autoStartChk   = NSButton()
    let updateCheckChk = NSButton()
    let checkUpdateBtn = NSButton()
    let updateMsgLbl   = NSTextField(labelWithString: "")
    let saveBtn        = NSButton()
    let noteLabel      = NSTextField(labelWithString: "")

    // export
    let withPasswordChk = NSButton(); let withKeyChk = NSButton()
    let exportFileBtn   = NSButton(); let exportClipBtn = NSButton()
    let importFileBtn   = NSButton(); let importClipBtn = NSButton()

    // service
    let serviceLbl  = NSTextField(labelWithString: "Status: unknown")
    let svcStartBtn = NSButton(); let svcStopBtn = NSButton(); let svcUninstallBtn = NSButton()

    var onBack: (() -> Void)?

    init(api: OneqAPI, state: OState) { self.api = api; self.state = state; super.init(nibName: nil, bundle: nil) }
    required init?(coder: NSCoder) { fatalError() }

    // container: header (fixed) + scroll (fills rest)
    override func loadView() { view = NSView() }

    override func viewDidLoad() {
        super.viewDidLoad()
        buildChrome()
    }

    // called by RootVC before showing this VC
    func fillFormAndRefresh() { fillForm(); refreshService() }

    func buildChrome() {
        // header
        let header = NSView(); header.translatesAutoresizingMaskIntoConstraints = false
        let backBtn = NSButton(title: "‹ Back", target: self, action: #selector(goBack))
        backBtn.bezelStyle = .inline; backBtn.isBordered = false; backBtn.font = .systemFont(ofSize: 13)
        backBtn.translatesAutoresizingMaskIntoConstraints = false
        let titleLbl = NSTextField(labelWithString: "Settings")
        titleLbl.font = .boldSystemFont(ofSize: 13); titleLbl.translatesAutoresizingMaskIntoConstraints = false
        header.addSubview(backBtn); header.addSubview(titleLbl)
        NSLayoutConstraint.activate([
            header.heightAnchor.constraint(equalToConstant: 40),
            backBtn.leadingAnchor.constraint(equalTo: header.leadingAnchor, constant: 10),
            backBtn.centerYAnchor.constraint(equalTo: header.centerYAnchor),
            titleLbl.centerXAnchor.constraint(equalTo: header.centerXAnchor),
            titleLbl.centerYAnchor.constraint(equalTo: header.centerYAnchor),
        ])
        let sep = NSBox(); sep.boxType = .separator; sep.translatesAutoresizingMaskIntoConstraints = false

        // scroll view — documentView is FlippedView so layout flows top→bottom
        let scroll = NSScrollView(); scroll.hasVerticalScroller = true; scroll.autohidesScrollers = true
        scroll.drawsBackground = false; scroll.translatesAutoresizingMaskIntoConstraints = false
        let docFV = FlippedView(); docFV.translatesAutoresizingMaskIntoConstraints = false
        scroll.documentView = docFV
        // width tracks scroll width; height grows from content via bottom spacer in buildUI
        docFV.widthAnchor.constraint(equalTo: scroll.contentView.widthAnchor).isActive = true

        view.addSubview(header); view.addSubview(sep); view.addSubview(scroll)
        NSLayoutConstraint.activate([
            header.topAnchor.constraint(equalTo: view.topAnchor),
            header.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            header.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            sep.topAnchor.constraint(equalTo: header.bottomAnchor),
            sep.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            sep.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            scroll.topAnchor.constraint(equalTo: sep.bottomAnchor),
            scroll.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            scroll.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            scroll.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])

        // build fields directly into docFV (one layer, no extra wrapper)
        buildUI(in: docFV)
        fillForm()
        refreshService()
    }

    @objc func goBack() { onBack?() }

    func fillForm() {
        let s = state.settings
        let locked = state.active || state.busy
        relaysField.string   = s.relaysText
        communityField.stringValue = s.community
        userField.stringValue      = s.user
        passwordField.stringValue  = state.password
        nameField.stringValue      = s.name
        caField.string             = s.caPem
        forceRelayChk.state    = s.forceRelay   ? .on : .off
        acceptRoutesChk.state  = s.acceptRoutes  ? .on : .off
        startHiddenChk.state   = s.startHidden   ? .on : .off
        autoStartChk.state     = s.autoStart     ? .on : .off
        updateCheckChk.state   = s.updateCheck   ? .on : .off
        for f in [communityField, userField, nameField] { f.isEnabled = !locked }
        [forceRelayChk, acceptRoutesChk, startHiddenChk, autoStartChk].forEach { $0.isEnabled = !locked }
        saveBtn.isEnabled = !locked
        importFileBtn.isEnabled = !locked; importClipBtn.isEnabled = !locked
        rebuildExitNodePopup()
    }

    func readForm() {
        state.settings.relaysText  = relaysField.string
        state.settings.community   = communityField.stringValue.trimmingCharacters(in: .whitespaces)
        state.settings.user        = userField.stringValue.trimmingCharacters(in: .whitespaces)
        state.settings.name        = nameField.stringValue.trimmingCharacters(in: .whitespaces)
        state.settings.caPem       = caField.string
        state.password             = passwordField.stringValue
        state.settings.forceRelay  = forceRelayChk.state == .on
        state.settings.acceptRoutes = acceptRoutesChk.state == .on
        state.settings.startHidden  = startHiddenChk.state == .on
        state.settings.autoStart    = autoStartChk.state == .on
        state.settings.updateCheck  = updateCheckChk.state == .on
        if let sel = exitNodePop.selectedItem?.representedObject as? String { state.settings.exitNode = sel }
    }

    func rebuildExitNodePopup() {
        exitNodePop.removeAllItems()
        let noneItem = NSMenuItem(title: "None — direct internet", action: nil, keyEquivalent: "")
        noneItem.representedObject = "" as AnyObject
        exitNodePop.menu?.addItem(noneItem)
        for p in state.peers where p["exit_node"] as? Bool == true {
            let nm = p["name"] as? String ?? ""; let pub = p["public_ip"] as? String ?? ""
            let title = pub.isEmpty ? nm : "\(nm)  (\(pub))"
            let it = NSMenuItem(title: title, action: nil, keyEquivalent: "")
            it.representedObject = nm as AnyObject
            exitNodePop.menu?.addItem(it)
        }
        // select current
        for it in exitNodePop.itemArray where (it.representedObject as? String) == state.settings.exitNode {
            exitNodePop.select(it); break
        }
    }

    func say(_ msg: String, error: Bool = false) {
        noteLabel.stringValue = msg
        noteLabel.textColor   = error ? .systemRed : .systemGreen
        noteLabel.isHidden    = false
    }

    @objc func doSave() {
        readForm()
        let j = state.settings.toJSON()
        api.post("api/settings", j) { [weak self] resp in
            if let err = resp?["error"] as? String { self?.say(err, error: true) }
            else { self?.say("Saved."); self?.onChanged?() }
        }
    }

    @objc func doCheckUpdate() {
        state.updateBusy = true; updateMsgLbl.stringValue = "Checking..."
        api.post("api/update", ["force": true]) { [weak self] resp in
            self?.state.updateBusy = false
            if let msg = resp?["message"] as? String { self?.updateMsgLbl.stringValue = msg }
            else { self?.updateMsgLbl.stringValue = "No update info available." }
        }
    }

    @objc func doExportFile() {
        readForm()
        guard confirmExportSecrets() else { return }
        let text = buildExportJSON(state: state, withPassword: withPasswordChk.state == .on, withKey: withKeyChk.state == .on)
        let panel = NSSavePanel(); panel.nameFieldStringValue = "oneq-settings.json"
        panel.allowedFileTypes = ["json"]
        panel.beginSheetModal(for: view.window!) { [weak self] r in
            guard r == .OK, let url = panel.url else { return }
            do { try text.write(to: url, atomically: true, encoding: .utf8); self?.say("Exported to \(url.path)") }
            catch { self?.say("Export failed: \(error)", error: true) }
        }
    }

    @objc func doExportClipboard() {
        readForm()
        guard confirmExportSecrets() else { return }
        let text = buildExportJSON(state: state, withPassword: withPasswordChk.state == .on, withKey: withKeyChk.state == .on)
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        say("Copied to the clipboard.")
    }

    @objc func doImportFile() {
        let panel = NSOpenPanel(); panel.allowedFileTypes = ["json"]
        panel.beginSheetModal(for: view.window!) { [weak self] r in
            guard let self = self, r == .OK, let url = panel.url else { return }
            do {
                let text = try String(contentsOf: url, encoding: .utf8)
                let msg  = try importJSON(text, state: self.state)
                self.fillForm(); self.say(msg); self.onChanged?()
            } catch { self.say("Import failed: \(error.localizedDescription)", error: true) }
        }
    }

    @objc func doImportClipboard() {
        guard let text = NSPasteboard.general.string(forType: .string) else { say("Clipboard is empty.", error: true); return }
        do { let msg = try importJSON(text, state: state); fillForm(); say(msg); onChanged?() }
        catch { say("Import failed: \(error.localizedDescription)", error: true) }
    }

    func confirmExportSecrets() -> Bool {
        let wPw = withPasswordChk.state == .on; let wKey = withKeyChk.state == .on
        guard wPw || wKey else { return true }
        let what = [wPw ? "your password in plain text" : nil, wKey ? "this device's node key" : nil].compactMap{$0}.joined(separator: " and ")
        let a = NSAlert(); a.messageText = "The file will contain secrets"
        a.informativeText = "The exported file will contain \(what). Anyone who gets the file can use it to join your network. Store it somewhere private."
        a.addButton(withTitle: "Export anyway"); a.addButton(withTitle: "Cancel")
        return a.runModal() == .alertFirstButtonReturn
    }

    func refreshService() {
        api.get("api/status") { [weak self] j in
            guard let self = self else { return }
            let running = j?["running"] as? Bool ?? false
            let state   = (j?["snapshot"] as? [String:Any])?["state"] as? String ?? ""
            self.serviceLbl.stringValue = running ? "running (\(state))" : "not running"
        }
    }

    @objc func doSvcAction(_ sender: NSButton) {
        let action = sender.identifier?.rawValue ?? "stop"
        svcStartBtn.isEnabled = false; svcStopBtn.isEnabled = false; svcUninstallBtn.isEnabled = false
        api.post("api/service", ["action": action]) { [weak self] resp in
            guard let self = self else { return }
            self.svcStartBtn.isEnabled = true; self.svcStopBtn.isEnabled = true; self.svcUninstallBtn.isEnabled = true
            if let err = resp?["error"] as? String { self.say(err, error: true) }
            else { self.say("Service: \(action) done."); self.refreshService(); self.onChanged?() }
        }
    }

    // MARK: - Build UI

    func buildUI(in container: NSView) {
        let p: CGFloat = 16
        var cursor: NSView? = nil

        func head(_ t: String) -> NSTextField {
            let l = NSTextField(labelWithString: t); l.font = .boldSystemFont(ofSize: 13); return l
        }
        func sub(_ t: String) -> NSTextField {
            let l = NSTextField(labelWithString: t); l.font = .systemFont(ofSize: 11); l.textColor = .secondaryLabelColor
            l.maximumNumberOfLines = 0; l.lineBreakMode = .byWordWrapping; return l
        }
        func lbl(_ t: String) -> NSTextField {
            let l = NSTextField(labelWithString: t); l.font = .systemFont(ofSize: 11); l.textColor = .secondaryLabelColor; return l
        }
        func chk(_ t: String, _ b: NSButton) { b.setButtonType(.switch); b.title = t }
        func btn(_ b: NSButton, _ t: String, _ act: Selector) { b.title = t; b.target = self; b.action = act; b.bezelStyle = .rounded }
        func obtn(_ b: NSButton, _ t: String, _ act: Selector) { b.title = t; b.target = self; b.action = act; b.bezelStyle = .rounded }

        func addV(_ v: NSView, spacing: CGFloat = 8) {
            v.translatesAutoresizingMaskIntoConstraints = false
            container.addSubview(v)
            let topC = cursor == nil ? v.topAnchor.constraint(equalTo: container.topAnchor, constant: p)
                                     : v.topAnchor.constraint(equalTo: cursor!.bottomAnchor, constant: spacing)
            NSLayoutConstraint.activate([topC,
                v.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: p),
                v.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -p)])
            cursor = v
        }

        func addScrollTV(_ tv: NSTextView, height: CGFloat) {
            let sv = NSScrollView(); sv.hasVerticalScroller = true; sv.autohidesScrollers = true
            sv.documentView = tv; sv.borderType = .bezelBorder
            tv.isVerticallyResizable = true; tv.autoresizingMask = .width
            sv.translatesAutoresizingMaskIntoConstraints = false
            container.addSubview(sv)
            let topC = cursor == nil ? sv.topAnchor.constraint(equalTo: container.topAnchor, constant: p)
                                     : sv.topAnchor.constraint(equalTo: cursor!.bottomAnchor, constant: 4)
            NSLayoutConstraint.activate([topC, sv.heightAnchor.constraint(equalToConstant: height),
                sv.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: p),
                sv.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -p)])
            cursor = sv
        }

        func divider() {
            let box = NSBox(); box.boxType = .separator
            addV(box, spacing: 16)
        }

        func hrow(_ views: [NSView], spacing: CGFloat = 8) -> NSView {
            let s = NSStackView(views: views); s.spacing = spacing; s.alignment = .centerY; return s
        }

        // ── Connection ──────────────────────────────────────────────────────
        addV(head("Connection"), spacing: p)
        addV(lbl("Relays (https://host:port, one per line)"), spacing: 10)
        addScrollTV(relaysField, height: 52)
        addV(lbl("Community"), spacing: 8); addV(communityField, spacing: 4)
        addV(lbl("User"), spacing: 8); addV(userField, spacing: 4)
        addV(lbl("Password (not saved)"), spacing: 8); addV(passwordField, spacing: 4)
        addV(lbl("Device name (optional)"), spacing: 8); addV(nameField, spacing: 4)
        addV(lbl("Private CA certificate, PEM (empty = public CAs)"), spacing: 8)
        addScrollTV(caField, height: 60)

        chk("Send everything through the relay", forceRelayChk); addV(forceRelayChk, spacing: 10)

        chk("Use routed networks", acceptRoutesChk); addV(acceptRoutesChk, spacing: 6)
        addV(sub("Reach the private networks routed through a gateway member."), spacing: 0)

        addV(lbl("Exit node (route internet traffic through)"), spacing: 10)
        exitNodePop.bezelStyle = .rounded; addV(exitNodePop, spacing: 4)

        chk("Start hidden in the tray", startHiddenChk); addV(startHiddenChk, spacing: 10)

        chk("Start at boot", autoStartChk); addV(autoStartChk, spacing: 6)
        addV(sub("The node runs as a background service. With this on, the service starts at boot, before anyone logs in."), spacing: 0)

        chk("Check for updates automatically", updateCheckChk); addV(updateCheckChk, spacing: 10)
        updateMsgLbl.textColor = .secondaryLabelColor; updateMsgLbl.font = .systemFont(ofSize: 12)
        checkUpdateBtn.title = "Check for updates"; checkUpdateBtn.bezelStyle = .rounded
        checkUpdateBtn.target = self; checkUpdateBtn.action = #selector(doCheckUpdate)
        addV(hrow([checkUpdateBtn, updateMsgLbl]), spacing: 6)

        saveBtn.title = "Save"; saveBtn.bezelStyle = .rounded; saveBtn.keyEquivalent = "\r"
        saveBtn.target = self; saveBtn.action = #selector(doSave)
        addV(saveBtn, spacing: 12)

        // ── Export / Import ─────────────────────────────────────────────────
        divider()
        addV(head("Export and import"), spacing: p)
        addV(sub("Settings are exported as a JSON file. Secrets are left out unless you tick them."), spacing: 4)

        chk("Include the password (plain text)", withPasswordChk); addV(withPasswordChk, spacing: 8)
        chk("Include this device's node key (keeps its address; moves the identity)", withKeyChk)
        addV(withKeyChk, spacing: 10)

        exportFileBtn.title = "Export to file…"; exportFileBtn.bezelStyle = .rounded; exportFileBtn.target = self; exportFileBtn.action = #selector(doExportFile)
        exportClipBtn.title = "Copy to clipboard"; exportClipBtn.bezelStyle = .rounded; exportClipBtn.target = self; exportClipBtn.action = #selector(doExportClipboard)
        importFileBtn.title = "Import from file…"; importFileBtn.bezelStyle = .rounded; importFileBtn.target = self; importFileBtn.action = #selector(doImportFile)
        importClipBtn.title = "Paste from clipboard"; importClipBtn.bezelStyle = .rounded; importClipBtn.target = self; importClipBtn.action = #selector(doImportClipboard)
        addV(hrow([exportFileBtn, exportClipBtn]), spacing: 6)
        addV(hrow([importFileBtn, importClipBtn]), spacing: 6)

        // ── Background service ──────────────────────────────────────────────
        divider()
        addV(head("Background service"), spacing: p)
        addV(sub("Keeps the node connected from boot, even when nobody is logged in and this window is closed."), spacing: 4)
        addV(serviceLbl, spacing: 8)

        svcStartBtn.title = "Start"; svcStartBtn.bezelStyle = .rounded; svcStartBtn.target = self; svcStartBtn.action = #selector(doSvcAction(_:))
        svcStartBtn.identifier = NSUserInterfaceItemIdentifier("start")
        svcStopBtn.title = "Stop"; svcStopBtn.bezelStyle = .rounded; svcStopBtn.target = self; svcStopBtn.action = #selector(doSvcAction(_:))
        svcStopBtn.identifier = NSUserInterfaceItemIdentifier("stop")
        svcUninstallBtn.title = "Uninstall"; svcUninstallBtn.bezelStyle = .rounded; svcUninstallBtn.target = self; svcUninstallBtn.action = #selector(doSvcAction(_:))
        svcUninstallBtn.identifier = NSUserInterfaceItemIdentifier("uninstall")
        addV(hrow([svcStartBtn, svcStopBtn, svcUninstallBtn]), spacing: 6)

        noteLabel.isHidden = true; noteLabel.font = .systemFont(ofSize: 12); noteLabel.maximumNumberOfLines = 3
        addV(noteLabel, spacing: 12)

        // bottom spacer — pins container height for scroll
        let bottom = NSView(); bottom.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(bottom)
        NSLayoutConstraint.activate([
            bottom.topAnchor.constraint(equalTo: cursor!.bottomAnchor, constant: p),
            bottom.heightAnchor.constraint(equalToConstant: 1),
            bottom.leadingAnchor.constraint(equalTo: container.leadingAnchor),
            bottom.bottomAnchor.constraint(equalTo: container.bottomAnchor),
        ])
    }
}

// MARK: - Navigation container
final class RootVC: NSViewController {
    let api   = OneqAPI()
    let state = OState()
    lazy var mainVC = MainVC(api: api, state: state)
    lazy var settVC = SettingsVC(api: api, state: state)

    override func loadView() { view = NSView() }
    override func viewDidLoad() {
        super.viewDidLoad()
        mainVC.onOpenSettings = { [weak self] in self?.showSettings() }
        settVC.onBack         = { [weak self] in self?.showMain() }
        settVC.onChanged      = { [weak self] in self?.mainVC.fetchStatus() }
        showMain()
    }

    func showMain() {
        swap(to: mainVC)
        view.window?.title = "oneq"
    }
    func showSettings() {
        settVC.fillForm()
        swap(to: settVC)
        view.window?.title = "oneq"
    }
    private func swap(to child: NSViewController) {
        for c in children { c.view.removeFromSuperview(); c.removeFromParent() }
        addChild(child)
        child.view.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(child.view)
        NSLayoutConstraint.activate([
            child.view.topAnchor.constraint(equalTo: view.topAnchor),
            child.view.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            child.view.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            child.view.trailingAnchor.constraint(equalTo: view.trailingAnchor),
        ])
    }
}

// MARK: - Main window (HomePage equivalent)
final class MainVC: NSViewController {
    let api:   OneqAPI
    let state: OState
    var onOpenSettings: (() -> Void)?
    init(api: OneqAPI, state: OState) { self.api = api; self.state = state; super.init(nibName: nil, bundle: nil) }
    required init?(coder: NSCoder) { fatalError() }
    var timer: Timer?

    // header
    let statusChip  = NSTextField(labelWithString: "● offline")
    // body
    let scrollView  = NSScrollView()
    let docView     = FlippedView()
    let bodyStack   = NSStackView()
    // static
    let configCard  = NSBox()         // "set up" card (no config)
    let connCard    = NSBox()         // configured summary card
    let connCardLbl = NSTextField(labelWithString: "")
    let pwField     = NSSecureTextField()
    let errorLbl    = NSTextField(labelWithString: "")
    let connectBtn  = NSButton()

    override func loadView() { view = NSView(frame: NSRect(x:0,y:0,width:480,height:700)) }

    override func viewDidLoad() {
        super.viewDidLoad()
        buildChrome()
        buildStaticBody()
        startPolling()
    }
    override func viewWillDisappear() { timer?.invalidate() }

    // MARK: Chrome (header + separator + scroll)
    func buildChrome() {
        let header = NSView(); header.translatesAutoresizingMaskIntoConstraints = false
        statusChip.font = .systemFont(ofSize: 13); statusChip.textColor = .secondaryLabelColor
        statusChip.translatesAutoresizingMaskIntoConstraints = false
        let gear = NSImage(named: NSImage.actionTemplateName) ?? NSImage()
        let gearBtn = NSButton(image: gear, target: self, action: #selector(openSettings))
        gearBtn.bezelStyle = .texturedRounded; gearBtn.isBordered = false; gearBtn.toolTip = "Settings"
        gearBtn.translatesAutoresizingMaskIntoConstraints = false
        header.addSubview(statusChip); header.addSubview(gearBtn)
        NSLayoutConstraint.activate([
            header.heightAnchor.constraint(equalToConstant: 40),
            statusChip.leadingAnchor.constraint(equalTo: header.leadingAnchor, constant: 14),
            statusChip.centerYAnchor.constraint(equalTo: header.centerYAnchor),
            gearBtn.trailingAnchor.constraint(equalTo: header.trailingAnchor, constant: -10),
            gearBtn.centerYAnchor.constraint(equalTo: header.centerYAnchor),
            gearBtn.widthAnchor.constraint(equalToConstant: 26), gearBtn.heightAnchor.constraint(equalToConstant: 26),
        ])
        let sep = NSBox(); sep.boxType = .separator; sep.translatesAutoresizingMaskIntoConstraints = false
        scrollView.translatesAutoresizingMaskIntoConstraints = false
        scrollView.hasVerticalScroller = true; scrollView.autohidesScrollers = true; scrollView.drawsBackground = false
        docView.translatesAutoresizingMaskIntoConstraints = false
        scrollView.documentView = docView
        docView.widthAnchor.constraint(equalTo: scrollView.contentView.widthAnchor).isActive = true
        bodyStack.orientation = .vertical; bodyStack.spacing = 12; bodyStack.alignment = .leading
        bodyStack.edgeInsets = NSEdgeInsets(top: 14, left: 16, bottom: 16, right: 16)
        bodyStack.translatesAutoresizingMaskIntoConstraints = false
        docView.addSubview(bodyStack)
        NSLayoutConstraint.activate([
            bodyStack.topAnchor.constraint(equalTo: docView.topAnchor),
            bodyStack.leadingAnchor.constraint(equalTo: docView.leadingAnchor),
            bodyStack.trailingAnchor.constraint(equalTo: docView.trailingAnchor),
            bodyStack.bottomAnchor.constraint(equalTo: docView.bottomAnchor),
        ])
        view.addSubview(header); view.addSubview(sep); view.addSubview(scrollView)
        NSLayoutConstraint.activate([
            header.topAnchor.constraint(equalTo: view.topAnchor),
            header.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            header.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            sep.topAnchor.constraint(equalTo: header.bottomAnchor),
            sep.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            sep.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            scrollView.topAnchor.constraint(equalTo: sep.bottomAnchor),
            scrollView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            scrollView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])
    }

    // MARK: Static body rows
    func buildStaticBody() {
        // "Set up the connection" info card
        configCard.boxType = .custom; configCard.cornerRadius = 8; configCard.borderWidth = 0
        configCard.fillColor = .controlBackgroundColor; configCard.contentViewMargins = .zero
        let configIcon = NSTextField(labelWithString: "ℹ️"); configIcon.font = .systemFont(ofSize: 20)
        let configTitle = mklbl("Set up the connection", 13, .semibold)
        let configSub   = mklbl("Open Settings to enter the relay, community and user, or import a settings file.", 12, color: .secondaryLabelColor)
        configSub.maximumNumberOfLines = 0; configSub.lineBreakMode = .byWordWrapping
        let cRow = NSStackView(views: [configIcon]); cRow.orientation = .horizontal; cRow.spacing = 10; cRow.alignment = .top
        let cText = NSStackView(views: [configTitle, configSub]); cText.orientation = .vertical; cText.spacing = 3; cText.alignment = .leading
        cRow.addArrangedSubview(cText)
        let configBtn = NSButton(title: "Open Settings →", target: self, action: #selector(openSettings))
        configBtn.bezelStyle = .inline
        let cInner = NSStackView(views: [cRow, configBtn]); cInner.orientation = .vertical; cInner.spacing = 8; cInner.alignment = .leading
        cInner.translatesAutoresizingMaskIntoConstraints = false
        configCard.contentView?.addSubview(cInner)
        pin(cInner, in: configCard, t:12,l:12,b2:12,r:12)
        addRow(configCard)

        // connection summary card (configured, not active) — hidden until first poll
        connCard.isHidden = true
        connCard.boxType = .custom; connCard.cornerRadius = 8; connCard.borderWidth = 0
        connCard.fillColor = .controlBackgroundColor; connCard.contentViewMargins = .zero
        connCardLbl.font = .systemFont(ofSize: 13); connCardLbl.maximumNumberOfLines = 0; connCardLbl.lineBreakMode = .byWordWrapping
        let editBtn = NSButton(); editBtn.image = NSImage(named: NSImage.actionTemplateName)
        editBtn.bezelStyle = .texturedRounded; editBtn.isBordered = false; editBtn.target = self; editBtn.action = #selector(openSettings)
        let spacer = NSView(); spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let ccRow = NSStackView(views: [connCardLbl, spacer, editBtn])
        ccRow.spacing = 8; ccRow.alignment = .centerY
        ccRow.translatesAutoresizingMaskIntoConstraints = false
        connCard.contentView?.addSubview(ccRow)
        pin(ccRow, in: connCard, t:10,l:12,b2:10,r:12)
        addRow(connCard)

        // password + connect
        pwField.placeholderString = "Password"
        connectBtn.title = "Connect"
        connectBtn.bezelStyle = .rounded; connectBtn.target = self; connectBtn.action = #selector(toggleConnect)
        connectBtn.setContentHuggingPriority(.required, for: .horizontal)
        let pwRow = NSStackView(views: [pwField, connectBtn]); pwRow.spacing = 8; pwRow.alignment = .centerY
        addRow(pwRow)

        errorLbl.textColor = .systemRed; errorLbl.font = .systemFont(ofSize: 12)
        errorLbl.isHidden = true; errorLbl.maximumNumberOfLines = 3; errorLbl.lineBreakMode = .byWordWrapping
        addRow(errorLbl)
    }

    func addRow(_ v: NSView) {
        bodyStack.addArrangedSubview(v)
        v.translatesAutoresizingMaskIntoConstraints = false
        v.setContentHuggingPriority(.defaultLow, for: .horizontal)
    }

    // MARK: Polling
    func startPolling() {
        fetchStatus()
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in self?.fetchStatus() }
    }
    func fetchStatus() {
        api.get("api/status") { [weak self] j in self?.applyStatus(j) }
    }

    func applyStatus(_ json: [String:Any]?) {
        guard let json = json else { return }
        state.active = json["running"] as? Bool ?? false
        let fromAPI  = json["settings"] as? [String:Any]
        if let fa = fromAPI, !state.active || state.settings.community.isEmpty {
            state.settings = OSettings.fromJSON(fa)
        }
        let snap  = json["snapshot"] as? [String:Any]
        let peers = snap?["peers"] as? [[String:Any]] ?? []
        state.snap = snap

        // header chip
        let st = snap?["state"] as? String ?? ""
        let hasSess = peers.contains { $0["session"] as? Bool == true }
        if state.active && st == "connected" && hasSess {
            statusChip.stringValue = "● connected"; statusChip.textColor = .systemGreen
        } else if state.active {
            statusChip.stringValue = "● \(st.isEmpty ? "connecting" : st)"; statusChip.textColor = .systemOrange
        } else {
            statusChip.stringValue = "● offline"; statusChip.textColor = .tertiaryLabelColor
        }

        // connect button
        connectBtn.isEnabled = !state.busy
        connectBtn.title = state.busy ? (state.active ? "Disconnecting…" : "Connecting…") : (state.active ? "Disconnect" : "Connect")

        // card visibility
        let configured = state.settings.configured
        configCard.isHidden = configured || state.active
        connCard.isHidden   = !configured || state.active
        if configured && !state.active {
            let relayLine = state.settings.relays.joined(separator: "\n")
            connCardLbl.stringValue = "\(state.settings.user) @ \(state.settings.community)\n\(relayLine)"
        }
        pwField.isHidden = state.active

        rebuildDynamic(snap: snap, peers: peers)
        (parent as? RootVC)?.settVC.rebuildExitNodePopup()
    }

    // MARK: Dynamic rebuild
    func rebuildDynamic(snap: [String:Any]?, peers: [[String:Any]]) {
        let keep = 4  // configCard + connCard + pwRow + errorLbl
        while bodyStack.arrangedSubviews.count > keep {
            let v = bodyStack.arrangedSubviews.last!
            bodyStack.removeArrangedSubview(v); v.removeFromSuperview()
        }
        guard state.active, let snap = snap else { return }

        let ip = snap["ip"] as? String ?? ""; let prefix = snap["prefix"] as? Int ?? 0
        let comm = snap["community"] as? String ?? ""; let mtu = snap["mtu"] as? Int ?? 0
        let relay = snap["relay_connected"] as? Bool ?? false
        let tx = snap["tx_bytes"] as? Int ?? 0; let rx = snap["rx_bytes"] as? Int ?? 0
        let nat = snap["nat_type"] as? String ?? ""; let natPub = snap["nat_public"] as? String ?? ""
        let msg = snap["message"] as? String ?? ""

        // status card
        var infoText = "\(comm)  ·  MTU \(mtu)  ·  relay \(relay ? "✓" : "✗")\n↑ \(fmtBytes(tx))   ↓ \(fmtBytes(rx))"
        if !nat.isEmpty { infoText += "\nNAT: \(nat)\(natPub.isEmpty ? "" : "  ·  \(natPub)")" }
        if !msg.isEmpty { infoText += "\n\(msg)" }
        let card = mkBox(false)
        let ipL  = mklbl("\(ip)/\(prefix)", 15, .semibold)
        let infoL = mklbl(infoText, 12, color: .secondaryLabelColor)
        infoL.maximumNumberOfLines = 6; infoL.lineBreakMode = .byWordWrapping
        let cs = NSStackView(views: [ipL, infoL]); cs.orientation = .vertical; cs.alignment = .leading; cs.spacing = 4
        cs.translatesAutoresizingMaskIntoConstraints = false
        pin(cs, in: card, t:10,l:12,b2:10,r:12)
        addRow(card)

        // members
        addRow(mklbl("Members", 13, .semibold))

        // exit node selector
        let exitPeers = peers.filter { $0["exit_node"] as? Bool == true }
        if !exitPeers.isEmpty {
            let exitBox = mkBox(true)
            let col = FlippedView(); col.translatesAutoresizingMaskIntoConstraints = false
            exitBox.contentView?.addSubview(col)
            if let cv = exitBox.contentView {
                NSLayoutConstraint.activate([col.topAnchor.constraint(equalTo: cv.topAnchor), col.bottomAnchor.constraint(equalTo: cv.bottomAnchor), col.leadingAnchor.constraint(equalTo: cv.leadingAnchor), col.trailingAnchor.constraint(equalTo: cv.trailingAnchor)])
            }
            var last: NSView? = nil
            func addExit(_ val: String, _ title: String, _ sub: String, _ enabled: Bool = true) {
                let row = makeRadioRow(val: val, title: title, sub: sub, enabled: enabled)
                col.addSubview(row); row.translatesAutoresizingMaskIntoConstraints = false
                let tc = last == nil ? row.topAnchor.constraint(equalTo: col.topAnchor) : row.topAnchor.constraint(equalTo: last!.bottomAnchor)
                NSLayoutConstraint.activate([tc, row.heightAnchor.constraint(equalToConstant: 46), row.leadingAnchor.constraint(equalTo: col.leadingAnchor), row.trailingAnchor.constraint(equalTo: col.trailingAnchor)])
                last = row
            }
            addExit("", "No exit node", "Direct internet")
            for p in exitPeers {
                let nm = p["name"] as? String ?? ""; let pip = p["ip"] as? String ?? ""
                let pub = p["public_ip"] as? String ?? ""; let on = p["online"] as? Bool ?? false
                addExit(nm, nm, pub.isEmpty ? pip : "\(pip)  ·  \(pub)", on)
            }
            last?.bottomAnchor.constraint(equalTo: col.bottomAnchor).isActive = true
            addRow(exitBox)
        }

        // peer rows
        for p in peers {
            let nm = p["name"] as? String ?? ""; let pip = p["ip"] as? String ?? ""
            let on = p["online"] as? Bool ?? false; let sess = p["session"] as? Bool ?? false
            let path = p["path"] as? String ?? ""
            let col: NSColor = sess ? .systemGreen : (on ? .systemOrange : .tertiaryLabelColor)
            let icon  = mklbl(sess ? "🔒" : "🔓", 14)
            let nameL = mklbl(nm, 13, .medium)
            let ipL   = mklbl(pip, 12, color: .secondaryLabelColor)
            let tr    = mklbl(sess ? path : (on ? "connecting" : "offline"), 12, color: col)
            tr.setContentHuggingPriority(.required, for: .horizontal)
            let sp = NSView(); sp.setContentHuggingPriority(.defaultLow, for: .horizontal)
            let row = NSStackView(views: [icon, nameL, ipL, sp, tr]); row.spacing = 6; row.alignment = .centerY
            addRow(row)
        }

        // log (disclosure)
        if let logArr = snap["log"] as? [String], !logArr.isEmpty {
            let logBox = NSBox(); logBox.boxType = .custom; logBox.cornerRadius = 6; logBox.borderWidth = 1
            logBox.borderColor = .separatorColor; logBox.fillColor = .controlBackgroundColor; logBox.contentViewMargins = .zero
            let logTV = NSTextView(); logTV.string = logArr.reversed().prefix(60).joined(separator: "\n")
            logTV.font = NSFont.monospacedSystemFont(ofSize: 11, weight: .regular)
            logTV.isEditable = false; logTV.backgroundColor = .clear
            logTV.isVerticallyResizable = true; logTV.autoresizingMask = .width
            let sv = NSScrollView(); sv.hasVerticalScroller = true; sv.autohidesScrollers = true
            sv.documentView = logTV; sv.drawsBackground = false
            sv.translatesAutoresizingMaskIntoConstraints = false
            sv.heightAnchor.constraint(equalToConstant: 120).isActive = true
            let disc = NSButton(title: "Log", target: nil, action: nil); disc.bezelStyle = .disclosure
            disc.setButtonType(.onOff); disc.state = .off
            disc.action = #selector(toggleLog(_:)); disc.target = self
            disc.translatesAutoresizingMaskIntoConstraints = false
            logBox.contentView?.addSubview(sv)
            sv.translatesAutoresizingMaskIntoConstraints = false
            if let cv = logBox.contentView {
                NSLayoutConstraint.activate([sv.topAnchor.constraint(equalTo: cv.topAnchor), sv.bottomAnchor.constraint(equalTo: cv.bottomAnchor), sv.leadingAnchor.constraint(equalTo: cv.leadingAnchor), sv.trailingAnchor.constraint(equalTo: cv.trailingAnchor)])
            }
            logBox.isHidden = true
            addRow(disc)
            addRow(logBox)
            disc.identifier = NSUserInterfaceItemIdentifier("log-disc")
            logBox.identifier = NSUserInterfaceItemIdentifier("log-box")
        }
    }

    @objc func toggleLog(_ sender: NSButton) {
        for v in bodyStack.arrangedSubviews {
            if v.identifier?.rawValue == "log-box" { v.isHidden = sender.state == .off }
        }
    }

    func makeRadioRow(val: String, title: String, sub: String, enabled: Bool) -> NSView {
        let row = FlippedView()
        let radio = NSButton(); radio.setButtonType(.radio); radio.title = ""
        radio.state = (state.settings.exitNode == val) ? .on : .off
        radio.identifier = NSUserInterfaceItemIdentifier("exit:\(val)")
        radio.target = self; radio.action = #selector(radioTapped(_:)); radio.isEnabled = enabled
        radio.translatesAutoresizingMaskIntoConstraints = false
        let tl = mklbl(title, 13, color: enabled ? .labelColor : .tertiaryLabelColor)
        let sl = mklbl(sub, 11, color: .secondaryLabelColor)
        let col = NSStackView(views: [tl, sl]); col.orientation = .vertical; col.spacing = 2; col.alignment = .leading
        col.translatesAutoresizingMaskIntoConstraints = false
        row.addSubview(radio); row.addSubview(col)
        NSLayoutConstraint.activate([radio.leadingAnchor.constraint(equalTo: row.leadingAnchor, constant: 12), radio.centerYAnchor.constraint(equalTo: row.centerYAnchor), col.leadingAnchor.constraint(equalTo: radio.trailingAnchor, constant: 6), col.trailingAnchor.constraint(equalTo: row.trailingAnchor, constant: -12), col.centerYAnchor.constraint(equalTo: row.centerYAnchor)])
        if !enabled { row.alphaValue = 0.4 }
        return row
    }

    @objc func radioTapped(_ sender: NSButton) {
        let id = sender.identifier?.rawValue ?? ""; let val = id.hasPrefix("exit:") ? String(id.dropFirst(5)) : ""
        state.settings.exitNode = val
        func walk(_ v: NSView) { for sub in v.subviews { if let btn = sub as? NSButton, let bid = btn.identifier?.rawValue, bid.hasPrefix("exit:") { btn.state = bid == "exit:\(val)" ? .on : .off }; walk(sub) } }
        walk(bodyStack)
        let j = state.settings.toJSON(); api.post("api/settings", j) { _ in }
    }

    @objc func toggleConnect() {
        errorLbl.isHidden = true; state.busy = true
        connectBtn.isEnabled = false
        if state.active {
            connectBtn.title = "Disconnecting…"
            api.post("api/service", ["action": "stop"]) { [weak self] _ in
                self?.state.busy = false; self?.fetchStatus()
            }
        } else {
            let pw = pwField.stringValue
            guard !pw.isEmpty else {
                state.busy = false; errorLbl.stringValue = "Enter the password."; errorLbl.isHidden = false
                connectBtn.isEnabled = true; return
            }
            state.password = pw; connectBtn.title = "Connecting…"
            let j = state.settings.toJSON()
            api.post("api/connect", ["settings": j, "password": pw]) { [weak self] resp in
                self?.state.busy = false
                if let err = resp?["error"] as? String { self?.errorLbl.stringValue = err; self?.errorLbl.isHidden = false }
                self?.fetchStatus()
            }
        }
    }

    @objc func openSettings() {
        onOpenSettings?()
    }

    // MARK: UI helpers
    func mklbl(_ t: String, _ sz: CGFloat = 13, _ w: NSFont.Weight = .regular, color: NSColor = .labelColor) -> NSTextField {
        let f = NSTextField(labelWithString: t); f.font = .systemFont(ofSize: sz, weight: w)
        f.textColor = color; f.lineBreakMode = .byTruncatingTail; return f
    }
    func mkBox(_ border: Bool) -> NSBox {
        let b = NSBox(); b.boxType = .custom; b.cornerRadius = 8; b.borderWidth = border ? 1 : 0
        b.borderColor = .separatorColor; b.fillColor = .controlBackgroundColor; b.contentViewMargins = .zero; return b
    }
    func pin(_ v: NSView, in b: NSBox, t: CGFloat, l: CGFloat, b2: CGFloat = 0, r: CGFloat) {
        v.translatesAutoresizingMaskIntoConstraints = false
        guard let cv = b.contentView else { return }
        cv.addSubview(v)
        NSLayoutConstraint.activate([v.topAnchor.constraint(equalTo: cv.topAnchor, constant: t), v.bottomAnchor.constraint(equalTo: cv.bottomAnchor, constant: -b2), v.leadingAnchor.constraint(equalTo: cv.leadingAnchor, constant: l), v.trailingAnchor.constraint(equalTo: cv.trailingAnchor, constant: -r)])
    }
}

// MARK: - App
class AppDelegate: NSObject, NSApplicationDelegate {
    var window: NSWindow!
    func applicationDidFinishLaunching(_ n: Notification) {
        guard OneqAPI().base != nil else {
            let a = NSAlert(); a.messageText = "oneq not running"
            a.informativeText = "Start oneqclient first, then reopen."; a.runModal(); NSApp.terminate(nil); return
        }
        let root = RootVC()
        window = NSWindow(contentViewController: root); window.title = "oneq"
        window.setContentSize(NSSize(width: 480, height: 700)); window.minSize = NSSize(width: 380, height: 500)
        window.setFrameAutosaveName("OneqUI"); window.isReleasedWhenClosed = false
        window.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ s: NSApplication) -> Bool { true }
}

let app = NSApplication.shared; app.setActivationPolicy(.regular)
let del = AppDelegate(); app.delegate = del; app.run()
