function createDeviceId() {
    if (crypto.getRandomValues) {
        const bytes = new Uint8Array(16);
        crypto.getRandomValues(bytes);
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        return [...bytes].map((byte, index) => {
            const value = byte.toString(16).padStart(2, "0");
            return [4, 6, 8, 10].includes(index) ? `-${value}` : value;
        }).join("");
    }
    return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (character) => {
        const value = Math.floor(Math.random() * 16);
        return (character === "x" ? value : (value & 0x3) | 0x8).toString(16);
    });
}

function sha256Fallback(buffer) {
    const constants = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    const source = new Uint8Array(buffer);
    const length = Math.ceil((source.length + 9) / 64) * 64;
    const padded = new Uint8Array(length);
    padded.set(source); padded[source.length] = 0x80;
    const view = new DataView(padded.buffer);
    const bits = source.length * 8;
    view.setUint32(length - 8, Math.floor(bits / 0x100000000));
    view.setUint32(length - 4, bits >>> 0);
    let hash = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    const rotate = (value, bits) => (value >>> bits) | (value << (32 - bits));
    for (let offset = 0; offset < length; offset += 64) {
        const words = new Uint32Array(64);
        for (let index = 0; index < 16; index++) words[index] = view.getUint32(offset + index * 4);
        for (let index = 16; index < 64; index++) {
            const small0 = rotate(words[index - 15], 7) ^ rotate(words[index - 15], 18) ^ (words[index - 15] >>> 3);
            const small1 = rotate(words[index - 2], 17) ^ rotate(words[index - 2], 19) ^ (words[index - 2] >>> 10);
            words[index] = (words[index - 16] + small0 + words[index - 7] + small1) | 0;
        }
        let [a, b, c, d, e, f, g, h] = hash;
        for (let index = 0; index < 64; index++) {
            const big1 = rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25);
            const choice = (e & f) ^ (~e & g);
            const first = (h + big1 + choice + constants[index] + words[index]) | 0;
            const big0 = rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22);
            const majority = (a & b) ^ (a & c) ^ (b & c);
            const second = (big0 + majority) | 0;
            [h, g, f, e, d, c, b, a] = [g, f, e, (d + first) | 0, c, b, a, (first + second) | 0];
        }
        hash = hash.map((value, index) => (value + [a, b, c, d, e, f, g, h][index]) | 0);
    }
    return hash.map((value) => (value >>> 0).toString(16).padStart(8, "0")).join("");
}

// Build the expandable device panel from text nodes only.
//
// This must never use innerHTML. device_id, ip, and transport are supplied by the
// peer rather than by us, so interpolating them into markup turns any device on
// the LAN into a script-execution vector against every other device viewing this
// page. The server also constrains device_id, but the client does not rely on it.
function buildDeviceDetails(device) {
    const details = document.createElement("div");
    details.className = "device-details";
    const rows = [
        ["Device ID", device.device_id || "unknown"],
        ["Transport", device.transport?.join(" + ") || "unknown"],
        ["IP", device.ip || "unknown"],
        ["Session", device.session_id || "n/a"],
    ];
    rows.forEach(([label, value]) => {
        const row = document.createElement("div");
        const key = document.createElement("span");
        key.textContent = `${label}:`;
        row.append(key, document.createTextNode(` ${value}`));
        details.append(row);
    });
    return details;
}

// Sanitise a file name for the browser's download attribute.
//
// A download name must never carry a directory component: browsers vary wildly in
// whether they honour "../" inside a `download` attribute, and a name that reaches
// the filesystem unchanged can escape the download directory.
function downloadFileName(name) {
    const basename = String(name ?? "").split(/[\\/]/).pop() ?? "";
    const cleaned = basename.replace(/[<>:"/\\|?*\x00-\x1f]/g, "_").trim();
    if (!cleaned || cleaned === "." || cleaned === "..") throw new Error(`Unusable download filename: ${JSON.stringify(name)}`);
    return cleaned;
}

// Mirror of seltransfer.transfers.safe_relative_path for names that keep their
// folder structure (webkitRelativePath). Rejecting here gives an immediate, clear
// error instead of an opaque 400 from the receiving server.
function safeRelativeName(name) {
    const value = String(name ?? "");
    if (!value || value.startsWith("/") || value.startsWith("\\") || /^[A-Za-z]:/.test(value)) throw new Error(`Invalid file path: ${JSON.stringify(name)}`);
    const raw = value.split(/[\\/]/);
    if (raw.some((part) => part === "" || part === "." || part === "..")) throw new Error(`Invalid file path: ${JSON.stringify(name)}`);
    const parts = raw.map((part) => part.replace(/[<>:"/\\|?*\x00-\x1f]/g, "_").trim()).filter(Boolean);
    if (!parts.length || parts.some((part) => part === "." || part === "..")) throw new Error(`Invalid file path: ${JSON.stringify(name)}`);
    return parts.join("/");
}

// Byte accounting for a transfer, clamped to the declared total so a retried or
// oversized chunk cannot drive progress past 100% or overshoot the history record.
class TransferProgress {
    constructor(total) { this.total = Number(total) || 0; this.bytes = 0; }
    add(count) { const delta = Number(count) || 0; if (delta <= 0) return; this.bytes = Math.min(this.total, this.bytes + delta); }
    rollback(count) { this.bytes = Math.max(0, this.bytes - (Number(count) || 0)); }
    percent(total) { const target = Number(total) || 0; if (target <= 0) return 100; return Math.max(0, Math.min(100, Math.round(this.bytes * 100 / target))); }
    get complete() { return this.bytes >= this.total; }
}

// Files above this size are transferred without a client-side digest. Hashing
// reads the entire file into memory, which is what used to crash the phone.
const HASH_LIMIT_BYTES = 16 * 1024 * 1024;

// Save a received blob to the device.
//
// Two things here are load-bearing on iOS and were both broken before:
// the object URL must be revoked only after the save has been picked up, and
// the anchor has to be in the document for the tap to be honoured at all.
async function saveBlob(blob, name) {
    const filename = downloadFileName(name);
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.rel = "noopener";
    link.style.display = "none";
    document.body.append(link);
    try {
        link.click();
    } finally {
        // Give the browser time to start reading the blob before tearing the URL
        // down. Revoking immediately races the download and silently yields an
        // empty file on some platforms.
        setTimeout(() => {
            link.remove();
            URL.revokeObjectURL(url);
        }, 60_000);
    }
    return filename;
}

class SeltransferApp {
    constructor() {
        this.devices = [];
        this.selected = null;
        this.expanded = new Set();
        this.session = JSON.parse(localStorage.getItem("seltransfer-session") || "null");
        this.serverDeviceId = null;
        this.refreshInFlight = false;
        // HTTP is the default. WebRTC is opt-in for users who want the
        // peer-to-peer path; see the transport toggle in index.html.
        this.transport = localStorage.getItem("seltransfer-transport") === "webrtc" ? "webrtc" : "http";
        this.$ = (id) => document.getElementById(id);
        this.$("refresh").addEventListener("click", () => this.loadDevices());
        this.$("save-device-name").addEventListener("click", () => this.saveDeviceNameFromInput());
        this.$("device-name-input").addEventListener("keydown", (event) => { if (event.key === "Enter") this.saveDeviceNameFromInput(); });
        this.$("clear-history").addEventListener("click", () => this.clearHistory());
        this.$("send-files").addEventListener("click", () => this.$("file-input").click());
        this.$("send-folder").addEventListener("click", () => this.$("folder-input").click());
        this.$("file-input").addEventListener("change", (event) => this.send(event.target.files));
        this.$("folder-input").addEventListener("change", (event) => this.send(event.target.files));
        const approvalRequest = this.$("pair-approval-request");
        if (approvalRequest) approvalRequest.addEventListener("click", () => this.requestApproval());
        const transportToggle = this.$("transport-mode");
        if (transportToggle) {
            transportToggle.value = this.transport;
            transportToggle.addEventListener("change", (event) => {
                this.transport = event.target.value === "webrtc" ? "webrtc" : "http";
                localStorage.setItem("seltransfer-transport", this.transport);
            });
        }
    }
    async api(url, options = {}) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), options.timeout || 10000);
        const { raw, ...rest } = options;
        const headers = { ...(rest.body ? { "Content-Type": "application/json" } : {}), ...(rest.headers || {}) };
        if (this.session?.session_id) headers["x-seltransfer-session"] = this.session.session_id;
        try {
            const response = await fetch(url, { ...rest, headers, signal: controller.signal });
            // A phone that was backgrounded past its session lifetime gets a 401
            // here. Re-register once and replay, rather than dead-ending the user
            // with a message they cannot act on.
            if (response.status === 401 && !rest._retried && this.session) {
                await this.registerBrowser(this.serverDeviceId);
                return this.api(url, { ...rest, _retried: true });
            }
            if (!response.ok) {
                const body = await response.json().catch(() => ({}));
                const error = new Error(body.detail || `Request failed (${response.status})`);
                // The status is needed to tell "not allowed, ask for a code" apart
                // from a genuine failure.
                error.status = response.status;
                throw error;
            }
            // Binary callers (file downloads) need the Response itself.
            if (raw) return response;
            return await response.json().catch(() => ({}));
        } catch (error) {
            if (error.name === "AbortError") throw new Error("Request timed out. Check the local network connection.");
            if (error instanceof TypeError) throw new Error("Cannot reach SELTRANSFER. Check the same hotspot or LAN.");
            throw error;
        } finally { clearTimeout(timer); }
    }
    async initialize() {
        this.$("device-name-input").value = this.getSavedDeviceName();
        try {
            const connection = await this.api("/api/connection");
            this.serverDeviceId = connection.device_id;
            this.$("network").textContent = `${connection.local_address}:${connection.server_port}`;
            await this.registerBrowser(connection.device_id);
            this.$("storage-location").textContent = `Native files received by this server are saved in: ${connection.download_directory}. Browser receivers download files using their own browser settings.`;
            await this.loadDevices(); await this.loadIncoming(); await this.loadHistory(); await this.loadPendingPairings();
            setInterval(() => this.heartbeat(), 7000); setInterval(() => this.loadDevices(), 4000); setInterval(() => this.loadIncoming(), 4000);
            // Codes live for two minutes, so the local user's panel refreshes often
            // enough that a code is on screen before the other device asks for it.
            setInterval(() => this.loadPendingPairings(), 4000);
            // A backgrounded phone has its timers throttled or suspended, so the
            // session expires while the user is elsewhere. Renew on return so an
            // incoming transfer is not waiting for a device that looks offline.
            document.addEventListener("visibilitychange", () => {
                if (document.visibilityState !== "visible") return;
                this.renewSession().catch(() => {});
            });
            window.addEventListener("pageshow", () => this.renewSession().catch(() => {}));
        } catch (error) { this.showError(error.message); }
    }
    async renewSession() {
        await this.registerBrowser(this.serverDeviceId);
        await Promise.all([this.loadDevices(), this.loadIncoming(), this.loadHistory()]);
    }
    detectBrowserDeviceInfo() {
        const ua = navigator.userAgent || "";
        const platform = navigator.userAgentData?.platform || navigator.platform || "Unknown";
        const mobile = navigator.userAgentData?.mobile || /android|iphone|ipad|ipod|mobile/i.test(ua);
        const model = (navigator.userAgentData && navigator.userAgentData.model && navigator.userAgentData.model.trim()) || "";
        const isAndroid = /android/i.test(ua) || platform === "Android";
        const isIOS = /iphone|ipad|ipod/i.test(ua) || platform === "iOS";
        const deviceType = mobile ? (isAndroid ? "Phone" : isIOS ? "Phone" : "Phone") : "Computer";
        const deviceHint = model || (isAndroid ? "Android Phone" : isIOS ? "iPhone" : "Computer");
        return { platform, deviceType, deviceHint, mobile, userAgent: ua };
    }
    getSavedDeviceName() {
        const raw = localStorage.getItem("seltransfer-device-name") || "";
        return raw.trim().slice(0, 50);
    }
    setDeviceName(name) {
        const cleaned = (name || "").trim().replace(/[\r\n\t]/g, " ").slice(0, 50);
        if (cleaned) localStorage.setItem("seltransfer-device-name", cleaned);
        else localStorage.removeItem("seltransfer-device-name");
        this.$("device-name-input").value = cleaned || "";
    }
    saveDeviceNameFromInput() {
        const raw = this.$("device-name-input").value;
        const cleaned = (raw || "").trim().replace(/[\r\n\t]/g, " ").slice(0, 50);
        if (!cleaned && !this.getSavedDeviceName()) return;
        this.setDeviceName(cleaned);
        this.registerBrowser(this.serverDeviceId).catch((error) => this.showError(error.message));
    }
    async registerBrowser(serverDeviceId) {
        let deviceId = localStorage.getItem("seltransfer-device-id");
        if (!deviceId) { deviceId = createDeviceId(); localStorage.setItem("seltransfer-device-id", deviceId); }
        const browserInfo = this.detectBrowserDeviceInfo();
        const savedName = this.getSavedDeviceName();
        const payload = {
            device_id: deviceId,
            display_name: savedName || undefined,
            device_hint: browserInfo.deviceHint,
            device_type: browserInfo.deviceType,
            type: browserInfo.deviceType.toLowerCase(),
            platform: browserInfo.platform,
            browser: browserInfo.userAgent,
            capabilities: ["webrtc", "multiple_files", "folders"],
        };
        if (this.session?.device_id === deviceId) payload.session_id = this.session.session_id;
        try { this.session = await this.api("/api/browser/register", { method: "POST", body: JSON.stringify(payload) }); }
        catch (error) { if (error.message.includes("already registered")) localStorage.removeItem("seltransfer-device-id"); throw error; }
        localStorage.setItem("seltransfer-session", JSON.stringify(this.session));
        this.setDeviceName(this.session.display_name || this.getSavedDeviceName() || deviceId.slice(0, 8));
        if (serverDeviceId) this.$("identity").textContent = `${this.session.display_name || deviceId.slice(0, 8)} / server ${serverDeviceId.slice(0, 8)}`;
    }
    async heartbeat() { if (!this.session) return; try { await this.api("/api/browser/heartbeat", { method: "POST", body: JSON.stringify(this.session) }); } catch (error) { this.showError(error.message); } }
    async loadDevices() {
        if (this.refreshInFlight) return; this.refreshInFlight = true;
        try {
            const data = await this.api("/api/devices");
            this.serverDeviceId = data.local_device_id || this.serverDeviceId;
            // Whether this browser is the machine's own user decides how pairing
            // works here: one click if so, otherwise an out-of-band code.
            if (typeof data.local_user === "boolean") this.localUser = data.local_user;
            // Exclude this browser and the server hosting the page. Selecting the
            // local server would create a transfer the page itself can never
            // accept, because the receiver is a different device than the sender.
            const excluded = new Set([this.session?.device_id, this.serverDeviceId]);
            this.devices = data.devices.filter((device) => !excluded.has(device.device_id) && device.status === "online");
            if (this.selected && !this.devices.some((device) => device.device_id === this.selected.device_id)) this.clearSelection();
            this.$("device-count").textContent = `${this.devices.length} online`; this.renderDevices();
        } catch (error) { this.showError(error.message); } finally { this.refreshInFlight = false; }
    }
    renderDevices() {
        const list = this.$("devices"); list.replaceChildren();
        if (!this.devices.length) { list.textContent = "No other online devices are registered or discovered."; return; }
        this.devices.forEach((device) => {
            const item = document.createElement("button"); item.type = "button"; item.className = "device"; item.classList.toggle("selected", this.selected?.device_id === device.device_id); item.setAttribute("aria-pressed", String(this.selected?.device_id === device.device_id));
            const name = document.createElement("strong"); name.textContent = device.display_name || device.name || device.device_type || "Device";
            const kind = document.createElement("span"); kind.textContent = device.device_type || device.type || "Computer";
            const state = document.createElement("small"); state.textContent = device.status === "online" ? "● Online" : "● Offline";
            const details = buildDeviceDetails(device);
            // Re-rendering on selection would detach the panel, so expansion is
            // tracked per device id and restored on every render.
            details.hidden = !this.expanded.has(device.device_id);
            item.append(name, kind, state);
            item.addEventListener("click", () => {
                this.select(device);
                if (this.expanded.has(device.device_id)) this.expanded.delete(device.device_id);
                else this.expanded.add(device.device_id);
                this.renderDevices();
            });
            item.append(details);
            list.append(item);
        });
    }
    async select(device) {
        this.selected = device; this.renderDevices(); this.$("destination").textContent = device.display_name || device.name; this.$("selection-note").textContent = `${device.device_type || device.type || "Computer"} · ${device.status}`;
        this.hideApprovalRequest();
        try {
            await this.api(`/api/devices/${device.device_id}/pair`, { method: "POST" });
            this.$("pair-status").textContent = "Paired";
            this.$("send-files").disabled = false; this.$("send-folder").disabled = false;
        } catch (error) {
            // One-click pairing is this machine's own user only. A browser on
            // another device has to ask this machine's user to approve it, so offer
            // that instead of just failing.
            this.$("send-files").disabled = true; this.$("send-folder").disabled = true;
            if (error.status === 403 && this.localUser === false) {
                this.$("pair-status").textContent = "Needs the user of this machine";
                this.showApprovalRequest();
            } else { this.$("pair-status").textContent = error.message; }
        }
    }
    showApprovalRequest() { const box = this.$("pair-approval"); if (box) box.hidden = false; }
    hideApprovalRequest() { const box = this.$("pair-approval"); if (box) box.hidden = true; }
    async requestApproval() {
        if (!this.selected) return;
        this.$("pair-status").textContent = "Waiting for the user of this machine...";
        try {
            const data = await this.api(`/api/devices/${this.selected.device_id}/pair/request`, { method: "POST", body: JSON.stringify({ device_id: this.selected.device_id }) });
            // The requester is never told the code - that would make the whole flow
            // self-service. It waits for the destination's user to approve instead.
            this.$("pair-status").textContent = "Requested. The user of this machine has to approve it.";
            this.awaitingApproval = data.request_id || null;
            this.startApprovalPoll();
        } catch (error) { this.$("pair-status").textContent = error.message; }
    }
    // After requesting, poll for the pairing appearing. Approval happens on the
    // other device's screen, so this is how the requester learns it succeeded
    // without ever being sent the code.
    startApprovalPoll() {
        if (this.approvalTimer) return;
        this.approvalTimer = setInterval(() => this.checkApproval(), 2000);
    }
    stopApprovalPoll() { if (this.approvalTimer) { clearInterval(this.approvalTimer); this.approvalTimer = null; } this.awaitingApproval = null; }
    async checkApproval() {
        const deviceId = this.selected?.device_id;
        if (!this.awaitingApproval || !deviceId) { this.stopApprovalPoll(); return; }
        try {
            const state = await this.api(`/api/pairing/status/${deviceId}`);
            if (state.paired) {
                this.stopApprovalPoll();
                this.$("pair-status").textContent = "Paired";
                this.$("send-files").disabled = false; this.$("send-folder").disabled = false;
                this.hideApprovalRequest();
            }
        } catch (error) {
            // A destination that went away must not leave the poll running forever.
            if (error.status === 404) { this.stopApprovalPoll(); this.$("pair-status").textContent = "destination device is unavailable"; }
        }
    }
    // The local user's side of pairing: approve what a remote device asked for.
    // This is the whole flow now - there is no code to read out or type in.
    async approvePairing(requestId) {
        try {
            await this.api(`/api/pairing/requests/${requestId}/approve`, { method: "POST" });
            await this.loadPendingPairings();
            await this.loadDevices();
        } catch (error) { this.showError(error.message); }
    }
    async loadPendingPairings() {
        if (this.localUser !== true) return;
        const panel = this.$("pairing-panel");
        if (panel) panel.hidden = false;
        try {
            const data = await this.api("/api/pairing/pending");
            const list = this.$("pairing-pending"); if (!list) return;
            list.replaceChildren();
            if (!data.requests.length) { list.textContent = "No pending requests."; return; }
            data.requests.forEach((entry) => {
                const row = document.createElement("div"); row.className = "pairing-row";
                // Who is asking, so the user can judge it before clicking. The code
                // is deliberately not rendered: there is no field to type it into any
                // more, and a big readable code next to an Approve button only
                // invites reading it out for no purpose. It stays available through
                // `GET /api/pairing/pending` for API callers.
                const who = document.createElement("span"); who.className = "pairing-requester"; who.textContent = entry.device_id.slice(0, 8);
                const meta = document.createElement("small"); meta.textContent = `expires in ${entry.seconds_remaining}s`;
                // The click is the intent, so the other device never has to read a
                // code out. This panel only renders for the local user (see the
                // guard above), so a LAN peer can neither see nor press it.
                const approve = document.createElement("button"); approve.type = "button"; approve.className = "pairing-approve"; approve.textContent = "Approve";
                approve.addEventListener("click", () => this.approvePairing(entry.request_id));
                row.append(who, meta, approve); list.append(row);
            });
        } catch (error) { /* the panel is informational; never let it break the page */ }
    }
    clearSelection() { this.selected = null; this.$("destination").textContent = "Choose a device"; this.$("selection-note").textContent = "Select an online device before sending."; this.$("send-files").disabled = true; this.$("send-folder").disabled = true; this.renderDevices(); }
    async send(files) {
        if (!files.length || !this.selected) return;
        try {
            this.setStatus("Preparing transfer request...");
            // Validate the name the same way the receiving server will, so a bad
            // path fails here with a readable message instead of a remote 400.
            const metadata = await Promise.all([...files].map(async (file) => {
                const name = safeRelativeName(file.webkitRelativePath || file.name);
                // Hashing reads the whole file into memory, so skip it above the
                // cap. The receiver still verifies the declared size.
                return { name, size: file.size, sha256: file.size <= HASH_LIMIT_BYTES ? await this.hash(file) : null };
            }));
            const transfer = await this.api("/api/transfers", { method: "POST", body: JSON.stringify({ receiver_id: this.selected.device_id, files: metadata, transport: this.transport }) });
            const base = this.selected.node_type === "server" ? `http://${this.selected.ip}:${this.selected.port}` : "";
            const transport = transfer.transfer_transport === "webrtc" ? "WebRTC" : "HTTP";
            this.setStatus(`Waiting for ${this.selected.display_name || this.selected.name} to accept via ${transport}...`); let accepted;
            for (let attempt = 0; attempt < 120; attempt++) { const state = await this.api(`/api/incoming-transfers/${transfer.transfer_id}`); if (state.status === "REJECTED") throw new Error("Receiver rejected the transfer."); if (state.status === "ACCEPTED") { accepted = state; break; } await new Promise((resolve) => setTimeout(resolve, 1000)); }
            if (!accepted) throw new Error("Timed out waiting for receiver acceptance.");
            // The server decides the transport and hands back the token to push
            // with. Do not infer it from the receiver's node type: a browser
            // receiver on the HTTP path is exactly the PC-to-phone case.
            if (transfer.transfer_transport === "webrtc") {
                await this.sendViaWebRTC(transfer.transfer_id, files);
                this.setStatus("Sent successfully. The file was downloaded on the phone.");
            } else {
                for (let index = 0; index < files.length; index++) await this.upload(base, transfer.transfer_id, index, files[index], accepted.transfer_token);
                this.setStatus("Sent successfully. The receiver saved the files locally.");
            }
            await this.loadHistory();
        } catch (error) { this.setStatus(error.message); }
    }
    async sendViaWebRTC(transferId, files) {
        if (!window.RTCPeerConnection) throw new Error("WebRTC is unavailable in this browser.");
        const session = await this.api("/api/webrtc/session", { method: "POST", body: JSON.stringify({ peer_device_id: this.selected.device_id, transfer_id: transferId }) });
        const peer = new RTCPeerConnection(); const channel = peer.createDataChannel("seltransfer-file"); channel.binaryType = "arraybuffer";
        channel.bufferedAmountLowThreshold = 256 * 1024;
        peer.onicecandidate = (event) => { if (event.candidate) this.api(`/api/webrtc/${session.session_id}/ice`, { method: "POST", body: JSON.stringify({ payload: event.candidate }) }).catch(() => {}); };
        const signalTask = this.pollWebRTCSignals(session.session_id, peer, true);
        await new Promise((resolve, reject) => { channel.onopen = resolve; channel.onerror = () => reject(new Error("WebRTC data channel failed.")); });
        for (let index = 0; index < files.length; index++) {
            const file = files[index]; const name = file.webkitRelativePath || file.name;
            channel.send(JSON.stringify({ type: "file-start", index, name, size: file.size, mime: file.type || "application/octet-stream" }));
            for (let offset = 0; offset < file.size; offset += 64 * 1024) {
                while (channel.bufferedAmount > 4 * 1024 * 1024) await new Promise((resolve) => { channel.onbufferedamountlow = resolve; });
                channel.send(await file.slice(offset, offset + 64 * 1024).arrayBuffer());
                this.setStatus(`Sending ${file.name} · ${Math.round((offset + Math.min(64 * 1024, file.size - offset)) * 100 / file.size)}%`);
            }
            channel.send(JSON.stringify({ type: "file-end", index }));
        }
        await signalTask; peer.close();
    }
    async pollWebRTCSignals(sessionId, peer, offerer) {
        let seen = 0;
        for (let attempt = 0; attempt < 120; attempt++) {
            const data = await this.api(`/api/webrtc/${sessionId}`);
            for (const signal of data.signals.slice(seen)) {
                seen++;
                if (signal.type === "answer" && offerer) await peer.setRemoteDescription(signal.payload);
                if (signal.type === "offer" && !offerer) { await peer.setRemoteDescription(signal.payload); const answer = await peer.createAnswer(); await peer.setLocalDescription(answer); await this.api(`/api/webrtc/${sessionId}/answer`, { method: "POST", body: JSON.stringify({ payload: answer }) }); }
                if (signal.type === "ice") await peer.addIceCandidate(signal.payload);
            }
            if (offerer && !peer.localDescription) { const offer = await peer.createOffer(); await peer.setLocalDescription(offer); await this.api(`/api/webrtc/${sessionId}/offer`, { method: "POST", body: JSON.stringify({ payload: offer }) }); }
            if (peer.connectionState === "connected") return;
            await new Promise((resolve) => setTimeout(resolve, 250));
        }
        throw new Error("WebRTC signaling timed out.");
    }
    upload(base, transferId, index, file, token) { return new Promise((resolve, reject) => { const request = new XMLHttpRequest(); request.open("PUT", `${base}/api/incoming-transfers/${transferId}/files/${index}`); request.setRequestHeader("x-seltransfer-token", token); request.upload.onprogress = (event) => { if (event.lengthComputable) this.setStatus(`Transferring ${file.name} · ${Math.round(event.loaded * 100 / event.total)}%`); }; request.onload = () => request.status >= 200 && request.status < 300 ? resolve() : reject(new Error(`Upload failed (${request.status})`)); request.onerror = () => reject(new Error("Receiver became unreachable.")); request.send(file); }); }
    async hash(file) {
        const buffer = await file.arrayBuffer();
        if (crypto.subtle) return [...new Uint8Array(await crypto.subtle.digest("SHA-256", buffer))].map((byte) => byte.toString(16).padStart(2, "0")).join("");
        return sha256Fallback(buffer);
    }
    async receiveViaWebRTC(transfer) {
        let session;
        for (let attempt = 0; attempt < 120 && !session; attempt++) {
            const sessions = await this.api("/api/webrtc/sessions");
            session = sessions.sessions.find((item) => item.transfer_id === transfer.transfer_id);
            if (!session) await new Promise((resolve) => setTimeout(resolve, 250));
        }
        if (!session) throw new Error("WebRTC session was not created.");
        const peer = new RTCPeerConnection(); let current = null; const received = new Map(); const completed = new Set();
        peer.onicecandidate = (event) => { if (event.candidate) this.api(`/api/webrtc/${session.session_id}/ice`, { method: "POST", body: JSON.stringify({ payload: event.candidate }) }).catch(() => {}); };
        peer.ondatachannel = (event) => { const channel = event.channel; channel.binaryType = "arraybuffer"; channel.onmessage = async (message) => {
            if (typeof message.data === "string") {
                const control = JSON.parse(message.data);
                if (control.type === "file-start") { current = { ...control, chunks: [], size: 0, sizeExpected: control.size, progress: new TransferProgress(control.size) }; received.set(control.index, current); this.setStatus(`Receiving ${control.name} · 0%`); }
                if (control.type === "file-end" && current) {
                    const blob = new Blob(current.chunks, { type: current.mime }); const digest = await this.hashBlob(blob);
                    if (blob.size !== current.size || (transfer.files[current.index].sha256 && digest !== transfer.files[current.index].sha256)) throw new Error(`Integrity check failed for ${current.name}`);
                    await saveBlob(blob, current.name);
                    await this.api(`/api/webrtc/${session.session_id}/files/${current.index}/complete`, { method: "POST", body: JSON.stringify({ size: blob.size, sha256: digest }) });
                    this.setStatus(`Received ${current.name}. Saved using your browser download settings.`);
                    // Recorded only once the bytes are saved, so the wait below
                    // cannot resolve while a file is still in flight.
                    completed.add(current.index);
                    current = null;
                }
            } else if (current) {
                // Clamp against the declared size so a misbehaving sender cannot
                // inflate the buffer or the reported progress beyond the total.
                if (current.progress.complete) throw new Error(`Sender sent more data than declared for ${current.name}`);
                current.chunks.push(message.data); current.size += message.data.byteLength; current.progress.add(message.data.byteLength);
                this.setStatus(`Receiving ${current.name} · ${current.progress.percent(current.sizeExpected)}%`);
            }
        }; };
        // Establish signalling and then wait for the data itself. Closing the peer
        // as soon as the connection reports "connected" tears the channel down
        // before a single chunk arrives, which is what made WebRTC delivery from a
        // PC to a phone always fail.
        await this.pollWebRTCSignals(session.session_id, peer, false);
        await this.waitForWebRTCFiles(completed, transfer.files.length);
        peer.close();
    }
    // Resolve once every declared file has been completed, or reject on timeout.
    // Tracked on completion rather than on file-start, so a large file cannot be
    // mistaken for a finished one and have its channel torn down mid-transfer.
    waitForWebRTCFiles(completed, expected) {
        return new Promise((resolve, reject) => {
            const deadline = Date.now() + 120_000;
            const check = setInterval(() => {
                if (completed.size >= expected) { clearInterval(check); resolve(); return; }
                if (Date.now() > deadline) { clearInterval(check); reject(new Error("WebRTC transfer timed out.")); }
            }, 200);
        });
    }
    // The default PC-to-phone path: the sender pushes the bytes to this server,
    // and the phone pulls them back with its own session.
    async receiveViaHttp(transfer) {
        const expected = transfer.files.length;
        // Accepting does not mean the bytes have landed yet, so wait for the
        // sender to finish pushing before reading anything back.
        const deadline = Date.now() + 15 * 60_000;
        for (;;) {
            const state = await this.api(`/api/incoming-transfers/${transfer.transfer_id}`);
            if (state.status === "FAILED" || state.status === "CANCELLED") throw new Error(`Transfer ${state.status.toLowerCase()}: ${state.error || "unknown reason"}`);
            // received_files is an object keyed by file index, not an array, so
            // .length is undefined. Counting keys reports what actually landed,
            // which a loop over the expected count would not.
            const receivedCount = Object.keys(state.received_files || {}).length;
            if (receivedCount >= expected) break;
            if (Date.now() > deadline) throw new Error("Timed out waiting for the sender to upload the files.");
            this.setStatus(`Waiting for the sender to upload · ${receivedCount}/${expected}`);
            await new Promise((resolve) => setTimeout(resolve, 1000));
        }
        const saved = [];
        for (let index = 0; index < expected; index++) {
            const meta = transfer.files[index];
            this.setStatus(`Downloading ${meta.name} · ${index + 1} of ${expected}`);
            const response = await this.api(
                `/api/incoming-transfers/${transfer.transfer_id}/files/${index}`,
                { raw: true, timeout: 15 * 60_000 });
            const blob = await response.blob();
            if (meta.size != null && blob.size !== meta.size) throw new Error(`Size mismatch for ${meta.name}`);
            saved.push(await saveBlob(blob, meta.name));
        }
        this.setStatus(`Received ${saved.length} file(s): ${saved.join(", ")}`);
        return saved;
    }
    async hashBlob(blob) { return this.hash(new File([blob], "received")); }
    async loadIncoming() { try { const data = await this.api("/api/incoming-transfers"); const target = this.$("incoming"); target.replaceChildren(); data.transfers.filter((item) => item.status === "PENDING" && (!item.receiver_id || item.receiver_id === this.session?.device_id || item.receiver_id === this.serverDeviceId)).forEach((item) => { const row = document.createElement("div"); row.className = "activity"; const text = document.createElement("span"); text.textContent = `Incoming from ${item.sender?.name || item.sender_id} · ${item.files.length} file(s) · ${item.total_bytes.toLocaleString()} bytes`; row.append(text); ["accept", "reject"].forEach((action) => { const button = document.createElement("button"); button.textContent = action.toUpperCase(); button.addEventListener("click", async () => { try { const accepted = await this.api(`/api/incoming-transfers/${item.transfer_id}/${action}`, { method: "POST" }); if (action === "accept") { if (accepted.transfer_transport === "webrtc") await this.receiveViaWebRTC(accepted); else await this.receiveViaHttp(accepted); } await this.loadIncoming(); } catch (error) { this.showError(error.message); } }); row.append(button); }); target.append(row); }); if (!target.children.length) target.textContent = "None pending."; } catch (error) { this.showError(error.message); } }
    async loadHistory() { const data = await this.api("/api/transfers"); const target = this.$("transfers"); target.replaceChildren(); if (!data.transfers.length) { target.textContent = "No transfers yet."; return; } data.transfers.forEach((item) => { const row = document.createElement("div"); row.className = "history-row"; row.textContent = `${item.file_count} file(s) · ${item.total_bytes.toLocaleString()} bytes · ${item.status}`; target.append(row); }); }
    async clearHistory() { if (!window.confirm("Clear transfer history? Received files will not be deleted.")) return; try { await this.api("/api/transfers/history/clear", { method: "POST" }); await this.loadHistory(); } catch (error) { this.showError(error.message); } }
    setStatus(message) { this.$("transfer-status").textContent = message; }
    showError(message) { this.$("error").textContent = message; this.$("error").hidden = false; }
}
document.addEventListener("DOMContentLoaded", () => { const app = new SeltransferApp(); app.initialize(); });
