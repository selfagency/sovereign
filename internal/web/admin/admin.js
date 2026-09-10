// Admin thin client. A hash-routed set of small render functions over the
// /api/v1 instance-admin REST API: dashboard, tenants, users, clients,
// backups, moderation, audit, IPFS pins, ToS, and deletion requests. Every
// request goes through the shared api.js module — no raw fetch, no framework,
// no build step. Session-cookie auth: the browser sends the session cookie
// automatically and api.js echoes the CSRF token on unsafe methods. User- and
// server-supplied data is only ever written with textContent, so nothing here
// can turn into HTML.
import { api, ApiError } from "../shared/api.js";

const BASE = "/api/v1";

const view = document.getElementById("view");
const nav = document.getElementById("nav");
const flash = document.getElementById("flash");

// --- DOM helpers (mirror panel.js) ---

// setProp applies one prop to a node: class/text special cases, event
// handlers for on* keys, and attributes otherwise.
function setProp(node, key, value) {
  if (key === "class") {
    node.className = value;
  } else if (key === "text") {
    node.textContent = value;
  } else if (key.startsWith("on") && typeof value === "function") {
    node.addEventListener(key.slice(2), value);
  } else {
    node.setAttribute(key, value === true ? "" : String(value));
  }
}

// appendChildren appends each non-null child: Nodes as-is, everything else as
// a text node (never parsed as HTML).
function appendChildren(node, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
}

// h builds a DOM node. Text children are appended as text nodes (never parsed
// as HTML), which is the whole XSS defence for this file.
function h(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === null || value === undefined || value === false) continue;
    setProp(node, key, value);
  }
  appendChildren(node, children);
  return node;
}

function mount(...nodes) {
  view.replaceChildren(...nodes);
}

function section(title, ...body) {
  return h("section", {}, h("h2", {}, title), ...body);
}

function labelled(text, input) {
  return h("label", {}, `${text} `, input);
}

function field(label, input) {
  return h("p", {}, labelled(label, input));
}

function button(text, onclick) {
  return h("button", { type: "button", onclick }, text);
}

function setFlash(message, kind = "error") {
  flash.textContent = message || "";
  flash.className = message ? kind : "";
  flash.hidden = !message;
}

// guard runs fn and surfaces an ApiError (or any error) as a flash message,
// so every action shares one error path.
async function guard(fn) {
  try {
    setFlash("");
    return await fn();
  } catch (err) {
    if (err instanceof ApiError) setFlash(err.problem?.detail || err.message);
    else setFlash(String(err?.message || err));
    return undefined;
  }
}

function fmt(ts) {
  return ts ? new Date(ts).toLocaleString() : "—";
}

// getOrNull fetches a resource that may legitimately 404 (backup config, ToS)
// and returns null in that case so views can render an empty state.
async function getOrNull(path) {
  try {
    return (await api.get(path)).data;
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) return null;
    throw err;
  }
}

// table renders a header row plus one row per cell array. Cells may be Nodes
// (buttons) or plain values; h() turns plain values into text nodes.
function table(headers, rows) {
  return h("table", {},
    h("thead", {}, h("tr", {}, ...headers.map((head) => h("th", {}, head)))),
    h("tbody", {}, ...rows.map((cells) => h("tr", {}, ...cells.map((cell) => h("td", {}, cell))))));
}

// jsonBlock renders an object as pretty-printed text (never HTML).
function jsonBlock(obj) {
  return h("pre", {}, JSON.stringify(obj, null, 2));
}

async function confirmAction(message, action) {
  if (!confirm(message)) return;
  await guard(action);
}

// --- dashboard ---

async function renderDashboard() {
  const info = (await api.get(`${BASE}/admin/system/info`)).data;
  const cards = h("dl", {}, ...Object.entries(info).map(([key, value]) =>
    h("div", {}, h("dt", {}, key), h("dd", {}, String(value)))));
  const caps = (await api.get(`${BASE}/meta/capabilities`)).data;
  const capEntries = Object.entries(caps);
  const capList = capEntries.length
    ? h("ul", {}, ...capEntries.map(([name, cap]) => {
      const wired = typeof cap === "boolean" ? cap : cap.wired;
      const desc = typeof cap === "boolean" ? "" : cap.description || "";
      return h("li", {}, `${name}: ${wired ? "wired" : "off"}${desc ? ` — ${desc}` : ""}`);
    }))
    : jsonBlock(caps);
  mount(section("System", cards), section("Capabilities", capList));
}

// --- tenants ---

async function renderTenants() {
  const { data } = await api.get(`${BASE}/admin/tenants`);
  const rows = data.data.map((t) => [
    t.id, t.handle, t.did, fmt(t.created_at),
    button("View", () => viewTenant(t.id)),
    button("Delete", () => confirmAction(`Delete tenant ${t.handle}?`, async () => {
      await api.delete(`${BASE}/admin/tenants/${encodeURIComponent(t.id)}`);
      await renderTenants();
    })),
  ]);
  const id = h("input", { type: "text", placeholder: "optional" });
  const handle = h("input", { type: "text", required: true });
  const did = h("input", { type: "text", required: true, placeholder: "did:web:example.com" });
  const didMethod = h("input", { type: "text", placeholder: "web" });
  const form = h("form", { onsubmit: (event) => {
    event.preventDefault();
    guard(async () => {
      await api.post(`${BASE}/admin/tenants`, {
        id: id.value.trim(), handle: handle.value.trim(), did: did.value.trim(), did_method: didMethod.value.trim(),
      });
      setFlash("Tenant created.", "ok");
      await renderTenants();
    });
  } }, h("fieldset", {}, h("legend", {}, "Create tenant"),
    field("Handle", handle), field("DID", did), field("DID method", didMethod), field("ID (optional)", id)),
    h("button", { type: "submit" }, "Create"));
  mount(section("Tenants", table(["ID", "Handle", "DID", "Created", "", ""], rows), form));
}

async function viewTenant(id) {
  await guard(async () => {
    const t = (await api.get(`${BASE}/admin/tenants/${encodeURIComponent(id)}`)).data;
    mount(section("Tenant", jsonBlock(t), button("Back", () => renderTenants())));
  });
}

// --- users ---

async function renderUsers() {
  const { data } = await api.get(`${BASE}/admin/users`);
  const rows = data.data.map((u) => [
    u.id, u.handle, u.email, u.display_name, u.is_admin ? "admin" : "", fmt(u.created_at),
    button("View", () => viewUser(u.id)),
    button("Delete", () => confirmAction(`Delete user ${u.handle}?`, async () => {
      await api.delete(`${BASE}/admin/users/${encodeURIComponent(u.id)}`);
      await renderUsers();
    })),
  ]);
  const tenantId = h("input", { type: "text", placeholder: "identity" });
  const handle = h("input", { type: "text", required: true });
  const email = h("input", { type: "email", required: true });
  const displayName = h("input", { type: "text" });
  const isAdmin = h("input", { type: "checkbox" });
  const form = h("form", { onsubmit: (event) => {
    event.preventDefault();
    guard(async () => {
      await api.post(`${BASE}/admin/users`, {
        tenant_id: tenantId.value.trim(), handle: handle.value.trim(), email: email.value.trim(),
        display_name: displayName.value.trim(), is_admin: isAdmin.checked,
      });
      setFlash("User created; invite emailed.", "ok");
      await renderUsers();
    });
  } }, h("fieldset", {}, h("legend", {}, "Create user"),
    field("Tenant ID", tenantId), field("Handle", handle), field("Email", email), field("Display name", displayName),
    h("label", {}, isAdmin, " Admin")),
    h("button", { type: "submit" }, "Create"));
  mount(section("Users", table(["ID", "Handle", "Email", "Name", "Role", "Created", "", ""], rows), form));
}

async function viewUser(id) {
  await guard(async () => {
    const u = (await api.get(`${BASE}/admin/users/${encodeURIComponent(id)}`)).data;
    const email = h("input", { type: "email", value: u.email });
    const displayName = h("input", { type: "text", value: u.display_name || "" });
    const isAdmin = h("input", { type: "checkbox" });
    isAdmin.checked = u.is_admin;
    const form = h("form", { onsubmit: (event) => {
      event.preventDefault();
      guard(async () => {
        await api.patch(`${BASE}/admin/users/${encodeURIComponent(id)}`, {
          email: email.value.trim(), display_name: displayName.value.trim(), is_admin: isAdmin.checked,
        });
        setFlash("User updated.", "ok");
        await viewUser(id);
      });
    } }, h("fieldset", {}, h("legend", {}, "Update"),
      field("Email", email), field("Display name", displayName), h("label", {}, isAdmin, " Admin")),
      h("button", { type: "submit" }, "Save"));
    const creds = (await api.get(`${BASE}/admin/users/${encodeURIComponent(id)}/credentials`)).data;
    const credList = h("ul", {}, ...creds.map((c) =>
      h("li", {}, `${c.credential_id} · created ${fmt(c.created_at)}`)));
    mount(section("User", jsonBlock(u), form,
      h("h3", {}, "Actions"),
      button("Send invite", () => guard(async () => {
        await api.post(`${BASE}/admin/users/${encodeURIComponent(id)}/invites`, {});
        setFlash("Invite emailed.", "ok");
      })),
      button("Revoke sessions", () => confirmAction("Revoke every session for this user?", async () => {
        await api.post(`${BASE}/admin/users/${encodeURIComponent(id)}/sessions:revoke`, {});
        setFlash("Sessions revoked.", "ok");
      })),
      h("h3", {}, "Passkeys"), credList,
      button("Back", () => renderUsers())));
  });
}

// --- clients ---

async function renderClients() {
  const { data } = await api.get(`${BASE}/admin/clients`);
  const rows = data.data.map((c) => [
    c.id, c.name || "", c.audience || "", fmt(c.created_at),
    button("View", () => viewClient(c.id)),
    button("Rotate secret", () => rotateSecret(c.id)),
    button("Delete", () => confirmAction(`Delete client ${c.id}?`, async () => {
      await api.delete(`${BASE}/admin/clients/${encodeURIComponent(c.id)}`);
      await renderClients();
    })),
  ]);
  const id = h("input", { type: "text", required: true });
  const form = h("form", { onsubmit: (event) => {
    event.preventDefault();
    guard(async () => {
      const { data: created } = await api.post(`${BASE}/admin/clients`, { id: id.value.trim() });
      showSecretOnce(created.secret);
    });
  } }, h("fieldset", {}, h("legend", {}, "Create client"), field("Client ID", id)),
    h("button", { type: "submit" }, "Create"));
  mount(section("Clients", table(["ID", "Name", "Audience", "Created", "", "", ""], rows), form));
}

async function viewClient(id) {
  await guard(async () => {
    const c = (await api.get(`${BASE}/admin/clients/${encodeURIComponent(id)}`)).data;
    mount(section("Client", jsonBlock(c), button("Back", () => renderClients())));
  });
}

async function rotateSecret(id) {
  await guard(async () => {
    const { data } = await api.post(`${BASE}/admin/clients/${encodeURIComponent(id)}/secret/rotate`, {});
    showSecretOnce(data.secret);
  });
}

// showSecretOnce renders a client secret that the server returns exactly once.
function showSecretOnce(secret) {
  mount(section("Client secret",
    h("p", {}, "Copy this secret now. It is shown only once and cannot be retrieved again."),
    h("p", {}, h("code", {}, secret),
      button("Copy", async () => {
        try {
          await navigator.clipboard.writeText(secret);
          setFlash("Copied.", "ok");
        } catch {
          setFlash("Copy failed; select and copy manually.");
        }
      })),
    h("p", {}, button("Done", () => renderClients()))));
}

// --- backups ---

async function renderBackups() {
  const cfg = await getOrNull(`${BASE}/admin/backup/config`);
  const schedule = h("input", { type: "text", value: cfg?.schedule || "", placeholder: "0 2 * * *" });
  const destination = h("input", { type: "text", value: cfg?.destination || "" });
  const prefix = h("input", { type: "text", value: cfg?.prefix || "" });
  const cfgForm = h("form", { onsubmit: (event) => {
    event.preventDefault();
    guard(async () => {
      await api.put(`${BASE}/admin/backup/config`, {
        schedule: schedule.value.trim(), destination: destination.value.trim(), prefix: prefix.value.trim(),
      });
      setFlash("Backup config saved.", "ok");
      await renderBackups();
    });
  } }, h("fieldset", {}, h("legend", {}, "Config"),
    field("Schedule (cron)", schedule), field("Destination", destination), field("Prefix", prefix)),
    h("button", { type: "submit" }, "Save"));

  const runs = (await api.get(`${BASE}/admin/backup/runs`)).data;
  const runRows = runs.data.map((r) => [
    r.id, r.status, fmt(r.started_at), r.finished_at ? fmt(r.finished_at) : "—", String(r.size_bytes),
    button("View", () => viewBackupRun(r.id)),
  ]);
  const restores = (await api.get(`${BASE}/admin/backup/restores`)).data;
  const restoreRows = restores.data.map((r) => [r.id, r.status, r.source_key, fmt(r.started_at), r.error || ""]);
  const sourceKey = h("input", { type: "text", required: true });
  const confirmBox = h("input", { type: "checkbox", required: true });
  const restoreForm = h("form", { onsubmit: (event) => {
    event.preventDefault();
    guard(async () => {
      await api.post(`${BASE}/admin/backup/restores`, { source_key: sourceKey.value.trim(), confirm: confirmBox.checked });
      setFlash("Restore started.", "ok");
      await renderBackups();
    });
  } }, h("fieldset", {}, h("legend", {}, "Restore"),
    field("Source key", sourceKey), h("label", {}, confirmBox, " I confirm this overwrites current data")),
    h("button", { type: "submit" }, "Restore"));

  mount(section("Backups", cfgForm,
    h("h3", {}, "Runs"), button("Run backup now", () => guard(async () => {
      await api.post(`${BASE}/admin/backup/runs`, {});
      setFlash("Backup started.", "ok");
      await renderBackups();
    })), table(["ID", "Status", "Started", "Finished", "Size", ""], runRows),
    h("h3", {}, "Restores"), restoreForm, table(["ID", "Status", "Source", "Started", "Error"], restoreRows)));
}

async function viewBackupRun(id) {
  await guard(async () => {
    const run = (await api.get(`${BASE}/admin/backup/runs/${encodeURIComponent(id)}`)).data;
    mount(section("Backup run", jsonBlock(run), button("Back", () => renderBackups())));
  });
}

// --- moderation ---

async function renderModeration() {
  const { data } = await api.get(`${BASE}/admin/moderation/takedowns`);
  const rows = data.data.map((t) => [
    t.id, t.resource, t.reason, t.acted_by, fmt(t.created_at),
    button("View", () => viewTakedown(t.id)),
    button("Lift", () => confirmAction("Lift this takedown?", async () => {
      await api.delete(`${BASE}/admin/moderation/takedowns/${encodeURIComponent(t.id)}`);
      await renderModeration();
    })),
  ]);
  const resource = h("input", { type: "text", required: true });
  const reason = h("input", { type: "text", required: true });
  const form = h("form", { onsubmit: (event) => {
    event.preventDefault();
    guard(async () => {
      await api.post(`${BASE}/admin/moderation/takedowns`, { resource: resource.value.trim(), reason: reason.value.trim() });
      setFlash("Takedown recorded.", "ok");
      await renderModeration();
    });
  } }, h("fieldset", {}, h("legend", {}, "New takedown"),
    field("Resource", resource), field("Reason", reason)),
    h("button", { type: "submit" }, "Record"));
  mount(section("Moderation", table(["ID", "Resource", "Reason", "Acted by", "Created", "", ""], rows), form));
}

async function viewTakedown(id) {
  await guard(async () => {
    const t = (await api.get(`${BASE}/admin/moderation/takedowns/${encodeURIComponent(id)}`)).data;
    mount(section("Takedown", jsonBlock(t), button("Back", () => renderModeration())));
  });
}

// --- audit ---

async function renderAudit() {
  const { data } = await api.get(`${BASE}/admin/audit`);
  const rows = data.data.map((e) => [e.id, e.actor, e.action, e.resource, e.detail, fmt(e.created_at)]);
  mount(section("Audit log", table(["ID", "Actor", "Action", "Resource", "Detail", "When"], rows)));
}

// --- IPFS pins ---

async function renderIPFS() {
  const pins = (await api.get(`${BASE}/admin/ipfs/pins`)).data;
  const rows = pins.map((p) => [
    p.cid, p.status, fmt(p.created_at),
    button("Status", () => pinStatus(p.cid)),
  ]);
  const cid = h("input", { type: "text", required: true, placeholder: "bafy…" });
  const form = h("form", { onsubmit: (event) => {
    event.preventDefault();
    guard(async () => {
      await api.post(`${BASE}/admin/ipfs/pins`, { cid: cid.value.trim() });
      setFlash("Pin added.", "ok");
      await renderIPFS();
    });
  } }, h("fieldset", {}, h("legend", {}, "Add pin"), field("CID", cid)),
    h("button", { type: "submit" }, "Pin"));
  mount(section("IPFS pins", table(["CID", "Status", "Created", ""], rows), form));
}

async function pinStatus(cid) {
  await guard(async () => {
    const pin = (await api.get(`${BASE}/admin/ipfs/pins/${encodeURIComponent(cid)}`)).data;
    mount(section("Pin", jsonBlock(pin), button("Back", () => renderIPFS())));
  });
}

// --- terms of service ---

async function renderToS() {
  const doc = await getOrNull(`${BASE}/admin/tos`);
  const version = h("input", { type: "text", value: doc?.version || "", required: true });
  const content = h("textarea", { rows: "10", required: true }, doc?.content || "");
  const form = h("form", { onsubmit: (event) => {
    event.preventDefault();
    guard(async () => {
      await api.put(`${BASE}/admin/tos`, { version: version.value.trim(), content: content.value.trim() });
      setFlash("ToS published.", "ok");
      await renderToS();
    });
  } }, h("fieldset", {}, h("legend", {}, "Publish Terms of Service"),
    field("Version", version), field("Content", content)),
    h("button", { type: "submit" }, "Publish"));
  mount(section("Terms of Service",
    doc ? h("p", {}, `Current: v${doc.version} (${fmt(doc.published_at)})`) : h("p", {}, "No ToS published yet."),
    form));
}

// --- deletion requests ---

async function renderDeletions() {
  const { data } = await api.get(`${BASE}/admin/deletion-requests`);
  const rows = data.data.map((d) => [
    d.id, d.user_id, d.status, fmt(d.requested_at),
    button("Approve", () => confirmAction("Approve deletion? This permanently deletes the account.", async () => {
      await api.post(`${BASE}/admin/deletion-requests/${encodeURIComponent(d.id)}/approve`, {});
      setFlash("Deletion approved.", "ok");
      await renderDeletions();
    })),
    button("Reject", () => confirmAction("Reject this deletion request?", async () => {
      await api.post(`${BASE}/admin/deletion-requests/${encodeURIComponent(d.id)}/reject`, {});
      setFlash("Deletion rejected.", "ok");
      await renderDeletions();
    })),
  ]);
  mount(section("Deletion requests", table(["ID", "User", "Status", "Requested", "", ""], rows)));
}

// --- routing ---

const VIEWS = {
  dashboard: renderDashboard,
  tenants: renderTenants,
  users: renderUsers,
  clients: renderClients,
  backups: renderBackups,
  moderation: renderModeration,
  audit: renderAudit,
  ipfs: renderIPFS,
  tos: renderToS,
  deletions: renderDeletions,
};

function currentView() {
  return (location.hash || "#dashboard").slice(1);
}

async function renderView(name) {
  const render = VIEWS[name] || VIEWS.dashboard;
  for (const link of nav.querySelectorAll("[data-view]")) {
    link.classList.toggle("active", link.dataset.view === name);
  }
  await guard(render);
}

window.addEventListener("hashchange", () => renderView(currentView()));
nav.addEventListener("click", (event) => {
  const link = event.target.closest("[data-view]");
  if (!link) return;
  event.preventDefault();
  location.hash = link.dataset.view;
});

renderView(currentView());
