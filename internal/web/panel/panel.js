// Panel thin client. A client-side step machine over the /api/v1 REST API:
// onboarding state drives the view (accept ToS → register passkey →
// dashboard), and each dashboard surface is a small render function. Every
// request goes through the shared api.js module — no raw fetch, no framework,
// no build step. User-supplied data is only ever written with textContent, so
// nothing here can turn into HTML.
import { api, ApiError } from "../shared/api.js";

const BASE = "/api/v1";

const view = document.getElementById("view");
const nav = document.getElementById("nav");
const flash = document.getElementById("flash");

// --- DOM helpers ---

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

// h builds a DOM node. Text children are appended as text nodes (never
// parsed as HTML), which is the whole XSS defence for this file.
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

// --- step machine ---

async function boot() {
  await guard(async () => {
    const { data } = await api.get(`${BASE}/me/onboarding`);
    nav.hidden = true;
    if (!data.tos_accepted) return renderToS();
    if (!data.has_passkey) return renderPasskey();
    nav.hidden = false;
    await renderSurface("profile");
  });
}

function renderToS() {
  const accept = h("input", { type: "checkbox", required: true });
  const form = h("form", { onsubmit: (event) => {
    event.preventDefault();
    if (!accept.checked) return setFlash("Tick the box to accept the Terms of Service.");
    guard(async () => {
      await api.post(`${BASE}/me/tos`, {});
      await boot();
    });
  } }, h("fieldset", {}, h("legend", {}, "Acceptance"),
    h("label", {}, accept, " I accept the Terms of Service")),
    h("button", { type: "submit" }, "Accept"));
  mount(section("Terms of Service",
    h("p", {}, "Welcome to Sovereign. Before you can use your account, please review and accept the Terms of Service."),
    form));
}

function renderPasskey() {
  const status = h("p", {});
  mount(section("Set up your passkey",
    h("p", {}, "Your account uses passkeys for authentication. Set one up now."),
    button("Register passkey", () => registerPasskey(status)), status));
}

// base64url decode/encode for the WebAuthn ceremony.
function b64urlToBuf(value) {
  const padded = `${value.replace(/-/g, "+").replace(/_/g, "/")}${"===".slice((value.length + 3) % 4)}`;
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function bufToB64url(buf) {
  const bytes = new Uint8Array(buf);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function registerPasskey(status) {
  await guard(async () => {
    status.textContent = "Contacting server…";
    // go-webauthn wraps the creation options under "publicKey" and returns
    // base64url strings; the browser needs ArrayBuffers for the binary fields.
    const { data } = await api.post(`${BASE}/auth/webauthn/register/begin`, {});
    const publicKey = data.publicKey || data;
    const challenge = publicKey.challenge;
    publicKey.challenge = b64urlToBuf(challenge);
    if (publicKey.user?.id) publicKey.user.id = b64urlToBuf(publicKey.user.id);
    if (publicKey.excludeCredentials) {
      publicKey.excludeCredentials = publicKey.excludeCredentials.map((c) => ({ ...c, id: b64urlToBuf(c.id) }));
    }
    status.textContent = "Waiting for your authenticator…";
    const cred = await navigator.credentials.create({ publicKey });
    await api.post(`${BASE}/auth/webauthn/register/finish?challenge=${encodeURIComponent(challenge)}`, {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bufToB64url(cred.response.clientDataJSON),
        attestationObject: bufToB64url(cred.response.attestationObject),
        transports: cred.response.getTransports ? cred.response.getTransports() : [],
      },
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
    });
    await boot();
  });
}

// --- dashboard ---

const SURFACES = {
  profile: renderProfile,
  keys: renderKeys,
  proofs: renderProofs,
  credentials: renderCredentials,
  sessions: renderSessions,
  tokens: renderTokens,
  account: renderAccount,
};

async function renderSurface(name) {
  const render = SURFACES[name] || SURFACES.profile;
  for (const tab of nav.querySelectorAll("[data-surface]")) {
    tab.classList.toggle("active", tab.dataset.surface === name);
  }
  await guard(render);
}

nav.addEventListener("click", (event) => {
  const target = event.target.closest("[data-surface]");
  if (!target) return;
  event.preventDefault();
  renderSurface(target.dataset.surface);
});

// --- profile ---

async function renderProfile() {
  let page = null;
  try {
    page = (await api.get(`${BASE}/me/profile`)).data;
  } catch (err) {
    if (!(err instanceof ApiError) || err.status !== 404) throw err;
  }

  const name = h("input", { type: "text", value: page?.display_name || "", required: true, maxlength: "100" });
  const bio = h("textarea", { rows: "4" }, page?.bio || "");
  const form = h("form", { onsubmit: (event) => {
    event.preventDefault();
    guard(async () => {
      await api.put(`${BASE}/me/profile`, { display_name: name.value.trim(), bio: bio.value.trim() });
      setFlash("Profile saved.", "ok");
      await renderProfile();
    });
  } }, h("fieldset", {}, h("legend", {}, "Profile"),
    labelled("Display name", name), labelled("Bio", bio)),
    h("button", { type: "submit" }, "Save"));

  const hasAvatar = Boolean(page?.avatar_url) && !page.avatar_url.endsWith("/avatar/");
  const file = h("input", { type: "file", accept: "image/*" });
  const avatarForm = h("form", { onsubmit: (event) => {
    event.preventDefault();
    if (!file.files[0]) return setFlash("Choose an image first.");
    guard(async () => {
      const body = new FormData();
      body.append("avatar", file.files[0]);
      await api.put(`${BASE}/me/profile/avatar`, body);
      setFlash("Avatar uploaded.", "ok");
      await renderProfile();
    });
  } }, h("fieldset", {}, h("legend", {}, "Avatar"),
    hasAvatar ? h("img", { src: page.avatar_url, alt: "Current avatar", width: "96", height: "96" })
      : h("p", {}, "No avatar yet."),
    labelled("Upload", file)),
    h("button", { type: "submit" }, "Upload"));

  const publishForm = page
    ? h("form", { onsubmit: (event) => {
      event.preventDefault();
      const action = page.is_published ? "unpublish" : "publish";
      guard(async () => {
        await api.post(`${BASE}/me/profile:${action}`, {});
        setFlash(`Profile ${action}ed.`, "ok");
        await renderProfile();
      });
    } }, h("fieldset", {}, h("legend", {}, "Visibility"),
      h("p", {}, page.is_published ? "Published." : "Draft (not public).")),
      h("button", { type: "submit" }, page.is_published ? "Unpublish" : "Publish"))
    : h("p", {}, "Save your profile before publishing.");

  mount(section("Profile", form, avatarForm, publishForm,
    h("h3", {}, "Links"), await renderLinks(page)));
}

async function renderLinks(page) {
  if (!page) return h("p", {}, "Save your profile to add links.");
  const links = (await api.get(`${BASE}/me/profile/links`)).data;

  const label = h("input", { type: "text", required: true });
  const url = h("input", { type: "url", required: true, placeholder: "https://example.com" });
  const add = h("form", { onsubmit: (event) => {
    event.preventDefault();
    guard(async () => {
      await api.post(`${BASE}/me/profile/links`, { label: label.value.trim(), url: url.value.trim() });
      await renderProfile();
    });
  } }, h("fieldset", {}, h("legend", {}, "Add link"),
    labelled("Label", label), labelled("URL", url)),
    h("button", { type: "submit" }, "Add"));

  const list = h("ul", {}, ...links.map((link, index) => {
    const l = h("input", { type: "text", value: link.label, required: true });
    const u = h("input", { type: "url", value: link.url, required: true });
    return h("li", {}, labelled("Label", l), labelled("URL", u),
      button("Save", () => guard(async () => {
        await api.patch(`${BASE}/me/profile/links/${encodeURIComponent(link.id)}`, { label: l.value.trim(), url: u.value.trim() });
        setFlash("Link saved.", "ok");
        await renderProfile();
      })),
      button("Up", () => moveLink(links, index, -1)),
      button("Down", () => moveLink(links, index, 1)),
      button("Delete", () => confirmAction("Delete this link?", async () => {
        await api.delete(`${BASE}/me/profile/links/${encodeURIComponent(link.id)}`);
        await renderProfile();
      })));
  }));
  return h("div", {}, list, add);
}

async function moveLink(links, index, delta) {
  const target = index + delta;
  if (target < 0 || target >= links.length) return;
  const ids = links.map((link) => link.id);
  [ids[index], ids[target]] = [ids[target], ids[index]];
  await guard(async () => {
    await api.post(`${BASE}/me/profile/links:reorder`, { ids });
    await renderProfile();
  });
}

// --- keys ---

async function renderKeys() {
  const keys = (await api.get(`${BASE}/me/keys`)).data;
  const type = h("select", {}, h("option", { value: "ssh" }, "SSH"), h("option", { value: "pgp" }, "PGP"));
  const material = h("textarea", { rows: "4", required: true, placeholder: "ssh-ed25519 AAAA… or -----BEGIN PGP PUBLIC KEY BLOCK-----" });
  const label = h("input", { type: "text" });
  const form = h("form", { onsubmit: (event) => {
    event.preventDefault();
    guard(async () => {
      await api.post(`${BASE}/me/keys`, { type: type.value, public_key: material.value.trim(), label: label.value.trim() });
      setFlash("Key added.", "ok");
      await renderKeys();
    });
  } }, h("fieldset", {}, h("legend", {}, "Add public key"),
    labelled("Type", type), labelled("Label", label), labelled("Public key", material)),
    h("button", { type: "submit" }, "Add key"));

  const list = h("ul", {}, ...keys.map((key) => h("li", {},
    h("strong", {}, `${key.type.toUpperCase()} ${key.fingerprint}`),
    h("code", {}, key.public_key || ""),
    key.revoked_at ? h("em", {}, " revoked") : button("Revoke", () => guard(async () => {
      await api.post(`${BASE}/me/keys/${encodeURIComponent(key.id)}/revoke`, {});
      await renderKeys();
    })),
    button("Delete", () => confirmAction("Delete this key?", async () => {
      await api.delete(`${BASE}/me/keys/${encodeURIComponent(key.id)}`);
      await renderKeys();
    })))));
  mount(section("Keys", list, form));
}

// --- proofs ---

async function renderProofs() {
  const proofs = (await api.get(`${BASE}/me/proofs`)).data;
  const anchorType = h("input", { type: "text", required: true, placeholder: "dns" });
  const anchorValue = h("input", { type: "text", required: true });
  const service = h("select", {}, ...["dns", "github_gist", "mastodon", "bluesky", "custom_url"]
    .map((name) => h("option", { value: name }, name)));
  const claimLocation = h("input", { type: "text", required: true });
  const expectedToken = h("input", { type: "text", required: true });
  const form = h("form", { onsubmit: (event) => {
    event.preventDefault();
    guard(async () => {
      await api.post(`${BASE}/me/proofs`, {
        anchor_type: anchorType.value.trim(),
        anchor_value: anchorValue.value.trim(),
        service: service.value,
        claim_location: claimLocation.value.trim(),
        expected_token: expectedToken.value.trim(),
      });
      await renderProofs();
    });
  } }, h("fieldset", {}, h("legend", {}, "Add proof"),
    labelled("Anchor type", anchorType), labelled("Anchor value", anchorValue),
    labelled("Service", service), labelled("Claim location", claimLocation),
    labelled("Expected token", expectedToken)),
    h("button", { type: "submit" }, "Add proof"));

  const list = h("ul", {}, ...proofs.map((proof) => h("li", {},
    h("strong", {}, `${proof.type} ${proof.target}`),
    h("em", {}, ` ${proof.status}`),
    button("Verify", () => guard(async () => {
      const { data } = await api.post(`${BASE}/me/proofs/${encodeURIComponent(proof.id)}/verify`, {});
      setFlash(`Proof ${data.status}.`, data.status === "verified" ? "ok" : "error");
      await renderProofs();
    })),
    button("Delete", () => confirmAction("Delete this proof?", async () => {
      await api.delete(`${BASE}/me/proofs/${encodeURIComponent(proof.id)}`);
      await renderProofs();
    })))));
  mount(section("Proofs", list, form));
}

// --- passkeys (credentials) ---

async function renderCredentials() {
  const creds = (await api.get(`${BASE}/me/credentials`)).data;
  const list = h("ul", {}, ...creds.map((cred) => h("li", {},
    h("strong", {}, cred.credential_id),
    h("span", {}, ` created ${fmt(cred.created_at)}`),
    button("Delete", () => confirmAction("Delete this passkey?", async () => {
      await api.delete(`${BASE}/me/credentials/${encodeURIComponent(cred.id)}`);
      await renderCredentials();
    })))));
  mount(section("Passkeys", creds.length ? list : h("p", {}, "No passkeys.")));
}

// --- sessions ---

async function renderSessions() {
  const sessions = (await api.get(`${BASE}/me/sessions`)).data;
  const list = h("ul", {}, ...sessions.map((session) => h("li", {},
    h("strong", {}, session.id),
    h("span", {}, ` last seen ${fmt(session.last_seen_at)} · expires ${fmt(session.expires_at)}`),
    session.revoked_at ? h("em", {}, " revoked") : button("Revoke", () => guard(async () => {
      await api.delete(`${BASE}/me/sessions/${encodeURIComponent(session.id)}`);
      await renderSessions();
    })))));
  mount(section("Sessions", list,
    button("Revoke all other sessions", () => confirmAction("Revoke every other session?", async () => {
      await api.delete(`${BASE}/me/sessions`);
      setFlash("Other sessions revoked.", "ok");
      await renderSessions();
    }))));
}

// --- API tokens ---

async function renderTokens() {
  const tokens = (await api.get(`${BASE}/me/tokens`)).data;
  const name = h("input", { type: "text", placeholder: "token name" });
  const scopes = h("input", { type: "text", required: true, placeholder: "self:read, keys:read" });
  const form = h("form", { onsubmit: (event) => {
    event.preventDefault();
    const requested = scopes.value.split(",").map((s) => s.trim()).filter(Boolean);
    guard(async () => {
      const { data } = await api.post(`${BASE}/me/tokens`, { name: name.value.trim(), scopes: requested });
      showTokenOnce(data.token);
    });
  } }, h("fieldset", {}, h("legend", {}, "Create token"),
    labelled("Name", name), labelled("Scopes (comma-separated)", scopes)),
    h("button", { type: "submit" }, "Create"));

  const list = h("ul", {}, ...tokens.map((token) => h("li", {},
    h("strong", {}, token.name || token.id),
    h("span", {}, ` ${(token.scopes || []).join(", ")} · expires ${fmt(token.expires_at)}`),
    button("Revoke", () => confirmAction("Revoke this token?", async () => {
      await api.delete(`${BASE}/me/tokens/${encodeURIComponent(token.family_id)}`);
      await renderTokens();
    })))));
  mount(section("API tokens",
    h("p", {}, "Requested scopes must be ones your account already holds."), list, form));
}

function showTokenOnce(token) {
  mount(section("Token created",
    h("p", {}, "Copy this token now. It is shown only once and cannot be retrieved again."),
    h("p", {}, h("code", {}, token),
      button("Copy", async () => {
        try {
          await navigator.clipboard.writeText(token);
          setFlash("Copied.", "ok");
        } catch {
          setFlash("Copy failed; select and copy manually.");
        }
      })),
    h("p", {}, button("Done", () => renderTokens()))));
}

// --- account ---

function renderAccount() {
  mount(section("Account",
    h("h3", {}, "Export"),
    h("p", {}, "Download everything Sovereign holds about you as a JSON document."),
    button("Download my data", () => guard(async () => {
      const { data } = await api.get(`${BASE}/me/export`);
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = h("a", { href: url, download: "sovereign-export.json" });
      document.body.append(link);
      link.click();
      link.remove();
      // Revoke after the download has had a chance to start.
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      setFlash("Export downloaded.", "ok");
    })),
    h("h3", {}, "Delete account"),
    h("p", {}, "Requests deletion. Your account stays usable until an administrator approves the request."),
    button("Request account deletion", () => confirmAction(
      "Request deletion of your account? An administrator must approve it.",
      async () => {
        await api.delete(`${BASE}/me`);
        setFlash("Deletion requested.", "ok");
      }))));
}

async function confirmAction(message, action) {
  if (!confirm(message)) return;
  await guard(action);
}

boot();
