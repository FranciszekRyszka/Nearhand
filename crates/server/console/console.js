// The Nearhand console: a page over the REST API (/api/v1), and nothing
// more — anything it does, a script can do with an API token.
//
// Everything shown comes from the server and is put on the page as text,
// never as HTML: `h()` builds elements, and sets text with textContent.
"use strict";

// --- Small tools -------------------------------------------------------------

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === undefined || value === null || value === false) continue;
    if (key.startsWith("on")) el.addEventListener(key.slice(2), value);
    else if (key === "class") el.className = value;
    else if (value === true) el.setAttribute(key, "");
    else el.setAttribute(key, String(value));
  }
  for (const child of children.flat(Infinity)) {
    if (child === undefined || child === null || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

class ApiError extends Error {
  constructor(status, body) {
    super((body && body.error) || `HTTP ${status}`);
    this.status = status;
    this.body = body || {};
  }
}

async function api(method, path, body) {
  const init = { method, headers: {}, credentials: "same-origin" };
  if (body !== undefined) {
    init.headers["content-type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  const response = await fetch("/api/v1" + path, init);
  const text = await response.text();
  const data = text ? JSON.parse(text) : null;
  if (!response.ok) {
    if (response.status === 401 && !path.startsWith("/login") && !path.startsWith("/setup")) {
      state.me = null;
      render();
    }
    throw new ApiError(response.status, data);
  }
  return data;
}

function when(seconds) {
  if (!seconds) return "—";
  const date = new Date(seconds * 1000);
  const ago = Math.round(Date.now() / 1000 - seconds);
  if (ago >= 0 && ago < 60) return "just now";
  if (ago >= 0 && ago < 3600) return `${Math.round(ago / 60)} min ago`;
  if (ago >= 0 && ago < 86400) return `${Math.round(ago / 3600)} h ago`;
  return date.toLocaleString();
}

function field(label, input) {
  return h("label", {}, label, input);
}

/// A form whose submit runs `action` with its values, showing any error.
function form(className, fields, submitText, action) {
  const error = h("span", { class: "error" });
  const el = h("form", { class: className }, fields, h("button", { class: "primary", type: "submit" }, submitText), error);
  el.addEventListener("submit", async (event) => {
    event.preventDefault();
    error.textContent = "";
    const values = Object.fromEntries(new FormData(el).entries());
    for (const box of el.querySelectorAll("input[type=checkbox]")) values[box.name] = box.checked;
    try {
      await action(values, el);
    } catch (e) {
      error.textContent = e.message;
    }
  });
  return el;
}

/// Run `action`, and on failure say why in an alert.
async function attempt(action) {
  try {
    await action();
  } catch (e) {
    alert(e.message);
  }
}

function table(headings, rows, empty) {
  if (!rows.length) return h("p", { class: "quiet" }, empty);
  return h("div", { class: "table-wrap" },
    h("table", {}, h("thead", {}, h("tr", {}, headings.map((t) => h("th", {}, t)))), h("tbody", {}, rows)));
}

function shownOnce(title, lines) {
  return h("div", { class: "once" },
    h("strong", {}, title),
    h("p", { class: "quiet" }, "Shown this once: copy it now."),
    lines.map(([label, text]) => [h("div", { class: "quiet" }, label), h("pre", {}, text)]));
}

// --- State and navigation ------------------------------------------------------

const state = { me: null, server: null };

const tabs = [
  { id: "devices", title: "Devices" },
  { id: "enroll", title: "Enrollment", admin: true },
  { id: "users", title: "Users", admin: true },
  { id: "groups", title: "Groups & grants", admin: true },
  { id: "audit", title: "Audit log", admin: true },
  { id: "account", title: "Account" },
];

function currentTab() {
  const id = location.hash.slice(1);
  const tab = tabs.find((t) => t.id === id && (!t.admin || state.me.admin));
  return tab ? tab.id : "devices";
}

window.addEventListener("hashchange", () => render());

async function start() {
  try {
    state.me = await api("GET", "/me");
  } catch {
    state.me = null;
  }
  render();
}

async function render() {
  const app = document.getElementById("app");
  const nav = document.getElementById("tabs");
  const who = document.getElementById("who");
  nav.replaceChildren();
  who.replaceChildren();
  const setup = location.hash.match(/^#setup=([0-9a-f]+)$/);
  if (setup && !state.me) {
    app.replaceChildren(setupPage(setup[1]));
    return;
  }
  if (!state.me) {
    app.replaceChildren(signInPage());
    return;
  }
  const current = currentTab();
  for (const tab of tabs) {
    if (tab.admin && !state.me.admin) continue;
    nav.append(h("a", { href: "#" + tab.id, class: tab.id === current ? "current" : "" }, tab.title));
  }
  who.append(
    h("span", {}, state.me.name, state.me.admin ? " (administrator)" : ""),
    h("button", { class: "link", onclick: signOut }, "Sign out"),
  );
  app.replaceChildren(h("p", { class: "quiet" }, "Loading…"));
  try {
    if (!state.server) state.server = await api("GET", "/server");
    const page = await pages[current]();
    app.replaceChildren(page);
  } catch (e) {
    if (e.status !== 401) app.replaceChildren(h("p", { class: "error" }, e.message));
  }
}

// --- Signing in -------------------------------------------------------------------

function signInPage() {
  let needCode = false;
  const code = h("input", { name: "totp", autocomplete: "one-time-code", inputmode: "numeric" });
  const codeField = field("Code from your authenticator app", code);
  codeField.hidden = true;
  return h("div", { class: "narrow" }, h("section", {},
    h("h2", {}, "Sign in"),
    form("", [
      field("Name", h("input", { name: "name", autocomplete: "username", required: true, autofocus: true })),
      field("Password", h("input", { name: "password", type: "password", autocomplete: "current-password", required: true })),
      codeField,
    ], "Sign in", async (values) => {
      const body = { name: values.name, password: values.password };
      if (needCode) body.totp = values.totp;
      try {
        state.me = await api("POST", "/login", body);
      } catch (e) {
        if (e.body.totp_needed) {
          needCode = true;
          codeField.hidden = false;
          code.focus();
          if (!body.totp) return;
        }
        throw e;
      }
      render();
    })));
}

function setupPage(token) {
  return h("div", { class: "narrow" }, h("section", {},
    h("h2", {}, "Create the first administrator"),
    h("p", { class: "quiet" }, "This link works once, and only while the server has no users."),
    form("", [
      field("Name", h("input", { name: "name", required: true, autofocus: true })),
      field("Password (at least 10 characters)", h("input", { name: "password", type: "password", autocomplete: "new-password", required: true, minlength: 10 })),
    ], "Create and sign in", async (values) => {
      await api("POST", "/setup", { token, name: values.name, password: values.password });
      state.me = await api("POST", "/login", { name: values.name, password: values.password });
      history.replaceState(null, "", "#devices");
      render();
    })));
}

async function signOut() {
  await attempt(async () => {
    await api("POST", "/logout");
    state.me = null;
    state.server = null;
    render();
  });
}

// --- Pages -----------------------------------------------------------------------

const pages = {
  async devices() {
    const devices = await api("GET", "/devices");
    const groups = state.me.admin ? await api("GET", "/device-groups") : [];
    const rows = devices.map((d) => {
      const actions = [];
      if (state.me.admin) {
        const move = h("select", {
          onchange: (e) => attempt(async () => {
            await api("PATCH", `/devices/${d.id}`, { group_id: e.target.value ? Number(e.target.value) : null });
            render();
          }),
        }, h("option", { value: "" }, "no group"),
          groups.map((g) => h("option", { value: g.id, selected: g.id === d.group_id }, g.name)));
        actions.push(
          move,
          h("button", {
            class: "link", onclick: () => attempt(async () => {
              const name = prompt("New name", d.name);
              if (name) await api("PATCH", `/devices/${d.id}`, { name });
              render();
            }),
          }, "Rename"),
          h("button", {
            class: "link danger", onclick: () => attempt(async () => {
              if (!confirm(`Remove ${d.name} from the list? It keeps running; a new token enrolls it again.`)) return;
              await api("DELETE", `/devices/${d.id}`);
              render();
            }),
          }, "Remove"),
        );
      }
      return h("tr", {},
        h("td", {}, h("span", { class: d.online ? "dot on" : "dot", title: d.online ? "online" : "offline" }), d.name),
        h("td", {}, h("code", {}, d.device_id)),
        h("td", {}, state.me.admin ? "" : d.group || "—"),
        h("td", {}, d.role || "—"),
        h("td", {}, d.online ? "online" : when(d.last_seen_at)),
        h("td", {}, d.os, " · ", d.version),
        state.me.admin ? h("td", {}, actions) : null,
      );
    });
    const headings = ["Name", "ID", state.me.admin ? "" : "Group", "Your role", "Seen", "System"];
    if (state.me.admin) headings.push("Group and actions");
    return h("div", {},
      h("section", {},
        h("h2", {}, "Devices"),
        table(headings, rows, state.me.admin
          ? "No devices yet. Make an enrollment token, and install the agent with it."
          : "No devices: you have no grants yet. An administrator gives them."),
      ),
      h("section", {},
        h("h2", {}, "Connecting"),
        h("p", {}, "With an API token of yours (Account), from a machine with the viewer:"),
        h("pre", {}, `NEARHAND_TOKEN=nht_… nearhand-viewer connect "<ID>" --server ${state.server.address} --server-fingerprint ${state.server.fingerprint}`),
      ));
  },

  async enroll() {
    const [tokens, groups] = await Promise.all([api("GET", "/enroll-tokens"), api("GET", "/device-groups")]);
    const made = h("div");
    const groupName = (id) => (groups.find((g) => g.id === id) || {}).name || "—";
    return h("section", {},
      h("h2", {}, "Enrollment tokens"),
      h("p", { class: "quiet" }, "A token lets agents join this server's device list, optionally into a group. It is shown once, when made."),
      form("row", [
        field("Name", h("input", { name: "name", required: true, placeholder: "front office rollout" })),
        field("Group", h("select", { name: "group" }, h("option", { value: "" }, "none"), groups.map((g) => h("option", { value: g.id }, g.name)))),
        field("Devices (empty: any number)", h("input", { name: "uses", type: "number", min: 1, value: 1 })),
        field("Days", h("input", { name: "days", type: "number", min: 1, max: 90, value: 1 })),
      ], "Make token", async (values) => {
        const answer = await api("POST", "/enroll-tokens", {
          name: values.name,
          group_id: values.group ? Number(values.group) : null,
          uses: values.uses ? Number(values.uses) : null,
          expires_in_days: Number(values.days || 1),
        });
        made.replaceChildren(shownOnce(`Token “${answer.details.name}”`, [
          ["Token", answer.token],
          ["Install, as administrator", answer.install],
          ["Or the MSI", answer.msi],
        ]));
        const list = await pages.enroll();
        list.querySelector("div.made").replaceWith(made);
        document.getElementById("app").replaceChildren(list);
      }),
      h("div", { class: "made" }, made),
      h("h3", {}, "Tokens that still enroll"),
      table(["Name", "Group", "Left", "Used", "Expires", ""], tokens.map((t) => h("tr", {},
        h("td", {}, t.name),
        h("td", {}, groupName(t.group_id)),
        h("td", {}, t.uses_left === null ? "any" : t.uses_left),
        h("td", {}, t.used),
        h("td", {}, new Date(t.expires_at * 1000).toLocaleString()),
        h("td", {}, h("button", {
          class: "link danger", onclick: () => attempt(async () => {
            await api("DELETE", `/enroll-tokens/${t.id}`);
            render();
          }),
        }, "Delete")),
      )), "None."),
    );
  },

  async users() {
    const users = await api("GET", "/users");
    return h("section", {},
      h("h2", {}, "Users"),
      form("row", [
        field("Name", h("input", { name: "name", required: true })),
        field("Password", h("input", { name: "password", type: "password", autocomplete: "new-password", required: true, minlength: 10 })),
        h("label", { class: "check" }, h("input", { name: "admin", type: "checkbox" }), "Administrator"),
      ], "Add user", async (values) => {
        await api("POST", "/users", { name: values.name, password: values.password, admin: values.admin });
        render();
      }),
      table(["Name", "Administrator", "TOTP", "Status", ""], users.map((u) => h("tr", {},
        h("td", {}, u.name),
        h("td", {}, u.admin ? "yes" : "no"),
        h("td", {}, u.totp ? "on" : "off"),
        h("td", {}, u.disabled ? "disabled" : "active"),
        h("td", {},
          h("button", {
            class: "link", onclick: () => attempt(async () => {
              await api("PATCH", `/users/${u.id}`, { admin: !u.admin });
              render();
            }),
          }, u.admin ? "Make user" : "Make administrator"),
          h("button", {
            class: "link", onclick: () => attempt(async () => {
              await api("PATCH", `/users/${u.id}`, { disabled: !u.disabled });
              render();
            }),
          }, u.disabled ? "Enable" : "Disable"),
          h("button", {
            class: "link danger", onclick: () => attempt(async () => {
              if (!confirm(`Delete ${u.name}?`)) return;
              await api("DELETE", `/users/${u.id}`);
              render();
            }),
          }, "Delete")),
      )), "No users."),
    );
  },

  async groups() {
    const [userGroups, deviceGroups, grants, users] = await Promise.all([
      api("GET", "/user-groups"), api("GET", "/device-groups"), api("GET", "/grants"), api("GET", "/users"),
    ]);
    const renamer = (path, name) => () => attempt(async () => {
      const next = prompt("New name", name);
      if (next) await api("PATCH", path, { name: next });
      render();
    });
    const deleter = (path, question) => () => attempt(async () => {
      if (!confirm(question)) return;
      await api("DELETE", path);
      render();
    });
    return h("div", {},
      h("section", {},
        h("h2", {}, "Grants"),
        h("p", { class: "quiet" }, "A grant lets a user group at a device group: view (watch only), control (keyboard, mouse, clipboard) or full. Administrators need one too, to connect."),
        form("row", [
          field("User group", h("select", { name: "user_group", required: true }, userGroups.map((g) => h("option", { value: g.id }, g.name)))),
          field("Device group", h("select", { name: "device_group", required: true }, deviceGroups.map((g) => h("option", { value: g.id }, g.name)))),
          field("Role", h("select", { name: "role" }, ["view", "control", "full"].map((r) => h("option", { value: r }, r)))),
        ], "Set grant", async (values) => {
          if (!values.user_group || !values.device_group) throw new Error("make a user group and a device group first");
          await api("POST", "/grants", {
            user_group_id: Number(values.user_group),
            device_group_id: Number(values.device_group),
            role: values.role,
          });
          render();
        }),
        table(["User group", "Device group", "Role", ""], grants.map((g) => h("tr", {},
          h("td", {}, g.user_group),
          h("td", {}, g.device_group),
          h("td", {}, g.role),
          h("td", {}, h("button", { class: "link danger", onclick: deleter(`/grants/${g.id}`, `Remove the grant ${g.user_group} → ${g.device_group}?`) }, "Remove")),
        )), "No grants."),
      ),
      h("section", {},
        h("h2", {}, "User groups"),
        form("row", [field("Name", h("input", { name: "name", required: true }))], "Add user group", async (values) => {
          await api("POST", "/user-groups", { name: values.name });
          render();
        }),
        table(["Name", "Members", ""], userGroups.map((g) => {
          const add = h("select", {
            onchange: (e) => attempt(async () => {
              if (e.target.value) await api("PUT", `/user-groups/${g.id}/members/${e.target.value}`);
              render();
            }),
          }, h("option", { value: "" }, "add…"),
            users.filter((u) => !g.members.some((m) => m.id === u.id)).map((u) => h("option", { value: u.id }, u.name)));
          return h("tr", {},
            h("td", {}, g.name),
            h("td", { class: "wrap" }, g.members.map((m) => h("span", {}, m.name,
              h("button", {
                class: "link", title: `Remove ${m.name}`, onclick: () => attempt(async () => {
                  await api("DELETE", `/user-groups/${g.id}/members/${m.id}`);
                  render();
                }),
              }, "×"), " ")), add),
            h("td", {},
              h("button", { class: "link", onclick: renamer(`/user-groups/${g.id}`, g.name) }, "Rename"),
              h("button", { class: "link danger", onclick: deleter(`/user-groups/${g.id}`, `Delete ${g.name} and its grants?`) }, "Delete")),
          );
        }), "No user groups."),
      ),
      h("section", {},
        h("h2", {}, "Device groups"),
        form("row", [field("Name", h("input", { name: "name", required: true }))], "Add device group", async (values) => {
          await api("POST", "/device-groups", { name: values.name });
          render();
        }),
        table(["Name", "Devices", ""], deviceGroups.map((g) => h("tr", {},
          h("td", {}, g.name),
          h("td", {}, g.devices),
          h("td", {},
            h("button", { class: "link", onclick: renamer(`/device-groups/${g.id}`, g.name) }, "Rename"),
            h("button", { class: "link danger", onclick: deleter(`/device-groups/${g.id}`, `Delete ${g.name}? Its devices stay, in no group; its grants and tokens go.`) }, "Delete")),
        )), "No device groups."),
      ));
  },

  async audit() {
    const body = h("tbody");
    const more = h("button", {}, "Older");
    let last = null;
    const load = async () => {
      const entries = await api("GET", "/audit?limit=100" + (last ? `&before=${last}` : ""));
      for (const e of entries) {
        body.append(h("tr", {},
          h("td", {}, new Date(e.at * 1000).toLocaleString()),
          h("td", {}, e.actor || "—"),
          h("td", {}, e.address || "—"),
          h("td", {}, h("code", {}, e.action)),
          h("td", { class: "wrap" }, e.target || ""),
          h("td", { class: "wrap" }, e.detail || ""),
        ));
        last = e.id;
      }
      more.hidden = entries.length < 100;
    };
    more.addEventListener("click", () => attempt(load));
    await load();
    return h("section", {},
      h("h2", {}, "Audit log"),
      h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, ["When", "Who", "From", "What", "To", "Detail"].map((t) => h("th", {}, t)))),
        body)),
      more);
  },

  async account() {
    const tokens = await api("GET", "/me/tokens");
    const made = h("div");
    const totp = h("div");
    if (state.me.totp) {
      totp.append(
        h("p", {}, "Two-step sign-in is on."),
        form("row", [field("Current code", h("input", { name: "code", inputmode: "numeric", required: true }))], "Turn off", async (values) => {
          await api("POST", "/me/totp/disable", { code: values.code });
          state.me = await api("GET", "/me");
          render();
        }));
    } else {
      totp.append(
        h("p", { class: "quiet" }, "Off. With it on, signing in also takes a code from an authenticator app."),
        h("button", {
          onclick: () => attempt(async () => {
            const { secret, uri } = await api("POST", "/me/totp");
            totp.replaceChildren(
              h("p", {}, "Add this to your authenticator app — the key by hand, or the link on a phone:"),
              h("pre", {}, secret),
              h("pre", {}, uri),
              form("row", [field("Then a code from the app", h("input", { name: "code", inputmode: "numeric", required: true, autofocus: true }))], "Turn on", async (values) => {
                await api("POST", "/me/totp/confirm", { code: values.code });
                state.me = await api("GET", "/me");
                render();
              }));
          }),
        }, "Set up"));
    }
    return h("div", {},
      h("section", {},
        h("h2", {}, "Password"),
        form("row", [
          field("Current", h("input", { name: "current", type: "password", autocomplete: "current-password", required: true })),
          field("New (at least 10 characters)", h("input", { name: "new", type: "password", autocomplete: "new-password", required: true, minlength: 10 })),
        ], "Change", async (values, el) => {
          await api("POST", "/me/password", { current: values.current, new: values.new });
          // Changing it ends every sign-in, this one included.
          alert("Password changed. Sign in again with the new one.");
          state.me = null;
          render();
        })),
      h("section", {}, h("h2", {}, "Two-step sign-in"), totp),
      h("section", {},
        h("h2", {}, "API tokens"),
        h("p", { class: "quiet" }, "For scripts and the viewer. A token acts as you: keep it like a password."),
        form("row", [
          field("Name", h("input", { name: "name", required: true, placeholder: "laptop viewer" })),
          field("Days (empty: no expiry)", h("input", { name: "days", type: "number", min: 1 })),
        ], "Make token", async (values) => {
          const answer = await api("POST", "/me/tokens", {
            name: values.name,
            expires_in_days: values.days ? Number(values.days) : null,
          });
          const page = await pages.account();
          page.querySelector("div.made").replaceChildren(shownOnce(`Token “${answer.details.name}”`, [["Token", answer.token]]));
          document.getElementById("app").replaceChildren(page);
        }),
        h("div", { class: "made" }, made),
        table(["Name", "Made", "Last used", "Expires", ""], tokens.map((t) => h("tr", {},
          h("td", {}, t.name),
          h("td", {}, when(t.created_at)),
          h("td", {}, when(t.last_used_at)),
          h("td", {}, t.expires_at ? new Date(t.expires_at * 1000).toLocaleDateString() : "never"),
          h("td", {}, h("button", {
            class: "link danger", onclick: () => attempt(async () => {
              await api("DELETE", `/me/tokens/${t.id}`);
              render();
            }),
          }, "Delete")),
        )), "None.")),
    );
  },
};

start();
