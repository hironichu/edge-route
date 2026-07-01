const commands = [
  ["Dashboard", "/ui/dashboard", "/dashboard"],
  ["Mappings", "/ui/mappings", "/mappings"],
  ["Tools", "/ui/tools", "/tools"],
  ["Topology", "/ui/topology", "/topology"],
  ["Oracle", "/ui/oracle", "/oracle"],
  ["Reconcile", "/ui/reconcile", "/reconcile"],
  ["NetBird", "/ui/netbird", "/netbird"],
  ["Logs", "/ui/logs", "/logs"],
];

const dialog = document.getElementById("cmdk");
const input = document.getElementById("cmdk-input");
const list = document.getElementById("cmdk-list");

function renderCommands(filter = "") {
  const q = filter.trim().toLowerCase();
  const rows = commands.filter(([name]) => name.toLowerCase().includes(q));
  list.innerHTML = rows
    .map(([name, url, path], i) => `<li data-url="${url}" data-path="${path}" aria-selected="${i === 0}"><span>${name}</span><span class="kind">view</span></li>`)
    .join("");
}

function openPalette() {
  renderCommands();
  dialog.showModal();
  input.value = "";
  input.focus();
}

function go(url, path) {
  dialog.close();
  if (window.htmx) {
    window.htmx.ajax("GET", url, { target: "#view", swap: "innerHTML transition:true" });
  }
  history.pushState({}, "", path);
  markNav(path);
}

function routeForPath(path = location.pathname) {
  return commands.find(([, , routePath]) => routePath === path) || commands[0];
}

function loadCurrentRoute() {
  const route = routeForPath();
  if (window.htmx) {
    window.htmx.ajax("GET", route[1], { target: "#view", swap: "innerHTML transition:true" });
  }
  markNav(route[2]);
}

function markNav(path = location.pathname) {
  document.querySelectorAll("[data-nav]").forEach((link) => {
    link.classList.toggle("active", link.getAttribute("href") === path);
  });
}

function updateSelectionState() {
  const boxes = [...document.querySelectorAll("[data-row-select]")];
  const selected = boxes.filter((box) => box.checked).length;
  document.querySelectorAll("[data-selection-count]").forEach((node) => {
    node.textContent = `${selected} selected`;
  });
  document.querySelectorAll("[data-bulk-action], [data-inspect-selected]").forEach((button) => {
    button.disabled = selected === 0;
  });
  const all = document.querySelector("[data-select-all]");
  if (all) {
    all.checked = boxes.length > 0 && selected === boxes.length;
    all.indeterminate = selected > 0 && selected < boxes.length;
  }
}

function openDialog(id) {
  const modal = document.getElementById(id);
  if (modal) modal.showModal();
}

function closeDialog(id) {
  const modal = document.getElementById(id);
  if (modal) modal.close();
}

document.getElementById("cmdk-open").addEventListener("click", openPalette);
document.addEventListener("keydown", (event) => {
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
    event.preventDefault();
    openPalette();
  }
  if (event.key === "Escape" && dialog.open) dialog.close();
});

input.addEventListener("input", () => renderCommands(input.value));
input.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    const selected = list.querySelector('[aria-selected="true"]') || list.querySelector("li");
    if (selected) go(selected.dataset.url, selected.dataset.path);
  }
});
list.addEventListener("click", (event) => {
  const row = event.target.closest("li");
  if (row) go(row.dataset.url, row.dataset.path);
});

document.body.addEventListener("click", async (event) => {
  const tab = event.target.closest("[data-tab-target]");
  if (tab) {
    event.preventDefault();
    const scope = tab.closest("[data-tabs-scope]") || document;
    const target = tab.dataset.tabTarget;
    scope.querySelectorAll("[data-tab-target]").forEach((button) => {
      const active = button.dataset.tabTarget === target;
      button.classList.toggle("active", active);
      button.setAttribute("aria-selected", String(active));
    });
    scope.querySelectorAll("[data-tab-panel]").forEach((panel) => {
      panel.classList.toggle("active", panel.dataset.tabPanel === target);
    });
  }

  const inspectSelected = event.target.closest("[data-inspect-selected]");
  if (inspectSelected) {
    const selected = document.querySelector("[data-row-select]:checked");
    if (selected?.dataset.dialogId) openDialog(selected.dataset.dialogId);
  }

  const opener = event.target.closest("[data-open-dialog]");
  if (opener) openDialog(opener.dataset.openDialog);

  const closer = event.target.closest("[data-close-dialog]");
  if (closer) closeDialog(closer.dataset.closeDialog);

  if (event.target.closest("[data-copy-logs]")) {
    const raw = document.querySelector("[data-raw-log]");
    if (raw && navigator.clipboard) await navigator.clipboard.writeText(raw.textContent);
  }

  const filter = event.target.closest("[data-log-filter]");
  if (filter) {
    const level = filter.dataset.logFilter;
    document.querySelectorAll("[data-raw-log] .log-line").forEach((line) => {
      line.hidden = level !== "all" && !line.dataset.level.includes(level);
    });
  }
});

document.body.addEventListener("change", (event) => {
  if (event.target.matches("[data-select-all]")) {
    document.querySelectorAll("[data-row-select]").forEach((box) => {
      box.checked = event.target.checked;
    });
  }
  if (event.target.matches("[data-select-all], [data-row-select]")) updateSelectionState();
});

// Typed-confirmation gate: a form's submit button stays disabled until the
// matching [data-confirm-input] value equals its data-confirm-word. The agent
// re-checks this server-side, so this is UX, not the security boundary.
document.body.addEventListener("input", (event) => {
  const field = event.target.closest("[data-confirm-input]");
  if (!field) return;
  const form = field.closest("form");
  if (!form) return;
  const word = (field.dataset.confirmWord || "").trim().toLowerCase();
  const ok = field.value.trim().toLowerCase() === word && word.length > 0;
  form.querySelectorAll("[data-confirm-submit]").forEach((btn) => {
    btn.disabled = !ok;
  });
});

document.body.addEventListener("htmx:afterSwap", (event) => {
  if (event.detail.target.id === "view") {
    document.getElementById("view").focus({ preventScroll: true });
    markNav();
    updateSelectionState();
  }
});

window.addEventListener("popstate", () => {
  const route = routeForPath();
  if (window.htmx) window.htmx.ajax("GET", route[1], { target: "#view", swap: "innerHTML transition:true" });
  markNav(route[2]);
});

markNav();
updateSelectionState();
loadCurrentRoute();
