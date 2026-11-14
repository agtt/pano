// Progressive enhancement only: every page works without this file.

// Live deploy log: polls the agent-backed endpoint until the deploy finishes.
for (const pre of document.querySelectorAll("[data-deploy-log]")) {
  let offset = 0;
  let idle = 0;
  const url = pre.getAttribute("data-deploy-log");
  const tick = async () => {
    try {
      const res = await fetch(`${url}?offset=${offset}`, { credentials: "same-origin" });
      const data = await res.json();
      if (data.text) {
        pre.textContent += data.text;
        pre.scrollTop = pre.scrollHeight;
        idle = 0;
      } else idle++;
      offset = data.offset;
      // Done: reload without the ?deploy=…, on the same tab when the log sits in one.
      const tab = pre.closest(".pane[data-tab]");
      if (/(deploy|build) \d+ done|toolchain ready|FAILED:/.test(pre.textContent))
        return setTimeout(() => location.replace(location.pathname + (tab ? `#tab-${tab.dataset.tab}` : "")), 1500);
    } catch {
      idle++;
    }
    if (idle < 600) setTimeout(tick, 1000);
  };
  tick();
}

// Click a command block to copy it.
for (const el of document.querySelectorAll("[data-copy]")) {
  el.title = "click to copy";
  el.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(el.textContent.trim());
      el.classList.add("copied");
      setTimeout(() => el.classList.remove("copied"), 1200);
    } catch {}
  });
}

// Keep log panes scrolled to the newest lines.
for (const pre of document.querySelectorAll("pre.log")) pre.scrollTop = pre.scrollHeight;

// Page search in the top bar: lists matching pages as you type; Cmd/Ctrl+K jumps here,
// Enter opens the first match, arrows move through the list, Escape clears.
const navSearch = document.getElementById("nav-search");
const results = document.getElementById("search-results");
if (navSearch && results) {
  const items = [...results.querySelectorAll("a[data-nav]")];
  const empty = results.querySelector(".search-empty");
  const shown = () => items.filter((a) => !a.parentElement.hidden);
  const filter = () => {
    const q = navSearch.value.trim().toLowerCase();
    for (const a of items) {
      a.parentElement.hidden = !q || !a.dataset.nav.includes(q);
      a.classList.remove("hit");
    }
    const list = shown();
    if (list[0]) list[0].classList.add("hit");
    if (empty) empty.hidden = !q || list.length > 0;
    results.hidden = !q;
  };
  navSearch.addEventListener("input", filter);
  navSearch.addEventListener("focus", () => navSearch.value && filter());
  const move = (from, step) => {
    const list = shown();
    const next = list[list.indexOf(from) + step];
    if (next) next.focus();
    else if (step < 0) navSearch.focus();
  };
  results.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      move(document.activeElement, e.key === "ArrowDown" ? 1 : -1);
    } else if (e.key === "Escape") navSearch.focus();
  });
  navSearch.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      const first = shown()[0];
      if (first) location.href = first.href;
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      shown()[0]?.focus();
    } else if (e.key === "Escape") {
      navSearch.value = "";
      filter();
      navSearch.blur();
    }
  });
  // Close the list when focus or a click leaves the search.
  const search = navSearch.closest(".search");
  document.addEventListener("click", (e) => {
    if (search && !search.contains(e.target)) results.hidden = true;
  });
  search?.addEventListener("focusout", (e) => {
    if (!search.contains(e.relatedTarget)) results.hidden = true;
  });
  document.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      navSearch.focus();
      navSearch.select();
    }
  });
}

// List filters: <input data-filter-for="table-id"> hides rows whose data-filter misses every word typed.
for (const input of document.querySelectorAll("input[data-filter-for]")) {
  const table = document.getElementById(input.dataset.filterFor);
  if (!table) continue;
  const rows = [...table.querySelectorAll("tbody tr[data-filter]")];
  const none = table.querySelector("tr.filter-empty");
  input.addEventListener("input", () => {
    const words = input.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
    let n = 0;
    for (const r of rows) {
      r.hidden = !words.every((w) => r.dataset.filter.includes(w));
      if (!r.hidden) n++;
    }
    if (none) none.hidden = n > 0;
  });
  input.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      input.value = "";
      input.dispatchEvent(new Event("input"));
    }
  });
}

// "Add" style menus: close when clicking elsewhere or pressing Escape.
document.addEventListener("click", (e) => {
  for (const d of document.querySelectorAll("details.menu[open]")) if (!d.contains(e.target)) d.open = false;
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") for (const d of document.querySelectorAll("details.menu[open]")) d.open = false;
});

// Refresh links (↻) that point at the page's own tab: reload instead of only jumping to it.
for (const a of document.querySelectorAll("a[data-reload]")) {
  a.addEventListener("click", (e) => {
    e.preventDefault();
    history.replaceState(null, "", a.href);
    location.reload();
  });
}

// Trusted window (a code was entered in the last minutes): routine forms drop the code field.
// Forms the agent always asks a code for (delete, restore, backup key, traffic switch, admins) keep it.
if (document.body.classList.contains("trusted")) {
  const always = /^\/(admins(\/|$)|backups\/key|backups\/runs\/\d+\/restore|edge\/(cutover|rollback))/;
  for (const input of document.querySelectorAll('input[name="otp"]')) {
    const form = input.form;
    if (input.hasAttribute("data-always") || !form || form.classList.contains("danger") || always.test(form.getAttribute("action") || "")) continue;
    input.required = false;
    (input.closest("label.field") || input).classList.add("otp-skip");
  }
}

// Tabs inside a page: CSS shows the pane named by #tab-…; here, forms in a pane come back to it
// after posting (a redirect keeps the fragment), and the selected tab is announced.
// Runs after the trusted-window check above, which reads the actions as they were.
for (const pane of document.querySelectorAll(".tabbed > .pane[data-tab]")) {
  const hash = `#tab-${pane.dataset.tab}`;
  for (const form of pane.querySelectorAll("form")) {
    const action = form.getAttribute("action");
    if (action && !action.includes("#")) form.setAttribute("action", action + hash);
  }
  for (const btn of pane.querySelectorAll("button[formaction]")) {
    const action = btn.getAttribute("formaction");
    if (action && !action.includes("#")) btn.setAttribute("formaction", action + hash);
  }
}
const markTab = () => {
  for (const tabbed of document.querySelectorAll(".tabbed")) {
    const links = [...tabbed.querySelectorAll(":scope > .tabs a")];
    const current = links.find((a) => a.getAttribute("href") === location.hash) || links.find((a) => a.classList.contains("on"));
    for (const a of links) {
      if (a === current) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    }
  }
};
markTab();
addEventListener("hashchange", markTab);
