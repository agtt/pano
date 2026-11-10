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
      if (/(deploy|build) \d+ done|toolchain ready|FAILED:/.test(pre.textContent)) return setTimeout(() => location.replace(location.pathname), 1500);
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

// Menu search: filters the sidebar as you type; Cmd/Ctrl+K jumps here, Enter opens the first match.
const navSearch = document.getElementById("nav-search");
if (navSearch) {
  const links = [...document.querySelectorAll(".side nav a[data-nav]")];
  const groups = [...document.querySelectorAll(".side .nav-group")];
  const empty = document.querySelector(".side .nav-empty");
  const filter = () => {
    const q = navSearch.value.trim().toLowerCase();
    let shown = 0;
    for (const a of links) {
      const hit = !q || a.dataset.nav.includes(q);
      a.hidden = !hit;
      if (hit) shown++;
    }
    for (const g of groups) g.hidden = ![...g.querySelectorAll("a[data-nav]")].some((a) => !a.hidden);
    if (empty) empty.hidden = shown > 0;
  };
  navSearch.addEventListener("input", filter);
  navSearch.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      const first = links.find((a) => !a.hidden);
      if (first) location.href = first.href;
    } else if (e.key === "Escape") {
      navSearch.value = "";
      filter();
      navSearch.blur();
    }
  });
  document.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      const toggle = document.getElementById("nav-toggle");
      if (toggle && getComputedStyle(document.querySelector(".nav-button")).display !== "none") toggle.checked = true;
      navSearch.focus();
      navSearch.select();
    }
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
