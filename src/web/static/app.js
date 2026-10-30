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
      if (/(deploy|build) \d+ done|image ready|FAILED:/.test(pre.textContent)) return setTimeout(() => location.replace(location.pathname), 1500);
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
