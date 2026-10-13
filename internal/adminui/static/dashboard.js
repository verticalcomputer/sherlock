(() => {
  "use strict";

  // Preserve old bookmarks after separating the operations workspace.
  if (location.pathname === "/admin/operations") {
    const destination = {"#repairs-title": "/admin/repairs", "#tickets-title": "/admin/incidents", "#investigations-title": "/admin/investigations"}[location.hash];
    if (destination) location.replace(destination);
  }

  const formatter = new Intl.DateTimeFormat(undefined, {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
    timeZoneName: "short",
  });

  for (const element of document.querySelectorAll("time[data-local-time]")) {
    const instant = new Date(element.dateTime);
    if (Number.isNaN(instant.getTime())) continue;
    element.title = `${element.textContent} · UTC source time`;
    element.textContent = formatter.format(instant);
  }

  const closeDialog = (dialog) => {
    if (typeof dialog.close === "function") dialog.close();
    else dialog.removeAttribute("open");
  };

  for (const trigger of document.querySelectorAll("[data-dialog-open]")) {
    trigger.addEventListener("click", () => {
      const dialog = document.getElementById(trigger.dataset.dialogOpen);
      if (!(dialog instanceof HTMLDialogElement)) return;
      if (typeof dialog.showModal === "function") dialog.showModal();
      else dialog.setAttribute("open", "");
    });
  }

  for (const trigger of document.querySelectorAll("[data-dialog-close]")) {
    trigger.addEventListener("click", () => {
      const dialog = trigger.closest("dialog");
      if (dialog) closeDialog(dialog);
    });
  }

  // In-page links to collapsed sections (the custom investigation form, or an
  // evidence entry inside the audit trail) open the target and every collapsed
  // ancestor instead of scrolling to a closed summary.
  const openLinkedDetails = (hash) => {
    let target = null;
    try {
      target = hash.length > 1 ? document.getElementById(decodeURIComponent(hash.slice(1))) : null;
    } catch {
      return;
    }
    for (let node = target; node; node = node.parentElement) {
      if (node instanceof HTMLDetailsElement) node.open = true;
    }
  };
  openLinkedDetails(window.location.hash);
  window.addEventListener("hashchange", () => openLinkedDetails(window.location.hash));
  for (const link of document.querySelectorAll('a[href^="#"]')) {
    link.addEventListener("click", () => openLinkedDetails(link.getAttribute("href")));
  }

  for (const dialog of document.querySelectorAll("dialog.repair-modal")) {
    dialog.addEventListener("click", (event) => {
      if (event.target === dialog) closeDialog(dialog);
    });
  }
})();
