// Hojas inferiores (en escritorio, diálogos centrados) basadas en <dialog>.
import { $$ } from "./dom.js";

export function openSheet(id) {
  const d = document.getElementById(id);
  if (d && !d.open) d.showModal();
  return d;
}

export function closeSheet(id) {
  const d = typeof id === "string" ? document.getElementById(id) : id;
  if (d && d.open) d.close();
}

export function initSheets() {
  $$("dialog.sheet").forEach((d) => {
    // Cerrar al pulsar fuera o en cualquier [data-close].
    d.addEventListener("click", (e) => {
      if (e.target === d || e.target.closest("[data-close]")) d.close();
    });

    // Arrastrar hacia abajo para cerrar (móvil).
    const handle = d.querySelector("[data-drag]");
    if (!handle) return;
    let y0 = null;
    let dy = 0;
    handle.addEventListener("pointerdown", (e) => {
      if (e.button !== 0 || e.target.closest("button, a")) return;
      y0 = e.clientY;
      dy = 0;
      d.classList.add("is-dragging");
      handle.setPointerCapture(e.pointerId);
    });
    handle.addEventListener("pointermove", (e) => {
      if (y0 === null) return;
      dy = Math.max(0, e.clientY - y0);
      d.style.transform = `translateY(${dy}px)`;
    });
    const end = () => {
      if (y0 === null) return;
      d.classList.remove("is-dragging");
      d.style.transform = "";
      y0 = null;
      if (dy > 110) d.close();
    };
    handle.addEventListener("pointerup", end);
    handle.addEventListener("pointercancel", end);
  });
}

// Pestañas dentro de una hoja (role="tab" + data-pane / data-pane-id).
export function selectPane(dialog, name) {
  $$('[role="tab"][data-pane]', dialog).forEach((t) => t.setAttribute("aria-selected", String(t.dataset.pane === name)));
  $$("[data-pane-id]", dialog).forEach((p) => (p.hidden = p.dataset.paneId !== name));
}
