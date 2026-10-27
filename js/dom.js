// Utilidades de interfaz compartidas.

export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

// Todo texto que venga del backend pasa por aquí antes de ir a innerHTML.
export function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

export const icon = (name, cls = "") => `<svg class="icon ${cls}" aria-hidden="true"><use href="#i-${name}"/></svg>`;

export function fmtTime(sec) {
  const t = Math.max(0, Math.floor(Number(sec) || 0));
  return Math.floor(t / 60) + ":" + String(t % 60).padStart(2, "0");
}

// "duracion" puede venir como "3:02" o como segundos.
export function fmtDuration(d) {
  if (d == null || d === "") return "";
  if (typeof d === "string" && d.includes(":")) {
    // "02:41" → "2:41"; tolera erratas como "3:·39". Lo irreconocible no se muestra.
    const m = d.trim().match(/^(\d{1,3})\D+([0-5]\d)$/);
    return m ? `${Number(m[1])}:${m[2]}` : "";
  }
  const n = Number(d);
  return Number.isFinite(n) && n > 0 ? fmtTime(n) : "";
}

export function timeAgo(iso) {
  const t = new Date(iso).getTime();
  if (!Number.isFinite(t)) return "";
  const mins = Math.floor((Date.now() - t) / 60000);
  if (mins < 1) return "Ahora";
  if (mins < 60) return `Hace ${mins} min`;
  const h = Math.floor(mins / 60);
  if (h < 24) return `Hace ${h} h`;
  const d = Math.floor(h / 24);
  if (d < 30) return `Hace ${d} d`;
  return new Date(iso).toLocaleDateString("es-ES", { day: "numeric", month: "short", year: "numeric" });
}

export function debounce(fn, ms = 200) {
  let t;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), ms);
  };
}

let toastTimer;
export function toast(message, { error = false } = {}) {
  const el = document.getElementById("toast");
  if (!el) return;
  el.classList.toggle("toast--error", error);
  el.innerHTML = icon(error ? "alert" : "check", "icon--sm") + `<span>${esc(message)}</span>`;
  el.classList.add("is-visible");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("is-visible"), error ? 4200 : 2800);
}

export function setStatus(el, message, type = "") {
  if (!el) return;
  el.textContent = message || "";
  el.dataset.type = type;
}

// Bloquea un botón mientras dura una petición y lo restaura al acabar.
export async function withBusy(button, label, task) {
  const original = button.innerHTML;
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  button.innerHTML = `<span class="spinner" aria-hidden="true"></span>${esc(label)}`;
  try {
    return await task();
  } finally {
    button.disabled = false;
    button.removeAttribute("aria-busy");
    button.innerHTML = original;
  }
}
