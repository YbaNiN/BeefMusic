// Hoja "Pedir": petición de canción + asistente de letras (IA).
import { auth, sendRequest, askAssistant } from "../api.js";
import { $, $$, esc, toast, setStatus, withBusy } from "../dom.js";
import { openSheet, selectPane } from "../sheets.js";
import { topStyles } from "../store.js";
import { invalidateRequestsCount } from "../views/home.js";

const DEFAULT_STYLES = ["Drill", "Trap", "Dembow", "Reggaetón", "Boom bap"];

export function openPedir(tab = "form") {
  const d = openSheet("sheet-pedir");
  selectPane(d, tab);
  const nick = $("#p-nick");
  if (!nick.value && auth.user()) nick.value = "@" + auth.user();

  const styles = [...new Set([...topStyles(5), ...DEFAULT_STYLES])].slice(0, 6);
  $("#p-style-chips").innerHTML = styles
    .map((s) => `<button type="button" class="chip" data-style="${esc(s)}" aria-pressed="false">${esc(s)}</button>`)
    .join("");
  syncStyleChips();
}

function syncStyleChips() {
  const v = $("#p-style").value.trim().toLowerCase();
  $$("#p-style-chips .chip").forEach((c) => c.setAttribute("aria-pressed", String(c.dataset.style.toLowerCase() === v)));
}

export function initPedir() {
  const d = $("#sheet-pedir");
  $$('[role="tab"][data-pane]', d).forEach((t) => t.addEventListener("click", () => selectPane(d, t.dataset.pane)));

  /* ---------- Petición ---------- */
  const form = $("#pedir-form");
  const status = $("#pedir-status");
  $("#p-style-chips").addEventListener("click", (e) => {
    const chip = e.target.closest("[data-style]");
    if (!chip) return;
    $("#p-style").value = chip.dataset.style;
    syncStyleChips();
  });
  $("#p-style").addEventListener("input", syncStyleChips);

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const data = { nick: form.nick.value.trim(), style: form.style.value.trim(), idea: form.idea.value.trim() };
    const missing = [["nick", "tu nick"], ["style", "un estilo"], ["idea", "la idea de la canción"]].find(([k]) => !data[k]);
    $$(".field", form).forEach((f) => f.classList.remove("field--error"));
    if (missing) {
      form[missing[0]].closest(".field").classList.add("field--error");
      form[missing[0]].focus();
      setStatus(status, `Falta ${missing[1]}.`, "error");
      return;
    }
    const btn = form.querySelector("button[type=submit]");
    await withBusy(btn, "Enviando…", async () => {
      try {
        const json = await sendRequest(data);
        form.reset();
        if (auth.user()) form.nick.value = "@" + auth.user();
        syncStyleChips();
        setStatus(status, "");
        d.close();
        toast(`Petición enviada${json.id ? " · ID " + json.id : ""}. Te avisaremos cuando avance.`);
        invalidateRequestsCount();
      } catch (err) {
        setStatus(status, err.message || "Error enviando la petición.", "error");
      }
    });
  });

  /* ---------- Asistente IA ---------- */
  const prompt = $("#ia-prompt");
  const send = $("#ia-send");
  const out = $("#ia-output");
  const text = $("#ia-text");
  const refresh = () => (send.disabled = !prompt.value.trim());

  prompt.addEventListener("input", refresh);
  $("#ia-chips").addEventListener("click", (e) => {
    const chip = e.target.closest("[data-prompt]");
    if (!chip) return;
    prompt.value = chip.dataset.prompt;
    refresh();
    prompt.focus();
  });

  send.addEventListener("click", async () => {
    const p = prompt.value.trim();
    if (!p) return;
    if (!auth.isLogged()) {
      out.hidden = false;
      text.textContent = "Inicia sesión para usar el asistente.";
      return;
    }
    out.hidden = false;
    text.textContent = "Montando tu letra con BeefMusic…";
    await withBusy(send, "Generando…", async () => {
      try {
        const data = await askAssistant(p);
        text.textContent = data.text || "No se pudo generar la letra.";
      } catch (err) {
        text.textContent = "Error generando la letra: " + (err.message || "error desconocido");
      }
    });
    refresh();
  });

  $("#ia-copy").addEventListener("click", async (e) => {
    const value = text.textContent.trim();
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      toast("Letra copiada");
    } catch {
      toast("No se pudo copiar", { error: true });
    }
  });
}
