// Hoja de sugerencias y reportes de problemas (antes eran dos modales).
import { auth, sendSuggestion, sendReport } from "../api.js";
import { $, toast, setStatus, withBusy } from "../dom.js";
import { openSheet } from "../sheets.js";

const MODES = {
  sugerencia: {
    title: "Enviar sugerencia",
    desc: "¿Qué mejorarías en BeefMusic? ¿Qué te gustaría que añadiéramos?",
    label: "Tu sugerencia",
    placeholder: "Cuéntanos tu idea, mejora o feedback…",
    send: sendSuggestion,
    ok: "Sugerencia enviada. ¡Gracias!",
  },
  reporte: {
    title: "Reportar problema",
    desc: "Si algo no funciona bien (un fallo, un error visual…), cuéntanoslo.",
    label: "¿Qué ha pasado?",
    placeholder: "Explica el problema, qué estabas haciendo y cómo reproducirlo…",
    send: sendReport,
    ok: "Reporte enviado. Lo revisamos pronto.",
  },
};

let mode = "sugerencia";

export function openFeedback(kind = "sugerencia") {
  mode = MODES[kind] ? kind : "sugerencia";
  const m = MODES[mode];
  $("#feedback-title").textContent = m.title;
  $("#feedback-desc").textContent = m.desc;
  $("#fb-msg-label").textContent = m.label;
  $("#fb-msg").placeholder = m.placeholder;
  $("#feedback-submit").textContent = m.title;
  setStatus($("#feedback-status"), "");
  const nick = $("#fb-nick");
  if (!nick.value && auth.user()) nick.value = "@" + auth.user();
  openSheet("sheet-feedback");
}

export function initFeedback() {
  const form = $("#feedback-form");
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const m = MODES[mode];
    const data = { nick: form.nick.value.trim(), mensaje: form.mensaje.value.trim() };
    const field = form.mensaje.closest(".field");
    field.classList.toggle("field--error", !data.mensaje);
    if (!data.mensaje) {
      setStatus($("#feedback-status"), "Escribe el mensaje antes de enviarlo.", "error");
      return form.mensaje.focus();
    }
    await withBusy($("#feedback-submit"), "Enviando…", async () => {
      try {
        await m.send(data);
        form.mensaje.value = "";
        $("#sheet-feedback").close();
        toast(m.ok);
      } catch (err) {
        setStatus($("#feedback-status"), err.message || "No se pudo enviar.", "error");
      }
    });
  });
}
