// Hoja "Editar perfil": bio, foto, enlaces y privacidad.
// Envía { bio, avatarUrl, links, isPublic }, que es lo que lee el backend
// (la página antigua mandaba avatar_url / is_public y no se guardaban).
import { auth, usersApi } from "../api.js";
import { $, $$, toast, setStatus, withBusy } from "../dom.js";
import { openSheet } from "../sheets.js";
import { getMe, refreshMe } from "../me.js";
import { SOCIALS, safeHttpUrl, avatarHtml } from "../user-ui.js";

const BIO_MAX = 280;

function paintPreview() {
  const url = $("#pe-avatar").value.trim();
  $("#pe-avatar-preview").innerHTML = avatarHtml(auth.user(), safeHttpUrl(url), "avatar--lg");
}

function paintCounter() {
  const len = $("#pe-bio").value.length;
  $("#pe-bio-count").textContent = `${len}/${BIO_MAX}`;
}

export async function openProfileEdit() {
  if (!auth.isLogged()) {
    toast("Inicia sesión para editar tu perfil", { error: true });
    return;
  }
  const form = $("#profile-form");
  const status = $("#profile-status");
  form.reset();
  $$(".field", form).forEach((f) => f.classList.remove("field--error"));
  setStatus(status, "Cargando tu perfil…");
  form.querySelector("button[type=submit]").disabled = true;
  openSheet("sheet-profile");
  paintPreview();
  paintCounter();

  try {
    const me = await getMe({ force: true });
    const p = me?.profile || {};
    $("#pe-bio").value = p.bio || "";
    $("#pe-avatar").value = p.avatarUrl || "";
    SOCIALS.forEach(([key]) => ($(`#pe-${key}`).value = (p.links || {})[key] || ""));
    $("#pe-public").checked = p.isPublic !== false;
    setStatus(status, "");
  } catch (err) {
    setStatus(status, "No se pudo cargar tu perfil: " + err.message, "error");
  } finally {
    form.querySelector("button[type=submit]").disabled = false;
    paintPreview();
    paintCounter();
  }
}

export function initProfileEdit() {
  const form = $("#profile-form");
  const status = $("#profile-status");
  $("#pe-avatar").addEventListener("input", paintPreview);
  $("#pe-bio").addEventListener("input", paintCounter);

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    $$(".field", form).forEach((f) => f.classList.remove("field--error"));

    // El backend descarta en silencio las URLs no válidas: mejor avisar aquí.
    const urlFields = ["avatar", ...SOCIALS.map(([k]) => k)];
    const bad = urlFields.find((k) => {
      const v = $(`#pe-${k}`).value.trim();
      return v && !safeHttpUrl(v);
    });
    if (bad) {
      const input = $(`#pe-${bad}`);
      input.closest(".field").classList.add("field--error");
      input.focus();
      setStatus(status, "Ese enlace no es válido. Debe empezar por https://", "error");
      return;
    }

    const links = {};
    SOCIALS.forEach(([key]) => {
      const v = $(`#pe-${key}`).value.trim();
      if (v) links[key] = v;
    });
    const body = {
      bio: $("#pe-bio").value.slice(0, BIO_MAX),
      avatarUrl: $("#pe-avatar").value.trim(),
      links,
      isPublic: $("#pe-public").checked,
    };

    await withBusy(form.querySelector("button[type=submit]"), "Guardando…", async () => {
      try {
        await usersApi.updateMe(body);
        setStatus(status, "");
        $("#sheet-profile").close();
        toast("Perfil guardado");
        refreshMe().catch(() => {});
      } catch (err) {
        setStatus(status, err.message || "No se pudo guardar.", "error");
      }
    });
  });
}
