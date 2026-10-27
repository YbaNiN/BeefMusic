// Pantallas de acceso: entrar (/api/login-user) y crear cuenta (/api/register).
// Guardan el token y el usuario en las mismas claves que antes.
import { api } from "./api.js";
import { TOKEN_KEY, USER_KEY } from "./config.js";

const MODE = document.body.dataset.mode; // "login" | "registro"
const MIN_PASSWORD = 6; // mismo mínimo que el backend

// Solo se permite volver a rutas internas de la app (#/…), nunca a otra web.
function safeNext(value) {
  const v = String(value || "");
  return /^#\/[\w\-./?=&%@]{0,200}$/.test(v) ? v : "";
}
const next = safeNext(new URLSearchParams(location.search).get("next"));
const destination = "index.html" + next;

if (localStorage.getItem(TOKEN_KEY)) location.replace(destination);

const $ = (s) => document.querySelector(s);

/* ---------- Escaparate de portadas (decorativo) ---------- */
const SHOWCASE = [
  ["Sol de Boca", "Dembow"], ["Titi", "Reggaetón"], ["No Perdono", "Drill"], ["Relaciones Venenosas", "Trap"],
  ["Mambo Inquieto", "Dembow"], ["Que Queda", "Rap"], ["Tota Mística", "Trap"], ["La Peruana", "Dembow"],
  ["Navidad Miente", "R&B"], ["Perreo Sentimiento", "Reggaetón"], ["Rafa Te Estafa", "Drill"], ["La Fácil", "Rap"],
];
$("#mosaic").innerHTML = SHOWCASE.map(([titulo, estilo], i) => window.BeefCover.html({ id: "auth" + i, titulo, estilo })).join("");
document.querySelectorAll("#mosaic .cover").forEach((c) => c.setAttribute("aria-hidden", "true"));

/* ---------- Enlaces que conservan el "volver a" ---------- */
document.querySelectorAll("[data-keep-next]").forEach((a) => {
  if (next) a.href = a.getAttribute("href").split("?")[0] + "?next=" + encodeURIComponent(next);
});

/* ---------- Mostrar / ocultar contraseña y aviso de mayúsculas ---------- */
const password = $("#password");
const toggle = $("#password-toggle");
toggle.addEventListener("click", () => {
  const show = password.type === "password";
  password.type = show ? "text" : "password";
  toggle.setAttribute("aria-pressed", String(show));
  toggle.setAttribute("aria-label", show ? "Ocultar contraseña" : "Mostrar contraseña");
  password.focus();
});
password.addEventListener("keyup", (e) => {
  if (e.getModifierState) $("#caps").classList.toggle("is-on", e.getModifierState("CapsLock"));
});

const pwHint = $("#password-hint");
if (MODE === "registro" && pwHint) {
  password.addEventListener("input", () => {
    const ok = password.value.length >= MIN_PASSWORD;
    pwHint.classList.toggle("field__hint--ok", ok);
    pwHint.textContent = ok ? "Contraseña válida" : `Mínimo ${MIN_PASSWORD} caracteres (${password.value.length}/${MIN_PASSWORD})`;
  });
}

/* ---------- Envío ---------- */
const form = $("#auth-form");
const alertEl = $("#auth-alert");
const submit = $("#auth-submit");
const ICONS = { error: "alert", info: "music", ok: "check" };

function showAlert(message, type = "error") {
  alertEl.hidden = !message;
  alertEl.dataset.type = type;
  alertEl.setAttribute("role", type === "error" ? "alert" : "status");
  alertEl.innerHTML = message ? `<svg class="icon" aria-hidden="true"><use href="#i-${ICONS[type]}"/></svg><span></span>` : "";
  if (message) alertEl.querySelector("span").textContent = message;
}

function markError(input, on) {
  input.closest(".field").classList.toggle("field--error", on);
  input.setAttribute("aria-invalid", String(on));
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const userInput = $("#username");
  // Al registrarse se quitan espacios de los extremos; al entrar se envía tal cual, como antes.
  const username = MODE === "registro" ? userInput.value.trim() : userInput.value;
  const pass = password.value;

  markError(userInput, !username.trim());
  markError(password, !pass || (MODE === "registro" && pass.length < MIN_PASSWORD));
  if (!username.trim()) {
    showAlert("Escribe tu usuario.");
    return userInput.focus();
  }
  if (!pass) {
    showAlert("Escribe tu contraseña.");
    return password.focus();
  }
  if (MODE === "registro" && pass.length < MIN_PASSWORD) {
    showAlert(`La contraseña debe tener al menos ${MIN_PASSWORD} caracteres.`);
    return password.focus();
  }

  const label = submit.innerHTML;
  submit.disabled = true;
  submit.innerHTML = `<span class="spinner" aria-hidden="true"></span>${MODE === "registro" ? "Creando tu cuenta…" : "Entrando…"}`;
  showAlert("");
  // Render puede tardar en despertar: si pasa un rato, se explica.
  const slow = setTimeout(() => showAlert("El servidor está despertando, puede tardar unos segundos…", "info"), 4000);

  try {
    const json = await api(MODE === "registro" ? "/api/register" : "/api/login-user", {
      method: "POST",
      body: { username, password: pass },
      withAuth: false,
    });
    clearTimeout(slow);
    if (!json.token) throw new Error("Respuesta inesperada del servidor.");
    localStorage.setItem(TOKEN_KEY, json.token);
    localStorage.setItem(USER_KEY, json.username || username);
    showAlert(MODE === "registro" ? "Cuenta creada. Entrando…" : "Dentro. Un momento…", "ok");
    setTimeout(() => location.replace(destination), 350);
  } catch (err) {
    clearTimeout(slow);
    submit.disabled = false;
    submit.innerHTML = label;
    const msg = err.message || "Error conectando con el servidor.";
    showAlert(msg);
    if (err.status === 401) {
      markError(password, true);
      password.select();
    } else if (/existe/i.test(msg)) {
      markError(userInput, true);
      userInput.select();
    }
  }
});
