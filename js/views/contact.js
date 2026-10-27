// Vista Contacto: mismo formulario, campos y validaciones que la página antigua.
// Se envía a POST /api/contacto (CONTACT_ENDPOINT). Si se dejara vacío, el
// mensaje se guardaría solo en este navegador, como el antiguo "modo demo".
import { auth } from "../api.js";
import { esc, icon, setStatus, toast, withBusy } from "../dom.js";
import { CONTACT_ENDPOINT, CONTACT_OUTBOX_KEY, SUPPORT_EMAIL, PRIVACY_EMAIL, COPYRIGHT_EMAIL } from "../config.js";

const TYPES = [
  ["soporte", "Soporte"],
  ["reporte", "Reportar problema"],
  ["sugerencia", "Sugerencia"],
  ["derechos", "Derechos de autor"],
  ["privacidad", "Privacidad"],
  ["otro", "Otro"],
];

const mailto = (email, subject) => `mailto:${email}?subject=${encodeURIComponent(subject)}`;

function validate(d) {
  if (!d.name) return ["name", "Escribe tu nombre."];
  if (!d.email) return ["email", "Escribe tu email."];
  if (!/^\S+@\S+\.\S+$/.test(d.email)) return ["email", "El email no parece válido."];
  if (!d.type) return ["type", "Selecciona el tipo."];
  if (!d.subject) return ["subject", "Escribe el asunto."];
  if (d.subject.length > 120) return ["subject", "El asunto es demasiado largo (máx. 120)."];
  if (!d.message) return ["message", "Escribe tu mensaje."];
  if (d.message.length > 2000) return ["message", "El mensaje es demasiado largo (máx. 2000)."];
  if (!d.consent) return ["consent", "Debes confirmar la casilla de consentimiento."];
  return null;
}

async function send(data) {
  if (CONTACT_ENDPOINT) {
    let res;
    try {
      res = await fetch(CONTACT_ENDPOINT, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) });
    } catch {
      throw new Error(`No hay conexión con el servidor. Inténtalo de nuevo o escribe a ${SUPPORT_EMAIL}.`);
    }
    const json = await res.json().catch(() => ({}));
    // 400 (dato no válido) y 429 (demasiados envíos) traen un mensaje claro del servidor.
    if (!res.ok) throw new Error(json.error || `No se pudo enviar. Inténtalo de nuevo o escribe a ${SUPPORT_EMAIL}.`);
    return "sent";
  }
  const outbox = JSON.parse(localStorage.getItem(CONTACT_OUTBOX_KEY) || "[]");
  outbox.unshift(data);
  localStorage.setItem(CONTACT_OUTBOX_KEY, JSON.stringify(outbox.slice(0, 30)));
  return "saved";
}

const counter = (id, max) => `<span class="t-caption tabular" id="${id}-count">0/${max}</span>`;

export const contactView = {
  title: "Contacto",
  mount(root, params) {
    const user = auth.user();
    root.innerHTML = `
      <header class="view-head">
        <p class="t-kicker">Ayuda</p>
        <h1 class="t-h1">Contacto</h1>
        <p class="t-body" style="max-width:56ch;margin-top:var(--s-2)">¿Tienes dudas, un reporte o una sugerencia? Escríbenos desde aquí. Si es un tema legal o de privacidad, revisa también la <a class="link-strong" href="#/privacidad">Política de privacidad</a>.</p>
        <div class="tags" style="margin-top:var(--s-3)">
          <span class="tag">${icon("mail", "icon--sm")}Soporte: ${esc(SUPPORT_EMAIL)}</span>
          <span class="tag">Respuesta típica: 24–72 h (orientativo)</span>
        </div>
      </header>

      <div class="contact-layout">
        <section class="panel panel--raised contact-form-panel" aria-labelledby="contact-form-title">
          <h2 class="t-h2" id="contact-form-title">Envíanos un mensaje</h2>
          <form class="stack" id="contact-form" novalidate style="margin-top:var(--s-4)">
            <div class="form-grid">
              <div class="field">
                <label class="field__label" for="c-name">Nombre</label>
                <input class="input" id="c-name" name="name" autocomplete="name" placeholder="Tu nombre" required />
                <span class="field__hint">Cómo quieres que te llamemos.</span>
              </div>
              <div class="field">
                <label class="field__label" for="c-email">Email</label>
                <input class="input" id="c-email" name="email" type="email" autocomplete="email" inputmode="email" placeholder="tucorreo@ejemplo.com" required />
                <span class="field__hint">Para poder responderte.</span>
              </div>
              <div class="field">
                <span class="field__label" id="c-type-label">Tipo</span>
                <div class="chips chips--tight" role="radiogroup" aria-labelledby="c-type-label" id="c-type">
                  ${TYPES.map(([v, l]) => `<button type="button" class="chip" role="radio" aria-checked="false" data-type="${v}">${l}</button>`).join("")}
                </div>
                <span class="field__hint">Nos ayuda a dirigir tu mensaje.</span>
              </div>
              <div class="field">
                <label class="field__label" for="c-username">Usuario (opcional)</label>
                <input class="input" id="c-username" name="username" autocomplete="nickname" placeholder="@tuusuario" value="${user ? "@" + esc(user) : ""}" />
                <span class="field__hint">Si estás registrado.</span>
              </div>
            </div>
            <div class="field">
              <div class="field__row"><label class="field__label" for="c-subject">Asunto</label>${counter("c-subject", 120)}</div>
              <input class="input" id="c-subject" name="subject" maxlength="120" placeholder="Ej: No puedo iniciar sesión" required />
            </div>
            <div class="field">
              <div class="field__row"><label class="field__label" for="c-message">Mensaje</label>${counter("c-message", 2000)}</div>
              <textarea class="textarea" id="c-message" name="message" maxlength="2000" rows="6" placeholder="Cuéntanos qué ocurre y, si puedes, pasos para reproducirlo." required></textarea>
              <span class="field__hint">No incluyas contraseñas.</span>
            </div>
            <div class="hp" aria-hidden="true">
              <label for="c-website">No rellenes este campo</label>
              <input id="c-website" name="website" tabindex="-1" autocomplete="off" />
            </div>
            <label class="consent" for="c-consent">
              <input type="checkbox" id="c-consent" class="checkbox" required />
              <span>Confirmo que la información es veraz y acepto que se use para responder a mi solicitud.</span>
            </label>
            <p class="form-status" id="contact-status" role="status" aria-live="polite"></p>
            <div class="cta-row" style="margin-top:0">
              <button class="btn btn--primary" type="submit">${icon("send", "icon--sm")}Enviar</button>
              <button class="btn btn--ghost" type="reset">Limpiar</button>
            </div>
            <p class="t-caption">Al enviar, aceptas el tratamiento de tus datos para gestionar tu solicitud. Más info en la <a class="link-strong" href="#/privacidad">Política de privacidad</a>.</p>
          </form>
        </section>

        <aside class="contact-aside" aria-labelledby="channels-title">
          <h2 class="t-kicker menu__title" id="channels-title">Canales rápidos</h2>
          <nav class="menu">
            <a class="menu__item" href="${mailto(SUPPORT_EMAIL, "Soporte BeefMusic")}"><span class="menu__icon">${icon("mail")}</span><span class="menu__text"><span class="menu__label">Soporte</span><span class="t-meta">${esc(SUPPORT_EMAIL)}</span></span>${icon("chevron-right", "icon--sm menu__chev")}</a>
            <a class="menu__item" href="${mailto(PRIVACY_EMAIL, "Privacidad BeefMusic")}"><span class="menu__icon">${icon("lock")}</span><span class="menu__text"><span class="menu__label">Privacidad</span><span class="t-meta">${esc(PRIVACY_EMAIL)}</span></span>${icon("chevron-right", "icon--sm menu__chev")}</a>
            <a class="menu__item" href="${mailto(COPYRIGHT_EMAIL, "Reclamación de derechos BeefMusic")}"><span class="menu__icon">${icon("file")}</span><span class="menu__text"><span class="menu__label">Derechos de autor</span><span class="t-meta">${esc(COPYRIGHT_EMAIL)}</span></span>${icon("chevron-right", "icon--sm menu__chev")}</a>
          </nav>
          <div class="tip">
            <strong>Si reportas un fallo</strong>, cuéntanos: dispositivo, navegador, pasos, y si pasa siempre o a veces.
          </div>
          <div class="tip">
            ¿Algo rápido? También puedes <button class="link-strong" data-action="sugerencia">enviar una sugerencia</button> o <button class="link-strong" data-action="reporte">reportar un problema</button> desde la app.
          </div>
          <div class="tip">Revisa los <a class="link-strong" href="#/terminos">Términos</a> y la <a class="link-strong" href="#/privacidad">Privacidad</a> para conocer las reglas y cómo tratamos tus datos.</div>
        </aside>
      </div>
    `;

    const form = root.querySelector("#contact-form");
    const status = root.querySelector("#contact-status");
    let type = "";

    const typeGroup = root.querySelector("#c-type");
    const setType = (v) => {
      type = v;
      typeGroup.querySelectorAll("[data-type]").forEach((c) => {
        const on = c.dataset.type === v;
        c.setAttribute("aria-checked", String(on));
        c.tabIndex = on || (!v && c === typeGroup.firstElementChild) ? 0 : -1;
      });
    };
    typeGroup.addEventListener("click", (e) => {
      const c = e.target.closest("[data-type]");
      if (c) setType(c.dataset.type);
    });
    // Flechas para moverse entre opciones (patrón de radio).
    typeGroup.addEventListener("keydown", (e) => {
      if (!["ArrowRight", "ArrowLeft", "ArrowDown", "ArrowUp"].includes(e.key)) return;
      e.preventDefault();
      const items = [...typeGroup.querySelectorAll("[data-type]")];
      const i = Math.max(0, items.findIndex((c) => c.dataset.type === type));
      const next = items[(i + (e.key === "ArrowRight" || e.key === "ArrowDown" ? 1 : -1) + items.length) % items.length];
      setType(next.dataset.type);
      next.focus();
    });
    if (TYPES.some(([v]) => v === params.tipo)) setType(params.tipo);
    else setType("");

    [["c-subject", 120], ["c-message", 2000]].forEach(([id, max]) => {
      const input = root.querySelector("#" + id);
      const out = root.querySelector(`#${id}-count`);
      input.addEventListener("input", () => (out.textContent = `${input.value.length}/${max}`));
    });

    form.addEventListener("reset", () => {
      setTimeout(() => {
        setType("");
        setStatus(status, "");
        root.querySelectorAll(".field--error, .consent--error").forEach((f) => f.classList.remove("field--error", "consent--error"));
        root.querySelectorAll("[id$='-count']").forEach((c) => (c.textContent = c.textContent.replace(/^\d+/, "0")));
      });
    });

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      root.querySelectorAll(".field--error, .consent--error").forEach((f) => f.classList.remove("field--error", "consent--error"));
      const v = (id) => root.querySelector("#" + id).value.trim();
      const data = {
        name: v("c-name"),
        email: v("c-email"),
        type,
        username: v("c-username"),
        subject: v("c-subject"),
        message: v("c-message"),
        consent: root.querySelector("#c-consent").checked,
        website: root.querySelector("#c-website").value, // campo trampa para bots
        createdAt: new Date().toISOString(),
      };
      const err = validate(data);
      if (err) {
        const [field, msg] = err;
        setStatus(status, msg, "error");
        if (field === "consent") {
          root.querySelector(".consent").classList.add("consent--error");
          root.querySelector("#c-consent").focus();
        } else if (field === "type") {
          typeGroup.closest(".field").classList.add("field--error");
          typeGroup.querySelector("[data-type]").focus();
        } else {
          const input = root.querySelector("#c-" + field);
          input.closest(".field").classList.add("field--error");
          input.focus();
        }
        return;
      }
      await withBusy(form.querySelector("button[type=submit]"), "Enviando…", async () => {
        try {
          const result = await send(data);
          form.reset();
          if (result === "sent") {
            toast("¡Mensaje enviado! Te responderemos lo antes posible.");
            setTimeout(() => setStatus(status, "Mensaje enviado. Te responderemos al email que nos has dado, normalmente en 24–72 h.", "ok"));
          } else {
            setTimeout(() => setStatus(status, `Mensaje guardado en este dispositivo. El envío por la web aún no está activado: si es urgente, escribe a ${SUPPORT_EMAIL}.`, "info"));
          }
        } catch (err) {
          setStatus(status, err.message, "error");
        }
      });
    });
  },
};
