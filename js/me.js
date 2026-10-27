// Datos públicos de la persona conectada (id, avatar, bio…), pedidos una vez.
import { auth, usersApi } from "./api.js";

let pending = null;
const listeners = new Set();

export function getMe({ force = false } = {}) {
  if (!auth.isLogged() || !auth.user()) return Promise.resolve(null);
  if (!pending || force) {
    pending = usersApi.get(auth.user()).catch((err) => {
      pending = null;
      throw err;
    });
  }
  return pending;
}

// Avisa a las vistas cuando cambia el perfil (p. ej. tras editarlo).
export function onMeChange(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export async function refreshMe() {
  const me = await getMe({ force: true });
  listeners.forEach((fn) => fn(me));
  return me;
}
