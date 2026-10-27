// Configuración común de la app.
export const API_URL = "https://beefmusic-backend.onrender.com";
export const TOKEN_KEY = "beefmusic_user_token";
export const USER_KEY = "beefmusic_user_name";
export const DISCORD_URL = "https://discord.gg/DywmTT78Wx";
export const LAST_PLAYED_KEY = "beefmusic_last_played";

// Formulario de contacto: el backend lo guarda en Supabase y avisa por Discord.
// Si lo dejas vacío, los mensajes se guardan solo en el navegador (modo demo).
export const CONTACT_ENDPOINT = API_URL + "/api/contacto";
export const CONTACT_OUTBOX_KEY = "beefmusic_contact_outbox";
export const SUPPORT_EMAIL = "soporte@tudominio.com";
export const PRIVACY_EMAIL = "privacidad@tudominio.com";
export const COPYRIGHT_EMAIL = "copyright@tudominio.com";
