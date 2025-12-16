require("dotenv").config();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const express = require("express");
const cors = require("cors");
const axios = require("axios");
const { createClient } = require("@supabase/supabase-js");

const app = express();
app.use(cors());
app.use(express.json());

// === SUPABASE ===
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY
);


// === USER STATS (para logros) ===
// Recomendación de tabla en Supabase:
//   user_stats:
//     - usuario_id (uuid/int, PK, mismo tipo que usuarios.id)
//     - vote_switches (int, default 0)
//     - vote_removals (int, default 0)
//     - created_at (timestamptz, default now()) [opcional]
async function bumpUserStat(userId, field, amount = 1) {
    try {
        if (!userId) return;

        const allowed = new Set(["vote_switches", "vote_removals"]);
        if (!allowed.has(field)) return;

        const { data: row, error: selErr } = await supabase
            .from("user_stats")
            .select("usuario_id, vote_switches, vote_removals")
            .eq("usuario_id", userId)
            .maybeSingle();

        if (selErr && selErr.code !== "PGRST116") {
            console.error("Supabase error (select user_stats):", selErr);
            return;
        }

        if (!row) {
            const payload = {
                usuario_id: userId,
                vote_switches: field === "vote_switches" ? amount : 0,
                vote_removals: field === "vote_removals" ? amount : 0,
            };

            const { error: insErr } = await supabase.from("user_stats").insert(payload);
            if (insErr) console.error("Supabase error (insert user_stats):", insErr);
            return;
        }

        const nextVal = (row[field] || 0) + amount;

        const { error: updErr } = await supabase
            .from("user_stats")
            .update({ [field]: nextVal })
            .eq("usuario_id", userId);

        if (updErr) console.error("Supabase error (update user_stats):", updErr);
    } catch (e) {
        console.error("Error en bumpUserStat:", e.message);
    }
}

async function getUserStats(userId) {
    try {
        if (!userId) return { voteSwitches: 0, voteRemovals: 0 };

        const { data, error } = await supabase
            .from("user_stats")
            .select("vote_switches, vote_removals")
            .eq("usuario_id", userId)
            .maybeSingle();

        if (error && error.code !== "PGRST116") {
            console.error("Supabase error (get user_stats):", error);
            return { voteSwitches: 0, voteRemovals: 0 };
        }

        return {
            voteSwitches: data?.vote_switches || 0,
            voteRemovals: data?.vote_removals || 0,
        };
    } catch (e) {
        console.error("Error en getUserStats:", e.message);
        return { voteSwitches: 0, voteRemovals: 0 };
    }
}


// === AUTH ADMIN ===
function crearTokenAdmin() {
    const payload = { role: "admin" };
    return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "7d" });
}

// === AUTH USER ===
function crearTokenUser(user) {
    const payload = {
        role: "user",
        userId: user.id,
        username: user.username,
    };
    return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "7d" });
}

function authUser(req, res, next) {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ")
        ? authHeader.slice(7)
        : null;

    if (!token) {
        return res.status(401).json({ error: "No autorizado" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (decoded.role !== "user") {
            return res.status(403).json({ error: "Permisos insuficientes" });
        }
        req.user = decoded;
        next();
    } catch (err) {
        console.error("Error verificando token user:", err.message);
        return res.status(401).json({ error: "Token no válido o expirado" });
    }
}

function authAdmin(req, res, next) {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ")
        ? authHeader.slice(7)
        : null;

    if (!token) {
        return res.status(401).json({ error: "No autorizado" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (decoded.role !== "admin") {
            return res.status(403).json({ error: "Permisos insuficientes" });
        }
        next();
    } catch (err) {
        console.error("Error verificando token admin:", err.message);
        return res.status(401).json({ error: "Token no válido o expirado" });
    }
}

// === AUTH USER OPCIONAL (para /api/canciones) ===
function getUserFromToken(req) {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ")
        ? authHeader.slice(7)
        : null;

    if (!token) return null;

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (decoded.role !== "user") return null;
        // decoded tiene: role, userId, username
        return decoded;
    } catch (err) {
        console.error("Error verificando token opcional:", err.message);
        return null;
    }
}

// === DISCORD WEBHOOKS (CONSTANTES GLOBALES) ===
const DISCORD_WEBHOOK_PETICIONES =
    process.env.DISCORD_WEBHOOK_PETICIONES || process.env.DISCORD_WEBHOOK_URL;

const DISCORD_WEBHOOK_SUGERENCIAS =
    process.env.DISCORD_WEBHOOK_SUGERENCIAS || process.env.DISCORD_WEBHOOK_URL;

const DISCORD_WEBHOOK_REPORTES =
    process.env.DISCORD_WEBHOOK_REPORTES || process.env.DISCORD_WEBHOOK_URL;

// === DISCORD: PETICIONES ===
async function enviarAPeticionDiscord({ nick, style, idea, idPeticion }) {
    const url = DISCORD_WEBHOOK_PETICIONES;
    if (!url) return;

    const content =
        `🎵 **Nueva petición de canción**\n` +
        `👤 Nick: ${nick}\n` +
        `🎧 Estilo: ${style}\n` +
        `📝 Idea:\n${idea}\n\n` +
        `🆔 ID petición: ${idPeticion}`;

    await axios.post(url, { content });
}

// === DISCORD: SUGERENCIAS ===
async function enviarASugerenciaDiscord({ nick, mensaje, idSugerencia }) {
    const url = DISCORD_WEBHOOK_SUGERENCIAS;
    if (!url) return;

    const content =
        `💡 **Nueva sugerencia para BeefMusic**\n` +
        `👤 Nick: ${nick || "Anónimo"}\n` +
        `📝 Sugerencia:\n${mensaje}\n\n` +
        `🆔 ID sugerencia: ${idSugerencia}`;

    await axios.post(url, { content });
}

// === DISCORD: REPORTES ===
async function enviarAReporteDiscord({ nick, mensaje, idReporte }) {
    const url = DISCORD_WEBHOOK_REPORTES;
    if (!url) return;

    const content =
        `🐛 **Nuevo reporte de problema en BeefMusic**\n` +
        `👤 Nick: ${nick || "Anónimo"}\n` +
        `📝 Detalle del problema:\n${mensaje}\n\n` +
        `🆔 ID reporte: ${idReporte}`;

    await axios.post(url, { content });
}

// === RUTA TEST ===
app.get("/", (req, res) => {
    res.send("API BeefMusic funcionando");
});

// === LOGIN ADMIN ===
app.post("/api/login", (req, res) => {
    const { username, password } = req.body;

    if (
        username === process.env.ADMIN_USER &&
        password === process.env.ADMIN_PASS
    ) {
        const token = crearTokenAdmin();
        return res.json({ token });
    }

    return res.status(401).json({ error: "Credenciales incorrectas" });
});

// === REGISTRO USUARIO NORMAL ===
app.post("/api/register", async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: "Faltan campos" });
        }

        if (password.length < 6) {
            return res
                .status(400)
                .json({ error: "La contraseña debe tener al menos 6 caracteres" });
        }

        // ¿ya existe?
        const { data: existente, error: errorCheck } = await supabase
            .from("usuarios")
            .select("id")
            .eq("username", username)
            .maybeSingle();

        if (errorCheck && errorCheck.code !== "PGRST116") {
            console.error("Supabase error (check user):", errorCheck);
            return res
                .status(500)
                .json({ error: "Error comprobando usuario existente" });
        }

        if (existente) {
            return res.status(400).json({ error: "Ese usuario ya existe" });
        }

        const password_hash = await bcrypt.hash(password, 10);

        const { data, error } = await supabase
            .from("usuarios")
            .insert({ username, password_hash })
            .select()
            .single();

        if (error) {
            console.error("Supabase error (insert user):", error);
            return res.status(500).json({ error: "Error creando el usuario" });
        }

        const token = crearTokenUser(data);

        res.status(201).json({
            message: "Usuario registrado correctamente",
            token,
            username: data.username,
        });
    } catch (err) {
        console.error("Error en POST /api/register:", err);
        res.status(500).json({ error: "Error en el servidor" });
    }
});

// === LOGIN USUARIO NORMAL ===
app.post("/api/login-user", async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: "Faltan campos" });
        }

        const { data: user, error } = await supabase
            .from("usuarios")
            .select("id, username, password_hash")
            .eq("username", username)
            .maybeSingle();

        if (error && error.code !== "PGRST116") {
            console.error("Supabase error (login user):", error);
            return res.status(500).json({ error: "Error buscando usuario" });
        }

        if (!user) {
            return res.status(401).json({ error: "Usuario o contraseña incorrectos" });
        }

        const ok = await bcrypt.compare(password, user.password_hash);
        if (!ok) {
            return res.status(401).json({ error: "Usuario o contraseña incorrectos" });
        }

        const token = crearTokenUser(user);

        res.json({
            message: "Login correcto",
            token,
            username: user.username,
        });
    } catch (err) {
        console.error("Error en POST /api/login-user:", err);
        res.status(500).json({ error: "Error en el servidor" });
    }
});

// === CREAR PETICIÓN (PÚBLICO) ===
// ✅ añadido: mostrarNick -> mostrar_nick
app.post("/api/peticiones", async (req, res) => {
    try {
        const { nick, style, idea, mostrarNick } = req.body;

        if (!nick || !style || !idea) {
            return res.status(400).json({ error: "Faltan campos obligatorios" });
        }

        const { data, error } = await supabase
            .from("peticiones")
            .insert({
                nick,
                estilo: style,
                idea,
                mostrar_nick: !!mostrarNick, // ✅ nuevo
            })
            .select()
            .single();

        if (error) {
            console.error("Supabase error (insert peticion):", error);
            return res.status(500).json({ error: "Error guardando la petición" });
        }

        const idPeticion = data.id;

        try {
            await enviarAPeticionDiscord({ nick, style, idea, idPeticion });
        } catch (err) {
            console.error("Error enviando a Discord:", err.message);
        }

        res.status(201).json({
            message: "Petición creada correctamente",
            id: idPeticion,
        });
    } catch (error) {
        console.error("Error en POST /api/peticiones:", error);
        res.status(500).json({ error: "Error en el servidor" });
    }
});

// === PETICIONES EN CURSO (PÚBLICO LIGHT) ===
// Devuelve: estado, estilo, fecha, y nick SOLO si mostrar_nick=true
app.get("/api/peticiones-publicas", async (req, res) => {
    try {
        const limit = Math.min(parseInt(req.query.limit || "30", 10), 100);
        const offset = Math.max(parseInt(req.query.offset || "0", 10), 0);

        // filtros opcionales:
        // ?estado=pendiente | en_produccion | terminada
        // ?estilo=Drill  (match exacto)
        const estado = (req.query.estado || "").trim();
        const estilo = (req.query.estilo || "").trim();

        let q = supabase
            .from("peticiones")
            .select("id, nick, estilo, estado, created_at, mostrar_nick")
            .order("created_at", { ascending: false })
            .range(offset, offset + limit - 1);

        if (estado) q = q.eq("estado", estado);
        if (estilo) q = q.eq("estilo", estilo);

        const { data, error } = await q;

        if (error) {
            console.error("Supabase error (select peticiones publicas):", error);
            return res.status(500).json({ error: "Error al obtener peticiones públicas" });
        }

        const clean = (data || []).map((p) => ({
            id: p.id,
            estilo: p.estilo,
            estado: p.estado,
            created_at: p.created_at,
            nick: p.mostrar_nick ? p.nick : null, // ✅ anonimiza si no aceptó
        }));

        res.json(clean);
    } catch (err) {
        console.error("Error en GET /api/peticiones-publicas:", err);
        res.status(500).json({ error: "Error en el servidor" });
    }
});

// === CREAR SUGERENCIA (PÚBLICO) ===
app.post("/api/sugerencias", async (req, res) => {
    try {
        const { nick, mensaje } = req.body;

        if (!mensaje) {
            return res.status(400).json({ error: "Falta el campo 'mensaje' de la sugerencia" });
        }

        const { data, error } = await supabase
            .from("sugerencias")
            .insert({
                nick: nick || null,
                mensaje,
            })
            .select()
            .single();

        if (error) {
            console.error("Supabase error (insert sugerencia):", error);
            return res.status(500).json({ error: "Error guardando la sugerencia" });
        }

        const idSugerencia = data.id;

        try {
            await enviarASugerenciaDiscord({ nick, mensaje, idSugerencia });
        } catch (err) {
            console.error("Error enviando sugerencia a Discord:", err.message);
        }

        res.status(201).json({
            message: "Sugerencia enviada correctamente",
            id: idSugerencia,
        });
    } catch (error) {
        console.error("Error en POST /api/sugerencias:", error);
        res.status(500).json({ error: "Error en el servidor" });
    }
});

// === CREAR REPORTE (PÚBLICO) ===
app.post("/api/reportes", async (req, res) => {
    try {
        const { nick, mensaje } = req.body;

        if (!mensaje) {
            return res.status(400).json({ error: "Falta el campo 'mensaje' del reporte" });
        }

        const { data, error } = await supabase
            .from("reportes")
            .insert({
                nick: nick || null,
                mensaje,
            })
            .select()
            .single();

        if (error) {
            console.error("Supabase error (insert reporte):", error);
            return res.status(500).json({ error: "Error guardando el reporte" });
        }

        const idReporte = data.id;

        try {
            await enviarAReporteDiscord({ nick, mensaje, idReporte });
        } catch (err) {
            console.error("Error enviando reporte a Discord:", err.message);
        }

        res.status(201).json({
            message: "Reporte enviado correctamente",
            id: idReporte,
        });
    } catch (error) {
        console.error("Error en POST /api/reportes:", error);
        res.status(500).json({ error: "Error en el servidor" });
    }
});

// === IA CASERA PARA GENERAR LETRAS (VERSIÓN "SUNO LOWCOST") ===

// Detectar género a partir del prompt
function detectarGeneroDesdePrompt(prompt) {
    const texto = prompt.toLowerCase();

    const mapping = [
        { genero: "Dembow", keywords: ["dembow"] },
        { genero: "Drill", keywords: ["drill"] },
        { genero: "Boom Bap", keywords: ["boom bap", "boombap"] },
        { genero: "Phonk", keywords: ["phonk"] },
        { genero: "Corridos tumbados", keywords: ["corridos tumbados", "corridos", "tumbados"] },
        { genero: "Afrobeat", keywords: ["afrobeat", "afrobeats"] },
        { genero: "Dancehall", keywords: ["dancehall"] },
        { genero: "R&B", keywords: ["r&b", "rnb", "r and b"] },
        { genero: "Reggaetón", keywords: ["reggaeton", "reggaetón"] },
        { genero: "Trap", keywords: ["trap"] },
        { genero: "Rap", keywords: ["rap", "hip hop", "hip-hop"] },
        { genero: "Pop urbano", keywords: ["pop urbano", "latin pop", "pop"] },
        { genero: "Club / EDM", keywords: ["techno", "house", "edm", "club"] },
    ];

    for (const item of mapping) {
        if (item.keywords.some((k) => texto.includes(k))) {
            return item.genero;
        }
    }

    // Por defecto, trap que nunca falla
    return "Trap";
}

// Detectar mood básico a partir del prompt
function detectarMoodDesdePrompt(prompt) {
    const texto = prompt.toLowerCase();

    if (
        texto.includes("triste") ||
        texto.includes("ruptura") ||
        texto.includes("desamor") ||
        texto.includes("llorar") ||
        texto.includes("corazón roto")
    ) {
        return "triste";
    }

    if (
        texto.includes("feliz") ||
        texto.includes("fiesta") ||
        texto.includes("perreo") ||
        texto.includes("discoteca") ||
        texto.includes("party")
    ) {
        return "fiesta";
    }

    if (
        texto.includes("beef") ||
        texto.includes("diss") ||
        texto.includes("tiradera") ||
        texto.includes("respuesta") ||
        texto.includes("enemigo")
    ) {
        return "beef";
    }

    if (
        texto.includes("motivar") ||
        texto.includes("superar") ||
        texto.includes("lograr") ||
        texto.includes("sueños") ||
        texto.includes("meta") ||
        texto.includes("progreso")
    ) {
        return "motivacional";
    }

    if (
        texto.includes("amor") ||
        texto.includes("enamora") ||
        texto.includes("enamorad") ||
        texto.includes("novia") ||
        texto.includes("novio") ||
        texto.includes("crush") ||
        texto.includes("romántic")
    ) {
        return "romantico";
    }

    if (
        texto.includes("nostal") ||
        texto.includes("recuerdo") ||
        texto.includes("antes") ||
        texto.includes("infancia") ||
        texto.includes("viejos tiempos")
    ) {
        return "nostalgico";
    }

    if (
        texto.includes("oscuro") ||
        texto.includes("noche") ||
        texto.includes("demonio") ||
        texto.includes("diablo") ||
        texto.includes("smoke") ||
        texto.includes("sombra")
    ) {
        return "oscuro";
    }

    return "neutro";
}

// Extraer posibles nombres / nicks del prompt (muy simple)
function extraerNombresDesdePrompt(prompt) {
    const posibles = [];
    const regexArroba = /@\w+/g;
    const encontrados = prompt.match(regexArroba);
    if (encontrados) {
        posibles.push(...encontrados);
    }
    return posibles;
}

// Extraer palabras clave (para meterlas en barras)
function extraerPalabrasClave(prompt) {
    const stopwords = new Set([
        "de","la","el","y","que","en","un","una","con","por","para","del","al","se",
        "me","te","lo","las","los","mi","tu","sus","su","ya","no","si","sí","es",
        "soy","eres","somos","son","como","cuando","donde","más","menos","muy"
    ]);

    return prompt
        .toLowerCase()
        .replace(/[.,!?¿¡()"]/g, " ")
        .split(/\s+/)
        .filter((w) => w.length > 3 && !stopwords.has(w))
        .slice(0, 8); // nos quedamos con unas pocas
}

// Plantillas de vocabulario por género/mood
const VOCABULARIO = {
    // Bases por género
    baseTrap: [
        "luces bajas en el bloque",
        "ruido de motos por la noche",
        "facturas que no quieren esperar",
        "miradas que no son de verdad",
        "humos en la ventana del cuarto",
        "la sirena suena pero ya ni me levanto",
        "otra noche corriendo de lo que siento",
        "en la esquina se negocia tiempo por dinero",
        "el brillo en la cadena tapa lo que duele",
        "la vida en modo rápido, nadie aquí se duerme",
    ],
    baseDrill: [
        "pasos firmes por la zona",
        "la lealtad se firma sin papel",
        "en mi esquina nadie se esconde",
        "el silencio vale más que el oro",
        "caras tapadas, cero gestos de cariño",
        "quien habló de más ya no pisa este camino",
        "la mirada fría como el metal que cargan",
        "en el bloque suena eco de las balas",
        "lo que tú llamas juego aquí es rutina",
        "piso fuerte y el suelo se inclina",
    ],
    baseDembow: [
        "la pista encendida hasta tarde",
        "lo nuestro se rompe en el dancefloor",
        "bajo las luces todo se olvida",
        "ese ritmo nos tiene enviciados",
        "las bocinas reventando el barrio entero",
        "el bajo rebota como tu cuerpo",
        "tu pana grabando todo en el cel",
        "los vecinos ya saben cómo es",
        "sube el volumen, que tiemble la acera",
        "esa cintura manda en la noche entera",
    ],
    baseReggaeton: [
        "te pienso cada vez que suena el beat",
        "tus mensajes que ya no contesté",
        "lo nuestro se quedó en aquel after",
        "tus amigas preguntando por qué",
        "bailábamos pegados, ahora ni me miras",
        "tus stories se ven pero no me etiquetas",
        "ese perfume tuyo se quedó en mi hoodie",
        "las discusiones siempre en medio del party",
        "te vas con otro pero vuelves pa' escribirme",
        "dices que me odias y eso es quererse",
    ],
    baseRap: [
        "escribo en la libreta lo que el mundo no escucha",
        "la verdad en cada barra aunque duela en la nuca",
        "las calles me criaron, los beats me adoptaron",
        "el micro es mi arma, mis versos dispararon",
        "la mente en otra parte mientras el tiempo corre",
        "lo que no dije en persona, el tema lo recoge",
        "la base suena cruda como la realidad",
        "los míos en la grada apoyando de verdad",
        "no quiero premio, quiero paz mental",
        "cada línea es terapia musical",
    ],
    baseBoomBap: [
        "zapatillas viejas pero el flow es nuevo",
        "sample viejito, mensaje moderno",
        "bombo y caja marcando mi paso",
        "el humo en el estudio se queda en el vaso",
        "grafitis en la esquina contando la historia",
        "cada loop que suena revive memoria",
        "vinilos girando, aguja en la herida",
        "boom bap sonando, salvando mi vida",
        "parques y bancos como escenario",
        "el underground nunca fue secundario",
    ],
    baseAfrobeat: [
        "el sol cayendo lento sobre la ciudad",
        "tus caderas hablan con sinceridad",
        "la vibra es dulce como tu voz",
        "en cada paso se nos olvida el reloj",
        "palmas arriba, energía que no se acaba",
        "el ritmo suave pero el corazón se dispara",
        "tu sonrisa brilla más que las luces",
        "nadie en la pista quiere que esto se cruce",
        "calor en el aire, sudor en la frente",
        "la música manda sobre toda la gente",
    ],
    baseRnb: [
        "tu voz en mi mente a las tres de la mañana",
        "las sábanas recuerdan que ya no estás en la cama",
        "los mensajes a medias que nunca mandé",
        "las notas de voz que borré por miedo a perder",
        "tu silueta en la ventana cuando cae la lluvia",
        "cada melodía me lleva otra vez a tu duda",
        "las luces tenues hablan más que nosotros",
        "lo nuestro era fuego, ahora quedan solo escombros",
        "suspiros mezclados con el delay del reverb",
        "en cada acorde vuelves aunque no quieras volver",
    ],
    basePhonk: [
        "neones morados reflejados en el vidrio",
        "el motor ruge como todo lo que me guardo",
        "la ciudad fantasma, yo corriendo sin frenos",
        "las sombras se ríen cuando piso el suelo",
        "filtro en la voz, pero el dolor es real",
        "los bajos retumban como mi potencial",
        "gafas oscuras aunque no dé el sol",
        "en la autopista solo mando yo",
        "fumo recuerdos que no quiero ver",
        "en cada giro me pierdo otra vez",
    ],
    baseCorridos: [
        "botas llenas de polvo del camino",
        "la troca levantada vibra con el destino",
        "billetes doblados en la bolsa del chaleco",
        "la banda sonando, celebrando lo que tengo",
        "de abajo venimos, lo saben los viejos",
        "el respeto se gana, no se compra con espejos",
        "botella en la mesa, historias en el aire",
        "las cicatrices cuentan por quién disparé",
        "la sierra de fondo, acordeón sonando",
        "mi nombre en la boca de los que andan criticando",
    ],
    baseEdm: [
        "las luces se cruzan como nuestros caminos",
        "las manos en alto, olvidando el destino",
        "el drop se aproxima, el pecho lo siente",
        "saltamos al tiempo, lo para la gente",
        "el humo en el aire dibuja tus formas",
        "cuando baja el bajo, la razón se deforma",
        "pierdo la noción cuando el kick se repite",
        "la noche parece un sueño que no se edite",
        "láseres marcan el ritmo en el suelo",
        "en cada subida tocamos el cielo",
    ],
    basePopUrbano: [
        "tus dramas convertidos en trending topic",
        "nuestro amor en IG se volvió caótico",
        "los planes de futuro se quedaron en typing",
        "ya no respondes pero sigues stalkeando",
        "canciones en la radio que llevan tu nombre",
        "amigos que preguntan qué fue lo que pasa",
        "selfies sonriendo pero nada encaja",
        "las noches de risa se fueron sin traza",
        "filmábamos todo como si fuera eterno",
        "ahora solo quedan recuerdos en cuaderno",
    ],

    // Líneas por mood para mezclar en los versos
    moodTriste: [
        "y aunque sonrío, por dentro no estoy bien",
        "cada salida se siente como un ayer",
        "la almohada sabe lo que tú no ves",
        "las lágrimas se esconden detrás del stress",
        "reviso tu chat aunque sé que es perder",
        "la canción se acaba, pero no tu querer",
    ],
    moodFiesta: [
        "las copas arriba, que nadie se siente",
        "mañana veremos qué dice la gente",
        "si suena este tema se cae la discoteca",
        "la noche está joven, la vibra está fresca",
        "bailando pegados hasta ver el sol",
        "los problemas se quedan fuera del control",
    ],
    moodBeef: [
        "no eres mi rival, solo ruido en la red",
        "tus números inflados no son poder",
        "hablas de calle y no pisas el andén",
        "mi pluma dispara, tú apagas el cel",
        "tu barra más dura es mi calentamiento",
        "yo no presumo, yo dejo el cemento",
    ],
    moodMotivacional: [
        "caí mil veces pero nunca me rendí",
        "las cicatrices me trajeron hasta aquí",
        "nadie apostaba pero yo seguí de pie",
        "el fracaso fue maestro, no un juez",
        "los míos en la mente en cada canción",
        "no vine a jugar, vine por mi bendición",
    ],
    moodRomantico: [
        "tu nombre sonando en cada melodía",
        "desde que llegaste cambió mi energía",
        "tu risa es mi hook favorito",
        "lo nuestro merece más que un mito",
        "aunque discutan boca y mente",
        "el corazón siempre te tiene presente",
    ],
    moodNostalgico: [
        "las fotos viejas guardan nuestro secreto",
        "el tiempo no borra lo que fue correcto",
        "camino lugares que ya no visitas",
        "la mente rebobina como una cinta",
        "mirando al pasado desde otro vagón",
        "queriendo volver a aquella versión",
    ],
    moodOscuro: [
        "la ciudad dormida y yo sin poder",
        "las voces internas no paran de arder",
        "la luna de testigo de lo que no cuento",
        "cada pensamiento es un tormento",
        "las sombras conocen mi nombre completo",
        "el lado oscuro me ofrece su respeto",
    ],
    moodNeutro: [
        "la vida va pasando entre beat y beat",
        "no todo es drama, a veces es chill",
        "aprendo del día, descargo en la noche",
        "la música siempre equilibra el coche",
    ],

    // Estribillos por mood
    estribilloTriste: [
        "y aunque digas que me olvidaste",
        "yo sé que en secreto todavía me extrañas",
        "bailas con otro pero no es igual",
        "porque nadie te canta como yo en el track",
        "borro tus fotos pero no tu señal",
        "en cada playlist vuelves a empezar",
    ],
    estribilloFiesta: [
        "sube el dembow que la noche está encendida",
        "hoy se bebe y nadie aquí se olvida",
        "si me miras así sabes que es tuyo el VIP",
        "que suene fuerte pa' que no puedan dormir",
        "y que se rompa la tarima otra vez",
        "si este tema suena, tú sabes qué es",
    ],
    estribilloBeef: [
        "tú tiras barras pero no das miedo",
        "tu movie entera se cae en el suelo",
        "hablas de calle pero no te creo",
        "aquí en el barrio respetan lo que veo",
        "no eres villano, eres extra en la escena",
        "tu credibilidad se quedó fuera",
    ],
    estribilloMotivacional: [
        "yo vengo de abajo y miro hacia arriba",
        "cada caída me dejó más vivo",
        "si se cierra una puerta, rompo la pared",
        "esta es la prueba de lo que sí se puede hacer",
        "que suene fuerte en el barrio y la city",
        "que los de siempre vean que no fue easy",
    ],
    estribilloRomantico: [
        "quédate cerquita aunque el mundo grite",
        "que lo que tenemos nadie lo repite",
        "si apagan las luces tú eres mi señal",
        "con solo mirarte se me olvida el mal",
        "baila despacito que el tiempo se para",
        "lo nuestro es canción que nunca se acaba",
    ],
    estribilloNostalgico: [
        "éramos fuego en medio del invierno",
        "lo que vivimos parecía eterno",
        "aunque el calendario diga que ya fue",
        "cada verso vuelve a aquel café",
        "si cierro los ojos te vuelvo a mirar",
        "en cada compás te vuelvo a encontrar",
    ],
    estribilloOscuro: [
        "de noche salgo solo con mi sombra",
        "los miedos se despegan cuando suena la tromba",
        "el bajo retumba como mi interior",
        "entre luz y sombra siempre gano yo",
        "no temo al vacío, ya estuve allí",
        "de cada caída me traje un beat",
    ],
    estribilloNeutro: [
        "será lo que tenga que ser",
        "si el beat nos llama, vamos a volver",
        "entre subidas, bajadas también",
        "la vida se escribe sobre este papel",
    ],

    // Adlibs varios
    adlibs: [
        "yeah, yeah",
        "uh, uh",
        "ey",
        "woah",
        "ajá",
        "yeah, mami",
        "beefmusic on the track",
        "ey, ey",
        "díselo",
        "prr",
        "skrrt",
        "ja",
        "ok, ok",
    ],
};

// Helpers de aleatoriedad
function pickRandom(array) {
    return array[Math.floor(Math.random() * array.length)];
}

function randomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

// Construir un estribillo según el mood
function generarEstribillo(mood, nombres, palabrasClave) {
    let base;
    if (mood === "triste") base = VOCABULARIO.estribilloTriste;
    else if (mood === "fiesta") base = VOCABULARIO.estribilloFiesta;
    else if (mood === "beef") base = VOCABULARIO.estribilloBeef;
    else if (mood === "motivacional") base = VOCABULARIO.estribilloMotivacional;
    else if (mood === "romantico") base = VOCABULARIO.estribilloRomantico;
    else if (mood === "nostalgico") base = VOCABULARIO.estribilloNostalgico;
    else if (mood === "oscuro") base = VOCABULARIO.estribilloOscuro;
    else base = VOCABULARIO.estribilloNeutro;

    const nombreExtra = nombres.length > 0 ? ` ${nombres[0]}` : "";
    const palabraExtra = palabrasClave[0] ? ` (${palabrasClave[0]})` : "";

    const estribillo = [];
    const lines = randomInt(4, 6);

    for (let i = 0; i < lines; i++) {
        let linea = pickRandom(base);
        if (i === 1 && nombreExtra) linea += nombreExtra;
        if (i === lines - 1 && palabraExtra) linea += palabraExtra;
        estribillo.push(linea);
    }

    return estribillo;
}

// Construir versos en función del género + mood
function generarVerso(genero, mood, topicResumen, palabrasClave) {
    let base;

    switch (genero) {
        case "Drill": base = VOCABULARIO.baseDrill; break;
        case "Dembow": base = VOCABULARIO.baseDembow; break;
        case "Reggaetón": base = VOCABULARIO.baseReggaeton; break;
        case "Rap": base = VOCABULARIO.baseRap; break;
        case "Boom Bap": base = VOCABULARIO.baseBoomBap; break;
        case "Afrobeat": base = VOCABULARIO.baseAfrobeat; break;
        case "R&B": base = VOCABULARIO.baseRnb; break;
        case "Phonk": base = VOCABULARIO.basePhonk; break;
        case "Corridos tumbados": base = VOCABULARIO.baseCorridos; break;
        case "Club / EDM": base = VOCABULARIO.baseEdm; break;
        case "Pop urbano": base = VOCABULARIO.basePopUrbano; break;
        case "Trap":
        default: base = VOCABULARIO.baseTrap; break;
    }

    let moodBase = VOCABULARIO.moodNeutro;
    if (mood === "triste") moodBase = VOCABULARIO.moodTriste;
    else if (mood === "fiesta") moodBase = VOCABULARIO.moodFiesta;
    else if (mood === "beef") moodBase = VOCABULARIO.moodBeef;
    else if (mood === "motivacional") moodBase = VOCABULARIO.moodMotivacional;
    else if (mood === "romantico") moodBase = VOCABULARIO.moodRomantico;
    else if (mood === "nostalgico") moodBase = VOCABULARIO.moodNostalgico;
    else if (mood === "oscuro") moodBase = VOCABULARIO.moodOscuro;

    const verso = [];
    const numLines = randomInt(4, 7);

    // Primera línea: muchas veces conectada al tema
    if (Math.random() < 0.6 && topicResumen) {
        verso.push(topicResumen);
    } else if (palabrasClave.length) {
        verso.push(`todo gira en torno a ${palabrasClave[0]}`);
    } else {
        verso.push(pickRandom(base));
    }

    for (let i = verso.length; i < numLines; i++) {
        const r = Math.random();
        if (r < 0.4) {
            verso.push(pickRandom(base));
        } else if (r < 0.8) {
            verso.push(pickRandom(moodBase));
        } else {
            // Línea mezclando keyword + base/mood
            const kw = palabrasClave[randomInt(0, Math.max(palabrasClave.length - 1, 0))] || "";
            if (kw) {
                verso.push(pickRandom(base) + ", " + kw);
            } else {
                verso.push(pickRandom(moodBase));
            }
        }
    }

    return verso;
}

// Pre-coro / puente corto en función del mood
function generarPreCoro(mood, palabrasClave) {
    const base = (mood === "triste" || mood === "romantico" || mood === "nostalgico")
        ? VOCABULARIO.moodTriste.concat(VOCABULARIO.moodRomantico)
        : VOCABULARIO.moodFiesta.concat(VOCABULARIO.moodMotivacional);

    const lines = [];
    const n = randomInt(2, 3);
    for (let i = 0; i < n; i++) {
        let l = pickRandom(base);
        if (i === n - 1 && palabrasClave[1]) {
            l += `, ${palabrasClave[1]}`;
        }
        lines.push(l);
    }
    return lines;
}

// “IA” que construye una canción entera
function generarLetraCancion({ prompt, username }) {
    const genero = detectarGeneroDesdePrompt(prompt);
    const mood = detectarMoodDesdePrompt(prompt);
    const nombres = extraerNombresDesdePrompt(prompt);
    const keywords = extraerPalabrasClave(prompt);

    const topicResumen =
        Math.random() < 0.8
            ? "Esta historia va de " +
              prompt.slice(0, 120).replace(/\s+/g, " ") +
              (prompt.length > 120 ? "..." : "")
            : "";

    const verso1 = generarVerso(genero, mood, topicResumen, keywords);
    const estribillo = generarEstribillo(mood, nombres, keywords);
    const verso2 = generarVerso(
        genero,
        mood,
        `@${username} metido en esta película sonora.`,
        keywords
    );

    const usarPreCoro = Math.random() < 0.7;
    const usarPuente = Math.random() < 0.5;
    const preCoro = usarPreCoro ? generarPreCoro(mood, keywords) : null;
    const puente = usarPuente ? generarPreCoro(mood, keywords.slice().reverse()) : null;

    const adlib1 = pickRandom(VOCABULARIO.adlibs);
    const adlib2 = pickRandom(VOCABULARIO.adlibs);

    // Título algo más variado
    let titulo;
    const kwForTitle = keywords[0]
        ? keywords[0].charAt(0).toUpperCase() + keywords[0].slice(1)
        : null;

    if (mood === "triste") {
        titulo = kwForTitle ? `${kwForTitle} (corazón roto en ${genero})` : `Corazón roto en ${genero}`;
    } else if (mood === "beef") {
        titulo = kwForTitle ? `Beef por ${kwForTitle} (${genero})` : `Beef en ${genero}`;
    } else if (mood === "fiesta") {
        titulo = kwForTitle ? `Noche de ${kwForTitle}` : `Noche de ${genero}`;
    } else if (mood === "motivacional") {
        titulo = kwForTitle ? `De barrio a ${kwForTitle}` : `De cero a todo (${genero})`;
    } else if (mood === "romantico") {
        titulo = kwForTitle ? `Carta para ${kwForTitle}` : `Carta en ${genero} para ti`;
    } else if (mood === "nostalgico") {
        titulo = kwForTitle ? `Recuerdos de ${kwForTitle}` : `Recuerdos en ${genero}`;
    } else if (mood === "oscuro") {
        titulo = kwForTitle ? `${kwForTitle} en la sombra` : `Lado oscuro en ${genero}`;
    } else {
        titulo = kwForTitle ? `${kwForTitle} (${genero})` : `Historia en ${genero}`;
    }

    const partes = [];

    partes.push(`Título sugerido: ${titulo}`);
    partes.push("");
    partes.push("[Intro]");
    partes.push(`${adlib1}`);
    if (topicResumen && Math.random() < 0.5) {
        partes.push(topicResumen);
    }
    partes.push("");

    partes.push("[Verso 1]");
    verso1.forEach((l) => partes.push(l));
    partes.push("");

    if (usarPreCoro) {
        partes.push("[Pre-coro]");
        preCoro.forEach((l) => partes.push(l));
        partes.push("");
    }

    partes.push("[Estribillo]");
    estribillo.forEach((l) => partes.push(l));
    partes.push("");

    partes.push("[Verso 2]");
    verso2.forEach((l) => partes.push(l));
    partes.push("");

    if (usarPuente) {
        partes.push("[Puente]");
        puente.forEach((l) => partes.push(l));
        partes.push("");
    }

    // Reprise del estribillo
    if (Math.random() < 0.9) {
        partes.push("[Estribillo – reprise]");
        estribillo.forEach((l) => partes.push(l));
        partes.push("");
    }

    partes.push("[Outro]");
    partes.push(`${adlib2}`);
    partes.push("BeefMusic, esto no es plantilla, es tu historia convertida en tema.");

    return partes.join("\n");
}

// === ASISTENTE IA BEEFMUSIC (USER) ===
// Generador propio de letras, sin llamar a OpenAI
app.post("/api/assistant", authUser, async (req, res) => {
    try {
        const { prompt } = req.body;

        if (!prompt || typeof prompt !== "string" || !prompt.trim()) {
            return res.status(400).json({ error: "Falta el campo 'prompt'" });
        }

        const username = req.user?.username || "usuario_beefmusic";

        const letra = generarLetraCancion({ prompt, username });

        return res.json({
            ok: true,
            text: letra,
        });
    } catch (err) {
        console.error("Error en POST /api/assistant (IA casera):", err);
        return res.status(500).json({ error: "Error generando la letra en el servidor" });
    }
});

// === LISTAR PETICIONES (ADMIN) ===
app.get("/api/peticiones", authAdmin, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from("peticiones")
            .select("id, nick, estilo, idea, estado, created_at, mostrar_nick") // ✅ añadido mostrar_nick
            .order("created_at", { ascending: false });

        if (error) {
            console.error("Supabase error (select peticiones):", error);
            return res
                .status(500)
                .json({ error: "Error al obtener las peticiones" });
        }

        res.json(data);
    } catch (error) {
        console.error("Error en GET /api/peticiones:", error);
        res.status(500).json({ error: "Error en el servidor" });
    }
});

// === ACTUALIZAR ESTADO DE UNA PETICIÓN (ADMIN) ===
app.patch("/api/peticiones/:id/estado", authAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { estado } = req.body;

        const estadosPermitidos = ["pendiente", "en_produccion", "terminada"];

        if (!estadosPermitidos.includes(estado)) {
            return res.status(400).json({
                error: "Estado no válido. Usa: pendiente, en_produccion o terminada",
            });
        }

        const { data, error } = await supabase
            .from("peticiones")
            .update({ estado })
            .eq("id", id)
            .select("id, estado")
            .single();

        if (error) {
            console.error("Supabase error (update estado):", error);
            return res
                .status(500)
                .json({ error: "Error al actualizar el estado de la petición" });
        }

        res.json({
            message: "Estado actualizado correctamente",
            peticion: data,
        });
    } catch (error) {
        console.error("Error en PATCH /api/peticiones/:id/estado:", error);
        res.status(500).json({ error: "Error en el servidor" });
    }
});

// === LISTAR CANCIONES (PÚBLICO, CON LIKES/DISLIKES Y VOTO DEL USUARIO) ===
app.get("/api/canciones", async (req, res) => {
    try {
        // usuario opcional (si hay token, lo usamos; si no, null)
        const user = getUserFromToken(req);
        const userId = user ? user.userId : null;

        // 1) Canciones base
        const { data: canciones, error: errorCanciones } = await supabase
            .from("canciones")
            .select(
                "id, titulo, estilo, duracion, descripcion, autor, estado, url_audio, created_at"
            )
            .order("created_at", { ascending: false });

        if (errorCanciones) {
            console.error("Supabase error (select canciones):", errorCanciones);
            return res
                .status(500)
                .json({ error: "Error al obtener las canciones" });
        }

        if (!canciones || canciones.length === 0) {
            return res.json([]);
        }

        // 2) Todos los votos (para agregarlos en Node)
        let votos = [];
        const { data: votosData, error: errorVotos } = await supabase
            .from("votos_cancion")
            .select("id, cancion_id, usuario_id, tipo");

        if (errorVotos) {
            console.error("Supabase error (select votos_cancion):", errorVotos);
            votos = [];
        } else {
            votos = votosData || [];
        }

        // 3) Agrupar votos por canción para contar likes y dislikes
        const votesBySong = new Map();
        for (const v of votos) {
            const list = votesBySong.get(v.cancion_id) || [];
            list.push(v);
            votesBySong.set(v.cancion_id, list);
        }

        // 4) Construir respuesta con likes, dislikes y userVote
        const respuesta = canciones.map((c) => {
            const songVotes = votesBySong.get(c.id) || [];

            let likes = 0;
            let dislikes = 0;
            let userVote = null;

            for (const v of songVotes) {
                if (v.tipo === "like") likes++;
                if (v.tipo === "dislike") dislikes++;
                if (userId && v.usuario_id === userId) {
                    userVote = v.tipo; // 'like' o 'dislike'
                }
            }

            return {
                id: c.id,
                titulo: c.titulo,
                estilo: c.estilo,
                duracion: c.duracion,
                descripcion: c.descripcion,
                autor: c.autor,
                estado: c.estado,
                url_audio: c.url_audio,
                created_at: c.created_at,
                likes,
                dislikes,
                userVote, // puede ser 'like', 'dislike' o null
            };
        });

        res.json(respuesta);
    } catch (err) {
        console.error("Error en GET /api/canciones:", err);
        res.status(500).json({ error: "Error en el servidor" });
    }
});

// === VOTAR CANCIÓN (like / dislike, 1 voto por usuario, posibilidad de quitar) ===
app.post("/api/canciones/:id/vote", authUser, async (req, res) => {
    try {
        const { id } = req.params;
        const { tipo } = req.body; // 'like' o 'dislike'
        const userId = req.user.userId; // viene del token (crearTokenUser)

        if (tipo !== "like" && tipo !== "dislike") {
            return res
                .status(400)
                .json({ error: "Tipo de voto no válido. Usa 'like' o 'dislike'." });
        }

        // Comprobar que la canción existe
        const { data: song, error: errorSong } = await supabase
            .from("canciones")
            .select("id")
            .eq("id", id)
            .maybeSingle();

        if (errorSong) {
            console.error("Supabase error (select cancion en voto):", errorSong);
            return res
                .status(500)
                .json({ error: "Error buscando la canción" });
        }

        if (!song) {
            return res.status(404).json({ error: "Canción no encontrada" });
        }

        // 1) Ver si ya hay un voto de este usuario para esta canción
        const { data: existingVote, error: errorExisting } = await supabase
            .from("votos_cancion")
            .select("id, tipo")
            .eq("cancion_id", id)
            .eq("usuario_id", userId)
            .maybeSingle();

        if (errorExisting && errorExisting.code !== "PGRST116") {
            console.error("Supabase error (select voto existente):", errorExisting);
            return res
                .status(500)
                .json({ error: "Error comprobando voto existente" });
        }

        let userVoteResult = null;

        if (!existingVote) {
            // No había voto -> insert
            const { error: errorInsert } = await supabase
                .from("votos_cancion")
                .insert({
                    cancion_id: id,
                    usuario_id: userId,
                    tipo,
                });

            if (errorInsert) {
                console.error("Supabase error (insert voto):", errorInsert);
                return res
                    .status(500)
                    .json({ error: "Error guardando el voto" });
            }

            userVoteResult = tipo;
        } else if (existingVote.tipo !== tipo) {
            // Había voto distinto -> cambiar tipo
            const { error: errorUpdateVote } = await supabase
                .from("votos_cancion")
                .update({ tipo })
                .eq("id", existingVote.id);

            if (errorUpdateVote) {
                console.error("Supabase error (update voto):", errorUpdateVote);
                return res
                    .status(500)
                    .json({ error: "Error actualizando el voto" });
            }

            // ✅ Logro: primera vez que cambias el voto / contador de cambios
            await bumpUserStat(userId, "vote_switches", 1);

            userVoteResult = tipo;
        } else {
            // Ya había un voto igual -> QUITAR voto (toggle off)
            const { error: errorDelete } = await supabase
                .from("votos_cancion")
                .delete()
                .eq("id", existingVote.id);

            if (errorDelete) {
                console.error("Supabase error (delete voto):", errorDelete);
                return res
                    .status(500)
                    .json({ error: "Error eliminando el voto" });
            }

            // ✅ Logro: quitaste tu voto / contador de removals
            await bumpUserStat(userId, "vote_removals", 1);

            userVoteResult = null; // sin voto
        }

        // 2) Recalcular likes/dislikes de esa canción
        const { data: votosSong, error: errorCounts } = await supabase
            .from("votos_cancion")
            .select("tipo")
            .eq("cancion_id", id);

        if (errorCounts) {
            console.error("Supabase error (contar votos):", errorCounts);
            return res
                .status(500)
                .json({ error: "Error obteniendo los votos actualizados" });
        }

        let likes = 0;
        let dislikes = 0;

        (votosSong || []).forEach((v) => {
            if (v.tipo === "like") likes++;
            if (v.tipo === "dislike") dislikes++;
        });

        res.json({
            message: "Voto registrado",
            likes,
            dislikes,
            userVote: userVoteResult, // 'like', 'dislike' o null
        });
    } catch (err) {
        console.error("Error en POST /api/canciones/:id/vote:", err);
        res.status(500).json({ error: "Error en el servidor" });
    }
});

// === CREAR CANCIÓN (ADMIN) ===
app.post("/api/canciones", authAdmin, async (req, res) => {
    try {
        const {
            titulo,
            estilo,
            duracion,
            descripcion,
            autor,
            estado = "publicada",
            url_audio,
        } = req.body;

        if (!titulo || !estilo || !autor) {
            return res.status(400).json({ error: "Faltan campos obligatorios" });
        }

        const { data, error } = await supabase
            .from("canciones")
            .insert({
                titulo,
                estilo,
                duracion,
                descripcion,
                autor,
                estado,
                url_audio,
            })
            .select()
            .single();

        if (error) {
            console.error("Supabase error (insert cancion):", error);
            return res.status(500).json({ error: "Error creando la canción" });
        }

        res.status(201).json({
            message: "Canción creada correctamente",
            cancion: data,
        });
    } catch (err) {
        console.error("Error en POST /api/canciones:", err);
        res.status(500).json({ error: "Error en el servidor" });
    }
});

// Normalizar nombres de género (para que "dembow", "Dembow", "DEMBOW" cuenten como uno)
function normalizarGenero(raw) {
    if (!raw) {
        return { key: "desconocido", label: "Desconocido" };
    }

    // quitar espacios, pasar a minúsculas y quitar acentos
    let base = raw.trim().toLowerCase();
    base = base.normalize("NFD").replace(/[\u0300-\u036f]/g, ""); // reggaetón -> reggaeton

    // mapa para nombres bonitos
    const mapa = {
        dembow: "Dembow",
        drill: "Drill",
        trap: "Trap",
        rap: "Rap",
        reggaeton: "Reggaetón",
        pop: "Pop",
        "boom bap": "Boom Bap",
        "reggaeton_dembow": "Reggaetón / Dembow",
    };

    const label = mapa[base] || (base.charAt(0).toUpperCase() + base.slice(1));

    return { key: base, label };
}


// === PERFIL SONORO DEL USUARIO (USER) ===
app.get("/api/sound-profile", authUser, async (req, res) => {
    try {
        const userId = req.user.userId;
        const username = req.user.username;

        // Extra: stats para logros (cambios de voto, quitar voto, etc.)
        const { voteSwitches, voteRemovals } = await getUserStats(userId);

        // 1) Votos del usuario
        const { data: votos, error: errorVotos } = await supabase
            .from("votos_cancion")
            .select("tipo, cancion_id")
            .eq("usuario_id", userId);

        if (errorVotos) {
            console.error("Supabase error (select votos usuario):", errorVotos);
            return res.status(500).json({ error: "Error obteniendo votos del usuario" });
        }

        // Si no ha votado nada, devolvemos un perfil vacío pero válido
        if (!votos || votos.length === 0) {
            return res.json({
                username,
                toxicity: 0,
                totalVotes: 0,
                totalLikes: 0,
                totalDislikes: 0,
                genres: [],
                dominantGenre: null,
                moodLabel: "Aún sin datos suficientes",
                moodTags: ["dale like o dislike a alguna canción"],
                badges: [],
                voteSwitches,
                voteRemovals,
            });
        }

        // 2) Sacar los IDs de canciones y traer sus estilos
        const songIds = [...new Set(votos.map((v) => v.cancion_id))];

        const { data: canciones, error: errorCancionesPerfil } = await supabase
            .from("canciones")
            .select("id, estilo")
            .in("id", songIds);

        if (errorCancionesPerfil) {
            console.error("Supabase error (select canciones perfil):", errorCancionesPerfil);
            return res.status(500).json({ error: "Error obteniendo canciones para el perfil" });
        }

        const songMap = new Map();
        (canciones || []).forEach((c) => {
            songMap.set(c.id, c.estilo || "Desconocido");
        });

        // 3) Calcular stats por género + likes/dislikes totales
        const statsByGenre = {};
        let totalVotes = 0;
        let totalLikes = 0;
        let totalDislikes = 0;

        for (const v of votos) {
            const estiloOriginal = songMap.get(v.cancion_id) || "Desconocido";
            const { key, label } = normalizarGenero(estiloOriginal);

            if (!statsByGenre[key]) {
                statsByGenre[key] = { label, likes: 0, dislikes: 0 };
            }

            if (v.tipo === "like") {
                statsByGenre[key].likes++;
                totalLikes++;
            } else if (v.tipo === "dislike") {
                statsByGenre[key].dislikes++;
                totalDislikes++;
            }

            totalVotes++;
        }

        // 4) Transformar a array y calcular porcentajes
        let genres = Object.values(statsByGenre).map((g) => ({
            name: g.label,
            likes: g.likes,
            dislikes: g.dislikes,
        }));

        // Si no hay likes, usamos votos totales para %; si hay likes, solo likes
        const baseForPercent = totalLikes > 0 ? totalLikes : totalVotes;

        genres = genres
            .map((g) => {
                const weight = totalLikes > 0 ? g.likes : g.likes + g.dislikes;
                const percent = baseForPercent > 0
                    ? Math.round((weight / baseForPercent) * 100)
                    : 0;
                return { ...g, percent };
            })
            .sort((a, b) => b.percent - a.percent);

        const dominantGenre = genres.length > 0 ? genres[0].name : null;

        // 5) Toxicidad = porcentaje de dislikes sobre votos totales
        const toxicity =
            totalVotes > 0 ? Math.round((totalDislikes / totalVotes) * 100) : 0;

        // 6) Mood y tags básicos (lógica simple pero resultona)
        function getMoodLabel(toxicity, dominantGenre) {
            if (!dominantGenre) return "Explorando sonidos";

            if (toxicity >= 70) {
                if (["Trap", "Drill", "Dembow", "Rap"].includes(dominantGenre)) {
                    return "Modo demonio nocturno";
                }
                return "Crítico profesional de Spotify";
            }

            if (toxicity >= 40) {
                return `Selectivo con el ${dominantGenre}`;
            }

            return `Buen rollo con el ${dominantGenre}`;
        }

        function getMoodTags(toxicity, dominantGenre, totalVotes) {
            const tags = [];

            if (dominantGenre) tags.push(`fan del ${dominantGenre.toLowerCase()}`);

            if (toxicity >= 70) {
                tags.push("hater fino", "no compro cualquier tema");
            } else if (toxicity >= 40) {
                tags.push("exigente", "o me flipa o nada");
            } else {
                tags.push("flow chill", "mente abierta");
            }

            if (totalVotes >= 50) tags.push("usuario veterano");
            if (totalVotes < 10) tags.push("recién llegado");

            return tags;
        }

        const moodLabel = getMoodLabel(toxicity, dominantGenre);
        const moodTags = getMoodTags(toxicity, dominantGenre, totalVotes);

        // 7) Badges desbloqueados
        const badges = [];

        if (totalVotes >= 1) {
            badges.push({ icon: "🔥", label: "Primer beef votado" });
        }
        if (totalLikes >= 10) {
            badges.push({ icon: "🎧", label: "10 canciones que te han volado la cabeza" });
        }
        if (totalLikes >= 30 && dominantGenre) {
            badges.push({ icon: "🖤", label: `Fan oficial del ${dominantGenre}` });
        }
        if (totalDislikes >= 10) {
            badges.push({ icon: "💣", label: "Hater elegante (10 no me gusta)" });
        }

        // 8) Respuesta final
        res.json({
            username,
            toxicity,
            totalVotes,
            totalLikes,
            totalDislikes,
            genres,
            dominantGenre,
            moodLabel,
            moodTags,
            badges,
            voteSwitches,
            voteRemovals,
        });
    } catch (err) {
        console.error("Error en GET /api/sound-profile:", err);
        res.status(500).json({ error: "Error en el servidor" });
    }
});

const port = process.env.PORT || 4000;
app.listen(port, () => {
    console.log(`BeefMusic API escuchando en http://localhost:${port}`);
});
