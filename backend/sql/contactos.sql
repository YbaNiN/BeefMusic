-- Tabla para los mensajes del formulario de contacto (POST /api/contacto).
-- Ejecútalo una vez en Supabase → SQL Editor.

create table if not exists public.contactos (
  id bigserial primary key,
  nombre text not null,
  email text not null,
  tipo text not null,
  usuario text,
  asunto text not null,
  mensaje text not null,
  created_at timestamptz not null default now()
);

-- Sin políticas = nadie puede leer ni escribir desde fuera.
-- El backend sí puede, porque usa la clave de servicio.
alter table public.contactos enable row level security;
