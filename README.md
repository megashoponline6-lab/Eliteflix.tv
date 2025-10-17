
# Éliteflix — Panel Streaming (ESP)

Node 20 + Express + SQLite. Listo para Render.
- Registro: nombre, apellido, país, teléfono (opcional), correo (único), contraseña.
- Admin (setup único): `/admin/setup` solo primera vez. Luego `/admin`.
- Catálogo con **barra de opciones** por etiqueta (1M, 3M, 6M, Anual, etc.).
- Productos editables; **sube logo** (imagen) o usa emoji. Incluyo **SVGs** de muestra en `/public/brand/`.
- Recargas con **historial** (topups).
- Ventas manuales con **cliente opcional**.
- Suscripción manual (usuario + producto + fecha).
- Soporte con **conversación** (hilo de mensajes).
- Reporte rápido: saldo total, ventas manuales del mes, suscripciones activas.

## Local
```bash
cp .env.example .env
npm install
npm start
```
Abrir http://localhost:3000

## Render
Sube a GitHub y crea Web Service. Establece `NODE_VERSION=20.19.5` y `SESSION_SECRET`.
