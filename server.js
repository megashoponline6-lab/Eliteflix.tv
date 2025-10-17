
import express from 'express';
import session from 'express-session';
import SQLiteStoreFactory from 'connect-sqlite3';
import helmet from 'helmet';
import morgan from 'morgan';
import path from 'path';
import dotenv from 'dotenv';
import csrf from 'csurf';
import cookieParser from 'cookie-parser';
import { body, validationResult } from 'express-validator';
import bcrypt from 'bcrypt';
import multer from 'multer';
import dayjs from 'dayjs';
import fs from 'fs';
import { run, all, get } from './db.js';

dotenv.config();

const app = express();
const SQLiteStore = SQLiteStoreFactory(session);
const upload = multer({ dest: path.join(process.cwd(),'public','uploads') });

app.set('view engine', 'ejs');
app.set('views', path.join(process.cwd(), 'views'));

app.use(helmet({ contentSecurityPolicy: false }));
app.use(morgan('dev'));
app.use(express.urlencoded({extended:true}));
app.use(express.json());
app.use(cookieParser());
app.use('/public', express.static(path.join(process.cwd(),'public')));

app.use(session({
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: path.join(process.cwd(),'data') }),
  secret: process.env.SESSION_SECRET || 'inseguro',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000*60*60*24*7 }
}));

const csrfProtection = csrf({ cookie: true });

function requireAuth(req,res,next){ if(!req.session.user) return res.redirect('/login'); next(); }
function requireAdmin(req,res,next){ if(!req.session.admin) return res.redirect('/admin'); next(); }
app.locals.appName = process.env.APP_NAME || 'Eliteflix';
app.locals.dayjs = dayjs;

await run(`CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY AUTOINCREMENT, usuario TEXT UNIQUE, passhash TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
await run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, nombre TEXT, apellido TEXT, pais TEXT, telefono TEXT, correo TEXT UNIQUE, passhash TEXT, saldo INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
await run(`CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY AUTOINCREMENT, nombre TEXT, etiqueta TEXT, precio INTEGER, logo TEXT, activo INTEGER DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
await run(`CREATE TABLE IF NOT EXISTS subscriptions (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, product_id INTEGER, vence_en TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
await run(`CREATE TABLE IF NOT EXISTS topups (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, monto INTEGER, nota TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
await run(`CREATE TABLE IF NOT EXISTS manual_sales (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, descripcion TEXT, monto INTEGER, fecha TEXT DEFAULT CURRENT_TIMESTAMP)`);
await run(`CREATE TABLE IF NOT EXISTS tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, estado TEXT DEFAULT 'abierto', created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
await run(`CREATE TABLE IF NOT EXISTS ticket_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id INTEGER, autor TEXT, mensaje TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);

// Seed products once
const c = await get(`SELECT COUNT(*) as c FROM products`);
if (c.c===0) {
  const seed = JSON.parse(fs.readFileSync(path.join(process.cwd(),'seed','products.json'),'utf-8'));
  for (const [nombre, etiqueta, precio, logo] of seed) {
    await run(`INSERT INTO products(nombre, etiqueta, precio, logo) VALUES (?,?,?,?)`, [nombre, etiqueta, precio, logo]);
  }
}

// Expose session
app.use((req,res,next)=>{ res.locals.sess = req.session; next(); });

// Filtros/Barra de opciones
app.get('/', async (req,res)=>{
  const etiquetas = await all(`SELECT DISTINCT etiqueta FROM products WHERE activo=1 ORDER BY etiqueta`);
  const filtro = req.query.f || '';
  const productos = filtro ? await all(`SELECT * FROM products WHERE activo=1 AND etiqueta=? ORDER BY nombre`, [filtro])
                           : await all(`SELECT * FROM products WHERE activo=1 ORDER BY nombre`);
  res.render('home', { productos, etiquetas, filtro });
});

app.get('/catalogo', async (req,res)=>{
  const etiquetas = await all(`SELECT DISTINCT etiqueta FROM products WHERE activo=1 ORDER BY etiqueta`);
  const filtro = req.query.f || '';
  const productos = filtro ? await all(`SELECT * FROM products WHERE activo=1 AND etiqueta=? ORDER BY nombre`, [filtro])
                           : await all(`SELECT * FROM products WHERE activo=1 ORDER BY nombre`);
  res.render('catalogo', { productos, etiquetas, filtro });
});

// Registro
app.get('/registro', csrfProtection, (req,res)=> res.render('registro', { csrfToken: req.csrfToken(), errores:[] }));

function normalizeEmail(correo){
  correo = (correo||'').trim().toLowerCase();
  const m = correo.match(/^([^@+]+)(\+[^@]+)?(@gmail\.com)$/);
  if (m) return m[1]+m[3];
  return correo;
}

app.post('/registro', csrfProtection,
  body('nombre').trim().notEmpty(),
  body('apellido').trim().notEmpty(),
  body('pais').trim().notEmpty(),
  body('correo').isEmail(),
  body('password').isLength({min:6}),
async (req,res)=>{
  const errores = validationResult(req);
  if(!errores.isEmpty()) return res.status(400).render('registro', { csrfToken: req.csrfToken(), errores: errores.array() });
  const {nombre, apellido, pais, telefono, password} = req.body;
  const correo = normalizeEmail(req.body.correo);
  const existe = await get(`SELECT id FROM users WHERE lower(correo)=?`, [correo]);
  if (existe) return res.status(400).render('registro', { csrfToken: req.csrfToken(), errores:[{msg:'Ese correo ya está registrado.'}] });
  const passhash = await bcrypt.hash(password, 10);
  await run(`INSERT INTO users (nombre, apellido, pais, telefono, correo, passhash) VALUES (?,?,?,?,?,?)`, [nombre,apellido,pais,telefono||'',correo,passhash]);
  res.redirect('/login?ok=1');
});

// Login/Logout
app.get('/login', csrfProtection, (req,res)=> res.render('login',{csrfToken:req.csrfToken(),errores:[], ok:req.query.ok}));
app.post('/login', csrfProtection, body('correo').isEmail(), body('password').notEmpty(), async (req,res)=>{
  const correo = normalizeEmail(req.body.correo);
  const u = await get(`SELECT * FROM users WHERE lower(correo)=?`, [correo]);
  if (!u) return res.status(400).render('login',{csrfToken:req.csrfToken(),errores:[{msg:'Credenciales inválidas'}]});
  const ok = await bcrypt.compare(req.body.password, u.passhash);
  if (!ok) return res.status(400).render('login',{csrfToken:req.csrfToken(),errores:[{msg:'Credenciales inválidas'}]});
  req.session.user = { id: u.id, nombre: u.nombre, correo: u.correo };
  res.redirect('/panel');
});
app.get('/logout', (req,res)=> req.session.destroy(()=>res.redirect('/')));

// Panel user
app.get('/panel', csrfProtection, requireAuth, async (req,res)=>{
  const user = await get(`SELECT * FROM users WHERE id=?`, [req.session.user.id]);
  const sub = await get(`SELECT s.*, p.nombre as prod_nombre FROM subscriptions s LEFT JOIN products p ON p.id=s.product_id WHERE s.user_id=? ORDER BY s.id DESC LIMIT 1`, [user.id]);
  const dias = sub ? Math.ceil((new Date(sub.vence_en)-new Date())/(1000*60*60*24)) : null;
  const tickets = await all(`SELECT * FROM tickets WHERE user_id=? ORDER BY id DESC`, [user.id]);
  res.render('panel', { csrfToken: req.csrfToken(), user, sub, dias, tickets });
});

// Ticket / conversación
app.post('/ticket', csrfProtection, requireAuth, body('mensaje').notEmpty(), async (req,res)=>{
  let ticketId = req.body.ticket_id;
  if (!ticketId) {
    const t = await run(`INSERT INTO tickets (user_id) VALUES (?)`, [req.session.user.id]);
    ticketId = t.lastID;
  }
  await run(`INSERT INTO ticket_messages (ticket_id, autor, mensaje) VALUES (?,?,?)`, [ticketId, 'cliente', req.body.mensaje]);
  res.redirect('/panel#soporte');
});

// Admin setup/login
app.get('/admin/setup', csrfProtection, async (req,res)=>{
  const c = await get(`SELECT COUNT(*) as c FROM admins`);
  if (c.c>0) return res.redirect('/admin');
  res.render('admin/setup', { csrfToken: req.csrfToken(), errores:[] });
});
app.post('/admin/setup', csrfProtection, body('usuario').notEmpty(), body('password').isLength({min:8}), async (req,res)=>{
  const c = await get(`SELECT COUNT(*) as c FROM admins`);
  if (c.c>0) return res.redirect('/admin');
  const passhash = await bcrypt.hash(req.body.password, 12);
  await run(`INSERT INTO admins (usuario, passhash) VALUES (?,?)`, [req.body.usuario, passhash]);
  res.redirect('/admin');
});

app.get('/admin', csrfProtection, async (req,res)=>{
  const c = await get(`SELECT COUNT(*) as c FROM admins`);
  if (c.c===0) return res.redirect('/admin/setup');
  res.render('admin/login', { csrfToken: req.csrfToken(), errores:[] });
});
app.post('/admin', csrfProtection, body('usuario').notEmpty(), body('password').notEmpty(), async (req,res)=>{
  const a = await get(`SELECT * FROM admins WHERE usuario=?`, [req.body.usuario]);
  if (!a) return res.status(400).render('admin/login', { csrfToken: req.csrfToken(), errores:[{msg:'Credenciales inválidas'}]});
  const ok = await bcrypt.compare(req.body.password, a.passhash);
  if (!ok) return res.status(400).render('admin/login', { csrfToken: req.csrfToken(), errores:[{msg:'Credenciales inválidas'}]});
  req.session.admin = { id: a.id, usuario: a.usuario };
  res.redirect('/admin/panel');
});
app.get('/admin/salir', (req,res)=> { delete req.session.admin; res.redirect('/admin'); });

// Admin panel
app.get('/admin/panel', requireAdmin, csrfProtection, async (req,res)=>{
  const usuarios = await all(`SELECT id,nombre,apellido,correo,saldo FROM users ORDER BY id DESC LIMIT 15`);
  const productos = await all(`SELECT * FROM products ORDER BY id DESC LIMIT 50`);
  const tickets = await all(`SELECT t.*, u.correo FROM tickets t LEFT JOIN users u ON u.id=t.user_id WHERE t.estado='abierto' ORDER BY t.id DESC LIMIT 10`);
  const manual = await all(`SELECT m.*, u.correo FROM manual_sales m LEFT JOIN users u ON u.id=m.user_id ORDER BY m.id DESC LIMIT 10`);
  const totSaldo = await get(`SELECT SUM(saldo) as s FROM users`);
  const totManualMes = await get(`SELECT SUM(monto) as s FROM manual_sales WHERE strftime('%Y-%m', fecha)=strftime('%Y-%m','now')`);
  const totSubsAct = await get(`SELECT COUNT(*) as c FROM subscriptions WHERE date(vence_en) >= date('now')`);
  res.render('admin/panel', { csrfToken: req.csrfToken(), usuarios, productos, tickets, manual, totSaldo, totManualMes, totSubsAct });
});

// Recargas
app.post('/admin/recargar', requireAdmin, csrfProtection, body('user_id').isInt(), body('monto').isInt({min:1}), async (req,res)=>{
  const uid = parseInt(req.body.user_id), m = parseInt(req.body.monto);
  await run(`UPDATE users SET saldo = saldo + ? WHERE id=?`, [m, uid]);
  await run(`INSERT INTO topups (user_id, monto, nota) VALUES (?,?,?)`, [uid, m, req.body.nota||'']);
  res.redirect('/admin/panel?ok=recarga');
});

// Productos
app.post('/admin/producto', requireAdmin, csrfProtection, upload.single('logoimg'), async (req,res)=>{
  const {nombre, etiqueta, precio, logo} = req.body;
  let logoField = logo || '/public/brand/netflix.svg';
  if (req.file) logoField = `/public/uploads/${req.file.filename}`;
  await run(`INSERT INTO products (nombre, etiqueta, precio, logo) VALUES (?,?,?,?)`, [nombre, etiqueta, parseInt(precio||0), logoField]);
  res.redirect('/admin/panel?ok=producto');
});
app.post('/admin/producto/:id/editar', requireAdmin, csrfProtection, upload.single('logoimg'), async (req,res)=>{
  const {nombre, etiqueta, precio, activo, logo} = req.body;
  let logoField = logo;
  if (req.file) logoField = `/public/uploads/${req.file.filename}`;
  await run(`UPDATE products SET nombre=?, etiqueta=?, precio=?, logo=?, activo=? WHERE id=?`,
    [nombre, etiqueta, parseInt(precio), logoField, activo?1:0, parseInt(req.params.id)]);
  res.redirect('/admin/panel?ok=editprod');
});
app.post('/admin/producto/:id/eliminar', requireAdmin, csrfProtection, async (req,res)=>{
  await run(`DELETE FROM products WHERE id=?`, [parseInt(req.params.id)]);
  res.redirect('/admin/panel?ok=delprod');
});

// Eliminar cliente
app.post('/admin/cliente/:id/eliminar', requireAdmin, csrfProtection, async (req,res)=>{
  await run(`DELETE FROM users WHERE id=?`, [parseInt(req.params.id)]);
  res.redirect('/admin/panel?ok=delcli');
});

// Ventas manuales
app.post('/admin/manual', requireAdmin, csrfProtection, async (req,res)=>{
  const {user_id, descripcion, monto} = req.body;
  const uid = user_id ? parseInt(user_id) : null;
  await run(`INSERT INTO manual_sales (user_id, descripcion, monto) VALUES (?,?,?)`, [uid, descripcion, parseInt(monto)]);
  res.redirect('/admin/panel?ok=manual');
});

// Suscripción
app.post('/admin/suscripcion', requireAdmin, csrfProtection, async (req,res)=>{
  const {user_id, product_id, vence_en} = req.body;
  await run(`INSERT INTO subscriptions (user_id, product_id, vence_en) VALUES (?,?,?)`, [parseInt(user_id), parseInt(product_id), vence_en]);
  res.redirect('/admin/panel?ok=suscripcion');
});

// Tickets threads
app.get('/admin/ticket/:id', requireAdmin, csrfProtection, async (req,res)=>{
  const t = await get(`SELECT t.*, u.correo FROM tickets t LEFT JOIN users u ON u.id=t.user_id WHERE t.id=?`, [parseInt(req.params.id)]);
  const msgs = await all(`SELECT * FROM ticket_messages WHERE ticket_id=? ORDER BY id`, [parseInt(req.params.id)]);
  res.render('support/thread', { csrfToken: req.csrfToken(), t, msgs });
});
app.post('/admin/ticket/:id/mensaje', requireAdmin, csrfProtection, body('mensaje').notEmpty(), async (req,res)=>{
  await run(`INSERT INTO ticket_messages (ticket_id, autor, mensaje) VALUES (?,?,?)`, [parseInt(req.params.id), 'admin', req.body.mensaje]);
  res.redirect(`/admin/ticket/${req.params.id}`);
});
app.post('/admin/ticket/:id/cerrar', requireAdmin, csrfProtection, async (req,res)=>{
  await run(`UPDATE tickets SET estado='cerrado' WHERE id=?`, [parseInt(req.params.id)]);
  res.redirect('/admin/panel?ok=ticket');
});

// 404
app.use((req,res)=> res.status(404).render('404'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=> console.log(`Servidor en http://localhost:${PORT}`));
