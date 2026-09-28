require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(48).toString('hex');
const ADMIN_ID = process.env.ADMIN_ID || '6900225457';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '690022';
const FEE = Number(process.env.ADMISSION_FEE || 1000);
const CENTER_NAME = process.env.CENTER_NAME || 'Your Computer Center';

const COURSES = [
  'BCC','DCA','ADCA','CCA','PGDCA','Graphic Designing','CorelDRAW','AutoCAD','Photoshop',
  'Advanced Excel','Tally Prime','Typing D/O','MS Word','MS Excel','C Language','Java','BCS',
  'ADIT','DCP','DIT','DCTT','DCAA','DDM','Other'
];

const db = new Database(path.join(__dirname, 'center.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS admin_users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_id TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS applications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  application_no TEXT UNIQUE NOT NULL,
  full_name TEXT NOT NULL,
  phone TEXT NOT NULL,
  email TEXT,
  dob TEXT,
  address TEXT,
  course TEXT NOT NULL,
  payment_txn TEXT,
  payment_status TEXT NOT NULL DEFAULT 'submitted',
  status TEXT NOT NULL DEFAULT 'pending',
  student_id TEXT,
  password_hash TEXT,
  plain_password_once TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  reviewed_at TEXT
);
`);

const admin = db.prepare('SELECT * FROM admin_users WHERE admin_id = ?').get(ADMIN_ID);
if (!admin) {
  db.prepare('INSERT INTO admin_users (admin_id, password_hash) VALUES (?, ?)').run(ADMIN_ID, bcrypt.hashSync(ADMIN_PASSWORD, 12));
}

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 60, standardHeaders: true, legacyHeaders: false });

function signToken(payload) { return jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' }); }
function auth(role) {
  return (req, res, next) => {
    const h = req.headers.authorization || '';
    const token = h.startsWith('Bearer ') ? h.slice(7) : '';
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (role && decoded.role !== role) return res.status(403).json({ error: 'Forbidden' });
      req.user = decoded;
      next();
    } catch { res.status(401).json({ error: 'Unauthorized' }); }
  };
}
function applicationNo() { return 'APP' + new Date().getFullYear() + String(Date.now()).slice(-7); }
function studentId() { return 'ST' + new Date().getFullYear() + crypto.randomInt(100000, 999999); }
function generatedPassword() { return crypto.randomBytes(4).toString('base64url').slice(0, 8); }

app.get('/api/config', (req,res) => res.json({ centerName: CENTER_NAME, fee: FEE, courses: COURSES }));

app.post('/api/admin/login', loginLimiter, (req,res) => {
  const { adminId, password } = req.body || {};
  const row = db.prepare('SELECT * FROM admin_users WHERE admin_id = ?').get(String(adminId || ''));
  if (!row || !bcrypt.compareSync(String(password || ''), row.password_hash)) return res.status(401).json({ error: 'Invalid admin credentials' });
  res.json({ token: signToken({ role: 'admin', adminId: row.admin_id }) });
});

app.post('/api/student/login', loginLimiter, (req,res) => {
  const { studentId: sid, password } = req.body || {};
  const row = db.prepare('SELECT * FROM applications WHERE student_id = ? AND status = ?').get(String(sid || ''), 'approved');
  if (!row || !row.password_hash || !bcrypt.compareSync(String(password || ''), row.password_hash)) return res.status(401).json({ error: 'Invalid student credentials' });
  res.json({ token: signToken({ role: 'student', applicationId: row.id, studentId: row.student_id }) });
});

app.post('/api/applications', authLimiter, (req,res) => {
  const { fullName, phone, email, dob, address, course, paymentTxn } = req.body || {};
  if (!fullName || !phone || !course) return res.status(400).json({ error: 'Name, mobile and course are required.' });
  if (!COURSES.includes(course)) return res.status(400).json({ error: 'Invalid course.' });
  const appNo = applicationNo();
  db.prepare(`INSERT INTO applications (application_no, full_name, phone, email, dob, address, course, payment_txn) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(appNo, String(fullName).trim(), String(phone).trim(), email || '', dob || '', address || '', course, paymentTxn || '');
  res.status(201).json({ applicationNo: appNo, fee: FEE, message: 'Application submitted. It is now waiting for admin approval.' });
});

app.get('/api/admin/applications', auth('admin'), (req,res) => {
  const rows = db.prepare(`SELECT id, application_no, full_name, phone, email, dob, address, course, payment_txn, payment_status, status, student_id, created_at, reviewed_at FROM applications ORDER BY id DESC`).all();
  res.json(rows);
});

app.post('/api/admin/applications/:id/approve', auth('admin'), (req,res) => {
  const row = db.prepare('SELECT * FROM applications WHERE id = ?').get(Number(req.params.id));
  if (!row) return res.status(404).json({ error: 'Application not found' });
  if (row.status === 'approved') return res.json({ studentId: row.student_id, password: row.plain_password_once || 'Already generated. Ask admin to reset.' });
  const sid = studentId();
  const pwd = generatedPassword();
  db.prepare(`UPDATE applications SET status='approved', student_id=?, password_hash=?, plain_password_once=?, reviewed_at=CURRENT_TIMESTAMP WHERE id=?`)
    .run(sid, bcrypt.hashSync(pwd, 12), pwd, row.id);
  res.json({ studentId: sid, password: pwd, message: 'Approved and student login generated.' });
});

app.post('/api/admin/applications/:id/reject', auth('admin'), (req,res) => {
  const row = db.prepare('SELECT id FROM applications WHERE id = ?').get(Number(req.params.id));
  if (!row) return res.status(404).json({ error: 'Application not found' });
  db.prepare(`UPDATE applications SET status='rejected', reviewed_at=CURRENT_TIMESTAMP WHERE id=?`).run(row.id);
  res.json({ message: 'Application rejected.' });
});

app.post('/api/admin/applications/:id/payment-verified', auth('admin'), (req,res) => {
  const row = db.prepare('SELECT id FROM applications WHERE id = ?').get(Number(req.params.id));
  if (!row) return res.status(404).json({ error: 'Application not found' });
  db.prepare(`UPDATE applications SET payment_status='verified' WHERE id=?`).run(row.id);
  res.json({ message: 'Payment marked verified.' });
});

app.get('/api/student/me', auth('student'), (req,res) => {
  const row = db.prepare(`SELECT application_no, full_name, phone, email, dob, address, course, payment_txn, payment_status, status, student_id, created_at FROM applications WHERE id=?`).get(req.user.applicationId);
  if (!row) return res.status(404).json({ error: 'Student not found' });
  res.json(row);
});

app.post('/api/student/change-password', auth('student'), (req,res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!newPassword || String(newPassword).length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters.' });
  const row = db.prepare('SELECT * FROM applications WHERE id=?').get(req.user.applicationId);
  if (!row || !bcrypt.compareSync(String(currentPassword || ''), row.password_hash)) return res.status(401).json({ error: 'Current password is incorrect.' });
  db.prepare('UPDATE applications SET password_hash=?, plain_password_once=NULL WHERE id=?').run(bcrypt.hashSync(String(newPassword),12), row.id);
  res.json({ message: 'Password changed.' });
});

app.get('*', (req,res) => res.sendFile(path.join(__dirname,'public','index.html')));

app.listen(PORT, () => console.log(`${CENTER_NAME} portal running on http://localhost:${PORT}`));
