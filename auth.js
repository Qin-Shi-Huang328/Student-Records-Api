const crypto = require('crypto');
const express = require('express');
const { requireRoles } = require('./access');

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  const test = crypto.scryptSync(password, salt, 64);
  const expected = Buffer.from(hash, 'hex');
  return expected.length === test.length && crypto.timingSafeEqual(expected, test);
}

// Signed token: base64url(payload).base64url(hmac-sha256), valid 8 hours.
function makeToken({ sid, type, name, role }) {
  const payload = Buffer.from(JSON.stringify({
    sid, type, name, role: role || null,
    exp: Date.now() + 8 * 60 * 60 * 1000,
  })).toString('base64url');
  const sig = crypto.createHmac('sha256', process.env.AUTH_SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

// pool is passed in from server.js so this file has no database setup of its own.
module.exports = function buildAuthRouter(pool) {
  const router = express.Router();

  router.post('/login', async (req, res) => {
    if (!process.env.AUTH_SECRET) return res.status(500).json({ error: 'AUTH_SECRET is not set on the server' });
    const { student_id, password } = req.body || {};
    if (!student_id || !password) return res.status(400).json({ error: 'student_id and password are required' });
    try {
      const r = await pool.query(
        'SELECT student_id, full_name, password_hash FROM students WHERE student_id = $1',
        [String(student_id).trim()]
      );
      const row = r.rows[0];
      if (!row || !verifyPassword(password, row.password_hash)) {
        return res.status(401).json({ error: 'Incorrect student number or password' });
      }
      res.json({
        token: makeToken({ sid: row.student_id, type: 'student', name: row.full_name }),
        student_id: row.student_id,
        type: 'student',
      });
    } catch (err) {
      console.error('[student login]', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  router.post('/staff-login', async (req, res) => {
    if (!process.env.AUTH_SECRET) return res.status(500).json({ error: 'AUTH_SECRET is not set on the server' });
    const { employee_id, password } = req.body || {};
    if (!employee_id || !password) return res.status(400).json({ error: 'employee_id and password are required' });
    try {
      const r = await pool.query(
        'SELECT employee_id, full_name, role, password_hash FROM employees WHERE employee_id = $1',
        [String(employee_id).trim()]
      );
      const row = r.rows[0];
      if (!row || !verifyPassword(password, row.password_hash)) {
        return res.status(401).json({ error: 'Incorrect employee ID or password' });
      }
      res.json({
        token: makeToken({ sid: row.employee_id, type: 'employee', name: row.full_name, role: row.role }),
        employee_id: row.employee_id,
        full_name: row.full_name,
        role: row.role,
        type: 'employee',
      });
    } catch (err) {
      console.error('[staff login]', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Admin and IT can reset student passwords. The service key still works for other groups.
  router.post('/set-password', requireRoles('admin', 'it'), async (req, res) => {
    const { student_id, password } = req.body || {};
    if (!student_id || !password) return res.status(400).json({ error: 'student_id and password are required' });
    if (String(password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    try {
      const r = await pool.query(
        'UPDATE students SET password_hash = $1 WHERE student_id = $2 RETURNING student_id',
        [hashPassword(String(password)), String(student_id).trim()]
      );
      if (!r.rows.length) return res.status(404).json({ error: 'Student not found' });
      res.json({ ok: true, student_id: r.rows[0].student_id });
    } catch (err) {
      console.error('[set-password]', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  // Only admin can change employee passwords.
  router.post('/set-staff-password', requireRoles('admin'), async (req, res) => {
    const { employee_id, password } = req.body || {};
    if (!employee_id || !password) return res.status(400).json({ error: 'employee_id and password are required' });
    if (String(password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    try {
      const r = await pool.query(
        'UPDATE employees SET password_hash = $1 WHERE employee_id = $2 RETURNING employee_id',
        [hashPassword(String(password)), String(employee_id).trim()]
      );
      if (!r.rows.length) return res.status(404).json({ error: 'Employee not found' });
      res.json({ ok: true, employee_id: r.rows[0].employee_id });
    } catch (err) {
      console.error('[set-staff-password]', err);
      res.status(500).json({ error: 'Server error' });
    }
  });

  return router;
};