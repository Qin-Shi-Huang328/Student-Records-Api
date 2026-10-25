const crypto = require('crypto');
const express = require('express');
module.exports = function (pool, requireApiKey) {
  const router = express.Router();

  function hashPassword(pw) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(pw, salt, 64).toString('hex');
    return `${salt}:${hash}`;
  }

  function verifyPassword(pw, stored) {
    const [salt, hash] = stored.split(':');
    const test = crypto.scryptSync(pw, salt, 64);
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), test);
  }

  function makeToken(id, type, name) {
    const payload = Buffer.from(JSON.stringify({
      sid: id,
      type: type,
      name: name,
      exp: Date.now() + 8 * 60 * 60 * 1000
    })).toString('base64url');
    const sig = crypto.createHmac('sha256', process.env.AUTH_SECRET).update(payload).digest('base64url');
    return `${payload}.${sig}`;
  }

  // Student login
  router.post('/login', async (req, res) => {
    if (!process.env.AUTH_SECRET) return res.status(500).json({ error: 'AUTH_SECRET is not set on the server' });
    const { student_id, password } = req.body || {};
    if (!student_id || !password) return res.status(400).json({ error: 'student_id and password are required' });
    try {
      const r = await pool.query('SELECT student_id, full_name, password_hash FROM students WHERE student_id = $1', [student_id.trim()]);
      const row = r.rows[0];
      if (!row || !row.password_hash || !verifyPassword(password, row.password_hash)) {
        return res.status(401).json({ error: 'Incorrect student number or password' });
      }
      res.json({ token: makeToken(row.student_id, 'student', row.full_name), student_id: row.student_id, type: 'student' });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Employee login
  router.post('/staff-login', async (req, res) => {
    if (!process.env.AUTH_SECRET) return res.status(500).json({ error: 'AUTH_SECRET is not set on the server' });
    const { employee_id, password } = req.body || {};
    if (!employee_id || !password) return res.status(400).json({ error: 'employee_id and password are required' });
    try {
      const r = await pool.query('SELECT employee_id, full_name, role, password_hash FROM employees WHERE employee_id = $1', [employee_id.trim()]);
      const row = r.rows[0];
      if (!row || !row.password_hash || !verifyPassword(password, row.password_hash)) {
        return res.status(401).json({ error: 'Incorrect employee ID or password' });
      }
      res.json({ token: makeToken(row.employee_id, 'employee', row.full_name), employee_id: row.employee_id, full_name: row.full_name, role: row.role, type: 'employee' });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Set/reset student password (API key)
  router.post('/set-password', requireApiKey, async (req, res) => {
    const { student_id, password } = req.body || {};
    if (!student_id || !password) return res.status(400).json({ error: 'student_id and password are required' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    try {
      const r = await pool.query('UPDATE students SET password_hash = $1 WHERE student_id = $2 RETURNING student_id', [hashPassword(password), student_id.trim()]);
      if (r.rows.length === 0) return res.status(404).json({ error: 'Student not found' });
      res.json({ ok: true, student_id: r.rows[0].student_id });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Set/reset employee password (API key)
  router.post('/set-staff-password', requireApiKey, async (req, res) => {
    const { employee_id, password } = req.body || {};
    if (!employee_id || !password) return res.status(400).json({ error: 'employee_id and password are required' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    try {
      const r = await pool.query('UPDATE employees SET password_hash = $1 WHERE employee_id = $2 RETURNING employee_id', [hashPassword(password), employee_id.trim()]);
      if (r.rows.length === 0) return res.status(404).json({ error: 'Employee not found' });
      res.json({ ok: true, employee_id: r.rows[0].employee_id });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  return router;
};