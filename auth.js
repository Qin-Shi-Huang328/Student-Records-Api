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

  function makeToken(studentId) {
    const payload = Buffer.from(JSON.stringify({
      sid: studentId,
      exp: Date.now() + 8 * 60 * 60 * 1000 // 8 hours
    })).toString('base64url');
    const sig = crypto.createHmac('sha256', process.env.AUTH_SECRET).update(payload).digest('base64url');
    return `${payload}.${sig}`;
  }

  // Student login: student_id + password → token
  router.post('/login', async (req, res) => {
    if (!process.env.AUTH_SECRET) return res.status(500).json({ error: 'AUTH_SECRET is not set on the server' });
    const { student_id, password } = req.body || {};
    if (!student_id || !password) return res.status(400).json({ error: 'student_id and password are required' });
    try {
      const r = await pool.query('SELECT student_id, password_hash FROM students WHERE student_id = $1', [student_id.trim()]);
      const row = r.rows[0];
      if (!row || !row.password_hash || !verifyPassword(password, row.password_hash)) {
        return res.status(401).json({ error: 'Incorrect student number or password' });
      }
      res.json({ token: makeToken(row.student_id), student_id: row.student_id });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Registrar / Web Portal sets or resets a student's password (needs API key)
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

  return router;
};