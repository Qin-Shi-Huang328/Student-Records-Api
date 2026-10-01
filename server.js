require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const VALID_STATUSES = ['enrolled', 'not-enrolled', 'irregular'];

// Simple shared-key check for any endpoint that writes data.
// Web Portal (and your own registrar UI) must send this header.
function requireApiKey(req, res, next) {
  const key = req.header('x-api-key');
  if (!key || key !== process.env.API_KEY) {
    return res.status(401).json({ error: 'Missing or invalid API key' });
  }
  next();
}

function validateStudentInput(body, isUpdate = false) {
  const errors = [];

  if (!isUpdate && (!body.student_id || !body.student_id.trim())) {
    errors.push('student_id is required');
  }
  if (!body.full_name || !body.full_name.trim()) {
    errors.push('full_name is required');
  }
  if (body.year_level !== null && body.year_level !== undefined && body.year_level !== '') {
    const yl = Number(body.year_level);
    if (isNaN(yl) || yl < 1 || yl > 6) {
      errors.push('year_level must be a number between 1 and 6');
    }
  }
  if (body.enrollment_status && !VALID_STATUSES.includes(body.enrollment_status)) {
    errors.push(`enrollment_status must be one of: ${VALID_STATUSES.join(', ')}`);
  }
  if (body.email && body.email.trim() && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email.trim())) {
    errors.push('email format is invalid');
  }

  return errors;
}

app.get('/', (req, res) => {
  res.json({ message: 'Student Records API is running' });
});

app.get('/api/db-check', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW()');
    res.json({ connected: true, time: result.rows[0].now });
  } catch (err) {
    res.status(500).json({ connected: false, error: err.message });
  }
});

// List / search all students
app.get('/api/students', async (req, res) => {
  const { search } = req.query;
  try {
    let result;
    if (search) {
      result = await pool.query(
        `SELECT student_id, full_name, year_level, section, enrollment_status
         FROM students WHERE full_name ILIKE $1 OR student_id ILIKE $1
         ORDER BY full_name`,
        [`%${search}%`]
      );
    } else {
      result = await pool.query(
        `SELECT student_id, full_name, year_level, section, enrollment_status
         FROM students ORDER BY full_name`
      );
    }
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Create a new student — Web Portal uses this for registration (generates student_id itself)
app.post('/api/students', requireApiKey, async (req, res) => {
  const errors = validateStudentInput(req.body);
  if (errors.length > 0) {
    return res.status(400).json({ error: errors.join('; ') });
  }

  const { student_id, full_name, contact_number, email, address, year_level, section, enrollment_status } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO students (student_id, full_name, contact_number, email, address, year_level, section, enrollment_status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
      [student_id, full_name, contact_number, email, address, year_level, section, enrollment_status]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get a student's profile
app.get('/api/students/:id/profile', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT student_id, full_name, contact_number, email, address, year_level, section, enrollment_status FROM students WHERE student_id = $1',
      [req.params.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Student not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update a student's record
app.put('/api/students/:id', requireApiKey, async (req, res) => {
  const errors = validateStudentInput(req.body, true);
  if (errors.length > 0) {
    return res.status(400).json({ error: errors.join('; ') });
  }

  const { full_name, contact_number, email, address, year_level, section, enrollment_status } = req.body;
  try {
    const result = await pool.query(
      `UPDATE students
       SET full_name = $1, contact_number = $2, email = $3, address = $4,
           year_level = $5, section = $6, enrollment_status = $7, updated_at = NOW()
       WHERE student_id = $8 RETURNING *`,
      [full_name, contact_number, email, address, year_level, section, enrollment_status, req.params.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Student not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete a student's record
app.delete('/api/students/:id', requireApiKey, async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM students WHERE student_id = $1 RETURNING student_id',
      [req.params.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Student not found' });
    }
    res.json({ deleted: true, student_id: result.rows[0].student_id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Verify a student (used by Finance)
app.get('/api/students/:id/verify', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT student_id, full_name, enrollment_status, year_level, section FROM students WHERE student_id = $1',
      [req.params.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Student not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Fast enrollment status lookup
app.get('/api/students/:id/enrollment-status', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT enrollment_status FROM students WHERE student_id = $1',
      [req.params.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Student not found' });
    }
    res.json({ status: result.rows[0].enrollment_status });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get a student's grades
app.get('/api/students/:id/grades', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT grade_id, subject_code, subject_name, school_year, semester, grade, remarks FROM grades WHERE student_id = $1',
      [req.params.id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Add a grade for a student
app.post('/api/students/:id/grades', requireApiKey, async (req, res) => {
  const { subject_code, subject_name, school_year, semester, grade, remarks } = req.body;

  if (!subject_code || !subject_name) {
    return res.status(400).json({ error: 'subject_code and subject_name are required' });
  }
  if (grade !== null && grade !== undefined && grade !== '') {
    const g = Number(grade);
    if (isNaN(g) || g < 0 || g > 100) {
      return res.status(400).json({ error: 'grade must be a number between 0 and 100' });
    }
  }

  try {
    const result = await pool.query(
      `INSERT INTO grades (student_id, subject_code, subject_name, school_year, semester, grade, remarks)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [req.params.id, subject_code, subject_name, school_year, semester, grade || null, remarks || null]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update a specific grade entry
app.put('/api/grades/:gradeId', requireApiKey, async (req, res) => {
  const { grade, remarks } = req.body;
  if (grade !== null && grade !== undefined && grade !== '') {
    const g = Number(grade);
    if (isNaN(g) || g < 0 || g > 100) {
      return res.status(400).json({ error: 'grade must be a number between 0 and 100' });
    }
  }
  try {
    const result = await pool.query(
      `UPDATE grades SET grade = $1, remarks = $2 WHERE grade_id = $3 RETURNING *`,
      [grade || null, remarks || null, req.params.gradeId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Grade entry not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete a specific grade entry
app.delete('/api/grades/:gradeId', requireApiKey, async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM grades WHERE grade_id = $1 RETURNING grade_id',
      [req.params.gradeId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Grade entry not found' });
    }
    res.json({ deleted: true, grade_id: result.rows[0].grade_id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Request a document (COR, TOR, COE)
app.post('/api/students/:id/document-request', requireApiKey, async (req, res) => {
  const { document_type } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO document_requests (student_id, document_type, status)
       VALUES ($1, $2, 'pending') RETURNING *`,
      [req.params.id, document_type]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Check a document request's status
app.get('/api/document-requests/:requestId/status', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT request_id, document_type, status, requested_at, released_at FROM document_requests WHERE request_id = $1',
      [req.params.requestId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Request not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));