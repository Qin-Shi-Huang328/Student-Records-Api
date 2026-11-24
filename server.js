require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const { Pool } = require('pg');
const buildAuthRouter = require('./auth');
const { requireRoles, requireSelfOrRoles, actorName } = require('./access');

const app = express();
app.use(cors());
app.use(express.json({ limit: '100kb' }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

const VALID_STATUSES = ['enrolled', 'not-enrolled', 'irregular'];
const TRACKED_FIELDS = ['full_name', 'contact_number', 'email', 'address', 'year_level', 'section', 'enrollment_status'];
const PROFILE_COLUMNS = 'student_id, full_name, contact_number, email, address, year_level, section, enrollment_status';
const IT_COLUMNS = 'student_id, full_name';   // IT sees name and ID only
const EMPLOYEE_ROLES = ['admin', 'records', 'it'];

function serverError(res, where, err) {
  console.error(`[${where}]`, err);
  return res.status(500).json({ error: 'Server error. Check the server log for details.' });
}

const blankToNull = v => (v === undefined || v === null || String(v).trim() === '' ? null : String(v).trim());
const toGrade = v => (v === undefined || v === null || v === '' ? null : Number(v));
const hasOwn = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);

function validateStudent(data, isUpdate) {
  const errors = [];
  if (!isUpdate && !blankToNull(data.student_id)) errors.push('student_id is required');
  if (!blankToNull(data.full_name)) errors.push('full_name is required');
  if (data.year_level !== undefined && data.year_level !== null && data.year_level !== '') {
    const yl = Number(data.year_level);
    if (!Number.isInteger(yl) || yl < 1 || yl > 6) errors.push('year_level must be a whole number between 1 and 6');
  }
  if (data.enrollment_status && !VALID_STATUSES.includes(data.enrollment_status)) {
    errors.push(`enrollment_status must be one of: ${VALID_STATUSES.join(', ')}`);
  }
  const email = blankToNull(data.email);
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) errors.push('email format is invalid');
  return errors;
}

// Writes one audit row per changed field. The actor is the signed-in user, never a typed header.
async function logChange(studentId, field, oldValue, newValue, actor) {
  await pool.query(
    `INSERT INTO audit_log (student_id, field_changed, old_value, new_value, changed_by)
     VALUES ($1, $2, $3, $4, $5)`,
    [studentId, field, oldValue, newValue, actor]
  );
}

// Which columns the caller may see on a student record.
function profileColumnsFor(caller) {
  return caller && caller.type === 'employee' && caller.role === 'it' ? IT_COLUMNS : PROFILE_COLUMNS;
}

app.use('/api/auth', buildAuthRouter(pool));

app.get('/', (req, res) => {
  res.json({ message: 'Student Records API is running', version: 'step2' });
});

app.get('/registrar', (req, res) => {
  res.sendFile(path.join(__dirname, 'registrar-ui.html'));
});

app.get('/api/db-check', async (req, res) => {
  try {
    await pool.query('SELECT NOW()');
    res.json({ connected: true });
  } catch (err) {
    console.error('[db-check]', err);
    res.status(503).json({ connected: false, error: 'Database unavailable' });
  }
});

// List or search. Records and admin see full rows; IT sees names and IDs only.
app.get('/api/students', requireRoles('admin', 'records', 'it'), async (req, res) => {
  const search = blankToNull(req.query.search);
  const cols = req.caller.type === 'employee' && req.caller.role === 'it'
    ? IT_COLUMNS : 'student_id, full_name, year_level, section, enrollment_status';
  try {
    const result = search
      ? await pool.query(
          `SELECT ${cols} FROM students WHERE full_name ILIKE $1 OR student_id ILIKE $1 ORDER BY full_name`,
          [`%${search}%`])
      : await pool.query(`SELECT ${cols} FROM students ORDER BY full_name`);
    res.json(result.rows);
  } catch (err) {
    return serverError(res, 'list students', err);
  }
});

app.post('/api/students', requireRoles('admin', 'records'), async (req, res) => {
  const body = req.body || {};
  const errors = validateStudent(body, false);
  if (errors.length) return res.status(400).json({ error: errors.join('; ') });
  try {
    const result = await pool.query(
      `INSERT INTO students (student_id, full_name, contact_number, email, address, year_level, section, enrollment_status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING ${PROFILE_COLUMNS}`,
      [blankToNull(body.student_id), blankToNull(body.full_name), blankToNull(body.contact_number),
        blankToNull(body.email), blankToNull(body.address), blankToNull(body.year_level),
        blankToNull(body.section), body.enrollment_status || 'not-enrolled']
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Student ID already exists' });
    return serverError(res, 'create student', err);
  }
});

// Student: own record. Records and admin: any. IT: name and ID only.
app.get('/api/students/:id/profile', requireSelfOrRoles('id', 'admin', 'records', 'it'), async (req, res) => {
  try {
    const cols = profileColumnsFor(req.caller);
    const result = await pool.query(`SELECT ${cols} FROM students WHERE student_id = $1`, [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Student not found' });
    res.json(result.rows[0]);
  } catch (err) {
    return serverError(res, 'get profile', err);
  }
});

// Regular fields are edited directly by records staff and admin. Fields not sent keep their value.
app.put('/api/students/:id', requireRoles('admin', 'records'), async (req, res) => {
  const body = req.body || {};
  const actor = actorName(req);
  try {
    const existing = await pool.query(`SELECT ${TRACKED_FIELDS.join(', ')} FROM students WHERE student_id = $1`, [req.params.id]);
    if (!existing.rows.length) return res.status(404).json({ error: 'Student not found' });
    const before = existing.rows[0];

    const merged = {};
    for (const f of TRACKED_FIELDS) merged[f] = hasOwn(body, f) ? body[f] : before[f];

    const errors = validateStudent(merged, true);
    if (errors.length) return res.status(400).json({ error: errors.join('; ') });

    const updated = await pool.query(
      `UPDATE students SET full_name = $1, contact_number = $2, email = $3, address = $4,
              year_level = $5, section = $6, enrollment_status = $7, updated_at = NOW()
       WHERE student_id = $8 RETURNING ${PROFILE_COLUMNS}`,
      [blankToNull(merged.full_name), blankToNull(merged.contact_number), blankToNull(merged.email),
        blankToNull(merged.address), blankToNull(merged.year_level), blankToNull(merged.section),
        merged.enrollment_status || 'not-enrolled', req.params.id]
    );
    const after = updated.rows[0];

    for (const f of TRACKED_FIELDS) {
      const oldVal = before[f] == null ? '' : String(before[f]);
      const newVal = after[f] == null ? '' : String(after[f]);
      if (oldVal !== newVal) await logChange(req.params.id, f, oldVal, newVal, actor);
    }
    res.json(after);
  } catch (err) {
    return serverError(res, 'update student', err);
  }
});

// Audit history: admin and IT. Students and records staff cannot view it.
app.get('/api/students/:id/history', requireRoles('admin', 'it'), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT log_id, field_changed, old_value, new_value, changed_by, changed_at
       FROM audit_log WHERE student_id = $1 ORDER BY changed_at DESC`,
      [req.params.id]
    );
    res.json(result.rows);
  } catch (err) {
    return serverError(res, 'history', err);
  }
});

// Deleting a student is admin only. Audit history is kept.
app.delete('/api/students/:id', requireRoles('admin'), async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM students WHERE student_id = $1 RETURNING student_id', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Student not found' });
    await logChange(req.params.id, 'record', 'exists', 'deleted', actorName(req));
    res.json({ deleted: true, student_id: result.rows[0].student_id });
  } catch (err) {
    return serverError(res, 'delete student', err);
  }
});

// Used by Finance (service key) and records staff.
app.get('/api/students/:id/verify', requireRoles('admin', 'records'), async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT student_id, full_name, enrollment_status, year_level, section FROM students WHERE student_id = $1',
      [req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Student not found' });
    res.json(result.rows[0]);
  } catch (err) {
    return serverError(res, 'verify', err);
  }
});

app.get('/api/students/:id/enrollment-status', requireSelfOrRoles('id', 'admin', 'records'), async (req, res) => {
  try {
    const result = await pool.query('SELECT enrollment_status FROM students WHERE student_id = $1', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Student not found' });
    res.json({ status: result.rows[0].enrollment_status });
  } catch (err) {
    return serverError(res, 'enrollment status', err);
  }
});

// Students read their own grades. Records and admin read any.
app.get('/api/students/:id/grades', requireSelfOrRoles('id', 'admin', 'records'), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT grade_id, subject_code, subject_name, school_year, semester, grade, remarks
       FROM grades WHERE student_id = $1 ORDER BY school_year, semester, subject_code`,
      [req.params.id]
    );
    res.json(result.rows);
  } catch (err) {
    return serverError(res, 'list grades', err);
  }
});

// Records staff enter grades during encoding. Every entry is logged.
app.post('/api/students/:id/grades', requireRoles('admin', 'records'), async (req, res) => {
  const body = req.body || {};
  if (!blankToNull(body.subject_code) || !blankToNull(body.subject_name)) {
    return res.status(400).json({ error: 'subject_code and subject_name are required' });
  }
  const grade = toGrade(body.grade);
  if (grade !== null && (Number.isNaN(grade) || grade < 0 || grade > 100)) {
    return res.status(400).json({ error: 'grade must be a number between 0 and 100' });
  }
  try {
    const result = await pool.query(
      `INSERT INTO grades (student_id, subject_code, subject_name, school_year, semester, grade, remarks)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [req.params.id, blankToNull(body.subject_code), blankToNull(body.subject_name),
        blankToNull(body.school_year), blankToNull(body.semester), grade, blankToNull(body.remarks)]
    );
    const row = result.rows[0];
    await logChange(req.params.id, `grade added: ${row.subject_code}`, '', String(row.grade ?? ''), actorName(req));
    res.status(201).json(row);
  } catch (err) {
    if (err.code === '23503') return res.status(404).json({ error: 'Student not found' });
    return serverError(res, 'add grade', err);
  }
});

app.put('/api/grades/:gradeId', requireRoles('admin', 'records'), async (req, res) => {
  if (!/^\d+$/.test(req.params.gradeId)) return res.status(400).json({ error: 'Invalid grade ID' });
  const body = req.body || {};
  try {
    const existing = await pool.query(
      'SELECT student_id, subject_code, grade, remarks FROM grades WHERE grade_id = $1', [req.params.gradeId]);
    if (!existing.rows.length) return res.status(404).json({ error: 'Grade entry not found' });
    const current = existing.rows[0];

    const grade = hasOwn(body, 'grade') ? toGrade(body.grade) : current.grade;
    if (grade !== null && (Number.isNaN(Number(grade)) || Number(grade) < 0 || Number(grade) > 100)) {
      return res.status(400).json({ error: 'grade must be a number between 0 and 100' });
    }
    const remarks = hasOwn(body, 'remarks') ? blankToNull(body.remarks) : current.remarks;

    const result = await pool.query(
      'UPDATE grades SET grade = $1, remarks = $2 WHERE grade_id = $3 RETURNING *',
      [grade, remarks, req.params.gradeId]
    );
    const oldVal = current.grade == null ? '' : String(current.grade);
    const newVal = result.rows[0].grade == null ? '' : String(result.rows[0].grade);
    if (oldVal !== newVal) {
      await logChange(current.student_id, `grade: ${current.subject_code}`, oldVal, newVal, actorName(req));
    }
    res.json(result.rows[0]);
  } catch (err) {
    return serverError(res, 'update grade', err);
  }
});

// Deleting a grade is admin only.
app.delete('/api/grades/:gradeId', requireRoles('admin'), async (req, res) => {
  if (!/^\d+$/.test(req.params.gradeId)) return res.status(400).json({ error: 'Invalid grade ID' });
  try {
    const result = await pool.query(
      'DELETE FROM grades WHERE grade_id = $1 RETURNING grade_id, student_id, subject_code, grade', [req.params.gradeId]);
    if (!result.rows.length) return res.status(404).json({ error: 'Grade entry not found' });
    const row = result.rows[0];
    await logChange(row.student_id, `grade removed: ${row.subject_code}`, String(row.grade ?? ''), '', actorName(req));
    res.json({ deleted: true, grade_id: row.grade_id });
  } catch (err) {
    return serverError(res, 'delete grade', err);
  }
});

app.post('/api/students/:id/document-request', requireRoles('admin', 'records'), async (req, res) => {
  const documentType = blankToNull((req.body || {}).document_type);
  if (!['COR', 'TOR', 'COE'].includes(documentType)) {
    return res.status(400).json({ error: 'document_type must be COR, TOR, or COE' });
  }
  try {
    const result = await pool.query(
      `INSERT INTO document_requests (student_id, document_type, status)
       VALUES ($1, $2, 'pending') RETURNING *`,
      [req.params.id, documentType]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23503') return res.status(404).json({ error: 'Student not found' });
    return serverError(res, 'document request', err);
  }
});

// Students may check only their own requests.
app.get('/api/document-requests/:requestId/status', requireRoles('admin', 'records', 'student'), async (req, res) => {
  if (!/^\d+$/.test(req.params.requestId)) return res.status(400).json({ error: 'Invalid request ID' });
  try {
    const result = await pool.query(
      'SELECT request_id, student_id, document_type, status, requested_at, released_at FROM document_requests WHERE request_id = $1',
      [req.params.requestId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Request not found' });
    const row = result.rows[0];
    if (req.caller.type === 'student' && req.caller.sid !== row.student_id) {
      return res.status(403).json({ error: 'Your account does not have permission for this action' });
    }
    const { student_id, ...publicRow } = row;
    res.json(publicRow);
  } catch (err) {
    return serverError(res, 'document status', err);
  }
});

// Employees: admin and IT can view. Only admin can add or remove.
app.get('/api/employees', requireRoles('admin', 'it'), async (req, res) => {
  try {
    const result = await pool.query('SELECT employee_id, full_name, role FROM employees ORDER BY full_name');
    res.json(result.rows);
  } catch (err) {
    return serverError(res, 'list employees', err);
  }
});

app.post('/api/employees', requireRoles('admin'), async (req, res) => {
  const body = req.body || {};
  const employeeId = blankToNull(body.employee_id);
  const fullName = blankToNull(body.full_name);
  const role = blankToNull(body.role) || 'records';
  if (!employeeId || !fullName) return res.status(400).json({ error: 'employee_id and full_name are required' });
  if (!EMPLOYEE_ROLES.includes(role)) {
    return res.status(400).json({ error: `role must be one of: ${EMPLOYEE_ROLES.join(', ')}` });
  }
  try {
    const result = await pool.query(
      'INSERT INTO employees (employee_id, full_name, role) VALUES ($1, $2, $3) RETURNING employee_id, full_name, role',
      [employeeId, fullName, role]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Employee ID already exists' });
    return serverError(res, 'create employee', err);
  }
});

app.delete('/api/employees/:id', requireRoles('admin'), async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM employees WHERE employee_id = $1 RETURNING employee_id', [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Employee not found' });
    res.json({ deleted: true, employee_id: result.rows[0].employee_id });
  } catch (err) {
    return serverError(res, 'delete employee', err);
  }
});

app.use((req, res) => res.status(404).json({ error: 'Route not found' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));