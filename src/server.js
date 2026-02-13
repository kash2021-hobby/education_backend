require('dotenv').config();

const express = require('express');
const morgan = require('morgan');
const cors = require('cors');
const mysql = require('mysql2/promise');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();

app.use(cors());
app.use(express.json());
app.use(morgan('dev'));

function sanitizePhone(phone) {
  if (!phone) return null;
  return String(phone).replace(/\D/g, '');
}

// Simple MySQL pool using explicit DB_* env vars
let pool;
try {
  if (!process.env.DB_HOST) {
    // eslint-disable-next-line no-console
    console.warn('DB_* env vars are not set. DB access will fail until they are configured.');
  } else {
    pool = mysql.createPool({
      host: process.env.DB_HOST,
      port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 3306,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
    });
  }
} catch (e) {
  // eslint-disable-next-line no-console
  console.error('Failed to initialize MySQL pool from DB_* env vars', e);
}

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    message: 'Backend is up (Express)',
  });
});

// Temporary root route
app.get('/', (req, res) => {
  res.send('Education backend (Express) is running');
});

// =========================
// Auth – login (JWT)
// =========================

app.post('/api/v1/auth/login', async (req, res) => {
  if (!pool) {
    return res
      .status(500)
      .json({ error: 'Database pool not initialized. Check DB_* env vars.' });
  }

  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }

  try {
    const [rows] = await pool.query(
      `
      SELECT id, full_name, email, password_hash, role, is_active
      FROM users
      WHERE email = ?
      LIMIT 1
      `,
      [String(email).toLowerCase().trim()],
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = rows[0];
    if (!user.is_active) {
      return res.status(403).json({ error: 'User is inactive' });
    }

    const passwordOk = await bcrypt.compare(password, user.password_hash);
    if (!passwordOk) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const payload = {
      userId: user.id,
      email: user.email,
      role: user.role,
      fullName: user.full_name,
    };

    const secret = process.env.JWT_SECRET || 'dev-secret-change-me';
    const token = jwt.sign(payload, secret, { expiresIn: '8h' });

    return res.json({
      token,
      user: {
        id: user.id,
        full_name: user.full_name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Login failed', err);
    return res.status(500).json({ error: 'Failed to login' });
  }
});

// Simple public registration endpoint
app.post('/api/v1/auth/register', async (req, res) => {
  if (!pool) {
    return res
      .status(500)
      .json({ error: 'Database pool not initialized. Check DB_* env vars.' });
  }

  const { full_name, email, password, role } = req.body || {};

  if (!full_name || !email || !password) {
    return res.status(400).json({ error: 'full_name, email, and password are required' });
  }

  const allowedRoles = ['SUPER_ADMIN', 'COUNSELOR', 'VIEWER'];
  const safeRole = allowedRoles.includes(role) ? role : 'COUNSELOR';

  try {
    const hashed = await bcrypt.hash(password, 10);
    const id = crypto.randomUUID();

    await pool.query(
      `
      INSERT INTO users
        (id, full_name, email, password_hash, role, is_active, assignment_available, last_lead_assigned_at)
      VALUES (?, ?, ?, ?, ?, 1, 1, NULL)
      `,
      [id, full_name, String(email).toLowerCase().trim(), hashed, safeRole],
    );

    return res.status(201).json({
      id,
      full_name,
      email: String(email).toLowerCase().trim(),
      role: safeRole,
    });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Register failed', err);
    if (err && err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'Email already exists' });
    }
    return res.status(500).json({ error: 'Failed to register' });
  }
});

// =========================
// Auth middleware (protect APIs)
// =========================

const AUTH_PUBLIC_PATHS = [
  '/health',
  '/',
  '/api/v1/auth/login',
  '/api/v1/auth/register',
  '/api/v1/leads/ingest',
  '/api/webhooks/telegram',
];

function isPublicPath(path) {
  return AUTH_PUBLIC_PATHS.some((p) => path === p);
}

function authMiddleware(req, res, next) {
  if (isPublicPath(req.path)) {
    return next();
  }

  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;

  if (!token) {
    // No token – allow request but proceed as anonymous user for now
    req.user = null;
    return next();
  }

  try {
    const secret = process.env.JWT_SECRET || 'dev-secret-change-me';
    const payload = jwt.verify(token, secret);
    req.user = payload;
    return next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

app.use(authMiddleware);

// Lead ingestion endpoint (Module 1: Acquisition Engine) using plain MySQL
app.post('/api/v1/leads/ingest', async (req, res) => {
  if (!pool) {
    return res.status(500).json({
      error: 'Database pool not initialized. Check DATABASE_URL.',
    });
  }

  const payload = req.body || {};

  const rawPhone = payload.phone || payload.phone_number;
  const rawEmail = payload.email;

  const cleanPhone = sanitizePhone(rawPhone);
  const cleanEmail = rawEmail ? String(rawEmail).toLowerCase().trim() : null;

  if (!cleanPhone && !cleanEmail) {
    return res.status(400).json({
      error: 'Either phone or email is required',
    });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // 1. Find existing lead by email/phone
    let existingLead = null;
    const whereParts = [];
    const params = [];

    if (cleanEmail) {
      whereParts.push('email = ?');
      params.push(cleanEmail);
    }
    if (cleanPhone) {
      whereParts.push('phone_number = ?');
      params.push(cleanPhone);
    }

    if (whereParts.length > 0) {
      const [rows] = await conn.query(
        `SELECT * FROM leads WHERE ${whereParts.join(' OR ')} LIMIT 1`,
        params,
      );
      if (rows.length > 0) {
        existingLead = rows[0];
      }
    }

    if (existingLead) {
      // Duplicate logic
      if (existingLead.status === 'LOST' || existingLead.status === 'REJECTED') {
        // Reactivation: set status NEW, retry_count 0
        await conn.query(
          'UPDATE leads SET status = ?, retry_count = 0, updated_at = NOW() WHERE id = ?',
          ['NEW', existingLead.id],
        );

        const activityId = crypto.randomUUID();
        await conn.query(
          'INSERT INTO lead_activities (id, lead_id, actor_id, activity_type, description, metadata, created_at) VALUES (?, ?, NULL, ?, ?, NULL, NOW())',
          [
            activityId,
            existingLead.id,
            'SYSTEM_LOG',
            'Lead Reactivated via new enquiry',
          ],
        );

        await conn.commit();
        return res.status(200).json({
          status: 200,
          message: 'Lead Reactivated',
          id: existingLead.id,
        });
      }

      // Non-lost/rejected duplicate
      const activityId = crypto.randomUUID();
      await conn.query(
        'INSERT INTO lead_activities (id, lead_id, actor_id, activity_type, description, metadata, created_at) VALUES (?, ?, NULL, ?, ?, NULL, NOW())',
        [
          activityId,
          existingLead.id,
          'SYSTEM_LOG',
          'Duplicate Enquiry Received',
        ],
      );

      await conn.commit();
      return res.status(200).json({
        status: 200,
        message: 'Lead already exists. Notified counselor.',
        id: existingLead.id,
      });
    }

    // 2. Round-robin counselor selection
    const [assignees] = await conn.query(
      `SELECT * FROM users
       WHERE role = 'COUNSELOR' AND assignment_available = 1
       ORDER BY (last_lead_assigned_at IS NULL) DESC, last_lead_assigned_at ASC
       LIMIT 1`,
    );
    const assignee = assignees.length > 0 ? assignees[0] : null;

    // 3. Create new lead
    const leadId = crypto.randomUUID();
    const fullName = payload.name || payload.full_name || 'Unknown';
    const courseInterest = payload.course || payload.course_interest || null;
    const source = payload.source || 'WEBSITE';

    await conn.query(
      `INSERT INTO leads
        (id, full_name, email, phone_country_code, phone_number, course_interest,
         source, status, retry_count, assigned_to, created_at, updated_at)
       VALUES (?, ?, ?, '+91', ?, ?, ?, 'NEW', 0, ?, NOW(), NOW())`,
      [
        leadId,
        fullName,
        cleanEmail,
        cleanPhone,
        courseInterest,
        source,
        assignee ? assignee.id : null,
      ],
    );

    // 4. Update counselor stats
    if (assignee) {
      await conn.query(
        'UPDATE users SET last_lead_assigned_at = NOW() WHERE id = ?',
        [assignee.id],
      );
      // TODO: emit async notification
    } else {
      // TODO: queue admin alert for unassigned leads
    }

    await conn.commit();
    return res.status(201).json({
      status: 201,
      id: leadId,
    });
  } catch (err) {
    await conn.rollback();
    // eslint-disable-next-line no-console
    console.error('Lead ingestion failed', err);
    return res.status(500).json({
      error: 'Lead Ingestion Failed',
    });
  } finally {
    conn.release();
  }
});

// List leads with basic filters & pagination
app.get('/api/v1/leads', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database pool not initialized. Check DB_* env vars.' });
  }

  const { status, assignedTo, page = 1, pageSize = 20 } = req.query;
  const limit = Number(pageSize) > 0 ? Number(pageSize) : 20;
  const offset = (Number(page) > 1 ? Number(page) - 1 : 0) * limit;

  const whereParts = [];
  const params = [];

  if (status) {
    whereParts.push('l.status = ?');
    params.push(status);
  }
  if (assignedTo) {
    whereParts.push('l.assigned_to = ?');
    params.push(assignedTo);
  }

  const whereClause = whereParts.length ? `WHERE ${whereParts.join(' AND ')}` : '';

  try {
    const [[countRow]] = await pool.query(
      `SELECT COUNT(*) AS total FROM leads l ${whereClause}`,
      params,
    );
    const total = Number(countRow?.total ?? 0);

    const [rows] = await pool.query(
      `
      SELECT
        l.id,
        l.full_name,
        l.email,
        l.phone_number,
        l.status,
        l.source,
        l.created_at,
        l.assigned_to,
        u.full_name AS counselor_name
      FROM leads l
      LEFT JOIN users u ON l.assigned_to = u.id
      ${whereClause}
      ORDER BY l.created_at DESC
      LIMIT ? OFFSET ?
      `,
      [...params, limit, offset],
    );

    return res.json({ data: rows, page: Number(page), pageSize: limit, total });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('List leads failed', err);
    return res.status(500).json({ error: 'Failed to list leads' });
  }
});

// Lead detail with activities (timeline)
app.get('/api/v1/leads/:id', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database pool not initialized. Check DB_* env vars.' });
  }

  const { id } = req.params;

  try {
    const [leadRows] = await pool.query(
      `
      SELECT
        l.*,
        u.full_name AS counselor_name
      FROM leads l
      LEFT JOIN users u ON l.assigned_to = u.id
      WHERE l.id = ?
      LIMIT 1
      `,
      [id],
    );

    if (leadRows.length === 0) {
      return res.status(404).json({ error: 'Lead not found' });
    }

    const lead = leadRows[0];

    const [activityRows] = await pool.query(
      `
      SELECT
        a.id,
        a.activity_type,
        a.description,
        a.metadata,
        a.created_at,
        au.full_name AS actor_name
      FROM lead_activities a
      LEFT JOIN users au ON a.actor_id = au.id
      WHERE a.lead_id = ?
      ORDER BY a.created_at DESC
      LIMIT 100
      `,
      [id],
    );

    return res.json({ lead, activities: activityRows });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Get lead detail failed', err);
    return res.status(500).json({ error: 'Failed to fetch lead detail' });
  }
});

// Create a lead activity (note / call log / status change)
app.post('/api/v1/leads/:id/activities', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database pool not initialized. Check DB_* env vars.' });
  }

  const { id } = req.params;
  const { type, description, actorId, metadata } = req.body || {};

  const allowedTypes = ['NOTE', 'STATUS_CHANGE', 'CALL_LOG', 'SYSTEM_LOG'];
  if (!type || !allowedTypes.includes(type)) {
    return res.status(400).json({ error: 'Invalid or missing activity type' });
  }

  try {
    // Ensure lead exists
    const [leadRows] = await pool.query('SELECT id FROM leads WHERE id = ? LIMIT 1', [id]);
    if (leadRows.length === 0) {
      return res.status(404).json({ error: 'Lead not found' });
    }

    const activityId = crypto.randomUUID();
    const metadataJson = metadata ? JSON.stringify(metadata) : null;

    await pool.query(
      `
      INSERT INTO lead_activities
        (id, lead_id, actor_id, activity_type, description, metadata, created_at)
      VALUES (?, ?, ?, ?, ?, ?, NOW())
      `,
      [activityId, id, actorId || null, type, description || null, metadataJson],
    );

    return res.status(201).json({
      id: activityId,
      lead_id: id,
      actor_id: actorId || null,
      activity_type: type,
      description: description || null,
      metadata: metadata || null,
    });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Create lead activity failed', err);
    return res.status(500).json({ error: 'Failed to create activity' });
  }
});

// Update lead status with basic transition validation
app.patch('/api/v1/leads/:id/status', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database pool not initialized. Check DB_* env vars.' });
  }

  const { id } = req.params;
  const { status } = req.body || {};
  const actorId = req.headers['x-actor-id'] || null;

  const allowedStatuses = [
    'NEW',
    'CONTACTED',
    'INTERESTED',
    'COLD',
    'REJECTED',
    'LOST',
    'CONVERTED',
  ];

  if (!status || !allowedStatuses.includes(status)) {
    return res.status(400).json({ error: 'Invalid or missing status' });
  }

  try {
    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      const [rows] = await conn.query('SELECT status FROM leads WHERE id = ? LIMIT 1', [id]);
      if (rows.length === 0) {
        await conn.rollback();
        conn.release();
        return res.status(404).json({ error: 'Lead not found' });
      }

      const currentStatus = rows[0].status;

      // Simple invalid transition rule from LLD: prevent NEW -> CONVERTED directly
      if (currentStatus === 'NEW' && status === 'CONVERTED') {
        await conn.rollback();
        conn.release();
        return res
          .status(422)
          .json({ error: 'Invalid state transition NEW -> CONVERTED without intermediate steps' });
      }

      if (currentStatus === status) {
        await conn.rollback();
        conn.release();
        return res.status(200).json({ status: currentStatus, message: 'Status unchanged' });
      }

      await conn.query('UPDATE leads SET status = ?, updated_at = NOW() WHERE id = ?', [
        status,
        id,
      ]);

      const activityId = crypto.randomUUID();
      const metadata = JSON.stringify({ old_status: currentStatus, new_status: status });

      await conn.query(
        `
        INSERT INTO lead_activities
          (id, lead_id, actor_id, activity_type, description, metadata, created_at)
        VALUES (?, ?, ?, 'STATUS_CHANGE', ?, ?, NOW())
        `,
        [
          activityId,
          id,
          actorId || null,
          `Status changed from ${currentStatus} to ${status}`,
          metadata,
        ],
      );

      await conn.commit();
      conn.release();

      return res.status(200).json({ status, message: 'Status updated' });
    } catch (err) {
      await pool.query('ROLLBACK');
      conn.release();
      // eslint-disable-next-line no-console
      console.error('Update lead status failed', err);
      return res.status(500).json({ error: 'Failed to update lead status' });
    }
  } catch (errOuter) {
    // eslint-disable-next-line no-console
    console.error('Update lead status outer error', errOuter);
    return res.status(500).json({ error: 'Failed to update lead status' });
  }
});

// List users (for teacher/counselor dropdowns)
app.get('/api/v1/users', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database pool not initialized. Check DB_* env vars.' });
  }

  try {
    const [rows] = await pool.query(
      'SELECT id, full_name, email, role FROM users WHERE is_active = 1 ORDER BY full_name',
    );
    return res.json({ data: rows });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('List users failed', err);
    return res.status(500).json({ error: 'Failed to list users' });
  }
});

// Toggle counselor assignment availability
app.patch('/api/v1/users/:id/assignment', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database pool not initialized. Check DB_* env vars.' });
  }

  const { id } = req.params;
  const { assignment_available } = req.body || {};

  if (typeof assignment_available !== 'boolean') {
    return res.status(400).json({ error: 'assignment_available must be a boolean' });
  }

  try {
    const [result] = await pool.query(
      'UPDATE users SET assignment_available = ? WHERE id = ?',
      [assignment_available ? 1 : 0, id],
    );

    // result.affectedRows is available on mysql2 for UPDATE
    if (!result.affectedRows) {
      return res.status(404).json({ error: 'User not found' });
    }

    return res.status(200).json({
      id,
      assignment_available,
    });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Update user assignment availability failed', err);
    return res.status(500).json({ error: 'Failed to update assignment availability' });
  }
});

// Helper: generate enrollment number YYYY-COURSECODE-SEQ
async function generateEnrollmentNumber(conn, courseCode) {
  const year = new Date().getFullYear();
  const prefix = `${year}-${courseCode}-`;

  const [rows] = await conn.query(
    `
    SELECT enrollment_number
    FROM students
    WHERE enrollment_number LIKE ?
    ORDER BY enrollment_number DESC
    LIMIT 1
    `,
    [`${prefix}%`],
  );

  if (rows.length === 0) {
    return `${prefix}001`;
  }

  const last = rows[0].enrollment_number;
  const parts = last.split('-');
  const lastSeqStr = parts[parts.length - 1];
  const lastSeq = parseInt(lastSeqStr, 10) || 0;
  const nextSeqStr = String(lastSeq + 1).padStart(3, '0');
  return `${prefix}${nextSeqStr}`;
}

// Enrollment conversion (Module 2: Enrollment Bridge) - simplified without real gateway
app.post('/api/v1/enrollment/convert', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database pool not initialized. Check DB_* env vars.' });
  }

  const { leadId, batchId, payment } = req.body || {};

  if (!leadId || !batchId || !payment) {
    return res.status(400).json({ error: 'leadId, batchId, and payment are required' });
  }

  const { amount, method, transactionRef } = payment;

  if (!amount || !method || !transactionRef) {
    return res
      .status(400)
      .json({ error: 'payment.amount, payment.method, and payment.transactionRef are required' });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // 1. Load batch + course for capacity & code
    const [batchRows] = await conn.query(
      `
      SELECT b.*, c.code AS course_code
      FROM batches b
      JOIN courses c ON b.course_id = c.id
      WHERE b.id = ?
      FOR UPDATE
      `,
      [batchId],
    );

    if (batchRows.length === 0) {
      await conn.rollback();
      conn.release();
      return res.status(404).json({ error: 'Batch not found' });
    }

    const batch = batchRows[0];
    if (batch.current_enrollment >= batch.max_seats) {
      await conn.rollback();
      conn.release();
      return res.status(422).json({ error: 'BATCH_FULL', message: 'This batch is full.' });
    }

    // 2. Ensure lead exists
    const [leadRows] = await conn.query('SELECT * FROM leads WHERE id = ? LIMIT 1', [leadId]);
    if (leadRows.length === 0) {
      await conn.rollback();
      conn.release();
      return res.status(404).json({ error: 'Lead not found' });
    }
    const lead = leadRows[0];

    // 3. Record payment
    const paymentId = crypto.randomUUID();
    await conn.query(
      `
      INSERT INTO payments (id, lead_id, amount, currency, payment_method, transaction_ref, status, invoice_url, created_at)
      VALUES (?, ?, ?, 'USD', ?, ?, 'COMPLETED', NULL, NOW())
      `,
      [paymentId, leadId, amount, method, transactionRef],
    );

    // 4. Determine user_id for student (simplified: NULL or to be linked later)
    // If you have a users-students mapping already, adjust this logic.
    const userId = null;

    // 5. Generate enrollment number
    const enrollmentNumber = await generateEnrollmentNumber(conn, batch.course_code);
    const studentId = crypto.randomUUID();

    await conn.query(
      `
      INSERT INTO students
        (id, user_id, lead_id, batch_id, enrollment_number, enrollment_date, status)
      VALUES (?, ?, ?, ?, ?, NOW(), 'ACTIVE')
      `,
      [studentId, userId, leadId, batchId, enrollmentNumber],
    );

    // 6. Update batch counter & lead status
    await conn.query(
      'UPDATE batches SET current_enrollment = current_enrollment + 1 WHERE id = ?',
      [batchId],
    );

    await conn.query('UPDATE leads SET status = ? WHERE id = ?', ['CONVERTED', leadId]);

    await conn.commit();
    conn.release();

    return res.status(201).json({
      success: true,
      studentId,
      enrollmentNumber,
      paymentId,
    });
  } catch (err) {
    await conn.rollback();
    conn.release();
    // eslint-disable-next-line no-console
    console.error('Enrollment conversion failed', err);
    return res.status(500).json({ error: 'Enrollment conversion failed' });
  }
});

// =========================
// Module 2 – Student & Catalog APIs
// =========================

// List students with optional filters
app.get('/api/v1/students', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database pool not initialized. Check DB_* env vars.' });
  }

  const { batchId, status, page = 1, pageSize = 20 } = req.query;
  const limit = Number(pageSize) > 0 ? Number(pageSize) : 20;
  const offset = (Number(page) > 1 ? Number(page) - 1 : 0) * limit;

  const whereParts = [];
  const params = [];

  if (batchId) {
    whereParts.push('s.batch_id = ?');
    params.push(batchId);
  }
  if (status) {
    whereParts.push('s.status = ?');
    params.push(status);
  }

  const whereClause = whereParts.length ? `WHERE ${whereParts.join(' AND ')}` : '';

  try {
    const [[countRow]] = await pool.query(
      `SELECT COUNT(*) AS total FROM students s JOIN leads l ON s.lead_id = l.id JOIN batches b ON s.batch_id = b.id JOIN courses c ON b.course_id = c.id ${whereClause}`,
      params,
    );
    const total = Number(countRow?.total ?? 0);

    const [rows] = await pool.query(
      `
      SELECT
        s.id,
        s.enrollment_number,
        s.status,
        s.enrollment_date,
        l.full_name AS lead_name,
        l.email,
        l.phone_number,
        b.name AS batch_name,
        c.name AS course_name,
        c.code AS course_code
      FROM students s
      JOIN leads l ON s.lead_id = l.id
      JOIN batches b ON s.batch_id = b.id
      JOIN courses c ON b.course_id = c.id
      ${whereClause}
      ORDER BY s.enrollment_date DESC
      LIMIT ? OFFSET ?
      `,
      [...params, limit, offset],
    );

    return res.json({ data: rows, page: Number(page), pageSize: limit, total });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('List students failed', err);
    return res.status(500).json({ error: 'Failed to list students' });
  }
});

// Student detail with linked lead, batch, course, and payments
app.get('/api/v1/students/:id', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database pool not initialized. Check DB_* env vars.' });
  }

  const { id } = req.params;

  try {
    const [rows] = await pool.query(
      `
      SELECT
        s.*,
        l.full_name AS lead_name,
        l.email AS lead_email,
        l.phone_number AS lead_phone,
        b.name AS batch_name,
        b.start_date,
        c.name AS course_name,
        c.code AS course_code
      FROM students s
      JOIN leads l ON s.lead_id = l.id
      JOIN batches b ON s.batch_id = b.id
      JOIN courses c ON b.course_id = c.id
      WHERE s.id = ?
      LIMIT 1
      `,
      [id],
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Student not found' });
    }

    const student = rows[0];

    const [payments] = await pool.query(
      `
      SELECT *
      FROM payments
      WHERE lead_id = ?
      ORDER BY created_at DESC
      `,
      [student.lead_id],
    );

    return res.json({ student, payments });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Get student detail failed', err);
    return res.status(500).json({ error: 'Failed to fetch student detail' });
  }
});

// List courses
app.get('/api/v1/courses', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database pool not initialized. Check DB_* env vars.' });
  }

  try {
    const [rows] = await pool.query(
      `
      SELECT id, name, code, base_fee, is_active
      FROM courses
      ORDER BY name
      `,
    );
    return res.json({ data: rows });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('List courses failed', err);
    return res.status(500).json({ error: 'Failed to list courses' });
  }
});

// List batches with optional filters
app.get('/api/v1/batches', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database pool not initialized. Check DB_* env vars.' });
  }

  const { courseId, status } = req.query;

  const whereParts = [];
  const params = [];

  if (courseId) {
    whereParts.push('b.course_id = ?');
    params.push(courseId);
  }
  if (status) {
    whereParts.push('b.status = ?');
    params.push(status);
  }

  const whereClause = whereParts.length ? `WHERE ${whereParts.join(' AND ')}` : '';

  try {
    const [rows] = await pool.query(
      `
      SELECT
        b.*,
        c.name AS course_name,
        c.code AS course_code
      FROM batches b
      JOIN courses c ON b.course_id = c.id
      ${whereClause}
      ORDER BY b.start_date DESC
      `,
      params,
    );

    return res.json({ data: rows });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('List batches failed', err);
    return res.status(500).json({ error: 'Failed to list batches' });
  }
});

// Single batch by id
app.get('/api/v1/batches/:id', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database pool not initialized. Check DB_* env vars.' });
  }

  const { id } = req.params;

  try {
    const [rows] = await pool.query(
      `
      SELECT
        b.*,
        c.name AS course_name,
        c.code AS course_code
      FROM batches b
      JOIN courses c ON b.course_id = c.id
      WHERE b.id = ?
      LIMIT 1
      `,
      [id],
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Batch not found' });
    }

    return res.json(rows[0]);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Get batch failed', err);
    return res.status(500).json({ error: 'Failed to fetch batch' });
  }
});

// =========================
// Module 3 – Attendance
// =========================

// Get students for a batch (for attendance)
app.get('/api/v1/batches/:id/students', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database pool not initialized. Check DB_* env vars.' });
  }

  const { id } = req.params;

  try {
    const [rows] = await pool.query(
      `
      SELECT
        s.id AS student_id,
        s.enrollment_number,
        l.full_name,
        l.email,
        l.phone_number
      FROM students s
      JOIN leads l ON s.lead_id = l.id
      WHERE s.batch_id = ?
      ORDER BY l.full_name
      `,
      [id],
    );

    return res.json({ data: rows });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Get batch students failed', err);
    return res.status(500).json({ error: 'Failed to fetch batch students' });
  }
});

// Create attendance session
app.post('/api/v1/attendance/sessions', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database pool not initialized. Check DB_* env vars.' });
  }

  const { batchId, teacherId, date, subject, startTime, endTime } = req.body || {};

  if (!batchId || !teacherId || !date || !subject || !startTime || !endTime) {
    return res.status(400).json({
      error: 'batchId, teacherId, date, subject, startTime, and endTime are required',
    });
  }

  const sessionId = crypto.randomUUID();

  try {
    await pool.query(
      `
      INSERT INTO attendance_sessions
        (id, batch_id, teacher_id, date, subject, start_time, end_time, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, NOW())
      `,
      [sessionId, batchId, teacherId, date, subject, startTime, endTime],
    );

    return res.status(201).json({ id: sessionId });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Create attendance session failed', err);
    return res.status(500).json({ error: 'Failed to create attendance session' });
  }
});

// Bulk mark attendance for a session
app.post('/api/v1/attendance/sessions/:id/records', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database pool not initialized. Check DB_* env vars.' });
  }

  const { id } = req.params;
  const { records } = req.body || {};

  if (!Array.isArray(records) || records.length === 0) {
    return res.status(400).json({ error: 'records array is required' });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    for (const rec of records) {
      const status = rec.status || 'PRESENT';

      await conn.query(
        `
        INSERT INTO attendance_records (id, session_id, student_id, status)
        VALUES (?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE status = VALUES(status)
        `,
        [crypto.randomUUID(), id, rec.studentId, status],
      );
    }

    await conn.commit();
    conn.release();

    return res.status(201).json({ success: true, count: records.length });
  } catch (err) {
    await conn.rollback();
    conn.release();
    // eslint-disable-next-line no-console
    console.error('Bulk attendance mark failed', err);
    return res.status(500).json({ error: 'Failed to mark attendance' });
  }
});

// Student attendance summary
app.get('/api/v1/students/:id/attendance', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database pool not initialized. Check DB_* env vars.' });
  }

  const { id } = req.params;

  try {
    const [summaryRows] = await pool.query(
      `
      SELECT
        COUNT(*) AS total_sessions,
        SUM(CASE WHEN status = 'PRESENT' THEN 1 ELSE 0 END) AS present_sessions
      FROM attendance_records
      WHERE student_id = ?
      `,
      [id],
    );

    const summary = summaryRows[0] || { total_sessions: 0, present_sessions: 0 };
    const total = Number(summary.total_sessions) || 0;
    const present = Number(summary.present_sessions) || 0;
    const percentage = total > 0 ? Math.round((present / total) * 100) : 0;

    const [records] = await pool.query(
      `
      SELECT
        ar.id,
        ar.status,
        s.date,
        s.subject,
        s.start_time,
        s.end_time
      FROM attendance_records ar
      JOIN attendance_sessions s ON ar.session_id = s.id
      WHERE ar.student_id = ?
      ORDER BY s.date DESC, s.start_time DESC
      LIMIT 50
      `,
      [id],
    );

    return res.json({
      total_sessions: total,
      present_sessions: present,
      percentage,
      records,
    });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Get student attendance failed', err);
    return res.status(500).json({ error: 'Failed to fetch attendance' });
  }
});

// =========================
// Module 3 – Exams
// =========================

// Create exam
app.post('/api/v1/exams', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database pool not initialized. Check DB_* env vars.' });
  }

  const { batchId, name, maxMarks, date } = req.body || {};

  if (!batchId || !name || !maxMarks || !date) {
    return res
      .status(400)
      .json({ error: 'batchId, name, maxMarks, and date are required' });
  }

  const examId = crypto.randomUUID();

  try {
    await pool.query(
      `
      INSERT INTO exams (id, batch_id, name, max_marks, date, is_published)
      VALUES (?, ?, ?, ?, ?, 0)
      `,
      [examId, batchId, name, maxMarks, date],
    );

    return res.status(201).json({ id: examId });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Create exam failed', err);
    return res.status(500).json({ error: 'Failed to create exam' });
  }
});

// Bulk upload exam results
app.post('/api/v1/exams/:id/results', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database pool not initialized. Check DB_* env vars.' });
  }

  const { id } = req.params;
  const { results } = req.body || {};

  if (!Array.isArray(results) || results.length === 0) {
    return res.status(400).json({ error: 'results array is required' });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    for (const r of results) {
      await conn.query(
        `
        INSERT INTO exam_results (id, exam_id, student_id, marks_obtained, remarks)
        VALUES (?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE marks_obtained = VALUES(marks_obtained), remarks = VALUES(remarks)
        `,
        [crypto.randomUUID(), id, r.studentId, r.marksObtained, r.remarks || null],
      );
    }

    await conn.commit();
    conn.release();

    return res.status(201).json({ success: true, count: results.length });
  } catch (err) {
    await conn.rollback();
    conn.release();
    // eslint-disable-next-line no-console
    console.error('Bulk exam results failed', err);
    return res.status(500).json({ error: 'Failed to save exam results' });
  }
});

// Get student's recent exam results
app.get('/api/v1/students/:id/exams', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database pool not initialized. Check DB_* env vars.' });
  }

  const { id } = req.params;

  try {
    const [rows] = await pool.query(
      `
      SELECT
        er.id,
        e.name,
        e.date,
        e.max_marks,
        er.marks_obtained,
        er.remarks
      FROM exam_results er
      JOIN exams e ON er.exam_id = e.id
      WHERE er.student_id = ?
      ORDER BY e.date DESC
      LIMIT 20
      `,
      [id],
    );

    return res.json({ data: rows });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Get student exams failed', err);
    return res.status(500).json({ error: 'Failed to fetch exam results' });
  }
});

// =========================
// Module 3 – Telegram Mapping (backend part)
// =========================

// Generate Telegram connect link for a student
app.post('/api/v1/telegram/connect-link', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database pool not initialized. Check DB_* env vars.' });
  }

  const { studentId } = req.body || {};

  if (!studentId) {
    return res.status(400).json({ error: 'studentId is required' });
  }

  const token = crypto.randomBytes(32).toString('hex');

  try {
    // Ensure student exists
    const [sRows] = await pool.query('SELECT id FROM students WHERE id = ? LIMIT 1', [studentId]);
    if (sRows.length === 0) {
      return res.status(404).json({ error: 'Student not found' });
    }

    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Upsert telegram mapping
    await pool.query(
      `
      INSERT INTO telegram_mappings
        (id, student_id, chat_id, username, verification_token, token_expires_at, is_active)
      VALUES (?, ?, NULL, NULL, ?, ?, 1)
      ON DUPLICATE KEY UPDATE
        verification_token = VALUES(verification_token),
        token_expires_at   = VALUES(token_expires_at),
        is_active          = 1
      `,
      [crypto.randomUUID(), studentId, token, expiresAt],
    );

    const botName = process.env.TELEGRAM_BOT_NAME || 'YOUR_BOT_NAME';
    const url = `https://t.me/${botName}?start=${token}`;

    return res.json({ url });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Generate Telegram connect link failed', err);
    return res.status(500).json({ error: 'Failed to generate connect link' });
  }
});

// Telegram webhook stub
app.post('/api/webhooks/telegram', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database pool not initialized. Check DB_* env vars.' });
  }

  const body = req.body || {};
  const message = body.message;

  if (!message || !message.text) {
    return res.sendStatus(200);
  }

  const chatId = message.chat && message.chat.id;
  const text = message.text;

  if (text.startsWith('/start ')) {
    const token = text.split(' ')[1];

    try {
      const [rows] = await pool.query(
        `
        SELECT * FROM telegram_mappings
        WHERE verification_token = ?
        LIMIT 1
        `,
        [token],
      );

      if (rows.length === 0) {
        return res.sendStatus(200);
      }

      const mapping = rows[0];
      const now = new Date();
      if (mapping.token_expires_at && now > mapping.token_expires_at) {
        return res.sendStatus(200);
      }

      await pool.query(
        `
        UPDATE telegram_mappings
        SET chat_id = ?, username = ?, verification_token = NULL, is_active = 1
        WHERE id = ?
        `,
        [chatId, message.from && message.from.username ? message.from.username : null, mapping.id],
      );
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('Telegram webhook failed', err);
      // Still respond 200 to Telegram
    }
  }

  return res.sendStatus(200);
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`Express server listening on port ${PORT}`);
});

