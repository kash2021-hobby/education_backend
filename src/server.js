require('dotenv').config();

const express = require('express');
const morgan = require('morgan');
const cors = require('cors');
const mysql = require('mysql2/promise');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { createMockPool, seedDefaultUser } = require('./memory-db');

const app = express();

app.use(cors());
app.use(express.json());
app.use(morgan('dev'));

function sanitizePhone(phone) {
  if (!phone) return null;
  return String(phone).replace(/\D/g, '');
}

// Use in-memory DB when MySQL is unreachable (set USE_IN_MEMORY_DB=true)
const USE_IN_MEMORY_DB = process.env.USE_IN_MEMORY_DB === 'true' || process.env.USE_IN_MEMORY_DB === '1';

async function initFeeTables(p) {
  try {
    await p.query(`
      CREATE TABLE IF NOT EXISTS fee_schedules (
        id INT AUTO_INCREMENT PRIMARY KEY,
        student_id VARCHAR(36) NOT NULL,
        lead_id VARCHAR(36) NOT NULL,
        total_amount DECIMAL(12,2) NOT NULL,
        plan_type ENUM('FULL','MONTHLY','INSTALLMENT_6') NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX (student_id),
        INDEX (lead_id)
      )
    `);
    await p.query(`
      CREATE TABLE IF NOT EXISTS fee_installments (
        id INT AUTO_INCREMENT PRIMARY KEY,
        schedule_id INT NOT NULL,
        installment_no INT NOT NULL,
        due_date DATE NOT NULL,
        amount_due DECIMAL(12,2) NOT NULL,
        status ENUM('PENDING','PAID') DEFAULT 'PENDING',
        paid_at TIMESTAMP NULL,
        payment_id VARCHAR(36) NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX (schedule_id),
        INDEX (status)
      )
    `);
    console.log('Fee schedule tables ready.');
  } catch (e) {
    console.error('Failed to init fee tables:', e.message);
  }
}

let pool;
if (USE_IN_MEMORY_DB) {
  pool = createMockPool();
  seedDefaultUser().catch((e) => console.error('Failed to seed in-memory DB', e));
  // eslint-disable-next-line no-console
  console.log('Using in-memory database (USE_IN_MEMORY_DB=true). Data is lost on restart.');
} else {
  try {
    if (!process.env.DB_HOST) {
      // eslint-disable-next-line no-console
      console.warn('DB_* env vars are not set. DB access will fail until they are configured.');
    } else {
      pool = mysql.createPool({
        host: process.env.DB_HOST.trim(),
        port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 3306,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME,
        waitForConnections: true,
        connectionLimit: 1,
        queueLimit: 0,
        connectTimeout: 60000,
        enableKeepAlive: true,
        ssl: false,
      });
      pool.query('SELECT 1')
        .then(() => {
          console.log('Database connected successfully.');
          return initFeeTables(pool);
        })
        .catch((e) => console.error('Database connection test failed:', e.code || e.errno, e.message || String(e)));
    }
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error('Failed to initialize MySQL pool from DB_* env vars', e);
  }
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
  const feePlanType = ['FULL', 'MONTHLY', 'INSTALLMENT_6'].includes(payload.feePlanType)
    ? payload.feePlanType
    : 'FULL';
  const totalFeeForSchedule = payload.totalFee != null && Number(payload.totalFee) > 0
    ? Number(payload.totalFee)
    : null;
  const emergencyContactNumber = payload.emergencyContactNumber != null
    ? String(payload.emergencyContactNumber).trim() || null
    : (payload.emergency_contact_number != null ? String(payload.emergency_contact_number).trim() || null : null);

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

    // 2. Counselor: use assigned_to from payload if valid, else round-robin
    let assignee = null;
    const requestedAssigneeId = payload.assigned_to || payload.assignedTo || payload.counselor_id || payload.counselorId;
    if (requestedAssigneeId) {
      const [userRows] = await conn.query(
        `SELECT * FROM users WHERE id = ? AND is_active = 1 LIMIT 1`,
        [requestedAssigneeId],
      );
      if (userRows.length > 0) {
        assignee = userRows[0];
      }
    }
    if (!assignee) {
      const [assignees] = await conn.query(
        `SELECT * FROM users
         WHERE role = 'COUNSELOR' AND assignment_available = 1
         ORDER BY (last_lead_assigned_at IS NULL) DESC, last_lead_assigned_at ASC
         LIMIT 1`,
      );
      assignee = assignees.length > 0 ? assignees[0] : null;
    }

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

// Update lead (e.g. assign counselor)
app.patch('/api/v1/leads/:id', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database pool not initialized. Check DB_* env vars.' });
  }
  const { id } = req.params;
  const { assignedTo } = req.body || {};
  try {
    const [rows] = await pool.query('SELECT id FROM leads WHERE id = ? LIMIT 1', [id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Lead not found' });
    }
    if (assignedTo !== undefined) {
      const assigneeId = assignedTo === '' || assignedTo === null ? null : assignedTo;
      if (assigneeId !== null) {
        const [users] = await pool.query('SELECT id FROM users WHERE id = ? AND is_active = 1 LIMIT 1', [assigneeId]);
        if (users.length === 0) {
          return res.status(400).json({ error: 'Invalid counselor / user not found' });
        }
      }
      await pool.query('UPDATE leads SET assigned_to = ?, updated_at = NOW() WHERE id = ?', [assigneeId, id]);
    }
    const [updated] = await pool.query(
      `SELECT l.*, u.full_name AS counselor_name FROM leads l LEFT JOIN users u ON l.assigned_to = u.id WHERE l.id = ?`,
      [id],
    );
    return res.json(updated[0]);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Update lead failed', err);
    return res.status(500).json({ error: 'Failed to update lead' });
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
// Accepts either batchId (single) or courseIds (array). With courseIds, one batch per course is chosen and one student created per course.
app.post('/api/v1/enrollment/convert', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database pool not initialized. Check DB_* env vars.' });
  }

  const { leadId, batchId, courseIds, payment, batchForCourse } = req.body || {};
  const useCourseIds = Array.isArray(courseIds) && courseIds.length > 0;
  const batchMap = batchForCourse && typeof batchForCourse === 'object' ? batchForCourse : {};

  if (!leadId || !payment) {
    return res.status(400).json({ error: 'leadId and payment are required' });
  }
  if (!useCourseIds && !batchId) {
    return res.status(400).json({ error: 'Either batchId or courseIds (non-empty array) is required' });
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

    // Resolve to list of batches: either [batchId] or one batch per courseId
    let batchesToEnroll = [];
    if (useCourseIds) {
      for (const courseId of courseIds) {
        const preferredBatchId = batchMap[courseId] || batchMap[String(courseId)];
        let batchRows = [];
        if (preferredBatchId) {
          const [rows] = await conn.query(
            `SELECT b.*, c.code AS course_code
             FROM batches b JOIN courses c ON b.course_id = c.id
             WHERE b.id = ? AND b.course_id = ?
             FOR UPDATE`,
            [preferredBatchId, courseId],
          );
          batchRows = rows;
          if (batchRows.length > 0 && batchRows[0].current_enrollment >= batchRows[0].max_seats) {
            await conn.rollback();
            conn.release();
            return res.status(422).json({
              error: 'BATCH_FULL',
              message: `Selected batch for course has no available seats.`,
            });
          }
        }
        if (batchRows.length === 0) {
          const [rows] = await conn.query(
            `
            SELECT b.*, c.code AS course_code
            FROM batches b
            JOIN courses c ON b.course_id = c.id
            WHERE b.course_id = ? AND b.current_enrollment < b.max_seats
            ORDER BY b.start_date ASC
            LIMIT 1
            FOR UPDATE
            `,
            [courseId],
          );
          batchRows = rows;
        }
        if (batchRows.length === 0) {
          await conn.rollback();
          conn.release();
          return res.status(422).json({
            error: 'NO_BATCH',
            message: `No batch with available seats for course ${courseId}.`,
          });
        }
        batchesToEnroll.push(batchRows[0]);
      }
    } else {
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
      if (batchRows[0].current_enrollment >= batchRows[0].max_seats) {
        await conn.rollback();
        conn.release();
        return res.status(422).json({ error: 'BATCH_FULL', message: 'This batch is full.' });
      }
      batchesToEnroll = [batchRows[0]];
    }

    // Ensure lead exists
    const [leadRows] = await conn.query('SELECT * FROM leads WHERE id = ? LIMIT 1', [leadId]);
    if (leadRows.length === 0) {
      await conn.rollback();
      conn.release();
      return res.status(404).json({ error: 'Lead not found' });
    }

    // One payment for the conversion
    const paymentId = crypto.randomUUID();
    await conn.query(
      `
      INSERT INTO payments (id, lead_id, amount, currency, payment_method, transaction_ref, status, invoice_url, created_at)
      VALUES (?, ?, ?, 'USD', ?, ?, 'COMPLETED', NULL, NOW())
      `,
      [paymentId, leadId, amount, method, transactionRef],
    );

    const userId = null;
    const created = [];

    const amountPerStudentForSchedule = totalFeeForSchedule != null && batchesToEnroll.length > 0
      ? totalFeeForSchedule / batchesToEnroll.length
      : (batchesToEnroll.length > 0 ? amount / batchesToEnroll.length : amount);
    const today = new Date();
    let instCount; let instMonths;
    if (feePlanType === 'FULL') {
      instCount = 1;
      instMonths = 0;
    } else if (feePlanType === 'MONTHLY') {
      instCount = 12;
      instMonths = 1;
    } else {
      instCount = 6;
      instMonths = 2;
    }
    const perInst = Math.round((amountPerStudentForSchedule / instCount) * 100) / 100;

    for (const batch of batchesToEnroll) {
      const enrollmentNumber = await generateEnrollmentNumber(conn, batch.course_code);
      const studentId = crypto.randomUUID();
      await conn.query(
        `
        INSERT INTO students
          (id, user_id, lead_id, batch_id, enrollment_number, enrollment_date, status)
        VALUES (?, ?, ?, ?, ?, NOW(), 'ACTIVE')
        `,
        [studentId, userId, leadId, batch.id, enrollmentNumber],
      );
      await conn.query(
        'UPDATE batches SET current_enrollment = current_enrollment + 1 WHERE id = ?',
        [batch.id],
      );
      created.push({ studentId, enrollmentNumber, batchId: batch.id });

      // Store payment timeline with selected plan; total is totalFee (or payment amount if not provided)
      try {
        const [fsIns] = await conn.query(
          `INSERT INTO fee_schedules (student_id, lead_id, total_amount, plan_type) VALUES (?, ?, ?, ?)`,
          [studentId, leadId, amountPerStudentForSchedule, feePlanType],
        );
        const scheduleId = fsIns.insertId;
        for (let i = 0; i < instCount; i++) {
          const d = new Date(today);
          d.setMonth(d.getMonth() + i * instMonths);
          const dueStr = d.toISOString().slice(0, 10);
          await conn.query(
            `INSERT INTO fee_installments (schedule_id, installment_no, due_date, amount_due, status) VALUES (?, ?, ?, ?, 'PENDING')`,
            [scheduleId, i + 1, dueStr, perInst],
          );
        }
      } catch (feeErr) {
        // fee_schedules/fee_installments may not exist; don't fail enrollment
        // eslint-disable-next-line no-console
        console.warn('Could not create fee schedule for new student', feeErr.message);
      }
    }

    await conn.query(
      'UPDATE leads SET status = ?, emergency_contact_number = ?, updated_at = NOW() WHERE id = ?',
      ['CONVERTED', emergencyContactNumber || null, leadId],
    );

    await conn.commit();
    conn.release();

    return res.status(201).json({
      success: true,
      paymentId,
      students: created,
      studentId: created[0]?.studentId,
      enrollmentNumber: created[0]?.enrollmentNumber,
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

    // Main list without fee subquery (works even if fee tables don't exist)
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

    // Add next_fee_payment_date if fee tables exist (don't fail list if they don't)
    let rowsWithFeeDate = rows;
    try {
      const studentIds = (rows || []).map((r) => r.id);
      if (studentIds.length > 0) {
        const placeholders = studentIds.map(() => '?').join(',');
        const [feeRows] = await pool.query(
          `SELECT f.student_id,
                  MIN(i.due_date) AS next_fee_payment_date,
                  SUBSTRING_INDEX(GROUP_CONCAT(i.amount_due ORDER BY i.due_date ASC, i.id), ',', 1) AS next_fee_payment_amount
           FROM fee_installments i
           JOIN fee_schedules f ON i.schedule_id = f.id
           WHERE f.student_id IN (${placeholders}) AND i.status = 'PENDING'
           GROUP BY f.student_id`,
          studentIds,
        );
        const feeByStudent = {};
        (feeRows || []).forEach((row) => {
          const sid = row.student_id != null ? String(row.student_id) : row.student_id;
          feeByStudent[sid] = {
            date: row.next_fee_payment_date,
            amount: row.next_fee_payment_amount != null ? Number(row.next_fee_payment_amount) : null,
          };
        });
        rowsWithFeeDate = (rows || []).map((r) => {
          const fee = feeByStudent[String(r.id)];
          return {
            ...r,
            next_fee_payment_date: fee?.date ?? null,
            next_fee_payment_amount: fee?.amount ?? null,
          };
        });
      }
    } catch (feeErr) {
      // fee_schedules/fee_installments may not exist; leave next fee fields null
      rowsWithFeeDate = (rows || []).map((r) => ({ ...r, next_fee_payment_date: null, next_fee_payment_amount: null }));
    }

    return res.json({ data: rowsWithFeeDate, page: Number(page), pageSize: limit, total });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('List students failed', err);
    return res.status(500).json({
      error: 'Failed to list students',
      detail: err && err.message ? err.message : undefined,
    });
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
        l.emergency_contact_number AS lead_emergency_contact_number,
        b.name AS batch_name,
        b.course_id AS batch_course_id,
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
    return res.status(500).json({
      error: 'Failed to fetch student detail',
      detail: err && err.message ? err.message : undefined,
    });
  }
});

// Update student (status, batch) and linked lead (name, email, phone, emergency contact)
app.patch('/api/v1/students/:id', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database pool not initialized. Check DB_* env vars.' });
  }
  const { id } = req.params;
  const {
    status,
    batchId,
    fullName,
    email,
    phoneNumber,
    emergencyContactNumber,
  } = req.body || {};
  const leadFields = {
    fullName: fullName != null ? String(fullName).trim() : undefined,
    email: email != null ? String(email).trim() || null : undefined,
    phoneNumber: phoneNumber != null ? String(phoneNumber).trim() : undefined,
    emergencyContactNumber: emergencyContactNumber != null ? String(emergencyContactNumber).trim() || null : undefined,
  };
  try {
    const [studentRows] = await pool.query('SELECT id, lead_id FROM students WHERE id = ? LIMIT 1', [id]);
    if (studentRows.length === 0) {
      return res.status(404).json({ error: 'Student not found' });
    }
    const leadId = studentRows[0].lead_id;

    const studentUpdates = [];
    const studentParams = [];
    if (status !== undefined) {
      const valid = ['ACTIVE', 'DROPPED', 'COMPLETED'];
      if (!valid.includes(status)) {
        return res.status(400).json({ error: 'status must be ACTIVE, DROPPED, or COMPLETED' });
      }
      studentUpdates.push('status = ?');
      studentParams.push(status);
    }
    if (batchId !== undefined) {
      const [batchRows] = await pool.query('SELECT id FROM batches WHERE id = ?', [batchId]);
      if (batchRows.length === 0) {
        return res.status(400).json({ error: 'Batch not found' });
      }
      studentUpdates.push('batch_id = ?');
      studentParams.push(batchId);
    }

    if (leadFields.fullName !== undefined || leadFields.email !== undefined || leadFields.phoneNumber !== undefined || leadFields.emergencyContactNumber !== undefined) {
      const leadUpdates = [];
      const leadParams = [];
      if (leadFields.fullName !== undefined) {
        leadUpdates.push('full_name = ?');
        leadParams.push(leadFields.fullName);
      }
      if (leadFields.email !== undefined) {
        leadUpdates.push('email = ?');
        leadParams.push(leadFields.email);
      }
      if (leadFields.phoneNumber !== undefined) {
        leadUpdates.push('phone_number = ?');
        leadParams.push(leadFields.phoneNumber);
      }
      if (leadFields.emergencyContactNumber !== undefined) {
        leadUpdates.push('emergency_contact_number = ?');
        leadParams.push(leadFields.emergencyContactNumber);
      }
      if (leadUpdates.length > 0) {
        leadParams.push(leadId);
        await pool.query(
          `UPDATE leads SET ${leadUpdates.join(', ')}, updated_at = NOW() WHERE id = ?`,
          leadParams,
        );
      }
    }

    if (studentUpdates.length > 0) {
      studentParams.push(id);
      const [result] = await pool.query(
        `UPDATE students SET ${studentUpdates.join(', ')} WHERE id = ?`,
        studentParams,
      );
      if (!result.affectedRows) {
        return res.status(404).json({ error: 'Student not found' });
      }
    }

    const [rows] = await pool.query(
      `SELECT s.*, l.full_name AS lead_name, l.email AS lead_email, l.phone_number AS lead_phone,
              l.emergency_contact_number AS lead_emergency_contact_number,
              b.name AS batch_name, b.course_id AS batch_course_id,
              c.name AS course_name, c.code AS course_code
       FROM students s
       JOIN leads l ON s.lead_id = l.id
       JOIN batches b ON s.batch_id = b.id
       JOIN courses c ON b.course_id = c.id
       WHERE s.id = ?`,
      [id],
    );
    return res.json(rows[0]);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Update student failed', err);
    return res.status(500).json({ error: 'Failed to update student' });
  }
});

// Fee schedule: get schedule with installments for a student
app.get('/api/v1/students/:id/fee-schedule', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database pool not initialized.' });
  }

  const { id } = req.params;

  try {
    const [schedRows] = await pool.query(
      `SELECT * FROM fee_schedules WHERE student_id = ? ORDER BY created_at DESC LIMIT 1`,
      [id],
    );

    if (schedRows.length === 0) {
      return res.json({ schedule: null, installments: [] });
    }

    const schedule = schedRows[0];
    const [instRows] = await pool.query(
      `SELECT * FROM fee_installments WHERE schedule_id = ? ORDER BY installment_no`,
      [schedule.id],
    );

    return res.json({ schedule, installments: instRows });
  } catch (err) {
    console.error('Get fee schedule failed', err);
    return res.status(500).json({ error: 'Failed to fetch fee schedule' });
  }
});

// Fee schedule: create schedule and installments
app.post('/api/v1/students/:id/fee-schedule', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database pool not initialized.' });
  }

  const { id } = req.params;
  const { totalAmount, planType } = req.body;

  if (!totalAmount || !planType) {
    return res.status(400).json({ error: 'totalAmount and planType are required.' });
  }

  const valid = ['FULL', 'MONTHLY', 'INSTALLMENT_6'];
  if (!valid.includes(planType)) {
    return res.status(400).json({ error: 'planType must be FULL, MONTHLY, or INSTALLMENT_6.' });
  }

  const amount = parseFloat(totalAmount);
  if (isNaN(amount) || amount <= 0) {
    return res.status(400).json({ error: 'totalAmount must be a positive number.' });
  }

  try {
    const [stRows] = await pool.query(
      `SELECT id, lead_id FROM students WHERE id = ? LIMIT 1`,
      [id],
    );
    if (stRows.length === 0) {
      return res.status(404).json({ error: 'Student not found.' });
    }
    const { lead_id } = stRows[0];

    const [existing] = await pool.query(
      `SELECT id FROM fee_schedules WHERE student_id = ?`,
      [id],
    );
    if (existing.length > 0) {
      return res.status(400).json({ error: 'A fee schedule already exists for this student.' });
    }

    const [ins] = await pool.query(
      `INSERT INTO fee_schedules (student_id, lead_id, total_amount, plan_type) VALUES (?, ?, ?, ?)`,
      [id, lead_id, amount, planType],
    );
    const scheduleId = ins.insertId;

    const installments = [];
    let count; let months;
    if (planType === 'FULL') {
      count = 1;
      months = 0;
    } else if (planType === 'MONTHLY') {
      count = 12;
      months = 1;
    } else {
      count = 6;
      months = 2;
    }

    const perInst = Math.round((amount / count) * 100) / 100;
    const today = new Date();

    for (let i = 0; i < count; i++) {
      const d = new Date(today);
      d.setMonth(d.getMonth() + i * months);
      const dueDate = d.toISOString().slice(0, 10);
      await pool.query(
        `INSERT INTO fee_installments (schedule_id, installment_no, due_date, amount_due, status) VALUES (?, ?, ?, ?, 'PENDING')`,
        [scheduleId, i + 1, dueDate, perInst],
      );
      installments.push({ installment_no: i + 1, due_date: dueDate, amount_due: perInst, status: 'PENDING' });
    }

    const [schedRow] = await pool.query(`SELECT * FROM fee_schedules WHERE id = ?`, [scheduleId]);
    return res.status(201).json({ schedule: schedRow[0], installments });
  } catch (err) {
    console.error('Create fee schedule failed', err);
    return res.status(500).json({ error: 'Failed to create fee schedule' });
  }
});

// Record payment for an installment
app.post('/api/v1/students/:studentId/fee-installments/:installmentId/pay', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database pool not initialized.' });
  }

  const { studentId, installmentId } = req.params;
  const { amount, method, transactionRef } = req.body;

  if (!amount || !transactionRef) {
    return res.status(400).json({ error: 'amount and transactionRef are required.' });
  }

  const pm = (method || 'CASH').toUpperCase();
  const validMethods = ['CASH', 'STRIPE', 'RAZORPAY', 'BANK_TRANSFER'];
  const payMethod = validMethods.includes(pm) ? pm : 'CASH';

  try {
    const [inst] = await pool.query(
      `SELECT i.*, s.lead_id FROM fee_installments i
       JOIN fee_schedules s ON i.schedule_id = s.id
       WHERE i.id = ? AND s.student_id = ?`,
      [installmentId, studentId],
    );
    if (inst.length === 0) {
      return res.status(404).json({ error: 'Installment not found.' });
    }
    const row = inst[0];
    if (row.status === 'PAID') {
      return res.status(400).json({ error: 'Installment is already paid.' });
    }

    const paymentUuid = crypto.randomUUID();
    await pool.query(
      `INSERT INTO payments (id, lead_id, amount, currency, payment_method, transaction_ref, status, invoice_url, created_at)
       VALUES (?, ?, ?, 'USD', ?, ?, 'COMPLETED', NULL, NOW())`,
      [paymentUuid, row.lead_id, parseFloat(amount), payMethod, transactionRef.trim()],
    );

    await pool.query(
      `UPDATE fee_installments SET status = 'PAID', paid_at = NOW(), payment_id = ? WHERE id = ?`,
      [paymentUuid, installmentId],
    );

    const [updated] = await pool.query(`SELECT * FROM fee_installments WHERE id = ?`, [installmentId]);
    return res.json({ installment: updated[0], paymentId: paymentUuid });
  } catch (err) {
    console.error('Record installment payment failed', err);
    return res.status(500).json({ error: 'Failed to record payment' });
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
    // Normalize id to string (MySQL may return UUID as Buffer or different format)
    const data = (rows || []).map((r) => ({
      ...r,
      id: r.id != null ? String(r.id) : r.id,
    }));
    return res.json({ data });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('List courses failed', err);
    return res.status(500).json({ error: 'Failed to list courses' });
  }
});

// Create course
app.post('/api/v1/courses', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database pool not initialized. Check DB_* env vars.' });
  }
  const { name, code, baseFee, isActive } = req.body || {};
  if (!name || !code) {
    return res.status(400).json({ error: 'name and code are required' });
  }
  const id = crypto.randomUUID();
  const baseFeeVal = baseFee != null ? Number(baseFee) : 0;
  const isActiveVal = isActive !== false;
  const nameVal = String(name).trim();
  const codeVal = String(code).trim().toUpperCase();
  const isActiveNum = isActiveVal ? 1 : 0;

  try {
    await pool.query(
      `INSERT INTO courses (id, name, code, base_fee, is_active) VALUES (?, ?, ?, ?, ?)`,
      [id, nameVal, codeVal, baseFeeVal, isActiveNum],
    );
    return res.status(201).json({ id, name: nameVal, code: codeVal, base_fee: baseFeeVal, is_active: isActiveVal });
  } catch (err) {
    if (err && err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'Course code already exists' });
    }
    // If table has Prisma-style camelCase columns (baseFee, isActive), try that
    const badField = err && err.code === 'ER_BAD_FIELD_ERROR' || (err.message && err.message.includes('Unknown column'));
    if (badField) {
      try {
        await pool.query(
          `INSERT INTO courses (id, name, code, baseFee, isActive) VALUES (?, ?, ?, ?, ?)`,
          [id, nameVal, codeVal, baseFeeVal, isActiveNum],
        );
        return res.status(201).json({ id, name: nameVal, code: codeVal, base_fee: baseFeeVal, is_active: isActiveVal });
      } catch (err2) {
        // eslint-disable-next-line no-console
        console.error('Create course failed (snake_case and camelCase)', err, err2);
        return res.status(500).json({
          error: 'Failed to create course',
          detail: err2.message || err.message || String(err2),
        });
      }
    }
    // eslint-disable-next-line no-console
    console.error('Create course failed', err);
    return res.status(500).json({
      error: 'Failed to create course',
      detail: err.message || err.code || String(err),
    });
  }
});

// Update course
app.patch('/api/v1/courses/:id', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database pool not initialized. Check DB_* env vars.' });
  }
  const { id } = req.params;
  const { name, code, baseFee, isActive } = req.body || {};
  try {
    const updates = [];
    const params = [];
    if (name !== undefined) { updates.push('name = ?'); params.push(String(name).trim()); }
    if (code !== undefined) { updates.push('code = ?'); params.push(String(code).trim().toUpperCase()); }
    if (baseFee !== undefined) { updates.push('base_fee = ?'); params.push(Number(baseFee)); }
    if (isActive !== undefined) { updates.push('is_active = ?'); params.push(isActive ? 1 : 0); }
    if (updates.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }
    params.push(id);
    const [result] = await pool.query(
      `UPDATE courses SET ${updates.join(', ')} WHERE id = ?`,
      params,
    );
    if (!result.affectedRows) {
      return res.status(404).json({ error: 'Course not found' });
    }
    const [rows] = await pool.query('SELECT id, name, code, base_fee, is_active FROM courses WHERE id = ?', [id]);
    return res.json(rows[0]);
  } catch (err) {
    if (err && err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'Course code already exists' });
    }
    console.error('Update course failed', err);
    return res.status(500).json({ error: 'Failed to update course' });
  }
});

// Delete course
app.delete('/api/v1/courses/:id', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database pool not initialized. Check DB_* env vars.' });
  }
  const { id } = req.params;
  try {
    const [batchCount] = await pool.query('SELECT COUNT(*) AS n FROM batches WHERE course_id = ?', [id]);
    if (batchCount[0].n > 0) {
      return res.status(422).json({ error: 'Cannot delete course that has batches. Delete or reassign batches first.' });
    }
    const [result] = await pool.query('DELETE FROM courses WHERE id = ?', [id]);
    if (!result.affectedRows) {
      return res.status(404).json({ error: 'Course not found' });
    }
    return res.status(204).send();
  } catch (err) {
    console.error('Delete course failed', err);
    return res.status(500).json({ error: 'Failed to delete course' });
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

// Create batch
app.post('/api/v1/batches', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database pool not initialized. Check DB_* env vars.' });
  }
  const { courseId, name, startDate, maxSeats, status } = req.body || {};
  if (!courseId || !name || !startDate || maxSeats == null) {
    return res.status(400).json({ error: 'courseId, name, startDate, and maxSeats are required' });
  }
  const courseIdTrimmed = String(courseId).trim();
  const maxSeatsNum = Math.max(0, Number(maxSeats));
  const batchStatus = ['OPEN', 'FULL', 'IN_PROGRESS', 'COMPLETED'].includes(status) ? status : 'OPEN';
  try {
    let [courseRows] = await pool.query('SELECT id FROM courses WHERE id = ?', [courseIdTrimmed]);
    if (courseRows.length === 0) {
      // Fallback: MySQL may return UUID as Buffer or different type; fetch all and match as string
      const [allCourses] = await pool.query('SELECT id FROM courses');
      const matched = (allCourses || []).find((c) => String(c.id) === courseIdTrimmed);
      if (matched) {
        courseRows = [matched];
      }
    }
    if (courseRows.length === 0) {
      // eslint-disable-next-line no-console
      console.error('Create batch: course not found. courseId=', courseIdTrimmed, 'courses table check: run SELECT id FROM courses;');
      return res.status(422).json({
        error: 'Course not found',
        message: 'The selected course was not found in the database. Ensure you have at least one course (Courses page → Add course) and that you selected it in the dropdown.',
      });
    }
    const resolvedCourseId = courseRows[0].id != null ? String(courseRows[0].id) : courseIdTrimmed;
    const id = crypto.randomUUID();
    await pool.query(
      `INSERT INTO batches (id, course_id, name, start_date, max_seats, current_enrollment, status)
       VALUES (?, ?, ?, ?, ?, 0, ?)`,
      [id, resolvedCourseId, String(name).trim(), startDate, maxSeatsNum, batchStatus],
    );
    const [rows] = await pool.query(
      `SELECT b.*, c.name AS course_name, c.code AS course_code
       FROM batches b JOIN courses c ON b.course_id = c.id WHERE b.id = ?`,
      [id],
    );
    return res.status(201).json(rows[0]);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Create batch failed', err);
    return res.status(500).json({ error: 'Failed to create batch' });
  }
});

// Update batch
app.patch('/api/v1/batches/:id', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database pool not initialized. Check DB_* env vars.' });
  }
  const { id } = req.params;
  const { name, startDate, maxSeats, status } = req.body || {};
  try {
    const updates = [];
    const params = [];
    if (name !== undefined) { updates.push('name = ?'); params.push(String(name).trim()); }
    if (startDate !== undefined) { updates.push('start_date = ?'); params.push(startDate); }
    if (maxSeats !== undefined) { updates.push('max_seats = ?'); params.push(Math.max(0, Number(maxSeats))); }
    if (status !== undefined && ['OPEN', 'FULL', 'IN_PROGRESS', 'COMPLETED'].includes(status)) {
      updates.push('status = ?'); params.push(status);
    }
    if (updates.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }
    params.push(id);
    const [result] = await pool.query(
      `UPDATE batches SET ${updates.join(', ')} WHERE id = ?`,
      params,
    );
    if (!result.affectedRows) {
      return res.status(404).json({ error: 'Batch not found' });
    }
    const [rows] = await pool.query(
      `SELECT b.*, c.name AS course_name, c.code AS course_code
       FROM batches b JOIN courses c ON b.course_id = c.id WHERE b.id = ?`,
      [id],
    );
    return res.json(rows[0]);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Update batch failed', err);
    return res.status(500).json({ error: 'Failed to update batch' });
  }
});

// Delete batch
app.delete('/api/v1/batches/:id', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database pool not initialized. Check DB_* env vars.' });
  }
  const { id } = req.params;
  try {
    const [studentCount] = await pool.query('SELECT COUNT(*) AS n FROM students WHERE batch_id = ?', [id]);
    if (studentCount[0].n > 0) {
      return res.status(422).json({ error: 'Cannot delete batch that has enrolled students. Remove students first.' });
    }
    const [result] = await pool.query('DELETE FROM batches WHERE id = ?', [id]);
    if (!result.affectedRows) {
      return res.status(404).json({ error: 'Batch not found' });
    }
    return res.status(204).send();
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Delete batch failed', err);
    return res.status(500).json({ error: 'Failed to delete batch' });
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

// Create attendance session (teacher_id = logged-in user; must exist in users table)
app.post('/api/v1/attendance/sessions', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database pool not initialized. Check DB_* env vars.' });
  }

  const teacherId = req.user?.userId || req.user?.id;
  if (!teacherId) {
    return res.status(401).json({
      error: 'You must be logged in to create an attendance session. teacher_id must reference a user.',
    });
  }

  const { batchId, date, subject, startTime, endTime } = req.body || {};

  if (!batchId || !date || !subject || !startTime || !endTime) {
    return res.status(400).json({
      error: 'batchId, date, subject, startTime, and endTime are required',
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

// Send a Telegram notification to a connected student
// type: EXAM_RESULT | FEES | CUSTOM
app.post('/api/v1/telegram/send', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database pool not initialized. Check DB_* env vars.' });
  }

  const { studentId, type, message } = req.body || {};

  const allowedTypes = ['EXAM_RESULT', 'FEES', 'CUSTOM'];
  if (!studentId || !type || !allowedTypes.includes(type)) {
    return res.status(400).json({ error: 'studentId and valid type (EXAM_RESULT, FEES, CUSTOM) are required' });
  }

  if (type === 'CUSTOM' && (!message || !String(message).trim())) {
    return res.status(400).json({ error: 'Custom message is required for CUSTOM type' });
  }

  const botToken = process.env.TELEGRAM_BOT_TOKEN;
  if (!botToken) {
    return res.status(500).json({ error: 'TELEGRAM_BOT_TOKEN is not configured on the server' });
  }

  try {
    const [rows] = await pool.query(
      `
      SELECT
        tm.*,
        s.lead_id,
        l.full_name,
        l.email
      FROM telegram_mappings tm
      JOIN students s ON tm.student_id = s.id
      JOIN leads l ON s.lead_id = l.id
      WHERE tm.student_id = ? AND tm.is_active = 1 AND tm.chat_id IS NOT NULL
      LIMIT 1
      `,
      [studentId],
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'No active Telegram mapping found for this student. Ask them to connect Telegram first.' });
    }

    const mapping = rows[0];
    const name = mapping.full_name || 'Student';

    let text;
    if (type === 'CUSTOM') {
      text = String(message).trim();
    } else if (type === 'EXAM_RESULT') {
      text = `Hi ${name}, your latest exam results are available in the portal. Please log in to check your marks and feedback.`;
    } else if (type === 'FEES') {
      text = `Hi ${name}, this is a reminder about your course fee payment. Please check your portal for the next due date and amount.`;
    }

    if (typeof fetch !== 'function') {
      // eslint-disable-next-line no-console
      console.error('Global fetch is not available in this Node version.');
      return res.status(500).json({ error: 'Telegram send is not supported on this server runtime (no fetch)' });
    }

    const tgRes = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: mapping.chat_id,
        text,
      }),
    });

    const tgJson = await tgRes.json().catch(() => ({}));
    if (!tgRes.ok || tgJson.ok === false) {
      // eslint-disable-next-line no-console
      console.error('Telegram send failed', tgJson);
      return res.status(502).json({ error: 'Failed to send Telegram message' });
    }

    return res.json({ ok: true });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Send Telegram notification failed', err);
    return res.status(500).json({ error: 'Failed to send Telegram notification' });
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

