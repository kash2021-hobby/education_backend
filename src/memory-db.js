/**
 * In-memory database fallback when MySQL is unreachable (e.g. ETIMEDOUT).
 * Set USE_IN_MEMORY_DB=true in .env to use this instead of MySQL.
 * Data is lost on restart.
 */

const crypto = require('crypto');
const bcrypt = require('bcrypt');

const users = new Map(); // email -> user row

function createMockPool() {
  const query = async (sql, params = []) => {
    const sqlLower = sql.replace(/\s+/g, ' ').toLowerCase();

    // Auth: SELECT user by email
    if (sqlLower.includes('select id, full_name, email, password_hash') && sqlLower.includes('from users') && sqlLower.includes('where email')) {
      const email = (params[0] || '').toString().toLowerCase();
      const user = users.get(email);
      return [user ? [user] : [], []];
    }

    // Auth: INSERT user
    if (sqlLower.includes('insert into users')) {
      const [id, fullName, email, passwordHash, role] = params;
      const key = String(email).toLowerCase().trim();
      if (users.has(key)) {
        const err = new Error('Duplicate entry');
        err.code = 'ER_DUP_ENTRY';
        throw err;
      }
      users.set(key, {
        id,
        full_name: fullName,
        email: key,
        password_hash: passwordHash,
        role,
        is_active: 1,
      });
      return [{ affectedRows: 1 }, []];
    }

    // Leads count (SELECT COUNT(*) FROM leads)
    if (sqlLower.includes('select count(*)') && sqlLower.includes('from leads')) {
      return [[{ total: 0 }], []];
    }
    // Leads list (SELECT l.id, l.full_name, ... FROM leads l)
    if (sqlLower.includes('from leads l') || sqlLower.includes('from leads')) {
      return [[], []];
    }

    // Lead detail
    if (sqlLower.includes('from leads l') && sqlLower.includes('where l.id')) {
      return [[], []];
    }
    if (sqlLower.includes('from lead_activities') && sqlLower.includes('where a.lead_id')) {
      return [[], []];
    }

    // Students list / count
    if (sqlLower.includes('students s join leads l') && sqlLower.includes('count')) {
      return [[{ total: 0 }], []];
    }
    if (sqlLower.includes('students s') && sqlLower.includes('join leads l')) {
      return [[], []];
    }

    // Student detail
    if (sqlLower.includes('from students s') && sqlLower.includes('where s.id')) {
      return [[], []];
    }
    if (sqlLower.includes('from payments') && sqlLower.includes('where lead_id')) {
      return [[], []];
    }

    // Courses
    if (sqlLower.includes('from courses')) {
      return [[], []];
    }

    // Batches
    if (sqlLower.includes('from batches b') || sqlLower.includes('batches b')) {
      return [[], []];
    }

    // Dashboard / summary
    if (sqlLower.includes('count') && sqlLower.includes('leads')) {
      return [[{ total: 0 }], []];
    }

    // Users for assignees
    if (sqlLower.includes('from users') && sqlLower.includes('is_active')) {
      return [[...users.values()].filter((u) => u.is_active).map((u) => ({
        id: u.id, full_name: u.full_name, email: u.email, role: u.role,
      })), []];
    }

    // Attendance summary
    if (sqlLower.includes('attendance_records') && sqlLower.includes('count')) {
      return [[{ total_sessions: 0, present_sessions: 0 }], []];
    }

    // Default: COUNT/SUM -> row with zeros; INSERT/UPDATE/DELETE -> affectedRows; else empty rows
    if (sqlLower.includes('count(') || sqlLower.includes('sum(')) {
      return [[{ total: 0, total_sessions: 0, present_sessions: 0 }], []];
    }
    if (sqlLower.includes('insert ') || sqlLower.includes('update ') || sqlLower.includes('delete ')) {
      return [{ affectedRows: 1 }, []];
    }
    return [[], []];
  };

  const getConnection = () => ({
    query: async (sql, params) => query(sql, params),
    beginTransaction: async () => {},
    commit: async () => {},
    rollback: async () => {},
    release: () => {},
  });

  return { query, getConnection };
}

async function seedDefaultUser() {
  const email = 'demo@example.com';
  if (users.has(email)) return;

  const id = crypto.randomUUID();
  const passwordHash = await bcrypt.hash('demo123', 10);
  users.set(email, {
    id,
    full_name: 'Demo User',
    email,
    password_hash: passwordHash,
    role: 'COUNSELOR',
    is_active: 1,
  });
  // eslint-disable-next-line no-console
  console.log('In-memory DB: seeded demo user (demo@example.com / demo123)');
}

module.exports = { createMockPool, seedDefaultUser };
