import express from 'express';
import pool from './db';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import crypto from 'crypto';
import { GoogleGenerativeAI } from '@google/generative-ai';

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'harare_poly_super_secret_key_2026';

app.use(cors());
app.use(express.json());

// ==========================================
// 🔐 SUPER ADMIN BOOTSTRAP SEEDER (MAX 2)
// ==========================================
const seedSuperAdmins = async () => {
  try {
    // Ensure columns exist even if SQL migration wasn't run yet
    await pool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS account_status VARCHAR(20) DEFAULT 'active'");
    await pool.query("ALTER TABLE alumni_profiles ALTER COLUMN graduation_year DROP NOT NULL");
    await pool.query("ALTER TABLE alumni_profiles ALTER COLUMN course_name DROP NOT NULL");

    const admins = [
      {
        email: process.env.SUPER_ADMIN_1_EMAIL,
        password: process.env.SUPER_ADMIN_1_PASSWORD,
        firstName: 'Super',
        lastName: 'Admin One'
      },
      {
        email: process.env.SUPER_ADMIN_2_EMAIL,
        password: process.env.SUPER_ADMIN_2_PASSWORD,
        firstName: 'Super',
        lastName: 'Admin Two'
      }
    ];

    for (const sa of admins) {
      if (!sa.email || !sa.password) continue;
      const cleanEmail = sa.email.trim().toLowerCase();
      const salt = await bcrypt.genSalt(10);
      const hash = await bcrypt.hash(sa.password, salt);

      const existing = await pool.query("SELECT id FROM users WHERE LOWER(email) = $1", [cleanEmail]);
      if (existing.rows.length === 0) {
        const inserted = await pool.query(
          "INSERT INTO users (email, password_hash, role, account_status) VALUES ($1, $2, 'super_admin', 'active') RETURNING id",
          [cleanEmail, hash]
        );
        await pool.query(
          "INSERT INTO alumni_profiles (user_id, first_name, last_name, department, course_name) VALUES ($1, $2, $3, 'System Administration', 'Super Admin')",
          [inserted.rows[0].id, sa.firstName, sa.lastName]
        );
        console.log(`🟢 Seeded Super Admin: ${cleanEmail}`);
      } else {
        await pool.query(
          "UPDATE users SET password_hash = $1, role = 'super_admin', account_status = 'active' WHERE id = $2",
          [hash, existing.rows[0].id]
        );
        console.log(`🟢 Verified Super Admin: ${cleanEmail}`);
      }
    }
  } catch (err: any) {
    console.error("🔴 Super Admin Seeder Error:", err.message);
  }
};
seedSuperAdmins();

// ==========================================
// 🛡️ AUTH & ROLE MIDDLEWARE + QUOTA CHECKER
// ==========================================
const verifyToken = (req: any, res: any, next: any) => {
  const token = req.header('Authorization');
  if (!token) return res.status(401).json({ error: 'Access denied' });

  try {
    const verified = jwt.verify(token.replace('Bearer ', ''), JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
};

// Super Admin automatically passes ALL role checks!
const hasRole = (userRole: string, allowedRoles: string[]) => {
  if (userRole === 'super_admin') return true;
  return allowedRoles.includes(userRole);
};

// Helper to detect staff role from official email suffix
const detectRoleFromEmail = (email: string): string => {
  const lower = email.trim().toLowerCase();
  if (lower.endsWith('.principal@hrepoly.ac.zw')) return 'principal';
  if (lower.endsWith('.vp@hrepoly.ac.zw')) return 'vp';
  if (lower.endsWith('.pro@hrepoly.ac.zw')) return 'pro';
  if (lower.endsWith('.hod@hrepoly.ac.zw')) return 'hod';
  if (lower.endsWith('.it@hrepoly.ac.zw')) return 'it';
  return 'alumni';
};

// Reusable Quota Validator before activating/creating any staff account
const checkQuotaAvailability = async (role: string, department?: string | null, excludeUserId?: number) => {
  const excludeId = excludeUserId || -1;

  if (role === 'super_admin') {
    const r = await pool.query("SELECT COUNT(*) FROM users WHERE role = 'super_admin' AND account_status = 'active' AND id != $1", [excludeId]);
    if (parseInt(r.rows[0].count) >= 2) return "Quota reached: Maximum of 2 Super Admin accounts allowed.";
  } else if (role === 'principal' || role === 'admin') {
    const r = await pool.query("SELECT COUNT(*) FROM users WHERE role IN ('principal', 'admin') AND account_status = 'active' AND id != $1", [excludeId]);
    if (parseInt(r.rows[0].count) >= 1) return "Quota reached: Only 1 Principal account is allowed in the system.";
  } else if (role === 'vp') {
    const r = await pool.query("SELECT COUNT(*) FROM users WHERE role = 'vp' AND account_status = 'active' AND id != $1", [excludeId]);
    if (parseInt(r.rows[0].count) >= 2) return "Quota reached: Maximum of 2 Vice Principal accounts allowed.";
  } else if (role === 'pro') {
    const r = await pool.query("SELECT COUNT(*) FROM users WHERE role = 'pro' AND account_status = 'active' AND id != $1", [excludeId]);
    if (parseInt(r.rows[0].count) >= 1) return "Quota reached: Only 1 Public Relations Officer (PRO) account is allowed.";
  } else if (role === 'it') {
    const r = await pool.query("SELECT COUNT(*) FROM users WHERE role = 'it' AND account_status = 'active' AND id != $1", [excludeId]);
    if (parseInt(r.rows[0].count) >= 5) return "Quota reached: Maximum of 5 IT Support accounts allowed.";
  } else if (role === 'hod') {
    if (!department) return "Department is required for an HOD account.";
    const r = await pool.query(
      `SELECT COUNT(*) FROM users u
       JOIN alumni_profiles a ON u.id = a.user_id
       WHERE u.role = 'hod' AND u.account_status = 'active' AND a.department = $1 AND u.id != $2`,
      [department, excludeId]
    );
    if (parseInt(r.rows[0].count) >= 1) return `Quota reached: ${department} already has an active HOD.`;
  }
  return null;
};

app.get('/', (req, res) => {
  res.send('Harare Poly Alumni API is live!');
});

// ==========================================
// 🔑 REGISTRATION & LOGIN (OPTION B APPROVAL)
// ==========================================
app.post('/api/alumni/register', async (req, res) => {
  try {
    const { first_name, last_name, student_id_number, graduation_year, department, course_name, email, password } = req.body;
    const cleanEmail = email.trim().toLowerCase();
    const finalStudentId = !student_id_number || student_id_number.trim() === '' ? null : student_id_number.trim();

    // Block arbitrary @hrepoly.ac.zw emails that don't match valid staff suffixes unless normal alumni
    const assignedRole = detectRoleFromEmail(cleanEmail);
    const isStaffRegistration = assignedRole !== 'alumni';

    if (assignedRole === 'hod' && (!department || department.trim() === '')) {
      return res.status(400).json({ error: "Please select your Department for HOD registration." });
    }

    const userExists = await pool.query("SELECT id FROM users WHERE LOWER(email) = $1", [cleanEmail]);
    if (userExists.rows.length > 0) {
      return res.status(400).json({ error: "Email is already registered" });
    }

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    // Staff self-registrations enter 'pending_staff' until Super Admin / IT approves!
    const accountStatus = isStaffRegistration ? 'pending_staff' : 'active';

    const newUser = await pool.query(
      "INSERT INTO users (email, password_hash, role, account_status) VALUES ($1, $2, $3, $4) RETURNING id",
      [cleanEmail, passwordHash, assignedRole, accountStatus]
    );
    const userId = newUser.rows[0].id;

    const finalGradYear = isStaffRegistration ? null : (graduation_year ? parseInt(graduation_year) : null);
    const finalDept = department && department.trim() !== '' ? department : (isStaffRegistration ? 'Administration' : '');
    const finalCourse = isStaffRegistration ? `Staff (${assignedRole.toUpperCase()})` : course_name;

    const newProfile = await pool.query(
      `INSERT INTO alumni_profiles (user_id, first_name, last_name, student_id_number, graduation_year, department, course_name)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [userId, first_name, last_name, finalStudentId, finalGradYear, finalDept, finalCourse]
    );

    if (isStaffRegistration) {
      return res.json({
        pendingApproval: true,
        role: assignedRole,
        message: "Staff account registered! Your account is pending verification by IT / Super Admin before you can sign in."
      });
    }

    const token = jwt.sign({ user_id: userId, role: assignedRole }, JWT_SECRET, { expiresIn: '2h' });
    res.json({ token, role: assignedRole, profile: newProfile.rows[0] });
  } catch (err: any) {
    console.error("🔴 Registration Error:", err.message);
    res.status(500).json({ error: err.message || "Server Error" });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const cleanEmail = email.trim().toLowerCase();

    const userResult = await pool.query("SELECT * FROM users WHERE LOWER(email) = $1", [cleanEmail]);
    if (userResult.rows.length === 0) return res.status(400).json({ error: "Invalid credentials" });

    const user = userResult.rows[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });

    if (user.account_status === 'pending_staff') {
      return res.status(403).json({
        error: "Your staff account is awaiting approval from IT Support or a Super Admin."
      });
    }

    const token = jwt.sign({ user_id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '2h' });
    res.json({ token, role: user.role });
  } catch (err: any) {
    console.error(err.message);
    res.status(500).json({ error: "Server Error" });
  }
});

// ==========================================
// 🎓 ALUMNI PROFILE, NETWORK & CONNECTIONS
// (Strictly isolated to active 'alumni'!)
// ==========================================
app.get('/api/alumni/me', verifyToken, async (req: any, res) => {
  try {
    const userQuery = await pool.query('SELECT email, role FROM users WHERE id = $1', [req.user.user_id]);
    const profileQuery = await pool.query('SELECT * FROM alumni_profiles WHERE user_id = $1', [req.user.user_id]);
    if (profileQuery.rows.length === 0) return res.status(404).json({ error: 'Profile not found' });

    const employmentData = await pool.query("SELECT * FROM employment_history WHERE user_id = $1 ORDER BY id DESC", [req.user.user_id]);
    const studiesData = await pool.query("SELECT * FROM further_studies WHERE user_id = $1 ORDER BY graduation_year DESC", [req.user.user_id]);

    res.json({
      ...profileQuery.rows[0],
      email: userQuery.rows[0]?.email || '',
      role: userQuery.rows[0]?.role || 'alumni',
      employment: employmentData.rows,
      studies: studiesData.rows
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/alumni/employment', verifyToken, async (req: any, res) => {
  try {
    const { company_name, job_title, start_date, end_date, is_current } = req.body;
    const newJob = await pool.query(
      "INSERT INTO employment_history (user_id, company_name, job_title, start_date, end_date, is_current) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *",
      [req.user.user_id, company_name, job_title, start_date, end_date, is_current]
    );

    if (req.user.role === 'alumni') {
      const companyCheck = await pool.query("SELECT * FROM companies WHERE name ILIKE $1", [company_name]);
      if (companyCheck.rows.length === 0) {
        await pool.query("INSERT INTO companies (name, industry) VALUES ($1, $2)", [company_name, "Various"]);
      }
    }
    res.json(newJob.rows[0]);
  } catch (err: any) {
    res.status(500).json({ error: "Server Error" });
  }
});

app.post('/api/alumni/studies', verifyToken, async (req: any, res) => {
  try {
    const { institution_name, degree_obtained, field_of_study, graduation_year } = req.body;
    const newStudy = await pool.query(
      "INSERT INTO further_studies (user_id, institution_name, degree_obtained, field_of_study, graduation_year) VALUES ($1, $2, $3, $4, $5) RETURNING *",
      [req.user.user_id, institution_name, degree_obtained, field_of_study, graduation_year]
    );
    res.json(newStudy.rows[0]);
  } catch (err: any) {
    res.status(500).json({ error: "Server Error" });
  }
});

// Network Directory — Strictly hides all Staff & Super Admins!
app.get('/api/alumni/network', verifyToken, async (req: any, res) => {
  try {
    const network = await pool.query(`
      SELECT 
        a.id, a.user_id, a.first_name, a.last_name, a.department, a.course_name, a.graduation_year,
        (SELECT job_title FROM employment_history WHERE user_id = a.user_id ORDER BY id DESC LIMIT 1) as current_job,
        (SELECT company_name FROM employment_history WHERE user_id = a.user_id ORDER BY id DESC LIMIT 1) as current_company
      FROM alumni_profiles a
      JOIN users u ON a.user_id = u.id
      WHERE u.role = 'alumni' AND u.account_status = 'active' AND a.user_id != $1
      ORDER BY a.graduation_year DESC, a.first_name ASC
    `, [req.user.user_id]);
    res.json(network.rows);
  } catch (err: any) {
    res.status(500).json({ error: "Server Error" });
  }
});

app.put('/api/alumni/profile', verifyToken, async (req: any, res) => {
  try {
    const { phone_number, linkedin_url } = req.body;
    await pool.query(
      "UPDATE alumni_profiles SET phone_number = $1, linkedin_url = $2 WHERE user_id = $3",
      [phone_number, linkedin_url, req.user.user_id]
    );
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ error: "Server Error" });
  }
});

app.post('/api/connections/send', verifyToken, async (req: any, res) => {
  try {
    const { receiver_id, message } = req.body;
    const sender_id = req.user.user_id;
    if (sender_id === receiver_id) return res.status(400).json({ error: "Cannot send a request to yourself." });

    const existingRequest = await pool.query(
      "SELECT * FROM connection_requests WHERE sender_id = $1 AND receiver_id = $2 AND status = 'Pending'",
      [sender_id, receiver_id]
    );
    if (existingRequest.rows.length > 0) return res.status(400).json({ error: "A pending request already exists." });

    const newRequest = await pool.query(
      "INSERT INTO connection_requests (sender_id, receiver_id, message) VALUES ($1, $2, $3) RETURNING *",
      [sender_id, receiver_id, message]
    );
    res.json(newRequest.rows[0]);
  } catch (err: any) {
    res.status(500).json({ error: "Server Error" });
  }
});

app.get('/api/connections/inbox', verifyToken, async (req: any, res) => {
  try {
    const inbox = await pool.query(
      `SELECT c.*, a.first_name, a.last_name, a.department, a.course_name 
       FROM connection_requests c 
       JOIN alumni_profiles a ON c.sender_id = a.user_id
       JOIN users u ON a.user_id = u.id
       WHERE c.receiver_id = $1 AND c.status = 'Pending' AND u.role = 'alumni'
       ORDER BY c.created_at DESC`,
      [req.user.user_id]
    );
    res.json(inbox.rows);
  } catch (err: any) {
    res.status(500).json({ error: "Server Error" });
  }
});

app.put('/api/connections/respond', verifyToken, async (req: any, res) => {
  try {
    const { request_id, status, shared_info_type, shared_info_value } = req.body;
    const updateRequest = await pool.query(
      "UPDATE connection_requests SET status = $1, shared_info_type = $2, shared_info_value = $3 WHERE id = $4 AND receiver_id = $5 RETURNING *",
      [status, shared_info_type, shared_info_value, request_id, req.user.user_id]
    );
    if (updateRequest.rows.length === 0) return res.status(404).json({ error: "Request not found or unauthorized." });
    res.json(updateRequest.rows[0]);
  } catch (err: any) {
    res.status(500).json({ error: "Server Error" });
  }
});

app.get('/api/connections/my-connections', verifyToken, async (req: any, res) => {
  try {
    const myConnections = await pool.query(
      `SELECT c.*, a.first_name, a.last_name, a.department 
       FROM connection_requests c 
       JOIN alumni_profiles a ON c.receiver_id = a.user_id
       JOIN users u ON a.user_id = u.id
       WHERE c.sender_id = $1 AND u.role = 'alumni'
       ORDER BY c.created_at DESC`,
      [req.user.user_id]
    );
    res.json(myConnections.rows);
  } catch (err: any) {
    res.status(500).json({ error: "Server Error" });
  }
});

// ==========================================
// 📊 PRINCIPAL, VP & HOD ANALYTICS
// (Strictly counts ONLY role = 'alumni'!)
// ==========================================
app.get('/api/dashboard/stats', verifyToken, async (req: any, res) => {
  try {
    if (!hasRole(req.user.role, ['principal', 'vp', 'admin'])) {
      return res.status(403).json({ error: "Management access required." });
    }

    const totalAlumniRes = await pool.query(`
      SELECT COUNT(*) FROM alumni_profiles a
      JOIN users u ON a.user_id = u.id
      WHERE u.role = 'alumni' AND u.account_status = 'active'
    `);

    const totalCompaniesRes = await pool.query(`
      SELECT COUNT(DISTINCT e.company_name) FROM employment_history e
      JOIN users u ON e.user_id = u.id
      WHERE u.role = 'alumni' AND u.account_status = 'active'
    `);

    const employedRes = await pool.query(`
      SELECT COUNT(DISTINCT e.user_id) FROM employment_history e
      JOIN users u ON e.user_id = u.id
      WHERE u.role = 'alumni' AND u.account_status = 'active'
    `);

    const studiesRes = await pool.query(`
      SELECT COUNT(DISTINCT f.user_id) FROM further_studies f
      JOIN users u ON f.user_id = u.id
      WHERE u.role = 'alumni' AND u.account_status = 'active'
    `);

    const deptStatsRes = await pool.query(`
      SELECT a.department as name, CAST(COUNT(*) AS INTEGER) as "Alumni"
      FROM alumni_profiles a
      JOIN users u ON a.user_id = u.id
      WHERE u.role = 'alumni' AND u.account_status = 'active'
      GROUP BY a.department
    `);

    const allAlumniRes = await pool.query(`
      SELECT 
        a.id, u.email, a.first_name, a.last_name, a.department, a.course_name, a.graduation_year, a.student_id_number,
        (SELECT job_title FROM employment_history WHERE user_id = a.user_id ORDER BY id DESC LIMIT 1) as job_title,
        (SELECT company_name FROM employment_history WHERE user_id = a.user_id ORDER BY id DESC LIMIT 1) as company_name
      FROM alumni_profiles a
      JOIN users u ON a.user_id = u.id
      WHERE u.role = 'alumni' AND u.account_status = 'active'
      ORDER BY a.id DESC
    `);

    res.json({
      totalAlumni: parseInt(totalAlumniRes.rows[0].count),
      totalCompanies: parseInt(totalCompaniesRes.rows[0].count),
      totalEmployed: parseInt(employedRes.rows[0].count),
      totalFurtherStudies: parseInt(studiesRes.rows[0].count),
      departmentStats: deptStatsRes.rows,
      tableData: allAlumniRes.rows
    });
  } catch (err: any) {
    console.error("🔴 Dashboard Fetch Error:", err.message);
    res.status(500).json({ error: "Server Error" });
  }
});

// HOD Stats — Supports ?department=... override for Super Admins!
app.get('/api/hod/stats', verifyToken, async (req: any, res) => {
  try {
    if (!hasRole(req.user.role, ['hod'])) {
      return res.status(403).json({ error: "HOD access required." });
    }

    let hodDept = req.query.department as string | undefined;

    if (!hodDept || req.user.role !== 'super_admin') {
      const hodProfile = await pool.query("SELECT department FROM alumni_profiles WHERE user_id = $1", [req.user.user_id]);
      if (hodProfile.rows.length === 0) return res.status(404).json({ error: "HOD profile not found" });
      hodDept = hodProfile.rows[0].department;
    }

    // Fallback default if Super Admin hasn't picked a department yet
    if (req.user.role === 'super_admin' && (!hodDept || hodDept === 'System Administration')) {
      hodDept = 'Information and Communication Technology';
    }

    const deptAlumniRes = await pool.query(`
      SELECT COUNT(*) FROM alumni_profiles a
      JOIN users u ON a.user_id = u.id
      WHERE a.department = $1 AND u.role = 'alumni' AND u.account_status = 'active'
    `, [hodDept]);

    const employedRes = await pool.query(`
      SELECT COUNT(DISTINCT e.user_id)
      FROM employment_history e
      JOIN alumni_profiles a ON e.user_id = a.user_id
      JOIN users u ON a.user_id = u.id
      WHERE a.department = $1 AND u.role = 'alumni' AND u.account_status = 'active'
    `, [hodDept]);

    const studiesRes = await pool.query(`
      SELECT COUNT(DISTINCT f.user_id)
      FROM further_studies f
      JOIN alumni_profiles a ON f.user_id = a.user_id
      JOIN users u ON a.user_id = u.id
      WHERE a.department = $1 AND u.role = 'alumni' AND u.account_status = 'active'
    `, [hodDept]);

    const topCompaniesRes = await pool.query(`
      SELECT e.company_name as name, CAST(COUNT(e.id) AS INTEGER) as count
      FROM employment_history e
      JOIN alumni_profiles a ON e.user_id = a.user_id
      JOIN users u ON a.user_id = u.id
      WHERE a.department = $1 AND u.role = 'alumni' AND u.account_status = 'active'
      GROUP BY e.company_name
      ORDER BY count DESC
      LIMIT 5
    `, [hodDept]);

    const allDeptAlumniRes = await pool.query(`
      SELECT 
        a.id, u.email, a.first_name, a.last_name, a.course_name, a.graduation_year, a.student_id_number,
        (SELECT job_title FROM employment_history WHERE user_id = a.user_id ORDER BY id DESC LIMIT 1) as job_title,
        (SELECT company_name FROM employment_history WHERE user_id = a.user_id ORDER BY id DESC LIMIT 1) as company_name
      FROM alumni_profiles a
      JOIN users u ON a.user_id = u.id
      WHERE a.department = $1 AND u.role = 'alumni' AND u.account_status = 'active'
      ORDER BY a.graduation_year DESC, a.first_name ASC
    `, [hodDept]);

    const getFallbackAdvice = (dept: string) => {
      const d = dept.toLowerCase();
      if (d.includes('construction') || d.includes('civil')) return "Building Information Modeling (BIM) and Sustainable Materials";
      if (d.includes('commerce') || d.includes('business')) return "Data Analytics (Power BI) and FinTech Integration";
      if (d.includes('information') || d.includes('software')) return "Advanced Cloud Architecture (AWS/Azure) and AI Engineering";
      if (d.includes('electrical')) return "Renewable Energy Systems and IoT Integration";
      if (d.includes('mechanical')) return "Robotics Automation and CAD/CAM Advancements";
      return "Advanced Data Literacy and Modern AI Workflows";
    };

    let aiAdvice = "";
    try {
      const rawJobs = allDeptAlumniRes.rows.map(r => r.job_title).filter(Boolean);
      const uniqueJobs = [...new Set(rawJobs)].join(', ');

      if (process.env.GEMINI_API_KEY && uniqueJobs.length > 0) {
        const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
        const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });
        const prompt = `You are an expert academic curriculum advisor. The ${hodDept} department at a polytechnic college has graduates working in these roles: ${uniqueJobs}. Based ONLY on these job titles, recommend ONE specific, modern technical skill or technology they should add to their syllabus to stay relevant. Keep the response under 10 words, outputting ONLY the skill name.`;
        const result = await model.generateContent(prompt);
        aiAdvice = result.response.text().replace(/\n/g, '').trim();
      } else {
        throw new Error("Skip AI");
      }
    } catch {
      aiAdvice = getFallbackAdvice(hodDept || '');
    }

    res.json({
      department: hodDept,
      totalAlumni: parseInt(deptAlumniRes.rows[0].count),
      totalEmployed: parseInt(employedRes.rows[0].count),
      totalFurtherStudies: parseInt(studiesRes.rows[0].count),
      topCompanies: topCompaniesRes.rows,
      tableData: allDeptAlumniRes.rows,
      curriculumAdvice: aiAdvice
    });
  } catch (err: any) {
    console.error("🔴 HOD Stats Error:", err.message);
    res.status(500).json({ error: "Server Error" });
  }
});

// ==========================================
// 📢 PUBLIC RELATIONS (PRO) ROUTES
// ==========================================
app.post('/api/feedback/submit', verifyToken, async (req: any, res) => {
  try {
    const { category, message } = req.body;
    await pool.query("INSERT INTO feedback (user_id, category, message) VALUES ($1, $2, $3)", [req.user.user_id, category, message]);
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ error: "Server Error" });
  }
});

app.get('/api/pro/feedback', verifyToken, async (req: any, res) => {
  try {
    if (!hasRole(req.user.role, ['pro', 'principal', 'admin'])) return res.status(403).json({ error: "Access Denied" });
    const feedback = await pool.query(`
      SELECT f.id, f.category, f.message, f.created_at,
             a.first_name, a.last_name, a.department, a.graduation_year, u.email
      FROM feedback f
      LEFT JOIN alumni_profiles a ON f.user_id = a.user_id
      JOIN users u ON f.user_id = u.id
      WHERE u.role = 'alumni'
      ORDER BY f.created_at DESC
    `);
    res.json(feedback.rows);
  } catch (err: any) {
    res.status(500).json({ error: "Server Error" });
  }
});

app.post('/api/pro/broadcast', verifyToken, async (req: any, res) => {
  try {
    if (!hasRole(req.user.role, ['pro', 'principal', 'admin'])) {
      return res.status(403).json({ error: "Unauthorized. PRO access required." });
    }
    const { title, message } = req.body;
    const newBroadcast = await pool.query("INSERT INTO broadcasts (title, message) VALUES ($1, $2) RETURNING *", [title, message]);
    res.json(newBroadcast.rows[0]);
  } catch (err: any) {
    res.status(500).json({ error: "Server Error" });
  }
});

app.get('/api/alumni/broadcasts', verifyToken, async (req: any, res) => {
  try {
    const broadcasts = await pool.query("SELECT * FROM broadcasts ORDER BY created_at DESC LIMIT 5");
    res.json(broadcasts.rows);
  } catch (err: any) {
    res.status(500).json({ error: "Server Error" });
  }
});

// ==========================================
// 💼 JOBS, COMPANIES & MENTORSHIP
// ==========================================
app.get('/api/jobs', verifyToken, async (req: any, res) => {
  try {
    const jobs = await pool.query(`
      SELECT j.*, a.first_name, a.last_name, a.department, a.profile_picture_url 
      FROM job_postings j
      LEFT JOIN alumni_profiles a ON j.poster_id = a.user_id
      WHERE j.status = 'Approved' OR j.poster_id = $1 OR $2 = true
      ORDER BY j.created_at DESC
    `, [req.user.user_id, hasRole(req.user.role, ['pro', 'principal', 'admin'])]);
    res.json(jobs.rows);
  } catch (err: any) {
    res.status(500).json({ error: "Server Error" });
  }
});

app.post('/api/jobs', verifyToken, async (req: any, res) => {
  try {
    const { company_name, job_title, location, job_type, description, application_link } = req.body;
    const newJob = await pool.query(
      "INSERT INTO job_postings (poster_id, company_name, job_title, location, job_type, description, application_link) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *",
      [req.user.user_id, company_name, job_title, location, job_type, description, application_link]
    );
    res.json(newJob.rows[0]);
  } catch (err: any) {
    res.status(500).json({ error: "Server Error" });
  }
});

app.delete('/api/jobs/:id', verifyToken, async (req: any, res) => {
  try {
    const jobId = req.params.id;
    const checkJob = await pool.query("SELECT * FROM job_postings WHERE id = $1", [jobId]);
    if (checkJob.rows.length === 0) return res.status(404).json({ error: "Job posting not found" });

    if (checkJob.rows[0].poster_id !== req.user.user_id && !hasRole(req.user.role, ['pro', 'principal', 'admin'])) {
      return res.status(403).json({ error: "Unauthorized" });
    }

    await pool.query("DELETE FROM job_postings WHERE id = $1", [jobId]);
    res.json({ success: true, message: "Job posting deleted successfully" });
  } catch (err: any) {
    res.status(500).json({ error: "Server Error" });
  }
});

app.get('/api/pro/pending-jobs', verifyToken, async (req: any, res) => {
  try {
    if (!hasRole(req.user.role, ['pro', 'principal', 'admin'])) return res.status(403).json({ error: "Access Denied" });
    const result = await pool.query("SELECT * FROM job_postings WHERE status = 'Pending' ORDER BY created_at ASC");
    res.json(result.rows);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/pro/jobs/:id/verify', verifyToken, async (req: any, res) => {
  try {
    if (!hasRole(req.user.role, ['pro', 'principal', 'admin'])) return res.status(403).json({ error: "Access Denied" });
    const { status } = req.body;
    await pool.query("UPDATE job_postings SET status = $1 WHERE id = $2", [status, req.params.id]);
    res.json({ success: true, message: `Job ${status}` });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// Corporate Directory — Excludes any company accidentally created by non-alumni staff
app.get('/api/companies', async (req, res) => {
  try {
    const companies = await pool.query(`
      SELECT c.* FROM companies c
      LEFT JOIN users u ON c.founder_id = u.id
      WHERE c.founder_id IS NULL OR u.role = 'alumni'
      ORDER BY c.is_alumni_owned DESC, c.name ASC
    `);
    res.json(companies.rows);
  } catch (err: any) {
    res.status(500).json({ error: "Server Error" });
  }
});

app.post('/api/companies', verifyToken, async (req: any, res) => {
  try {
    const { name, industry, website, description } = req.body;
    const isAlumni = req.user.role === 'alumni';
    const newCompany = await pool.query(
      "INSERT INTO companies (name, industry, website, description, is_alumni_owned, founder_id) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *",
      [name, industry, website || null, description || null, isAlumni, isAlumni ? req.user.user_id : null]
    );
    res.json(newCompany.rows[0]);
  } catch (err: any) {
    res.status(500).json({ error: "Server Error" });
  }
});

// Mentors — Strictly role = 'alumni'
app.get('/api/mentors', verifyToken, async (req: any, res) => {
  try {
    const mentors = await pool.query(`
      SELECT a.user_id, a.first_name, a.last_name, a.department, a.course_name, a.graduation_year, a.mentorship_bio 
      FROM alumni_profiles a
      JOIN users u ON a.user_id = u.id
      WHERE a.is_mentor = true AND u.role = 'alumni' AND u.account_status = 'active'
      ORDER BY a.graduation_year ASC
    `);
    res.json(mentors.rows);
  } catch (err: any) {
    res.status(500).json({ error: "Server Error" });
  }
});

app.put('/api/mentors/toggle', verifyToken, async (req: any, res) => {
  try {
    if (req.user.role !== 'alumni') {
      return res.status(403).json({ error: "Only Alumni accounts can appear in the Mentorship directory." });
    }
    const { is_mentor, mentorship_bio } = req.body;
    const updated = await pool.query(
      "UPDATE alumni_profiles SET is_mentor = $1, mentorship_bio = $2 WHERE user_id = $3 RETURNING is_mentor, mentorship_bio",
      [is_mentor, mentorship_bio, req.user.user_id]
    );
    res.json(updated.rows[0]);
  } catch (err: any) {
    res.status(500).json({ error: "Server Error" });
  }
});

// ==========================================
// 🛠️ IT SUPPORT, STAFF APPROVAL & SUPER ADMIN USER ENGINE
// ==========================================
app.post('/api/auth/request-reset', async (req, res) => {
  try {
    const { email } = req.body;
    const userCheck = await pool.query("SELECT id FROM users WHERE LOWER(email) = LOWER($1)", [email]);
    if (userCheck.rows.length === 0) {
      return res.json({ success: true, message: "If your email exists in our system, a request has been sent to IT Support." });
    }
    const userId = userCheck.rows[0].id;
    const existingTicket = await pool.query("SELECT id FROM password_resets WHERE user_id = $1 AND status = 'Pending'", [userId]);
    if (existingTicket.rows.length === 0) {
      await pool.query("INSERT INTO password_resets (user_id, email, status) VALUES ($1, $2, 'Pending')", [userId, email]);
    }
    res.json({ success: true, message: "If your email exists in our system, a request has been sent to IT Support." });
  } catch (err: any) {
    res.status(500).json({ error: "Server Error" });
  }
});

app.get('/api/it/reset-requests', verifyToken, async (req: any, res) => {
  try {
    if (!hasRole(req.user.role, ['it'])) return res.status(403).json({ error: "IT Privileges Required." });
    const tickets = await pool.query(`
      SELECT pr.id, pr.email, pr.status, pr.created_at, a.first_name, a.last_name, a.student_id_number
      FROM password_resets pr
      LEFT JOIN alumni_profiles a ON pr.user_id = a.user_id
      WHERE pr.status = 'Pending'
      ORDER BY pr.created_at ASC
    `);
    res.json(tickets.rows);
  } catch (err: any) {
    res.status(500).json({ error: "Server Error" });
  }
});

// FIXED: Updates password_hash (previously tried to update non-existent 'password' column)
app.put('/api/it/resolve-reset', verifyToken, async (req: any, res) => {
  try {
    if (!hasRole(req.user.role, ['it'])) return res.status(403).json({ error: "IT Privileges Required." });
    const { ticket_id, email, temp_password } = req.body;
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(temp_password, salt);

    await pool.query("UPDATE users SET password_hash = $1 WHERE LOWER(email) = LOWER($2)", [hashedPassword, email]);
    await pool.query("UPDATE password_resets SET status = 'Resolved' WHERE id = $1", [ticket_id]);
    res.json({ success: true, message: "Temporary password generated and applied." });
  } catch (err: any) {
    res.status(500).json({ error: "Server Error" });
  }
});

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER || 'your-email@gmail.com',
    pass: process.env.EMAIL_PASS || 'your-app-password'
  }
});

app.post('/api/auth/send-reset-email', async (req, res) => {
  try {
    const { email } = req.body;
    const userCheck = await pool.query("SELECT id, email FROM users WHERE LOWER(email) = LOWER($1)", [email]);
    if (userCheck.rows.length === 0) {
      return res.json({ success: true, message: "If your email exists, a reset link has been sent." });
    }

    const userId = userCheck.rows[0].id;
    const resetToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 3600000); // 1 hour from now

    await pool.query(
      "INSERT INTO password_resets (user_id, email, status, reset_token, expires_at) VALUES ($1, $2, 'Pending', $3, $4)",
      [userId, email, resetToken, expiresAt]
    );

    const frontendUrl = process.env.FRONTEND_URL || 'https://harare-poly-alumni.vercel.app';
    const resetLink = `${frontendUrl}/reset-password?token=${resetToken}&email=${email}`;

    const mailOptions = {
      from: `"Harare Poly Alumni Support" <${process.env.EMAIL_USER || 'your-email@gmail.com'}>`,
      to: email,
      subject: 'Password Reset Request',
      html: `
        <h2>Password Reset</h2>
        <p>You requested to reset your Harare Polytechnic Alumni Network password.</p>
        <p>Click the link below to set a new password. This link expires in 1 hour.</p>
        <a href="${resetLink}" style="padding: 10px 20px; background-color: #1e3a8a; color: white; text-decoration: none; border-radius: 5px; display: inline-block;">Reset Password</a>
        <p>If you did not request this, please ignore this email.</p>
      `
    };

    transporter.sendMail(mailOptions, (error) => {
      if (error) {
        console.error("🔴 Email Send Error:", error);
      }
    });

    res.json({ success: true, message: "If your email exists, a reset link has been sent." });
  } catch (err: any) {
    console.error("🔴 Error sending reset email:", err.message);
    res.status(500).json({ error: "Server Error" });
  }
});

app.post('/api/auth/reset-password-with-token', async (req, res) => {
  try {
    const { email, token, newPassword } = req.body;
    const ticketCheck = await pool.query(
      "SELECT id FROM password_resets WHERE LOWER(email) = LOWER($1) AND reset_token = $2 AND status = 'Pending' AND expires_at > NOW()",
      [email, token]
    );
    if (ticketCheck.rows.length === 0) return res.status(400).json({ error: "Invalid or expired reset link." });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    await pool.query("UPDATE users SET password_hash = $1 WHERE LOWER(email) = LOWER($2)", [hashedPassword, email]);
    await pool.query("UPDATE password_resets SET status = 'Resolved' WHERE id = $1", [ticketCheck.rows[0].id]);
    res.json({ success: true, message: "Password updated successfully!" });
  } catch (err: any) {
    res.status(500).json({ error: "Server Error" });
  }
});

// Fetch Users (Hides Super Admins from regular IT view so IT cannot tamper with them)
app.get('/api/it/users', verifyToken, async (req: any, res) => {
  try {
    if (!hasRole(req.user.role, ['it'])) {
      return res.status(403).json({ error: "Access Denied: IT or Super Admin Privileges Required." });
    }

    const isSuper = req.user.role === 'super_admin';
    const users = await pool.query(`
      SELECT u.id, u.email, u.role, u.account_status, u.created_at,
             a.first_name, a.last_name, a.department, a.student_id_number
      FROM users u
      LEFT JOIN alumni_profiles a ON u.id = a.user_id
      WHERE ($1 = true OR u.role != 'super_admin')
      ORDER BY CASE WHEN u.account_status = 'pending_staff' THEN 0 ELSE 1 END, u.created_at DESC
    `, [isSuper]);

    res.json(users.rows);
  } catch (err: any) {
    res.status(500).json({ error: "Server Error" });
  }
});

// Approve Pending Staff Account (Enforces Strict Role Quotas!)
app.put('/api/it/users/:id/approve', verifyToken, async (req: any, res) => {
  try {
    if (!hasRole(req.user.role, ['it'])) {
      return res.status(403).json({ error: "Access Denied." });
    }

    const targetId = parseInt(req.params.id, 10);
    const userRes = await pool.query(
      `SELECT u.id, u.role, u.account_status, a.department
       FROM users u LEFT JOIN alumni_profiles a ON u.id = a.user_id
       WHERE u.id = $1`,
      [targetId]
    );

    if (userRes.rows.length === 0) return res.status(404).json({ error: "Account not found." });
    const target = userRes.rows[0];

    // Only Super Admin can approve Principal or Vice Principal accounts
    if ((target.role === 'principal' || target.role === 'vp' || target.role === 'admin') && req.user.role !== 'super_admin') {
      return res.status(403).json({ error: "Only a Super Admin can approve Principal or Vice Principal accounts." });
    }

    const quotaError = await checkQuotaAvailability(target.role, target.department, targetId);
    if (quotaError) return res.status(400).json({ error: quotaError });

    await pool.query("UPDATE users SET account_status = 'active' WHERE id = $1", [targetId]);
    res.json({ success: true, message: `${target.role.toUpperCase()} account approved and activated!` });
  } catch (err: any) {
    res.status(400).json({ error: err.message || "Failed to approve staff account." });
  }
});

// Super Admin: Direct Create Any Account (Staff or Alumni)
app.post('/api/super-admin/users', verifyToken, async (req: any, res) => {
  try {
    if (req.user.role !== 'super_admin') {
      return res.status(403).json({ error: "Only Super Admins can directly create accounts." });
    }

    const { first_name, last_name, email, password, role, department, graduation_year, course_name, student_id_number } = req.body;
    const cleanEmail = email.trim().toLowerCase();

    if (role === 'super_admin') {
      return res.status(400).json({ error: "Super Admins are strictly managed via backend environment configuration (Max 2)." });
    }

    const existing = await pool.query("SELECT id FROM users WHERE LOWER(email) = $1", [cleanEmail]);
    if (existing.rows.length > 0) return res.status(400).json({ error: "Email already exists." });

    const quotaError = await checkQuotaAvailability(role, department);
    if (quotaError) return res.status(400).json({ error: quotaError });

    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);

    await pool.query("BEGIN");
    const newU = await pool.query(
      "INSERT INTO users (email, password_hash, role, account_status) VALUES ($1, $2, $3, 'active') RETURNING id",
      [cleanEmail, hash, role]
    );

    const isStaff = role !== 'alumni';
    await pool.query(
      `INSERT INTO alumni_profiles (user_id, first_name, last_name, student_id_number, graduation_year, department, course_name)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        newU.rows[0].id,
        first_name,
        last_name,
        student_id_number || null,
        isStaff ? null : (graduation_year ? parseInt(graduation_year) : null),
        department || (isStaff ? 'Administration' : ''),
        isStaff ? `Staff (${role.toUpperCase()})` : (course_name || '')
      ]
    );
    await pool.query("COMMIT");

    res.status(201).json({ success: true, message: "Account created and activated!" });
  } catch (err: any) {
    await pool.query("ROLLBACK");
    res.status(400).json({ error: err.message || "Failed to create account." });
  }
});

// Delete User (Super Admin can delete ANY non-super_admin account; IT can delete alumni & pending requests)
app.delete('/api/it/users/:id', verifyToken, async (req: any, res) => {
  try {
    if (!hasRole(req.user.role, ['it'])) {
      return res.status(403).json({ error: "Access Denied." });
    }

    const targetUserId = parseInt(req.params.id, 10);
    const targetCheck = await pool.query("SELECT role, account_status FROM users WHERE id = $1", [targetUserId]);
    if (targetCheck.rows.length === 0) return res.status(404).json({ error: "User not found." });

    const targetRole = targetCheck.rows[0].role;
    const targetStatus = targetCheck.rows[0].account_status;

    if (targetRole === 'super_admin') {
      return res.status(403).json({ error: "Super Admin accounts are protected and cannot be deleted." });
    }

    // Regular IT cannot delete active staff/executives—only Super Admin can
    if (req.user.role !== 'super_admin' && targetRole !== 'alumni' && targetStatus === 'active') {
      return res.status(403).json({ error: "Only a Super Admin can delete active Staff or Executive accounts." });
    }

    await pool.query("BEGIN");
    await pool.query("DELETE FROM password_resets WHERE user_id = $1", [targetUserId]);
    await pool.query("DELETE FROM connection_requests WHERE sender_id = $1 OR receiver_id = $2", [targetUserId, targetUserId]);
    try { await pool.query("DELETE FROM feedback WHERE user_id = $1", [targetUserId]); } catch {}
    try { await pool.query("DELETE FROM employment_history WHERE user_id = $1", [targetUserId]); } catch {}
    try { await pool.query("DELETE FROM further_studies WHERE user_id = $1", [targetUserId]); } catch {}
    try { await pool.query("DELETE FROM job_postings WHERE poster_id = $1", [targetUserId]); } catch {}
    try { await pool.query("UPDATE companies SET founder_id = NULL WHERE founder_id = $1", [targetUserId]); } catch {}
    await pool.query("DELETE FROM alumni_profiles WHERE user_id = $1", [targetUserId]);
    await pool.query("DELETE FROM users WHERE id = $1", [targetUserId]);
    await pool.query("COMMIT");

    res.json({ success: true, message: "User account permanently deleted." });
  } catch (err: any) {
    await pool.query("ROLLBACK");
    res.status(500).json({ error: "Failed to delete user." });
  }
});

// ==========================================
// 🖼️ GALLERY, STORIES, TRENDS & MARKETPLACE
// ==========================================
app.get('/api/gallery', async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM gallery_highlights ORDER BY created_at DESC");
    res.json(result.rows);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/pro/gallery', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM gallery_highlights ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch gallery highlights' });
  }
});

app.post('/api/pro/gallery', verifyToken, async (req: any, res) => {
  if (!hasRole(req.user.role, ['pro', 'principal', 'admin'])) {
    return res.status(403).json({ error: 'Only PR can post highlights' });
  }
  const { title, description, image_url, category } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO gallery_highlights (title, description, image_url, category) VALUES ($1, $2, $3, $4) RETURNING *',
      [title, description, image_url, category || 'Achievement']
    );
    res.status(201).json(result.rows[0]);
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to add gallery highlight' });
  }
});

app.delete('/api/pro/gallery/:id', verifyToken, async (req: any, res) => {
  if (!hasRole(req.user.role, ['pro', 'principal', 'admin'])) {
    return res.status(403).json({ error: 'Only PR can delete highlights' });
  }
  try {
    await pool.query('DELETE FROM gallery_highlights WHERE id = $1', [req.params.id]);
    res.json({ message: 'Highlight deleted successfully' });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to delete gallery highlight' });
  }
});

app.get('/api/stories/latest', async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM alumni_stories ORDER BY created_at DESC LIMIT 1");
    res.json(result.rows[0] || null);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/stories/:id', async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM alumni_stories WHERE id = $1", [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: "Story not found" });
    res.json(result.rows[0]);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/stories', verifyToken, async (req: any, res) => {
  if (!hasRole(req.user.role, ['pro', 'principal', 'admin'])) {
    return res.status(403).json({ error: "Unauthorized. Only PR Officers can publish stories." });
  }
  const { title, excerpt, content, image_url } = req.body;
  if (!title || !excerpt || !content) return res.status(400).json({ error: "Title, excerpt, and content are required." });

  try {
    const result = await pool.query(
      "INSERT INTO alumni_stories (title, excerpt, content, image_url) VALUES ($1, $2, $3, $4) RETURNING *",
      [title, excerpt, content, image_url]
    );
    res.json({ success: true, story: result.rows[0] });
  } catch (err: any) {
    res.status(500).json({ error: "Failed to publish story" });
  }
});

// Public Trends — Strictly counts ONLY active 'alumni' jobs!
app.get('/api/public/trends', async (req, res) => {
  try {
    const topJobsRes = await pool.query(`
      SELECT e.job_title as name, COUNT(e.id) as count
      FROM employment_history e
      JOIN users u ON e.user_id = u.id
      WHERE e.job_title IS NOT NULL AND e.job_title != '' AND u.role = 'alumni' AND u.account_status = 'active'
      GROUP BY e.job_title
      ORDER BY count DESC
      LIMIT 3
    `);

    const topCompaniesRes = await pool.query(`
      SELECT e.company_name as name, COUNT(e.id) as count
      FROM employment_history e
      JOIN users u ON e.user_id = u.id
      WHERE e.company_name IS NOT NULL AND e.company_name != '' AND u.role = 'alumni' AND u.account_status = 'active'
      GROUP BY e.company_name
      ORDER BY count DESC
      LIMIT 4
    `);

    res.json({
      trendingProfessions: topJobsRes.rows,
      topCompanies: topCompaniesRes.rows
    });
  } catch (err: any) {
    res.status(500).json({ error: "Failed to fetch trends" });
  }
});

// Marketplace Routes
app.get('/api/marketplace', async (req, res) => {
  try {
    const featuredOnly = req.query.featured === 'true';
    const query = featuredOnly
      ? "SELECT * FROM products_services WHERE is_featured = true ORDER BY created_at DESC LIMIT 3"
      : "SELECT * FROM products_services ORDER BY is_featured DESC, created_at DESC";
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (err: any) {
    res.status(500).json({ error: "Failed to fetch marketplace items" });
  }
});

app.post('/api/pro/marketplace', verifyToken, async (req: any, res) => {
  try {
    if (!hasRole(req.user.role, ['pro', 'principal', 'admin'])) {
      return res.status(403).json({ error: "Unauthorized. PRO access required." });
    }
    const { company_name, title, category, description, price, image_url, contact_phone, contact_email, is_featured } = req.body;
    if (!company_name || !title) return res.status(400).json({ error: "Company name and title are required." });

    const result = await pool.query(
      `INSERT INTO products_services 
       (company_name, title, category, description, price, image_url, contact_phone, contact_email, is_featured) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [company_name, title, category || 'Product', description || '', price || 'Request Quote', image_url || '', contact_phone || '', contact_email || '', Boolean(is_featured)]
    );
    res.status(201).json(result.rows[0]);
  } catch (err: any) {
    res.status(500).json({ error: "Failed to add marketplace item" });
  }
});

app.patch('/api/pro/marketplace/:id/feature', verifyToken, async (req: any, res) => {
  try {
    if (!hasRole(req.user.role, ['pro', 'principal', 'admin'])) {
      return res.status(403).json({ error: "Unauthorized. PRO access required." });
    }
    const { is_featured } = req.body;
    const result = await pool.query(
      "UPDATE products_services SET is_featured = $1 WHERE id = $2 RETURNING *",
      [Boolean(is_featured), req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Item not found" });
    res.json(result.rows[0]);
  } catch (err: any) {
    res.status(500).json({ error: "Failed to update featured status" });
  }
});

app.delete('/api/pro/marketplace/:id', verifyToken, async (req: any, res) => {
  try {
    if (!hasRole(req.user.role, ['pro', 'principal', 'admin'])) {
      return res.status(403).json({ error: "Unauthorized. PRO access required." });
    }
    await pool.query("DELETE FROM products_services WHERE id = $1", [req.params.id]);
    res.json({ success: true, message: "Marketplace item deleted" });
  } catch (err: any) {
    res.status(500).json({ error: "Failed to delete marketplace item" });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});