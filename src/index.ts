import express from 'express';
import pool from './db';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer'; // NEW: Import nodemailer
import crypto from 'crypto'; // NEW: Built-in Node library for secure tokens
import { GoogleGenerativeAI } from '@google/generative-ai';

const app = express();
const PORT = 3000;
const JWT_SECRET = 'harare_poly_super_secret_key_2026';

app.use(cors());
app.use(express.json()); 

app.get('/', (req, res) => {
  res.send('Harare Poly Alumni API is live!');
});

// 1. Route to ADD a company
app.post('/api/companies', async (req, res) => {
  try {
    const { name, industry } = req.body; 
    const newCompany = await pool.query(
      "INSERT INTO companies (name, industry) VALUES ($1, $2) RETURNING *",
      [name, industry]
    );
    res.json(newCompany.rows[0]);
  } catch (err: any) {
    console.error(err.message);
    res.status(500).send("Server Error");
  }
});

// 2. Route to GET all companies
app.get('/api/companies', async (req, res) => {
  try {
    const allCompanies = await pool.query("SELECT * FROM companies");
    res.json(allCompanies.rows);
  } catch (err: any) {
    console.error(err.message);
    res.status(500).send("Server Error");
  }
});

// 3. Route to Register Alumnus (with Automated HOD Detection)
app.post('/api/alumni/register', async (req, res) => {
  try {
    const { first_name, last_name, student_id_number, graduation_year, department, course_name, email, password } = req.body;
    
    // Convert empty string to proper NULL so it doesn't trigger duplicate errors
    const finalStudentId = student_id_number.trim() === '' ? null : student_id_number.trim();

    // Check if user already exists
    const userExists = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (userExists.rows.length > 0) {
        return res.status(400).json({ error: "Email is already registered" });
    }
    
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    // 🚀 NEW: AUTOMATED ROLE PROVISIONING 🚀
    // If the email ends with .hod@hrepoly.ac.zw, make them an HOD. Otherwise, normal alumni.
    let assignedRole = 'alumni';
    if (email.toLowerCase().endsWith('.hod@hrepoly.ac.zw')) {
        assignedRole = 'hod';
        console.log(`🟢 AUTO-PROVISION: Assigned HOD role to ${email}`);
    }

    const newUser = await pool.query(
        "INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3) RETURNING id",
        [email, passwordHash, assignedRole] // Uses our dynamic role variable!
    );
    const userId = newUser.rows[0].id;

    const newAlumnus = await pool.query(
        "INSERT INTO alumni_profiles (user_id, first_name, last_name, student_id_number, graduation_year, department, course_name) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *",
        [userId, first_name, last_name, finalStudentId, graduation_year, department, course_name]
    );

    const token = jwt.sign({ user_id: userId, role: assignedRole }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, profile: newAlumnus.rows[0] });
  } catch (err: any) {
    console.error(err.message);
    res.status(500).json({ error: "Server Error" });
  }
});

// 4. ROUTE: Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const userResult = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (userResult.rows.length === 0) return res.status(400).json({ error: "Invalid credentials" });
    
    const user = userResult.rows[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign({ user_id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, role: user.role });
  } catch (err: any) {
    console.error(err.message);
    res.status(500).json({ error: "Server Error" });
  }
});

const verifyToken = (req: any, res: any, next: any) => {
  const token = req.header('Authorization');
  if (!token) return res.status(401).json({ error: 'Access denied' });

  try {
    const verified = jwt.verify(token.replace('Bearer ', ''), JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    // Changed to 401 Unauthorized so the frontend knows to log the user out
    res.status(401).json({ error: 'Invalid or expired token' });
  }
};

// 5. Get My Profile 
app.get('/api/alumni/me', verifyToken, async (req: any, res) => {
  try {
    const userQuery = await pool.query('SELECT email FROM users WHERE id = $1', [req.user.user_id]);
    const profileQuery = await pool.query('SELECT * FROM alumni_profiles WHERE user_id = $1', [req.user.user_id]);
    if (profileQuery.rows.length === 0) return res.status(404).json({ error: 'Profile not found' });

    const employmentData = await pool.query("SELECT * FROM employment_history WHERE user_id = $1 ORDER BY id DESC", [req.user.user_id]);
    const studiesData = await pool.query("SELECT * FROM further_studies WHERE user_id = $1 ORDER BY graduation_year DESC", [req.user.user_id]);

    const fullProfile = {
        ...profileQuery.rows[0],
        email: userQuery.rows[0]?.email || '',
        employment: employmentData.rows,
        studies: studiesData.rows
    };
    res.json(fullProfile);
  } catch (err: any) {
    console.error("CRASH DETAILS:", err.message);
    res.status(500).json({ error: err.message }); 
  }
});

// 6. Add Employment History
app.post('/api/alumni/employment', verifyToken, async (req: any, res) => {
    try {
        const { company_name, job_title, start_date, end_date, is_current } = req.body;
        const newJob = await pool.query(
            "INSERT INTO employment_history (user_id, company_name, job_title, start_date, end_date, is_current) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *",
            [req.user.user_id, company_name, job_title, start_date, end_date, is_current]
        );
        
        const companyCheck = await pool.query("SELECT * FROM companies WHERE name ILIKE $1", [company_name]);
        if (companyCheck.rows.length === 0) {
             await pool.query("INSERT INTO companies (name, industry) VALUES ($1, $2)", [company_name, "Various"]);
        }
        res.json(newJob.rows[0]);
    } catch (err: any) {
        console.error(err.message);
        res.status(500).json({ error: "Server Error" });
    }
});

// 7. Add Further Studies
app.post('/api/alumni/studies', verifyToken, async (req: any, res) => {
    try {
        const { institution_name, degree_obtained, field_of_study, graduation_year } = req.body;
        const newStudy = await pool.query(
            "INSERT INTO further_studies (user_id, institution_name, degree_obtained, field_of_study, graduation_year) VALUES ($1, $2, $3, $4, $5) RETURNING *",
            [req.user.user_id, institution_name, degree_obtained, field_of_study, graduation_year]
        );
        res.json(newStudy.rows[0]);
    } catch (err: any) {
        console.error(err.message);
        res.status(500).json({ error: "Server Error" });
    }
});

// 8. Network Directory Route
app.get('/api/alumni/network', verifyToken, async (req: any, res) => {
    console.log("🟡 NETWORK ROUTE HIT! Token verified.");
    try {
        const network = await pool.query(`
            SELECT 
                a.id, 
                a.user_id, 
                a.first_name, 
                a.last_name, 
                a.department, 
                a.course_name, 
                a.graduation_year,
                (SELECT job_title FROM employment_history WHERE user_id = a.user_id ORDER BY id DESC LIMIT 1) as current_job,
                (SELECT company_name FROM employment_history WHERE user_id = a.user_id ORDER BY id DESC LIMIT 1) as current_company
            FROM alumni_profiles a
            JOIN users u ON a.user_id = u.id
            WHERE u.role = 'alumni' AND a.user_id != $1
            ORDER BY a.graduation_year DESC, a.first_name ASC
        `, [req.user.user_id]);
        
        console.log(`🟢 Network Success! Found ${network.rows.length} profiles.`);
        res.json(network.rows);
    } catch (err: any) {
        console.error("🔴 Network Fetch Error:", err.message);
        res.status(500).json({ error: "Server Error" });
    }
});

// 5. Route to Update Alumni Profile (Phone & LinkedIn)
app.put('/api/alumni/profile', verifyToken, async (req: any, res) => {
    try {
        const { phone_number, linkedin_url } = req.body;
        
        await pool.query(
            "UPDATE alumni_profiles SET phone_number = $1, linkedin_url = $2 WHERE user_id = $3",
            [phone_number, linkedin_url, req.user.user_id]
        );
        
        res.json({ success: true });
    } catch (err: any) {
        console.error("🔴 Profile Update Error:", err.message);
        res.status(500).json({ error: "Server Error" });
    }
});

// A. Send a Connection Request
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
    } catch (err: any) { res.status(500).json({ error: "Server Error" }); }
});

// B. Get My Inbox 
app.get('/api/connections/inbox', verifyToken, async (req: any, res) => {
    try {
        const inbox = await pool.query(
            `SELECT c.*, a.first_name, a.last_name, a.department, a.course_name 
             FROM connection_requests c 
             JOIN alumni_profiles a ON c.sender_id = a.user_id 
             WHERE c.receiver_id = $1 AND c.status = 'Pending'
             ORDER BY c.created_at DESC`,
            [req.user.user_id]
        );
        res.json(inbox.rows);
    } catch (err: any) { res.status(500).json({ error: "Server Error" }); }
});

// C. Respond to a Request
app.put('/api/connections/respond', verifyToken, async (req: any, res) => {
    try {
        const { request_id, status, shared_info_type, shared_info_value } = req.body;
        const updateRequest = await pool.query(
            "UPDATE connection_requests SET status = $1, shared_info_type = $2, shared_info_value = $3 WHERE id = $4 AND receiver_id = $5 RETURNING *",
            [status, shared_info_type, shared_info_value, request_id, req.user.user_id]
        );
        if (updateRequest.rows.length === 0) return res.status(404).json({ error: "Request not found or unauthorized." });
        res.json(updateRequest.rows[0]);
    } catch (err: any) { res.status(500).json({ error: "Server Error" }); }
});

// D. Get My Connections
app.get('/api/connections/my-connections', verifyToken, async (req: any, res) => {
    try {
        const myConnections = await pool.query(
            `SELECT c.*, a.first_name, a.last_name, a.department 
             FROM connection_requests c 
             JOIN alumni_profiles a ON c.receiver_id = a.user_id 
             WHERE c.sender_id = $1
             ORDER BY c.created_at DESC`,
            [req.user.user_id]
        );
        res.json(myConnections.rows);
    } catch (err: any) { res.status(500).json({ error: "Server Error" }); }
});

// ==========================================
// THE PUBLIC RELATIONS (PRO) ENGINE
// ==========================================

// 1. PRO: Read all incoming Feedback, Memories, and Partnerships
// 2. PRO: Read all Feedback on Dashboard
app.get('/api/pro/feedback', verifyToken, async (req: any, res) => {
    try {
        const feedback = await pool.query(`
            SELECT 
                f.id, f.category, f.message, f.created_at,
                a.first_name, a.last_name, a.department, a.graduation_year,
                u.email
            FROM feedback f
            LEFT JOIN alumni_profiles a ON f.user_id = a.user_id
            JOIN users u ON f.user_id = u.id
            ORDER BY f.created_at DESC
        `);
        res.json(feedback.rows);
    } catch (err: any) {
        console.error("🔴 PRO Feedback Fetch Error:", err.message);
        res.status(500).json({ error: "Server Error" });
    }
});

// 2. PRO: Send a Broadcast Notification to all Alumni
app.post('/api/pro/broadcast', verifyToken, async (req: any, res) => {
    try {
        if (req.user.role !== 'pro' && req.user.role !== 'admin') {
            return res.status(403).json({ error: "Unauthorized. PRO access required." });
        }
        const { title, message } = req.body;
        const newBroadcast = await pool.query(
            "INSERT INTO broadcasts (title, message) VALUES ($1, $2) RETURNING *",
            [title, message]
        );
        res.json(newBroadcast.rows[0]);
    } catch (err: any) { res.status(500).json({ error: "Server Error" }); }
});

// 3. ALUMNI: Read Broadcasts on their Profile
app.get('/api/alumni/broadcasts', verifyToken, async (req: any, res) => {
    try {
        const broadcasts = await pool.query("SELECT * FROM broadcasts ORDER BY created_at DESC LIMIT 5");
        res.json(broadcasts.rows);
    } catch (err: any) { res.status(500).json({ error: "Server Error" }); }
});

// E. Principal Dashboard Analytics (UPGRADED)
app.get('/api/dashboard/stats', verifyToken, async (req: any, res) => {
    console.log("🟡 DASHBOARD ROUTE HIT! Fetching Analytics...");
    try {
        const totalAlumniRes = await pool.query("SELECT COUNT(*) FROM alumni_profiles");
        const totalCompaniesRes = await pool.query("SELECT COUNT(DISTINCT company_name) FROM employment_history");
        
        // THE MISSING INSIGHT QUERIES
        const employedRes = await pool.query("SELECT COUNT(DISTINCT user_id) FROM employment_history");
        const studiesRes = await pool.query("SELECT COUNT(DISTINCT user_id) FROM further_studies");

        const deptStatsRes = await pool.query(`
            SELECT department as name, CAST(COUNT(*) AS INTEGER) as "Alumni"
            FROM alumni_profiles
            GROUP BY department
        `);

        const allAlumniRes = await pool.query(`
            SELECT 
                a.id, 
                u.email,
                a.first_name, 
                a.last_name, 
                a.department, 
                a.course_name, 
                a.graduation_year, 
                a.student_id_number,
                (SELECT job_title FROM employment_history WHERE user_id = a.user_id ORDER BY id DESC LIMIT 1) as job_title,
                (SELECT company_name FROM employment_history WHERE user_id = a.user_id ORDER BY id DESC LIMIT 1) as company_name
            FROM alumni_profiles a
            JOIN users u ON a.user_id = u.id
            ORDER BY a.id DESC
        `);

        console.log(`🟢 Dashboard Success! Sending ${allAlumniRes.rows.length} rows with insights.`);
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

// F. HOD Dashboard Analytics (Department Specific & AI Powered)
app.get('/api/hod/stats', verifyToken, async (req: any, res) => {
    try {
        // 1. Get the HOD's department
        const hodProfile = await pool.query("SELECT department FROM alumni_profiles WHERE user_id = $1", [req.user.user_id]);
        if (hodProfile.rows.length === 0) return res.status(404).json({ error: "HOD profile not found" });
        const hodDept = hodProfile.rows[0].department;

        // 2. Get department-specific stats
        const deptAlumniRes = await pool.query("SELECT COUNT(*) FROM alumni_profiles WHERE department = $1", [hodDept]);
        
        const employedRes = await pool.query(`
            SELECT COUNT(DISTINCT e.user_id) 
            FROM employment_history e
            JOIN alumni_profiles a ON e.user_id = a.user_id
            WHERE a.department = $1
        `, [hodDept]);

        const studiesRes = await pool.query(`
            SELECT COUNT(DISTINCT f.user_id) 
            FROM further_studies f
            JOIN alumni_profiles a ON f.user_id = a.user_id
            WHERE a.department = $1
        `, [hodDept]);

        const topCompaniesRes = await pool.query(`
            SELECT e.company_name as name, CAST(COUNT(e.id) AS INTEGER) as count
            FROM employment_history e
            JOIN alumni_profiles a ON e.user_id = a.user_id
            WHERE a.department = $1
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
            WHERE a.department = $1
            ORDER BY a.graduation_year DESC, a.first_name ASC
        `, [hodDept]);

        // 3. 🧠 LIVE AI CURRICULUM ANALYSIS 🧠
        let aiAdvice = "";
        
        // The Fallback System
        const getFallbackAdvice = (dept: string) => {
            const d = dept.toLowerCase();
            if (d.includes('construction') || d.includes('civil')) return "Building Information Modeling (BIM) and Sustainable Materials";
            if (d.includes('commerce') || d.includes('business')) return "Data Analytics (Power BI) and FinTech Integration";
            if (d.includes('information') || d.includes('software')) return "Advanced Cloud Architecture (AWS/Azure) and AI Engineering";
            if (d.includes('electrical')) return "Renewable Energy Systems and IoT Integration";
            if (d.includes('mechanical')) return "Robotics Automation and CAD/CAM Advancements";
            return "Advanced Data Literacy and Modern AI Workflows";
        };

        try {
            // Extract a unique list of what jobs alumni are actually doing right now
            const rawJobs = allDeptAlumniRes.rows.map(r => r.job_title).filter(Boolean);
            const uniqueJobs = [...new Set(rawJobs)].join(', ');

            if (process.env.GEMINI_API_KEY && uniqueJobs.length > 0) {
                const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
                const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });
                
                const prompt = `You are an expert academic curriculum advisor. The ${hodDept} department at a polytechnic college has graduates working in these roles: ${uniqueJobs}. Based ONLY on these job titles, recommend ONE specific, modern technical skill or technology they should add to their syllabus to stay relevant. Keep the response under 10 words, outputting ONLY the skill name (e.g., "Advanced Cloud Computing").`;
                
                const result = await model.generateContent(prompt);
                aiAdvice = result.response.text().replace(/\n/g, '').trim();
                console.log(`🟢 AI Advice Generated for ${hodDept}: ${aiAdvice}`);
            } else {
                throw new Error("No API key or no job data available.");
            }
        } catch (error) {
            console.error("🟡 AI Generation skipped or failed, using smart fallback.");
            aiAdvice = getFallbackAdvice(hodDept);
        }

        res.json({
            department: hodDept,
            totalAlumni: parseInt(deptAlumniRes.rows[0].count),
            totalEmployed: parseInt(employedRes.rows[0].count),
            totalFurtherStudies: parseInt(studiesRes.rows[0].count),
            topCompanies: topCompaniesRes.rows,
            tableData: allDeptAlumniRes.rows,
            curriculumAdvice: aiAdvice // Send the final advice (AI or Fallback) to the frontend
        });

    } catch (err: any) {
        console.error("🔴 HOD Stats Error:", err.message);
        res.status(500).json({ error: "Server Error" });
    }
});

// ==========================================
// 📢 PUBLIC RELATIONS (PRO) ROUTES
// ==========================================

// 1. ALUMNI: Submit Feedback to PRO
app.post('/api/feedback/submit', verifyToken, async (req: any, res) => {
    try {
        const { category, message } = req.body;
        const user_id = req.user.user_id;

        await pool.query(
            "INSERT INTO feedback (user_id, category, message) VALUES ($1, $2, $3)",
            [user_id, category, message]
        );
        
        res.json({ success: true });
    } catch (err: any) {
        console.error("🔴 Feedback Submit Error:", err.message);
        res.status(500).json({ error: "Server Error" });
    }
});

// 2. PRO: Read all Feedback on Dashboard
app.get('/api/pro/feedback', verifyToken, async (req: any, res) => {
    try {
        const feedback = await pool.query(`
            SELECT 
                f.id, f.category, f.message, f.created_at,
                a.first_name, a.last_name, a.department, a.graduation_year,
                u.email
            FROM feedback f
            JOIN alumni_profiles a ON f.user_id = a.user_id
            JOIN users u ON f.user_id = u.id
            ORDER BY f.created_at DESC
        `);
        res.json(feedback.rows);
    } catch (err: any) {
        console.error("🔴 PRO Feedback Fetch Error:", err.message);
        res.status(500).json({ error: "Server Error" });
    }
});

// 3. PRO: Send Broadcast to all Alumni
app.post('/api/pro/broadcast', verifyToken, async (req: any, res) => {
    try {
        const { title, message } = req.body;
        await pool.query(
            "INSERT INTO broadcasts (title, message) VALUES ($1, $2)",
            [title, message]
        );
        res.json({ success: true });
    } catch (err: any) {
        console.error("🔴 Broadcast Error:", err.message);
        res.status(500).json({ error: "Server Error" });
    }
});

// 7. Route to Fetch Job Postings
app.get('/api/jobs', verifyToken, async (req: any, res) => {
    try {
        // We use a JOIN to get the name and department of the person who posted it
        const jobs = await pool.query(`
            SELECT j.*, a.first_name, a.last_name, a.department, a.profile_picture_url 
            FROM job_postings j
            LEFT JOIN alumni_profiles a ON j.poster_id = a.user_id
            ORDER BY j.created_at DESC
        `);
        res.json(jobs.rows);
    } catch (err: any) {
        console.error("🔴 Error fetching jobs:", err.message);
        res.status(500).json({ error: "Server Error" });
    }
});

// 8. Route to Post a New Job
app.post('/api/jobs', verifyToken, async (req: any, res) => {
    try {
        const { company_name, job_title, location, job_type, description, application_link } = req.body;
        
        const newJob = await pool.query(
            "INSERT INTO job_postings (poster_id, company_name, job_title, location, job_type, description, application_link) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *",
            [req.user.user_id, company_name, job_title, location, job_type, description, application_link]
        );
        
        res.json(newJob.rows[0]);
    } catch (err: any) {
        console.error("🔴 Error posting job:", err.message);
        res.status(500).json({ error: "Server Error" });
    }
});

// 9. Route to Delete a Job Posting
app.delete('/api/jobs/:id', verifyToken, async (req: any, res) => {
    try {
        const jobId = req.params.id;
        const userId = req.user.user_id;
        const userRole = req.user.role;

        // Check if job exists
        const checkJob = await pool.query("SELECT * FROM job_postings WHERE id = $1", [jobId]);
        if (checkJob.rows.length === 0) {
            return res.status(404).json({ error: "Job posting not found" });
        }

        const job = checkJob.rows[0];

        // Ensure user is the owner OR an admin
        if (job.poster_id !== userId && userRole !== 'admin') {
            return res.status(403).json({ error: "Unauthorized: You can only delete your own job postings" });
        }

        await pool.query("DELETE FROM job_postings WHERE id = $1", [jobId]);
        res.json({ success: true, message: "Job posting deleted successfully" });
    } catch (err: any) {
        console.error("🔴 Error deleting job:", err.message);
        res.status(500).json({ error: "Server Error" });
    }
});

// 10. Route to Fetch Companies (Corporate Directory)
app.get('/api/companies', async (req, res) => {
    try {
        const companies = await pool.query("SELECT * FROM companies ORDER BY is_alumni_owned DESC, name ASC");
        res.json(companies.rows);
    } catch (err: any) {
        console.error("🔴 Error fetching companies:", err.message);
        res.status(500).json({ error: "Server Error" });
    }
});

// 11. Route to Register a Startup
app.post('/api/companies', verifyToken, async (req: any, res) => {
    try {
        const { name, industry, website, description } = req.body;
        
        const newCompany = await pool.query(
            "INSERT INTO companies (name, industry, website, description, is_alumni_owned, founder_id) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *",
            [name, industry, website, description, true, req.user.user_id]
        );
        
        res.json(newCompany.rows[0]);
    } catch (err: any) {
        console.error("🔴 Error registering startup:", err.message);
        res.status(500).json({ error: "Server Error" });
    }
});

// ==========================================
// 🎓 MENTORSHIP HUB API
// ==========================================

// 16. Fetch all available mentors
app.get('/api/mentors', verifyToken, async (req: any, res) => {
    try {
        const mentors = await pool.query(`
            SELECT user_id, first_name, last_name, department, course_name, graduation_year, mentorship_bio 
            FROM alumni_profiles 
            WHERE is_mentor = true
            ORDER BY graduation_year ASC
        `);
        res.json(mentors.rows);
    } catch (err: any) {
        console.error("🔴 Error fetching mentors:", err.message);
        res.status(500).json({ error: "Server Error" });
    }
});

// 17. Toggle Mentorship Status (Opt-in / Opt-out)
app.put('/api/mentors/toggle', verifyToken, async (req: any, res) => {
    try {
        const { is_mentor, mentorship_bio } = req.body;
        const updated = await pool.query(
            "UPDATE alumni_profiles SET is_mentor = $1, mentorship_bio = $2 WHERE user_id = $3 RETURNING is_mentor, mentorship_bio",
            [is_mentor, mentorship_bio, req.user.user_id]
        );
        res.json(updated.rows[0]);
    } catch (err: any) {
        console.error("🔴 Error toggling mentorship:", err.message);
        res.status(500).json({ error: "Server Error" });
    }
});

// ==========================================
// 🛠️ IT SUPPORT & PASSWORD RECOVERY API
// ==========================================

// 18. User requests a password reset
app.post('/api/auth/request-reset', async (req, res) => {
    try {
        const { email } = req.body;
        
        // 1. Check if user exists
        const userCheck = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
        if (userCheck.rows.length === 0) {
            // For security, we don't tell the user the email doesn't exist to prevent email scraping
            return res.json({ success: true, message: "If your email exists in our system, a request has been sent to IT Support." });
        }

        const userId = userCheck.rows[0].id;

        // 2. Check if they already have a pending ticket to prevent spam
        const existingTicket = await pool.query(
            "SELECT id FROM password_resets WHERE user_id = $1 AND status = 'Pending'", [userId]
        );

        if (existingTicket.rows.length === 0) {
            // 3. Create the ticket for IT Support
            await pool.query(
                "INSERT INTO password_resets (user_id, email, status) VALUES ($1, $2, 'Pending')",
                [userId, email]
            );
        }

        res.json({ success: true, message: "If your email exists in our system, a request has been sent to IT Support." });
    } catch (err: any) {
        console.error("🔴 Error requesting reset:", err.message);
        res.status(500).json({ error: "Server Error" });
    }
});

// 19. IT Support fetches all pending tickets
app.get('/api/it/reset-requests', verifyToken, async (req: any, res) => {
    try {
        const tickets = await pool.query(`
            SELECT pr.id, pr.email, pr.status, pr.created_at, a.first_name, a.last_name, a.student_id_number
            FROM password_resets pr
            JOIN alumni_profiles a ON pr.user_id = a.user_id
            WHERE pr.status = 'Pending'
            ORDER BY pr.created_at ASC
        `);
        res.json(tickets.rows);
    } catch (err: any) {
        console.error("🔴 Error fetching tickets:", err.message);
        res.status(500).json({ error: "Server Error" });
    }
});

// 20. IT Support resolves ticket & sets temporary password
app.put('/api/it/resolve-reset', verifyToken, async (req: any, res) => {
    try {
        const { ticket_id, email, temp_password } = req.body;
        
        // Hash the temporary password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(temp_password, salt);

        // Update the user's password
        await pool.query("UPDATE users SET password = $1 WHERE email = $2", [hashedPassword, email]);

        // Mark the ticket as resolved
        await pool.query("UPDATE password_resets SET status = 'Resolved' WHERE id = $1", [ticket_id]);

        res.json({ success: true, message: "Temporary password generated and applied." });
    } catch (err: any) {
        console.error("🔴 Error resolving ticket:", err.message);
        res.status(500).json({ error: "Server Error" });
    }
});

// ==========================================
// 📧 NEW: AUTOMATED EMAIL RESET ROUTES
// ==========================================

// Configure the Email Sender (Replace with your actual credentials)
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'your-email@gmail.com', // YOUR GMAIL
        pass: 'your-app-password'     // YOUR GOOGLE APP PASSWORD (NOT regular password)
    }
});

// 21. User requests an email reset link
app.post('/api/auth/send-reset-email', async (req, res) => {
    try {
        const { email } = req.body;
        
        const userCheck = await pool.query("SELECT id, email FROM users WHERE email = $1", [email]);
        if (userCheck.rows.length === 0) {
            return res.json({ success: true, message: "If your email exists, a reset link has been sent." });
        }

        const userId = userCheck.rows[0].id;
        
        // Generate a random, secure token
        const resetToken = crypto.randomBytes(32).toString('hex');
        const expiresAt = new Date(Date.now() + 3600000); // 1 hour from now

        // Save token to database
        await pool.query(
            "INSERT INTO password_resets (user_id, email, status, reset_token, expires_at) VALUES ($1, $2, 'Pending', $3, $4)",
            [userId, email, resetToken, expiresAt]
        );

        // Send the Email
        // Note: Make sure the URL matches where your frontend is running (usually port 3000 or 3001)
        const frontendUrl = process.env.FRONTEND_URL || 'https://harare-poly-alumni.vercel.app';
        const resetLink = `${frontendUrl}/reset-password?token=${resetToken}&email=${email}`;
        
        const mailOptions = {
            from: '"Harare Poly Alumni Support" <your-email@gmail.com>',
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

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error("🔴 Email Send Error:", error);
                // Even if email fails locally due to missing credentials, we don't crash the server
            }
        });

        res.json({ success: true, message: "If your email exists, a reset link has been sent." });
    } catch (err: any) {
        console.error("🔴 Error sending reset email:", err.message);
        res.status(500).json({ error: "Server Error" });
    }
});

// 22. User submits their new password using the email token
app.post('/api/auth/reset-password-with-token', async (req, res) => {
    try {
        const { email, token, newPassword } = req.body;

        // Verify the token exists, matches the email, and hasn't expired
        const ticketCheck = await pool.query(
            "SELECT id FROM password_resets WHERE email = $1 AND reset_token = $2 AND status = 'Pending' AND expires_at > NOW()",
            [email, token]
        );

        if (ticketCheck.rows.length === 0) {
            return res.status(400).json({ error: "Invalid or expired reset link. Please request a new one." });
        }

        // Hash the new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        // Update User's password
        await pool.query("UPDATE users SET password = $1 WHERE email = $2", [hashedPassword, email]);

        // Mark the token as used (Resolved)
        await pool.query("UPDATE password_resets SET status = 'Resolved' WHERE id = $1", [ticketCheck.rows[0].id]);

        res.json({ success: true, message: "Password updated successfully!" });
    } catch (err: any) {
        console.error("🔴 Error resetting via token:", err.message);
        res.status(500).json({ error: "Server Error" });
    }
});

// ==========================================
// 🛡️ NEW: IT USER MANAGEMENT ROUTES
// ==========================================

// 23. IT Fetches all users
app.get('/api/it/users', verifyToken, async (req: any, res) => {
    try {
        // Security Check: Only IT can do this
        if (req.user.role !== 'it') {
            return res.status(403).json({error: "Access Denied: IT Privileges Required."});
        }

        const users = await pool.query(`
            SELECT u.id, u.email, u.role, 
                   a.first_name, a.last_name, a.department, a.student_id_number
            FROM users u
            LEFT JOIN alumni_profiles a ON u.id = a.user_id
            ORDER BY u.created_at DESC
        `);
        
        res.json(users.rows);
    } catch (err: any) {
        console.error("🔴 Error fetching users:", err.message);
        res.status(500).json({ error: "Server Error" });
    }
});

// 24. IT Deletes a User (Hard Delete with Cleanup)
app.delete('/api/it/users/:id', verifyToken, async (req: any, res) => {
    try {
        if (req.user.role !== 'it') {
            return res.status(403).json({error: "Access Denied: IT Privileges Required."});
        }
        
        // FORCE IT TO BE A NUMBER to prevent any database matching errors
        const targetUserId = parseInt(req.params.id, 10);

        await pool.query("BEGIN");
        
        // 1. Clean up their dependencies 
        await pool.query("DELETE FROM password_resets WHERE user_id = $1", [targetUserId]);
        
        // BULLETPROOF FIX: Use two explicit parameters ($1 and $2)
        await pool.query("DELETE FROM connection_requests WHERE sender_id = $1 OR receiver_id = $2", [targetUserId, targetUserId]);
        
        // Clean up any feedback they might have created
        try { await pool.query("DELETE FROM feedback WHERE user_id = $1", [targetUserId]); } catch(e) {}
        
        // Clean up Employment and Studies
        try { await pool.query("DELETE FROM employment_history WHERE user_id = $1", [targetUserId]); } catch(e) {}
        try { await pool.query("DELETE FROM further_studies WHERE user_id = $1", [targetUserId]); } catch(e) {}
        try { await pool.query("DELETE FROM jobs WHERE posted_by = $1", [targetUserId]); } catch(e) {}
        
        try { await pool.query("UPDATE companies SET founder_id = NULL WHERE founder_id = $1", [targetUserId]); } catch(e) {}
        
        // 2. Finally, delete the profile and the main user account
        await pool.query("DELETE FROM alumni_profiles WHERE user_id = $1", [targetUserId]);
        await pool.query("DELETE FROM users WHERE id = $1", [targetUserId]);
        
        await pool.query("COMMIT");

        res.json({ success: true, message: "User account and associated data permanently deleted." });
    } catch (err: any) {
        await pool.query("ROLLBACK"); 
        console.error("🔴 Error deleting user:", err.message);
        res.status(500).json({ error: "Failed to delete user due to database constraints." });
    }
});

app.get('/api/jobs', verifyToken, async (req: any, res) => {
    try {
        // Only show jobs that are Approved, OR jobs that belong to the logged-in user
        const result = await pool.query(
            "SELECT * FROM job_postings WHERE status = 'Approved' OR posted_by = $1 ORDER BY created_at DESC",
            [req.user.userId]
        );
        res.json(result.rows);
    } catch (err: any) {
        res.status(500).json({error: err.message});
    }
});

// --- NEW ROUTES FOR THE PRO COMMAND CENTER ---
// 1. PRO fetches all pending jobs
app.get('/api/pro/pending-jobs', verifyToken, async (req: any, res) => {
    try {
        if (req.user.role !== 'pro') return res.status(403).json({error: "Access Denied"});
        const result = await pool.query("SELECT * FROM job_postings WHERE status = 'Pending' ORDER BY created_at ASC");
        res.json(result.rows);
    } catch (err: any) {
        res.status(500).json({error: err.message});
    }
});

// 2. PRO Approves or Rejects a job
app.put('/api/pro/jobs/:id/verify', verifyToken, async (req: any, res) => {
    try {
        if (req.user.role !== 'pro') return res.status(403).json({error: "Access Denied"});
        const { status } = req.body; // 'Approved' or 'Rejected'
        
        await pool.query("UPDATE job_postings SET status = $1 WHERE id = $2", [status, req.params.id]);
        res.json({ success: true, message: `Job ${status}` });
    } catch (err: any) {
        res.status(500).json({error: err.message});
    }
});

// --- GALLERY & HIGHLIGHTS ROUTES ---
// 1. Public route to fetch gallery (used by PRO dashboard and Homepage)
app.get('/api/gallery', async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM gallery_highlights ORDER BY created_at DESC");
        res.json(result.rows);
    } catch (err: any) {
        res.status(500).json({error: err.message});
    }
});

// 2. PRO route to add a new highlight
app.post('/api/pro/gallery', verifyToken, async (req: any, res) => {
    try {
        if (req.user.role !== 'pro') return res.status(403).json({error: "Access Denied"});
        const { title, description, image_url, category } = req.body;
        
        await pool.query(
            "INSERT INTO gallery_highlights (title, description, image_url, category) VALUES ($1, $2, $3, $4)",
            [title, description, image_url, category]
        );
        res.json({ success: true, message: "Highlight added!" });
    } catch (err: any) {
        res.status(500).json({error: err.message});
    }
});

// 3. PRO route to delete a highlight
app.delete('/api/pro/gallery/:id', verifyToken, async (req: any, res) => {
    try {
        if (req.user.role !== 'pro') return res.status(403).json({error: "Access Denied"});
        await pool.query("DELETE FROM gallery_highlights WHERE id = $1", [req.params.id]);
        res.json({ success: true, message: "Highlight deleted" });
    } catch (err: any) {
        res.status(500).json({error: err.message});
    }
});

// --- PHASE 2.5: GALLERY & HIGHLIGHTS ROUTES ---

// 1. Get all gallery images (Public - for the Homepage)
app.get('/api/pro/gallery', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM gallery_highlights ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err: any) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch gallery highlights' });
  }
});

// 2. Add a new gallery highlight (PRO only)
app.post('/api/pro/gallery', verifyToken, async (req: any, res) => {
  if (req.user.role !== 'pro') {
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
    console.error(err);
    res.status(500).json({ error: 'Failed to add gallery highlight' });
  }
});

// 3. Delete a gallery highlight (PRO only)
app.delete('/api/pro/gallery/:id', verifyToken, async (req: any, res) => {
  if (req.user.role !== 'pro') {
    return res.status(403).json({ error: 'Only PR can delete highlights' });
  }
  try {
    await pool.query('DELETE FROM gallery_highlights WHERE id = $1', [req.params.id]);
    res.json({ message: 'Highlight deleted successfully' });
  } catch (err: any) {
    console.error(err);
    res.status(500).json({ error: 'Failed to delete gallery highlight' });
  }
});

// --- SUCCESS STORIES API ---

// Fetch the single newest story for the Landing Page spotlight
app.get('/api/stories/latest', async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM alumni_stories ORDER BY created_at DESC LIMIT 1");
        res.json(result.rows[0] || null);
    } catch (err: any) {
        res.status(500).json({ error: err.message });
    }
});

// Fetch a specific full story for the Blog Page
app.get('/api/stories/:id', async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM alumni_stories WHERE id = $1", [req.params.id]);
        if (result.rows.length === 0) return res.status(404).json({ error: "Story not found" });
        res.json(result.rows[0]);
    } catch (err: any) {
        res.status(500).json({ error: err.message });
    }
});

// Publish a new story (Restricted to PROs and Admins)
app.post('/api/stories', verifyToken, async (req: any, res) => {
    // Security check: Only allow PROs or Admins to publish
    if (req.user.role !== 'pro' && req.user.role !== 'admin') {
        return res.status(403).json({ error: "Unauthorized. Only PR Officers can publish stories." });
    }

    const { title, excerpt, content, image_url } = req.body;

    if (!title || !excerpt || !content) {
        return res.status(400).json({ error: "Title, excerpt, and content are required." });
    }

    try {
        const result = await pool.query(
            "INSERT INTO alumni_stories (title, excerpt, content, image_url) VALUES ($1, $2, $3, $4) RETURNING *",
            [title, excerpt, content, image_url]
        );
        res.json({ success: true, story: result.rows[0] });
    } catch (err: any) {
        console.error("Error publishing story:", err);
        res.status(500).json({ error: "Failed to publish story" });
    }
});

// --- PUBLIC LANDING PAGE TRENDS ---
app.get('/api/public/trends', async (req, res) => {
    try {
        // Top 3 Trending Professions (Job Titles)
        const topJobsRes = await pool.query(`
            SELECT job_title as name, COUNT(id) as count
            FROM employment_history
            WHERE job_title IS NOT NULL AND job_title != ''
            GROUP BY job_title
            ORDER BY count DESC
            LIMIT 3
        `);

        // Top 4 Hiring Partners (Companies)
        const topCompaniesRes = await pool.query(`
            SELECT company_name as name, COUNT(id) as count
            FROM employment_history
            WHERE company_name IS NOT NULL AND company_name != ''
            GROUP BY company_name
            ORDER BY count DESC
            LIMIT 4
        `);

        res.json({
            trendingProfessions: topJobsRes.rows,
            topCompanies: topCompaniesRes.rows
        });
    } catch (err: any) {
        console.error("Error fetching public trends:", err);
        res.status(500).json({ error: "Failed to fetch trends" });
    }
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});