const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const mysql = require('mysql2/promise');

const hostname = '127.0.0.1';
const port = 3000;
const rootDir = __dirname;

const dbConfig = {
  host: '127.0.0.1',
  user: 'root',
  password: '',
  database: 'youtharise',
  waitForConnections: true,
  connectionLimit: 10,
  charset: 'utf8mb4',
};

const mimeTypes = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.webp': 'image/webp',
  '.php': 'text/html; charset=utf-8',
};

const server = http.createServer((req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || '127.0.0.1'}`);
    const pathname = url.pathname;

    if (req.method === 'POST' && pathname === '/signup.php') {
      handleSignup(req, res);
      return;
    }

    if (req.method === 'POST' && pathname === '/sign_in.php') {
      handleSignin(req, res);
      return;
    }

    let reqPath = pathname === '/' ? '/index.html' : pathname;
    reqPath = decodeURIComponent(reqPath);
    reqPath = reqPath.replace(/\\/g, '/');

    const normalized = path.posix.normalize(reqPath).replace(/^\/+/, '');
    const filePath = path.resolve(rootDir, normalized);

    if (!filePath.startsWith(rootDir)) {
      sendText(res, 403, 'Forbidden');
      return;
    }

    fs.stat(filePath, (err, stats) => {
      if (err) {
        sendText(res, 404, 'Not Found');
        return;
      }

      if (stats.isDirectory()) {
        const indexFile = path.join(filePath, 'index.html');
        fs.stat(indexFile, (indexErr) => {
          if (indexErr) {
            sendText(res, 404, 'Not Found');
            return;
          }
          serveFile(indexFile, res);
        });
        return;
      }

      serveFile(filePath, res);
    });
  } catch (error) {
    sendText(res, 500, 'Server Error');
  }
});

async function ensureDatabase() {
  const connection = await mysql.createConnection({
    host: dbConfig.host,
    user: dbConfig.user,
    password: dbConfig.password,
    charset: 'utf8mb4',
  });

  try {
    await connection.query('CREATE DATABASE IF NOT EXISTS `youtharise` CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci');
    await connection.query('USE `youtharise`');
    await connection.query(`CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      fullname VARCHAR(255) NOT NULL,
      email VARCHAR(255) NOT NULL UNIQUE,
      username VARCHAR(100) NOT NULL UNIQUE,
      password VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);
  } finally {
    await connection.end();
  }
}

function parseForm(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk.toString();
    });
    req.on('end', () => {
      try {
        const params = new URLSearchParams(body);
        const result = {};
        for (const [key, value] of params.entries()) {
          result[key] = value;
        }
        resolve(result);
      } catch (error) {
        reject(error);
      }
    });
    req.on('error', reject);
  });
}

async function handleSignup(req, res) {
  try {
    await ensureDatabase();

    const form = await parseForm(req);
    const fullname = String(form.fullname || '').trim();
    const email = String(form.email || '').trim();
    const username = String(form.username || '').trim();
    const password = String(form.password || '');
    const confirm = String(form.confirm_password || '');

    const errors = [];

    if (!fullname) errors.push('Full name is required.');
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) errors.push('A valid email is required.');
    if (!username) errors.push('Username is required.');
    if (password.length < 6) errors.push('Password must be at least 6 characters.');
    if (password !== confirm) errors.push('Passwords do not match.');

    if (errors.length === 0) {
      const connection = await mysql.createConnection(dbConfig);
      try {
        const [existing] = await connection.execute(
          'SELECT id FROM users WHERE email = ? OR username = ? LIMIT 1',
          [email, username]
        );

        if (existing.length > 0) {
          errors.push('Email or username already registered.');
        }
      } finally {
        await connection.end();
      }
    }

    if (errors.length > 0) {
      const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Sign Up - Error</title><style>body{font-family:Arial,sans-serif;background:#f4f4f4;padding:40px} .card{max-width:520px;margin:40px auto;background:#fff;padding:20px;border-radius:6px;box-shadow:0 2px 6px rgba(0,0,0,.1)} ul{color:#d9534f} a{color:#007bff;text-decoration:none}</style></head><body><div class="card"><h2>Registration Errors</h2><ul>${errors.map((e) => `<li>${escapeHtml(e)}</li>`).join('')}</ul><p><a href="/Sign%20Up.html">Go back to Sign Up</a></p></div></body></html>`;
      res.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
      return;
    }

    const passwordHash = crypto.createHash('sha256').update(password).digest('hex');
    const connection = await mysql.createConnection(dbConfig);
    try {
      await connection.execute(
        'INSERT INTO users (fullname, email, username, password) VALUES (?, ?, ?, ?)',
        [fullname, email, username, passwordHash]
      );
    } finally {
      await connection.end();
    }

    res.writeHead(302, { Location: '/signin.html?registered=1' });
    res.end();
  } catch (error) {
    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Database Error</title><style>body{font-family:Arial,sans-serif;background:#f4f4f4;padding:40px} .card{max-width:520px;margin:40px auto;background:#fff;padding:20px;border-radius:6px;box-shadow:0 2px 6px rgba(0,0,0,.1)} a{color:#007bff;text-decoration:none}</style></head><body><div class="card"><h2>Database Error</h2><p>${escapeHtml(error.message)}</p><p><a href="/Sign%20Up.html">Go back to Sign Up</a></p></div></body></html>`;
    res.writeHead(500, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
  }
}

async function handleSignin(req, res) {
  try {
    await ensureDatabase();

    const form = await parseForm(req);
    const username = String(form.username || '').trim();
    const password = String(form.password || '');

    const errors = [];

    if (!username) errors.push('Username is required.');
    if (!password) errors.push('Password is required.');

    if (errors.length === 0) {
      const connection = await mysql.createConnection(dbConfig);
      try {
        const [users] = await connection.execute(
          'SELECT id, username, password FROM users WHERE username = ? LIMIT 1',
          [username]
        );

        if (users.length > 0) {
          const user = users[0];
          const passwordHash = crypto.createHash('sha256').update(password).digest('hex');
          
          if (passwordHash === user.password) {
            // Login successful - redirect to homepage
            res.writeHead(302, { Location: '/homepage.html' });
            res.end();
            return;
          } else {
            errors.push('Invalid username or password.');
          }
        } else {
          errors.push('Invalid username or password.');
        }
      } finally {
        await connection.end();
      }
    }

    if (errors.length > 0) {
      res.writeHead(302, { Location: `/signin.html?error=${encodeURIComponent(errors[0])}` });
      res.end();
      return;
    }
  } catch (error) {
    res.writeHead(302, { Location: `/signin.html?error=${encodeURIComponent(error.message)}` });
    res.end();
  }
}

function serveFile(filePath, res) {
  const ext = path.extname(filePath).toLowerCase();
  const contentType = mimeTypes[ext] || 'application/octet-stream';

  fs.readFile(filePath, (readErr, data) => {
    if (readErr) {
      sendText(res, 500, 'Server Error');
      return;
    }

    res.writeHead(200, { 'Content-Type': contentType });
    res.end(data);
  });
}

function sendText(res, statusCode, message) {
  res.writeHead(statusCode, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end(message);
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

server.listen(port, hostname, () => {
  console.log(`Local server running at http://${hostname}:${port}`);
});
