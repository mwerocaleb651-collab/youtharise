<?php
// signup.php - simple sign-up handler for XAMPP (MySQL)
// Assumes MySQL user 'root' with no password and a database named 'youtharise'.

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: Sign%20Up.html');
    exit;
}

$fullname = trim($_POST['fullname'] ?? '');
$email = trim($_POST['email'] ?? '');
$username = trim($_POST['username'] ?? '');
$password = $_POST['password'] ?? '';
$confirm = $_POST['confirm_password'] ?? '';

$errors = [];
if ($fullname === '') $errors[] = 'Full name is required.';
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = 'A valid email is required.';
if ($username === '') $errors[] = 'Username is required.';
if (strlen($password) < 6) $errors[] = 'Password must be at least 6 characters.';
if ($password !== $confirm) $errors[] = 'Passwords do not match.';

// DB connection settings for XAMPP default
$dbHost = '127.0.0.1';
$dbUser = 'root';
$dbPass = '';
$dbName = 'youtharise';

if (empty($errors)) {
    $conn = new mysqli($dbHost, $dbUser, $dbPass);
    if ($conn->connect_error) {
        $errors[] = 'Database connection failed: ' . $conn->connect_error;
    } else {
        $conn->set_charset('utf8mb4');

        // Create database if it doesn't exist
        $createDb = $conn->query("CREATE DATABASE IF NOT EXISTS `$dbName` CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci");
        if (!$createDb) {
            $errors[] = 'Database creation failed: ' . $conn->error;
        } else {
            $conn->select_db($dbName);

            // Create users table if not exists
            $createSql = "CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                fullname VARCHAR(255) NOT NULL,
                email VARCHAR(255) NOT NULL UNIQUE,
                username VARCHAR(100) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";
            if (!$conn->query($createSql)) {
                $errors[] = 'User table creation failed: ' . $conn->error;
            } else {
                // Check for existing email or username
                $check = $conn->prepare('SELECT id FROM users WHERE email = ? OR username = ? LIMIT 1');
                if (!$check) {
                    $errors[] = 'Database query preparation failed: ' . $conn->error;
                } else {
                    $check->bind_param('ss', $email, $username);
                    $check->execute();
                    $check->store_result();
                    if ($check->num_rows > 0) {
                        $errors[] = 'Email or username already registered.';
                    } else {
                        $hash = hash('sha256', $password);
                        $ins = $conn->prepare('INSERT INTO users (fullname, email, username, password) VALUES (?, ?, ?, ?)');
                        if (!$ins) {
                            $errors[] = 'Insert preparation failed: ' . $conn->error;
                        } else {
                            $ins->bind_param('ssss', $fullname, $email, $username, $hash);
                            if ($ins->execute()) {
                                $conn->close();
                                header('Location: signin.html?registered=1');
                                exit;
                            } else {
                                $errors[] = 'Registration failed. Please try again.';
                            }
                            $ins->close();
                        }
                    }
                    $check->close();
                }
            }
            $conn->close();
        }
    }
}

// If we reach here there are errors — show a simple page with messages
?><!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Sign Up - Error</title>
  <style>body{font-family:Arial,Helvetica,sans-serif;background:#f4f4f4;padding:40px} .card{max-width:520px;margin:40px auto;background:#fff;padding:20px;border-radius:6px;box-shadow:0 2px 6px rgba(0,0,0,.1)}</style>
</head>
<body>
  <div class="card">
    <h2>Registration Errors</h2>
    <ul>
      <?php foreach ($errors as $e): ?>
        <li><?php echo htmlspecialchars($e); ?></li>
      <?php endforeach; ?>
    </ul>
    <p><a href="Sign%20Up.html">Go back to Sign Up</a></p>
  </div>
</body>
</html>
