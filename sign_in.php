<?php
// sign_in.php - handle user login

session_start();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: signin.html');
    exit;
}

$username = trim($_POST['username'] ?? '');
$password = $_POST['password'] ?? '';

$errors = [];

if ($username === '') {
    $errors[] = 'Username is required.';
}
if ($password === '') {
    $errors[] = 'Password is required.';
}

// DB connection settings for XAMPP default
$dbHost = '127.0.0.1';
$dbUser = 'root';
$dbPass = '';
$dbName = 'youtharise';

if (empty($errors)) {
    $conn = new mysqli($dbHost, $dbUser, $dbPass, $dbName);
    
    if ($conn->connect_error) {
        $errors[] = 'Database connection failed: ' . $conn->connect_error;
    } else {
        $conn->set_charset('utf8mb4');
        
        // Query the user by username
        $query = $conn->prepare('SELECT id, username, password FROM users WHERE username = ? LIMIT 1');
        
        if (!$query) {
            $errors[] = 'Database query preparation failed: ' . $conn->error;
        } else {
            $query->bind_param('s', $username);
            $query->execute();
            $result = $query->get_result();
            
            if ($result->num_rows > 0) {
                $user = $result->fetch_assoc();
                
                // Verify password using SHA256 (matching server.js hashing)
                $passwordHash = hash('sha256', $password);
                if ($passwordHash === $user['password']) {
                    // Login successful - set session and redirect to homepage
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['username'] = $user['username'];
                    $query->close();
                    $conn->close();
                    header('Location: homepage.html');
                    exit;
                } else {
                    $errors[] = 'Invalid username or password.';
                }
            } else {
                $errors[] = 'Invalid username or password.';
            }
            $query->close();
        }
        $conn->close();
    }
}

// If we reach here there are errors - redirect back with error
if (!empty($errors)) {
    header('Location: signin.html?error=' . urlencode($errors[0]));
    exit;
}
?>
