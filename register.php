<?php
// 1. Include ไฟล์ config และ csrf ที่ส่วนบนสุดของไฟล์
require __DIR__ . '/config_mysqli.php';
require __DIR__ . '/csrf.php';

$errors = [];
$success = "";

// สร้างฟังก์ชัน e() สำหรับป้องกัน XSS
function e($str){ return htmlspecialchars($str ?? "", ENT_QUOTES, "UTF-8"); }

// กำหนดค่าเริ่มต้นให้ตัวแปร เพื่อไม่ให้เกิด error ตอนเปิดหน้าครั้งแรก
$username = "";
$email = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  // 2. ใช้ฟังก์ชัน csrf_check() ที่ import มา
  if (!csrf_check($_POST['csrf'] ?? '')) {
    $errors[] = "Invalid request. Please refresh and try again.";
  }

  // รับค่าจากฟอร์ม (ลบ full_name ออก)
  $username  = trim($_POST['username'] ?? "");
  $password  = $_POST['password'] ?? "";
  $email     = trim($_POST['email'] ?? "");

  // ตรวจความถูกต้องของข้อมูล
  if ($username === "" || !preg_match('/^[A-Za-z0-9_\.]{3,30}$/', $username)) {
    $errors[] = "กรุณากรอก username 3–30 ตัวอักษร (a-z, A-Z, 0-9, _, .)";
  }
  if (strlen($password) < 8) {
    $errors[] = "รหัสผ่านต้องยาวอย่างน้อย 8 ตัวอักษร";
  }
  if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $errors[] = "อีเมลไม่ถูกต้อง";
  }

  // 3. แก้ไข SQL ให้ตรวจสอบเฉพาะ email ที่ซ้ำ
  if (!$errors) {
    $sql = "SELECT 1 FROM users WHERE email = ? LIMIT 1";
    if ($stmt = $mysqli->prepare($sql)) {
      $stmt->bind_param("s", $email);
      $stmt->execute();
      $stmt->store_result();
      if ($stmt->num_rows > 0) {
        $errors[] = "Email นี้ถูกใช้แล้ว"; // แก้ไขข้อความ error
      }
      $stmt->close();
    } else {
      $errors[] = "เกิดข้อผิดพลาดในการตรวจสอบข้อมูล (prepare)";
    }
  }

  // 4. แก้ไข SQL INSERT ให้ตรงกับโครงสร้างตาราง users
  if (!$errors) {
    $password_hash = password_hash($password, PASSWORD_DEFAULT);

    // ใช้ display_name แทน username และลบ full_name ออก
    $sql = "INSERT INTO users (display_name, email, password_hash) VALUES (?, ?, ?)";
    if ($stmt = $mysqli->prepare($sql)) {
      // bind ค่า username จากฟอร์มไปยังคอลัมน์ display_name
      $stmt->bind_param("sss", $username, $email, $password_hash);
      if ($stmt->execute()) {
        $success = "สมัครสมาชิกสำเร็จ! คุณสามารถล็อกอินได้แล้วค่ะ";
        // ล้างค่าในฟอร์มหลังสมัครสำเร็จ
        $username = $email = "";
      } else {
        // ตรวจจับกรณี email ซ้ำ
        if ($mysqli->errno == 1062) {
          $errors[] = "Email ซ้ำ กรุณาใช้ค่าอื่น";
        } else {
          $errors[] = "บันทึกข้อมูลไม่สำเร็จ: " . e($mysqli->error);
        }
      }
      $stmt->close();
    } else {
      $errors[] = "เกิดข้อผิดพลาดในการบันทึกข้อมูล (prepare)";
    }
  }
}
?>
<!doctype html>
<html lang="th">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Register</title>
  <style>
    body{font-family:system-ui, sans-serif; background:#f7f7fb; margin:0; padding:0;}
    .container{max-width:480px; margin:40px auto; background:#fff; border-radius:16px; padding:24px; box-shadow:0 10px 30px rgba(0,0,0,.06);}
    h1{margin:0 0 16px;}
    .alert{padding:12px 14px; border-radius:12px; margin-bottom:12px; font-size:14px;}
    .alert.error{background:#ffecec; color:#a40000; border:1px solid #ffc9c9;}
    .alert.success{background:#efffed; color:#0a7a28; border:1px solid #c9f5cf;}
    label{display:block; font-size:14px; margin:10px 0 6px;}
    input{width:100%; padding:12px; border-radius:12px; border:1px solid #ddd;}
    button{width:100%; padding:12px; border:none; border-radius:12px; margin-top:14px; background:#3b82f6; color:#fff; font-weight:600; cursor:pointer;}
    button:hover{filter:brightness(.95);}
    .hint{font-size:12px; color:#666;}
    .login-link {display: block;text-align: center;margin-top: 10px;color: #3b82f6;text-decoration: none;font-weight: 500;}
    .login-link:hover {text-decoration: underline;}
  </style>
</head>
<body>
  <div class="container">
    <h1>สมัครสมาชิก</h1>

    <?php if ($errors): ?>
      <div class="alert error">
        <?php foreach ($errors as $m) echo "<div>".e($m)."</div>"; ?>
      </div>
    <?php endif; ?>

    <?php if ($success): ?>
      <div class="alert success"><?= e($success) ?></div>
    <?php endif; ?>

    <form method="post" action="">
      <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
      <label>Username</label>
      <input type="text" name="username" value="<?= e($username) ?>" required>
      <div class="hint">ชื่อนี้จะถูกใช้เป็นชื่อที่แสดง (display name)</div>

      <label>Password</label>
      <input type="password" name="password" required>
      <div class="hint">อย่างน้อย 8 ตัวอักษร</div>

      <label>Email</label>
      <input type="email" name="email" value="<?= e($email) ?>" required>
      <div class="hint">ใช้สำหรับเข้าสู่ระบบ</div>

      <button type="submit">สมัครสมาชิก</button>
      <a href="login.php" class="login-link">ล็อคอิน</a>
    </form>
  </div>
</body>
</html>
