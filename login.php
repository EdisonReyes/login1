<?php
// Datos de conexión a la base de datos
$dbhost = "localhost";
$dbuser = "root";
$dbpassword = "usuario123";
$dbdatabase = "usuario1";

// Crear conexión
$conn = new mysqli($dbhost, $dbuser, $dbpassword, $dbdatabase);

// Verificar conexión
if ($conn->connect_error) {
    die("Error de conexión: " . $conn->connect_error);
}

// Procesar el formulario
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $nombre = trim($_POST["userusuario"]);
    $password = trim($_POST["userpassword"]);

    // Usar sentencias preparadas para evitar inyección SQL
    $stmt = $conn->prepare("SELECT password FROM login WHERE usuario = ?");
    if ($stmt) {
        $stmt->bind_param("s", $nombre);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows == 1) {
            $stmt->bind_result($hashed_password);
            $stmt->fetch();

            // Verificar la contraseña usando password_verify
            if (password_verify($password, $hashed_password)) {
                echo "<script>alert('Bienvenido: " . htmlspecialchars($nombre) . "'); window.location='dashboard.php';</script>";
            } else {
                echo "<script>alert('Usuario o contraseña incorrectos'); window.location='login.html';</script>";
            }
        } else {
            echo "<script>alert('Usuario o contraseña incorrectos'); window.location='login.html';</script>";
        }
        $stmt->close();
    } else {
        echo "Error al preparar la consulta.";
    }
}

$conn->close();
?>
