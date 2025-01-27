<?php
require_once dirname(__FILE__) . '/conf.php';

session_start(); // Iniciar sesión en lugar de usar cookies

// Verificar si ya está logueado
if (isset($_SESSION['userId'])) {
    // Si el usuario ya está logueado, redirigir a otra página (ej. Dashboard)
    header("Location: dashboard.php"); // Cambia esto por la página que quieras redirigir
    exit;
}

$userId = FALSE;
$login_ok = FALSE; // Inicializamos la variable para evitar el error

// Comprobar si el usuario y la contraseña son válidos
function areUserAndPasswordValid($user, $password) {
    global $db, $userId;

    // Sentencia preparada para evitar SQL Injection
    $query = "SELECT userId, password FROM users WHERE username = :username";
    $stmt = $db->prepare($query);
    $stmt->bindParam(':username', $user, SQLITE3_TEXT);
    $result = $stmt->execute();
    $row = $result->fetchArray();

    if (!isset($row['password'])) return FALSE;

    // Verificar si la contraseña es válida
    if (password_verify($password, $row['password'])) {
        $userId = $row['userId'];
        $_SESSION['userId'] = $userId; // Almacenar en sesión
        $_SESSION['user'] = $user; // Guardar usuario en sesión
        return TRUE;
    } else {
        return FALSE;
    }
}

// Login
if (isset($_POST['username']) && isset($_POST['password'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];

    if (areUserAndPasswordValid($username, $password)) {
        $login_ok = TRUE;
        $error = "";
        header("Location: list_players.php"); // Redirigir a la lista de jugadores u otra página
        exit;
    } else {
        $login_ok = FALSE;
        $error = "Invalid user or password.<br>";
    }
}

// Logout
if (isset($_POST['Logout'])) {
    // Cerrar sesión de manera segura
    session_unset(); // Eliminar todas las variables de sesión
    session_destroy(); // Destruir la sesión
    header("Location: index.php"); // Redirigir a la página de inicio de sesión
    exit;
}

// Si el usuario no está logueado, mostrar la página de login
if (!$login_ok) {
    header("Location: login.php");
    exit();
}
?>
    <!doctype html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport"
              content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
        <meta http-equiv="X-UA-Compatible" content="ie=edge">
        <link rel="stylesheet" href="css/style.css">
        <title>Práctica RA3 - Authentication page</title>
    </head>
    <body>
    <header class="auth">
        <h1>Authentication page</h1>
    </header>
    <section class="auth">
        <div class="message">
            <?= isset($error) ? $error : ""; ?> <!-- Mostrar el mensaje de error -->
        </div>
        <section>
            <div>
                <h2>Login</h2>
                <form action="#" method="post">
                    <label>User</label>
                    <input type="text" name="username" required><br>
                    <label>Password</label>
                    <input type="password" name="password" required><br>
                    <input type="submit" value="Login">
                </form>
            </div>

            <!-- Mostrar botón de logout solo si el usuario está logueado -->
            <?php if (isset($_SESSION['userId'])) { ?>
                <div>
                    <h2>Logout</h2>
                    <form action="#" method="post">
                        <input type="submit" name="Logout" value="Logout">
                    </form>
                </div>
            <?php } ?>
        </section>
    </section>
    <footer>
        <h4>Puesta en producción segura</h4>
        <p><a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/">Donate</a></p>
    </footer>
    </body>
    </html>
<?php
    exit(0);
}
?>
