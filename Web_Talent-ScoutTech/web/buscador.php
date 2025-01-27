<?php
require_once dirname(__FILE__) . '/private/conf.php';

# Requiere que el usuario esté autenticado
require dirname(__FILE__) . '/private/auth.php';

# Validar y sanitizar la entrada de 'name' para evitar inyecciones SQL
if (isset($_GET['name'])) {
    $name = $_GET['name'];

    # Sanitizar el valor de 'name' para evitar inyecciones XSS
    $name = htmlspecialchars($name, ENT_QUOTES, 'UTF-8');

    # Usar una consulta preparada para prevenir la inyección SQL
    $stmt = $db->prepare("SELECT playerid, name, team FROM players WHERE name = :name ORDER BY playerId DESC");
    $stmt->bindValue(':name', $name, SQLITE3_TEXT);

    # Ejecutar la consulta
    $result = $stmt->execute() or die("Invalid query");
} else {
    die("No name parameter provided.");
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
    <title>Práctica RA3 - Búsqueda</title>
</head>
<body>
    <header class="listado">
        <h1>Búsqueda de <?php echo $name; ?></h1>
    </header>
    <main class="listado">
        <ul>
        <?php
        while ($row = $result->fetchArray()) {
            echo "
                <li>
                <div>
                <span>Name: " . htmlspecialchars($row['name'], ENT_QUOTES, 'UTF-8')
                . "</span><span>Team: " . htmlspecialchars($row['team'], ENT_QUOTES, 'UTF-8')
                . "</span></div>
                <div>
                <a href=\"show_comments.php?id=" . htmlspecialchars($row['playerid'], ENT_QUOTES, 'UTF-8') . "\">(show/add comments)</a> 
                <a href=\"insert_player.php?id=" . htmlspecialchars($row['playerid'], ENT_QUOTES, 'UTF-8') . "\">(edit player)</a>
                </div>
                </li>\n";
        }
        ?>
        </ul>
        <form action="#" method="post" class="menu-form">
            <a href="index.php">Back to home</a>
            <a href="list_players.php">Back to list</a>
            <input type="submit" name="Logout" value="Logout" class="logout">
        </form>
    </main>
    <footer class="listado">
        <img src="images/logo-iesra-cadiz-color-blanco.png">
        <h4>Puesta en producción segura</h4>
        <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/"> donate</a>
    </footer>
</body>
</html>
