<?php
require_once dirname(__FILE__) . '/private/conf.php';
require dirname(__FILE__) . '/private/auth.php';

?>
<!doctype html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <link rel="stylesheet" href="css/style.css">
    <title>Práctica RA3 - Comments editor</title>
</head>
<body>
<header>
    <h1>Comments editor</h1>
</header>
<main class="player">

<?php
// Verificamos si existe el parámetro 'id' en la URL
if (isset($_GET['id'])) {
    // Validamos que el 'id' sea un número entero
    $playerId = (int)$_GET['id'];

    // Usamos una consulta preparada para evitar inyecciones SQL
    $query = "SELECT commentId, username, body FROM comments C JOIN users U ON U.userId = C.userId WHERE C.playerId = :playerId ORDER BY C.commentId DESC";
    $stmt = $db->prepare($query);
    $stmt->bindValue(':playerId', $playerId, SQLITE3_INTEGER);
    $result = $stmt->execute();

    // Verificamos si existen comentarios
    if ($result->numColumns() > 0) {
        while ($row = $result->fetchArray()) {
            // Escapamos los datos antes de mostrarlos para prevenir XSS
            $username = htmlspecialchars($row['username'], ENT_QUOTES, 'UTF-8');
            $body = htmlspecialchars($row['body'], ENT_QUOTES, 'UTF-8');
            echo "<div>
                    <h4>{$username}</h4>
                    <p>commented: {$body}</p>
                  </div>";
        }
    } else {
        echo "<p>No comments available for this player.</p>";
    }
} else {
    echo "<p>No player ID provided.</p>";
}

?>

<div>
    <a href="list_players.php">Back to list</a>
    <a class="black" href="add_comment.php?id=<?php echo $playerId; ?>"> Add comment</a>
</div>

</main>
<footer class="listado">
    <img src="images/logo-iesra-cadiz-color-blanco.png">
    <h4>Puesta en producción segura</h4>
    <Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/"> donate</a> >
</footer>
</body>
</html>
