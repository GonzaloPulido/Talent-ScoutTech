<?php
require_once dirname(__FILE__) . '/private/conf.php';

# Require logged users
require dirname(__FILE__) . '/private/auth.php';

if (isset($_POST['name']) && isset($_POST['team'])) {
    # Get input data
    $name = $_POST['name'];
    $team = $_POST['team'];

    # Prepare query and execute based on whether `id` exists
    if (isset($_GET['id']) && is_numeric($_GET['id'])) {
        $id = $_GET['id'];
        $stmt = $db->prepare('INSERT OR REPLACE INTO players (playerid, name, team) VALUES (:id, :name, :team)');
        $stmt->bindValue(':id', $id, SQLITE3_INTEGER);
        $stmt->bindValue(':name', $name, SQLITE3_TEXT);
        $stmt->bindValue(':team', $team, SQLITE3_TEXT);
        $stmt->execute();
    } else {
        $stmt = $db->prepare('INSERT INTO players (name, team) VALUES (:name, :team)');
        $stmt->bindValue(':name', $name, SQLITE3_TEXT);
        $stmt->bindValue(':team', $team, SQLITE3_TEXT);
        $stmt->execute();
    }
} else {
    # Show info to modify if id is provided
    if (isset($_GET['id']) && is_numeric($_GET['id'])) {
        $id = $_GET['id'];
    
        $stmt = $db->prepare("SELECT name, team FROM players WHERE playerid = :id");
        $stmt->bindValue(':id', $id, SQLITE3_INTEGER);
        $result = $stmt->execute();
        
        $row = $result->fetchArray();
        if ($row) {
            $name = $row['name'];
            $team = $row['team'];
        } else {
            die("Modifying a nonexistent player!");
        }
    }
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
        <title>Práctica RA3 - Players list</title>
    </head>
    <body>
        <header>
            <h1>Player</h1>
        </header>
        <main class="player">
            <form action="#" method="post">
                <input type="hidden" name="id" value="<?=$id?>"><br>
                <h3>Player name</h3>
                <textarea name="name"><?=$name?></textarea><br>
                <h3>Team name</h3>
                <textarea name="team"><?=$team?></textarea><br>
                <input type="submit" value="Send">
            </form>
            <form action="#" method="post" class="menu-form">
                <a href="index.php">Back to home</a>
                <a href="list_players.php">Back to list</a>
                <input type="submit" name="Logout" value="Logout" class="logout">
            </form>
        </main>
        <footer class="listado">
            <img src="images/logo-iesra-cadiz-color-blanco.png">
            <h4>Puesta en producción segura</h4>
            < Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/"> donate</a> >
        </footer>
    </body>
</html>
