<?php
// ABSICHTLICH UNSICHER – Uebungscode fuer den Vigil-Benchmark. Nicht verwenden!
// Eigene kleine Beispiele nach typischen Mustern aus DVWA (keine Kopie des Projekts).

// SQL-Injection: Benutzer-ID direkt in die Abfrage
$result = mysqli_query($conn, "SELECT first_name, last_name FROM users WHERE user_id = '" . $_GET['id'] . "'");

// Befehls-Injection: Ping mit Eingabe
$out = shell_exec('ping -c 4 ' . $_REQUEST['ip']);

// Reflektiertes XSS: Name ungeprueft ausgeben
echo $_GET['name'];

// Datei-Einbindung (LFI/RFI) aus Eingabe
include($_GET['page']);

// Unsichere Deserialisierung eines Cookies
$prefs = unserialize($_COOKIE['prefs']);

// Passwort mit MD5 gespeichert
$hash = md5($password);

// Variablen aus der Anfrage ueberschreiben
extract($_POST);
