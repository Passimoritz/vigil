// ABSICHTLICH UNSICHER – Uebungscode fuer den Vigil-Benchmark. Nicht verwenden!
// Eigene kleine Beispiele nach typischen Mustern aus OWASP WebGoat / WebGoat.NET (keine Kopie).
using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Net;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;

public class Lessons
{
    // SQL-Injection: Nachname wird an die Abfrage gehaengt
    public SqlDataReader Accounts(SqlConnection conn, string name)
    {
        var cmd = new SqlCommand("SELECT * FROM user_data WHERE last_name = '" + name + "'", conn);
        return cmd.ExecuteReader();
    }

    // Befehls-Injection: Eingabe im Befehlstext
    public void Lookup(string host)
    {
        Process.Start("cmd.exe", "/c nslookup " + host);
    }

    // Zertifikatspruefung abgeschaltet
    public void TrustAll()
    {
        ServicePointManager.ServerCertificateValidationCallback = (s, c, ch, e) => true;
    }

    // Unsicheres Einlesen von Objekten
    public object Load(System.IO.Stream input)
    {
        return new BinaryFormatter().Deserialize(input);
    }

    // Passwort-Hash mit MD5
    public byte[] HashPassword(byte[] password)
    {
        return MD5.Create().ComputeHash(password);
    }
}
