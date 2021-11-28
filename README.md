# Cryptdings

Beispiel, wie ein SecretKey zur Verschlüsselung mit AES erzeugt wird.
Dabei stellen sich verschiedene Fragen.

* Wie wird mit dem Encoding der Zeichenkette (Passwort) umgegangen?
* Wie lang soll ein Salt sein?
* Ist es ok, den Salt mitzuübertragen?
* Wo wird der Salt als Präfix davorgehangen?

Mit dem erzeugten Secret Key sollen zwei Dinge getan werden.

1. Er soll via RSA gewrapped und uwrapped werden
2. Es soll etwas im Betriebsmodus GCM ver- und entschlüsselt werden.
3. Wie lang ist eine IV und wo wird diese davorgehangen? 

Was ist der OCB Betriebsmodus und wie kann er verwendet werden.
https://stackoverflow.com/questions/1220751/how-to-choose-an-aes-encryption-mode-cbc-ecb-ctr-ocb-cfb

## RFC8018

Im RFC wird zur Passwort Wahl folgendes gesagt.

```
 Throughout this document, a password is considered to be an octet string of arbitrary
 length whose interpretation as a text string is unspecified.  
 In the interest of interoperability, however, it is recommended that applications follow 
 some common text encoding rules.
 ASCII and UTF-8 [RFC3629] are two possibilities.  (ASCII is a subset of UTF-8.)

 Although the selection of passwords is outside the scope of this document, 
 guidelines have been published [NISTSP63] that may well be taken into account.
```

Zum Salt findet sich dieses.

```
1.  If there is no concern about interactions between multiple
    uses of the same key (or a prefix of that key) with the
    password-based encryption and authentication techniques
    supported for a given password, then the salt may be generated
    at random and need not be checked for a particular format by
    the party receiving the salt.  It should be at least eight
    octets (64 bits) long.

2.  Otherwise, the salt should contain data that explicitly
    distinguishes between different operations and different key
    lengths, in addition to a random part that is at least eight
    octets long, and this data should be checked or regenerated by
    the party receiving the salt.  For instance, the salt could
    have an additional non-random octet that specifies the purpose
    of the derived key.  Alternatively, it could be the encoding
    of a structure that specifies detailed information about the
    derived key, such as the encryption or authentication
    technique and a sequence number among the different keys
    derived from the password.  The particular format of the
    additional data is left to the application.
```
Das bedeutet für 1. mindestens 8 bytes.