/*

Este programa lee de la entrada estándar y cifra los datos bien con AES128 o RC4,
imprimiéndolos en la salida estándar.


ejemplos de uso:

go run cif.go -k "Esto es una clave"

go run cif.go -k "Esto es una clave" -a "RC4"


-lectura y escritura (io.Writer e io.Reader)
-parámetros en línea de comandos (flag)
-cifradores y hash (crypto)
-interfaces
*/
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rc4"
	"crypto/sha256"
	"flag"
	"io"
	"os"
	"strings"
)

// función que sirve para comprobar si hay error y salir del programa (panic) en tal caso
func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {

	// definimos los flags del programa,
	// ej. de uso: go run ejemplo2.go -k "Clave para cifrar" -a RC4

	// estas variables son punteros
	pA := flag.String("a", "AES128", "algoritmo de cifrado (AES128, RC4)")
	pK := flag.String("k", "", "clave para cifrar o descifrar")

	// hay que llamar a flag.Parse para que compruebe los flags y asigne valores
	flag.Parse()

	// si no hay clave (parámetro obligatorio) imprimimos el mensaje de uso y salimos
	if *pK == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Obtenemos el hash (256bit) de la clave introducida por el usuario
	// De esta forma podemos usar cualquier cadena como clave
	h := sha256.New()
	h.Reset()
	_, err := h.Write([]byte(*pK))
	check(err)
	key := h.Sum(nil)

	// Utilizamos la misma función hash para obtener un valor de inicialización (256 bit),
	// necesario en el modo CTR y que ha de ser el mismo para el correcto descifrado
	h.Reset()
	_, err = h.Write([]byte("<inicializar>"))
	check(err)
	iv := h.Sum(nil)

	/*
		Para cifrar y descifrar utilizamos el interfaz cipher.Stream que luego utilizamos en cipher.StreamWriter o
		cipher.StreamReader según necesitemos cifrar o descifrar. Este enfoque nos permite trabajar con todos los
		cifradores del mismo modo, tanto si son de bloque (en modo CTR) como en flujo.
	*/

	// definimos la variable de tipo cipher.Stream
	var S cipher.Stream

	// comprobamos el algoritmo seleccionado
	switch strings.ToUpper(*pA) {

	case "AES128":
		block, err := aes.NewCipher(key[:16]) // obtenemos un cifrador en bloque AES con clave de 128bits (16 bytes)
		check(err)
		S = cipher.NewCTR(block, iv[:16]) // obtenemos un cipher.Stream con el modo CTR en AES con un IV de 128bits

	case "RC4": // RC4 proporciona un cipher.Stream directamente al ser cifrador en flujo
		c, err := rc4.NewCipher(key) // usamos toda la clave
		check(err)
		S = c

	default:
		flag.PrintDefaults()
		os.Exit(1)
	}

	// definimos un lector y un escritor que asignaremos para copiar al final del lector al escritor
	var rd io.Reader
	var wr io.WriteCloser

	var enc cipher.StreamWriter // variable que contiene el cifrador
	enc.S = S                   // asignamos el cipher.Stream
	enc.W = os.Stdout           // y el fichero (io.Writer) donde escribir (salida estándar)

	rd = os.Stdin // el lector (io.Reader) es el fichero de entrada (entrada estándar)
	wr = enc      // el escritor (io.Writer) es el cifrador (cipher.StreamWriter)

	_, err = io.Copy(wr, rd) // copiamos del lector al escritor (ejecuta la acción de cifrado/descifrado)
	check(err)
	wr.Close() // es importante cerrar el escritor para que escriba todo lo que tiene en buffer antes de salir
}
