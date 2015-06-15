/*

Este programa demuestra el uso de clave pública para establecer una clave de sesión y un túnel cifrado
en una arquitectura cliente servidor:
	- intercambio de claves con RSA
	- transmisión de mensajes utilizando encoding (JSON, pero puede ser gob, etc.)

El servidor es concurrente, siendo capaz de manejar múltiples clientes simultáneamente.

ejemplos de uso:

go run pub.go srv

go run pub.go cli

*/

package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"time"
)

//Credentials for user
const user_name = "sds@gmail.com"
const user_password = "sds2015"

// función para comprobar errores (ahorra escritura)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	client()
}

// Mensaje genérico con un identificador y un argumento asociado
type Msg struct {
	Id  string
	Arg interface{}
}

func client() {

	cli_keys, err := rsa.GenerateKey(rand.Reader, 1024) // generamos un par de claves (privada, pública) para el servidor
	chk(err)
	cli_keys.Precompute() // aceleramos su uso con un precálculo

	conn, err := net.Dial("tcp", "localhost:1337") // llamamos al servidor
	chk(err)
	defer conn.Close() // es importante cerrar la conexión al finalizar

	fmt.Println("Conected at ", conn.RemoteAddr())
	fmt.Println("You are going to be ask for your user credentials")
	var srv_pub rsa.PublicKey // contendrá la clave pública del servidor

	je := json.NewEncoder(conn) // creamos un encoder/decoder de JSON sobre la conexión
	jd := json.NewDecoder(conn)

	err = je.Encode(&cli_keys.PublicKey) // envíamos la clave pública del cliente
	chk(err)

	err = jd.Decode(&srv_pub) // recibimos la clave pública del servidor
	chk(err)

	cli_token := make([]byte, 48) // 384 bits (256 bits de clave + 128 bits para el IV)
	buff := make([]byte, 256)     // contendrá el token cifrado con clave pública (puede ocupar más que el texto en claro)
	rand.Read(cli_token)          // generación del token aleatorio para el cliente

	// ciframos el token del cliente con la clave pública del servidor
	enctoken, err := rsa.EncryptPKCS1v15(rand.Reader, &srv_pub, cli_token)
	chk(err)

	err = je.Encode(&enctoken) // envíamos el token cifrado codificado con JSON
	chk(err)

	err = jd.Decode(&buff) // leemos el token cifrado procedente del servidor
	chk(err)

	// desciframos el token del servidor con nuestra clave privada
	session_key, err := rsa.DecryptPKCS1v15(rand.Reader, cli_keys, buff)
	chk(err)

	// realizamos el XOR entre ambos tokens (cliente y servidor acaban con la misma clave de sesión)
	for i := 0; i < len(cli_token); i++ {
		session_key[i] ^= cli_token[i]
	}

	aesblock, err := aes.NewCipher(session_key[:32]) // cifrador en bloque AES con la clave de sesión
	chk(err)

	aeswr := cipher.StreamWriter{S: cipher.NewCTR(aesblock, session_key[32:48]), W: conn} // un writer AES en modo CTR sobre la conexión
	aesrd := cipher.StreamReader{S: cipher.NewCTR(aesblock, session_key[32:48]), R: conn} // un reader AES en modo CTR sobre la conexión

	// redefinimos los encoder/decoder JSON para que trabajen sobre la conexión cifrada con AES
	je = json.NewEncoder(aeswr)
	jd = json.NewDecoder(aesrd)
	username := ""
	password := ""

	fmt.Println("Type your username:")
	fmt.Scan(&username)
	fmt.Println("Type your password:")
	fmt.Scan(&password)

	// We send the user credentials to server side
	je.Encode(&Msg{Id: "username", Arg: username})
	je.Encode(&Msg{Id: "password", Arg: password})

	// We read the response from server side
	var m Msg
	jd.Decode(&m)
	fmt.Println(m.Arg)

	keyscan := bufio.NewScanner(os.Stdin) // scanner para la entrada estándar (teclado)
	netscan := bufio.NewScanner(conn)     // scanner para la conexión (datos desde el servidor)

	for keyscan.Scan() {
		acc := keyscan.Text() // Texto que recibimos del CLIENTE
		arg := strings.Split(acc, " ")
		switch arg[0] { //Según la orden hacemos una cosa u otra. (MOVE, GET, etc...)

		case "upload":

			//Primero ENCRIPTAMOS en el cliente, situando el archivo en la carpeta temp/ del cliente.
			//Luego se manda el mensaje al servidor, que subirá el archivo ya cifrado previamente, desde temp/ a /uploads.

			fmt.Println("Encrypting file...")
			cipherFile("local/" + arg[1])

			//Enviamos la entrada al servidor, escaneamos conexion, y mostramos respuesta del servidor.
			fmt.Fprintln(conn, keyscan.Text())
			time.Sleep(1500 * time.Millisecond)
			netscan.Scan()
			fmt.Println("servidor: " + netscan.Text())

		case "download":

			//En este caso, primero descargarmos el archivo encriptado, que se situará temporalmente en la carpeta temp/.
			//Luego, desciframos en el cliente, leyendo de la carpeta temp/, y guardando en local/

			//Enviamos la entrada al servidor, escaneamos conexion, y mostramos respuesta del servidor.
			fmt.Println("Donwloading file...")
			fmt.Fprintln(conn, keyscan.Text())
			time.Sleep(1500 * time.Millisecond)
			netscan.Scan()
			fmt.Println("servidor: " + netscan.Text())

			decipherFile("temp/" + arg[1])
			fmt.Println("File has been downloaded and deciphered succesfully.")
			fmt.Println("You can see it in local/ dir, with the same name follow by 'recovered'. ")

			//Si la acción es GETSIZE o GETDATE, el procedimiento residirá en el servidor, simplemente mandamos la orden y escuchamos respuesta.
		default:
			//Enviamos la entrada al servidor, escaneamos conexion, y mostramos respuesta del servidor.
			fmt.Fprintln(conn, keyscan.Text())
			time.Sleep(1500 * time.Millisecond)
			netscan.Scan()
			fmt.Println("servidor: " + netscan.Text())

		}

	}
}

func checkCredentials(username string, pass string) bool {
	if username == user_name && pass == user_password {
		return true
	} else {
		return false
	}

}

func cipherFile(filein string) {

	//Leemos el contenido
	data, err := ioutil.ReadFile(filein)

	//Datos a cifrar
	dataC := []byte(string(data))

	//Encriptamos AES del modo CFB
	//Creamos el cifrador
	key := []byte("zI93JjM5NgH12AJD")
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// IV tiene que ser unica (no segura), es común
	// incluirla al principio del ciphertext
	ciphertext := make([]byte, aes.BlockSize+len(dataC))
	iv := ciphertext[:aes.BlockSize]
	//Leemos len(IV) con datos aleatorios para que sea unica
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	//Creamos el cifradorCFB y ciframos el texto
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], dataC)
	//Encriptamos el archivo

	dest := strings.Split(filein, "/")
	err = ioutil.WriteFile("temp/"+dest[1], ciphertext, 0777)
	if err != nil {
		panic(err)
	}

}

func decipherFile(filein string) {

	//Leemos el contenido
	data, err := ioutil.ReadFile(filein)

	//Datos a descifrar
	ciphertext := data

	//Desencriptamos AES del modo CFB
	//Creamos el cifrador
	key := []byte("zI93JjM5NgH12AJD")
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// Asignamos IV y ciphertext
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	//Creamos el descifradorCFB y desciframos el texto
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	dest := strings.Split(filein, "/")
	//Guardamos el archivo recuperado
	err = ioutil.WriteFile("local/recovered"+dest[1], ciphertext, 0777)

}

// CopyFile copies a file from src to dst. If src and dst files exist, and are
// the same, then return success. Otherise, attempt to create a hard link
// between the two files. If that fail, copy the file contents from src to dst.
func CopyFile(src, dst string) (err error) {
	sfi, err := os.Stat(src)
	if err != nil {
		return
	}
	if !sfi.Mode().IsRegular() {
		// cannot copy non-regular files (e.g., directories,
		// symlinks, devices, etc.)
		return fmt.Errorf("CopyFile: non-regular source file %s (%q)", sfi.Name(), sfi.Mode().String())
	}
	dfi, err := os.Stat(dst)
	if err != nil {
		if !os.IsNotExist(err) {
			return
		}
	} else {
		if !(dfi.Mode().IsRegular()) {
			return fmt.Errorf("CopyFile: non-regular destination file %s (%q)", dfi.Name(), dfi.Mode().String())
		}
		if os.SameFile(sfi, dfi) {
			return
		}
	}
	if err = os.Link(src, dst); err == nil {
		return
	}
	err = copyFileContents(src, dst)
	return
}

// copyFileContents copies the contents of the file named src to the file named
// by dst. The file will be created if it does not already exist. If the
// destination file exists, all it's contents will be replaced by the contents
// of the source file.
func copyFileContents(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return
	}
	defer func() {
		cerr := out.Close()
		if err == nil {
			err = cerr
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return
	}
	err = out.Sync()
	return
}
