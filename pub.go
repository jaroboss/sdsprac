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
	s := "Introduce srv para funcionalidad de servidor y cli para funcionalidad de cliente"
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "srv":
			fmt.Println("Server started...")
			server()
		case "cli":
			client()
		default:
			fmt.Println("Parámetro '", os.Args[1], "' desconocido. ", s)
		}
	} else {
		fmt.Println(s)
	}
}

// Mensaje genérico con un identificador y un argumento asociado
type Msg struct {
	Id  string
	Arg interface{}
}

// gestiona el modo servidor
func server() {

	srv_keys, err := rsa.GenerateKey(rand.Reader, 1024) // generamos un par de claves (privada, pública) para el servidor
	chk(err)
	srv_keys.Precompute() // aceleramos su uso con un precálculo

	ln, err := net.Listen("tcp", "localhost:1337") // escucha en espera de conexión
	chk(err)
	defer ln.Close() // nos aseguramos que cerramos las conexiones aunque el programa falle

	for { // búcle infinito, se sale con ctrl+c
		conn, err := ln.Accept() // para cada nueva petición de conexión
		chk(err)
		go func() { // lanzamos un cierre (lambda, función anónima) en concurrencia

			_, port, err := net.SplitHostPort(conn.RemoteAddr().String()) // obtenemos el puerto remoto para identificar al cliente (decorativo)
			chk(err)

			fmt.Println("conexión: ", conn.LocalAddr(), " <--> ", conn.RemoteAddr())

			var cli_pub rsa.PublicKey // contendrá la clave pública del cliente

			je := json.NewEncoder(conn) // creamos un encoder/decoder de JSON sobre la conexión
			jd := json.NewDecoder(conn)

			err = je.Encode(&srv_keys.PublicKey) // envíamos la clave pública del servidor
			chk(err)

			err = jd.Decode(&cli_pub) // recibimos la clave pública del cliente
			chk(err)

			srv_token := make([]byte, 48) // 384 bits (256 bits de clave + 128 bits para el IV)
			buff := make([]byte, 256)     // contendrá el token cifrado con clave pública (puede ocupar más que el texto en claro)
			rand.Read(srv_token)          // generación del token aleatorio para el servidor

			// ciframos el token del servidor con la clave pública del cliente
			enctoken, err := rsa.EncryptPKCS1v15(rand.Reader, &cli_pub, srv_token)
			chk(err)

			err = je.Encode(&enctoken) // envíamos el token cifrado codificado con JSON
			chk(err)

			err = jd.Decode(&buff) // leemos el token cifrado procedente del cliente
			chk(err)

			// desciframos el token del cliente con nuestra clave privada
			session_key, err := rsa.DecryptPKCS1v15(rand.Reader, srv_keys, buff)
			chk(err)

			// realizamos el XOR entre ambos tokens (cliente y servidor acaban con la misma clave de sesión)
			for i := 0; i < len(srv_token); i++ {
				session_key[i] ^= srv_token[i]
			}

			aesblock, err := aes.NewCipher(session_key[:32]) // cifrador en bloque AES con la clave de sesión
			chk(err)

			aeswr := cipher.StreamWriter{S: cipher.NewCTR(aesblock, session_key[32:48]), W: conn} // un writer AES en modo CTR sobre la conexión
			aesrd := cipher.StreamReader{S: cipher.NewCTR(aesblock, session_key[32:48]), R: conn} // un reader AES en modo CTR sobre la conexión

			// redefinimos los encoder/decoder JSON para que trabajen sobre la conexión cifrada con AES
			je = json.NewEncoder(aeswr)
			jd = json.NewDecoder(aesrd)

			// leemos el mensaje de HELLO del cliente y lo imprimimos
			var m Msg
			jd.Decode(&m)
			username := m.Arg.(string)
			jd.Decode(&m)
			password := m.Arg.(string)

			//We check the user credentials and response to client
			if checkCredentials(username, password) {
				je.Encode(&Msg{Id: "Success", Arg: "Welcome to SaferFile"})
				fmt.Println("User logged in correctyly")
				scanner := bufio.NewScanner(conn) // el scanner nos permite trabajar con la entrada línea a línea (por defecto)

				for scanner.Scan() { // escaneamos la conexión

					acc := scanner.Text()          // Texto que recibimos del CLIENTE
					arg := strings.Split(acc, " ") //Separamos la orden del parámetro con split.
					salida := ""

					switch arg[0] { //Según la orden hacemos una cosa u otra. (MOVE, GET, etc...)

					case "upload":
						fmt.Println("cliente[", port, "]: ", acc)

						cipherFile("local/" + arg[1])
						CopyFile("local/"+arg[1], "uploads/"+arg[1])
						salida = "File " + arg[1] + " has been uploaded succesfully.\n "
					case "download":
						fmt.Println("Donwloading file...")
						decipherFile("temp/" + arg[1])
						CopyFile("uploads/"+arg[1], "downloads/"+arg[1])
						salida = "File " + arg[1] + " has been downloaded succesfully. Have a look into directory donwloads, and you will find it.\n "
					default:
						salida = "Available actions: Type UPLOAD or DOWNLOAD follow by blank space and the name of the file."
					}
					// mostramos el mensaje del cliente
					fmt.Fprintln(conn, "ack: ", salida) // enviamos ack al cliente
				}
			} else {
				je.Encode(&Msg{Id: "Failure", Arg: "User name or password is incorrect"})
				fmt.Println("User couldn't log in")
			}

			conn.Close() // cerramos la conexión
			fmt.Println("cierre[", port, "]")

		}()
	}
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

	for keyscan.Scan() { // escaneamos la entrada
		fmt.Fprintln(conn, keyscan.Text())         // enviamos la entrada al servidor
		netscan.Scan()                             // escaneamos la conexión
		fmt.Println("servidor: " + netscan.Text()) // mostramos mensaje desde el servidor
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
	fmt.Println("datos del archivo: " + string(data))
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
	fmt.Println("datos del encripto: " + string(ciphertext))
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
