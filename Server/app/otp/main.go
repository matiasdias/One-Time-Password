package app

import (
	"bufio"
	"bytes"
	"encoding/base32"
	"fmt"
	"image/png"
	"io/ioutil"
	"os"
	"time"
)

// Exibe para o usuario
func display(key *Key, data []byte) {
	fmt.Printf("Issuer: %s\n", key.Issuer())
	fmt.Printf("Account Name: %s\n", key.AccountName())
	fmt.Printf("Secret: %s\n", key.Secret())
	fmt.Printf("URL: %s\n", key.URL())
	fmt.Println("Escrevendo PNG para qr-code.png....")
	ioutil.WriteFile("qr-code.png", data, 0644)
	fmt.Println("")
	fmt.Println("Por favor, adicione seu TOTP ao seu aplicativo OTP agora!")
	fmt.Println("")
}

func promptForPasscode() string {
	re := bufio.NewReader(os.Stdin)
	fmt.Print("Digite a senha")
	text, _ := re.ReadString('\n')
	return text
}

//GeneratesPasscode Gera a senha usando um segredo UTF-8 (não base32) e parâmetros personalizados
func GeneratePassCode(utf8string string) string {
	secret := base32.StdEncoding.EncodeToString([]byte(utf8string))
	passcode, err := GenerateCodeCustoms(secret, time.Now(), ValidateOtp{
		Period:    30,
		Skew:      1,
		Digits:    DigitsSix,
		Algorithm: AlgorithmSHA1,
	})

	if err != nil {
		panic(err)
	}
	return passcode
}

func main() {
	k, err := Generates(GeneratesOtp{
		Issuer:      "Example1.com",
		AccountName: "matiasdias@gmail.com",
		Algorithm:   AlgorithmSHA1,
	})
	if err != nil {
		panic(err)
	}
	// Converte a chave TOTP em um código QR codificado como uma imagem PNG.
	var buf bytes.Buffer
	img, err := k.Image(200, 200)
	if err != nil {
		panic(err)
	}
	png.Encode(&buf, img)

	// Exibe o código QR para o usuário.
	display(k, buf.Bytes())

	// Agora valida se o usuário adicionou a senha com sucesso.
	fmt.Println("Validando TOTP...")
	passcode := promptForPasscode()          //oega a senha
	valid := Validates(passcode, k.Secret()) // validar a senha

	if valid { // O usuário usou seu TOTP com sucesso, salve-o em seu backend!
		println("Senha valida")
		os.Exit(0)
	} else {
		println("Senha invalida")
		os.Exit(0)
	}
}

/*func logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		/*if r.Header.Get("logged") == "true" {
			next.ServeHTTP(w, r)
			return
		}
		r.Header.Set("logged", "true") //loga só uma vez

		log.Printf("from %q request %q\n", r.RemoteAddr, r.RequestURI)
		next.ServeHTTP(w, r)
	})
}*/
