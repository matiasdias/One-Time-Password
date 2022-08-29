package app

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"image"
	"net/url"
	"strconv"
	"strings"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
)

var ErrValidateSecretInvalidBase32 = errors.New("Falha na decodificação do secredo com a base 32")
var ErrValidateInputInvalidLength = errors.New("Comprimento de entrada inesperado")
var ErrGenerateMissingIssuer = errors.New("Emissor deve ser definido")
var ErrGenerateMissingAccountName = errors.New("AccountName deve ser difinido ")

type Key struct {
	//Chave representa uma chave TOTP ou HTOP.
	orig string
	url  *url.URL
}

// NewKeyFromURL cria uma nova chave a partir de uma url TOTP ou HOTP.
//formato da url
//otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30
func NewKeyFromURL(orig string) (*Key, error) {

	s := strings.TrimSpace(orig)
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}

	return &Key{
		orig: s,
		url:  u,
	}, nil
}

func (k *Key) String() string {
	return k.orig
}

// A image retorna uma imagem QR-Code da largura e altura especificadas,
func (k *Key) Image(width int, height int) (image.Image, error) {
	b, err := qr.Encode(k.orig, qr.M, qr.Auto)
	if err != nil {
		return nil, err
	}
	b, err = barcode.Scale(b, width, height) // retorna um codigo de barras redimencionado
	if err != nil {
		return nil, err
	}
	return b, nil
}

// Type retorna um TOTP ou HOTP
func (k *Key) Type() string {
	return k.url.Host
}

//Issuer Retorna o nome da organização emissora
func (k *Key) Issuer() string {
	q := k.url.Query().Get("issuer")
	if q != "" {
		return q
	}
	p := strings.TrimPrefix(k.url.Path, "/")
	i := strings.Index(p, ":")
	if i == -1 {
		return ""
	}
	return p[:i]
}

// AccountName retorna o nome da conta do usuário.
func (k *Key) AccountName() string {
	p := strings.TrimPrefix(k.url.Path, "/")
	i := strings.Index(p, ":")

	if i == -1 {
		return p
	}

	return p[i+1:]
}

// Secret retorna um segredo para essa chave
func (k *Key) Secret() string {
	return k.url.Query().Get("secret")
}

// Period retorna um pequeno int representando o tempo de rotação em segundos.
func (k *Key) Period() uint64 {
	a := k.url.Query().Get("period")
	if n, err := strconv.ParseUint(a, 10, 64); err == nil {
		return n
	}
	// Se nenhum período for definido, 30 segundos é o padrão
	return 30
}

// Digits retorna um int representando o número de dígitos OTP
func (k *Key) Digits() Digits {
	d := k.url.Query().Get("digits")
	if m, err := strconv.ParseUint(d, 10, 64); err == nil {
		switch m {
		case 8:
			return DigitsEight
		default:
			return DigitsSix
		}
	}
	// seis é o valor mais comum
	return DigitsSix
}

// Algoritmo retorna o algoritmo usado ou o padrão (SHA1).
func (k *Key) Algorithm() Algorithm {
	al := k.url.Query().Get("algorithm")
	c := strings.ToLower(al)
	switch c {
	case "md5":
		return AlgorithmMD5
	case "sha256":
		return AlgorithmSHA256
	case "sha512":
		return AlgorithmSHA512
	default:
		return AlgorithmSHA1
	}
}

// URL retorna a URL OTP como uma string
func (k *Key) URL() string {
	return k.url.String()
}

type Algorithm int

const (
	//Algoritmo representa a função de hash para usar na operação HMAC necessária para OTPs.
	AlgorithmSHA1 Algorithm = iota // padrão
	AlgorithmSHA256
	AlgorithmSHA512
	AlgorithmMD5
)

// String retorna uma representação de string de HmacAlgorithm.
func (a Algorithm) String() string {
	switch a {
	case AlgorithmSHA1:
		return "SHA1"
	case AlgorithmSHA256:
		return "SHA256"
	case AlgorithmSHA512:
		return "SHA512"
	case AlgorithmMD5:
		return "MD5"
	}
	panic("unreached")
}

// Hash retorna uma instância hash.Hash correspondente ao tipo HmacAlgorithm.
func (a Algorithm) Hash() (h hash.Hash) {
	switch a {
	case AlgorithmSHA1:
		h = sha1.New()
	case AlgorithmSHA256:
		h = sha256.New()
	case AlgorithmSHA512:
		h = sha512.New()
	case AlgorithmMD5:
		h = md5.New()
	default:
		panic("unreached")
	}
	return h
}

// MarshalJSON retorna uma representação JSON de HmacAlgorithm.
/*func (a Algorithm) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.String())
}*/

type Digits int

const (
	//Dígitos representa o número de dígitos presentes na senha OTP do usuário.
	//Seis e Oito são os valores mais comuns.
	DigitsSix   Digits = 6
	DigitsEight Digits = 8
)

// Format converte um inteiro no tamanho preenchido com zero para este Digits.
func (d Digits) Format(in int32) string {
	f := fmt.Sprintf("%%0%dd", d)
	return fmt.Sprintf(f, in)
}

// Length retorna o número de caracteres para este Digits.
func (d Digits) Length() int {
	return int(d)
}

func (d Digits) String() string {
	return fmt.Sprintf("%d", d)
}
