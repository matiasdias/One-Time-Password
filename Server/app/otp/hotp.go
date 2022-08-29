package app

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net/url"
	"strings"
)

const debug = false

func Validate(passcode string, counter uint64, secret string) bool {
	r, _ := ValidateCustom(
		passcode,
		counter,
		secret,
		ValidateOtps{
			Digits:    DigitsSix,
			Algorithm: AlgorithmSHA1,
		},
	)
	return r
}

type ValidateOtps struct {
	Digits    Digits
	Algorithm Algorithm
}

func GenerateCode(secret string, counter uint64) (string, error) {
	return GenerateCodeCustom(secret, counter, ValidateOtps{
		Digits:    DigitsSix,
		Algorithm: AlgorithmSHA1,
	})
}

// GenerateCodeCustom pega um ponto de tempo e produz uma senha usando um secret e os opts fornecido.
func GenerateCodeCustom(secret string, counter uint64, opts ValidateOtps) (passcode string, err error) {
	secret = strings.TrimSpace(secret)
	if n := len(secret) % 8; n != 0 {
		secret = secret + strings.Repeat("=", 8-n)
	}
	// Certifique-se de que a chave esteja em letras maiúsculas
	secret = strings.ToUpper(secret)
	secretBytes, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", ErrValidateSecretInvalidBase32
	}

	// Converte o contador em bytes
	buf := make([]byte, 8)
	mac := hmac.New(opts.Algorithm.Hash, secretBytes)
	binary.BigEndian.PutUint64(buf, counter)
	if debug {
		fmt.Printf("counter=%v\n", counter)
		fmt.Printf("buf=%v\n", buf)
	}

	mac.Write(buf)
	sum := mac.Sum(nil)

	// Construir o inteiro resultado
	offset := sum[len(sum)-1] & 0xf
	v := int64(((int(sum[offset]) & 0x7f) << 24) |
		((int(sum[offset+1] & 0xff)) << 16) |
		((int(sum[offset+2] & 0xff)) << 8) |
		(int(sum[offset+3]) & 0xff))

	l := opts.Digits.Length()
	m := int32(v % int64(math.Pow10(l)))

	if debug {
		fmt.Printf("offset=%v\n", offset)
		fmt.Printf("value=%v\n", v)
		fmt.Printf("mod'ed=%v\n", m)
	}

	return opts.Digits.Format(m), nil
}

func ValidateCustom(passcode string, counter uint64, secret string, otps ValidateOtps) (bool, error) {
	passcode = strings.TrimSpace(passcode)

	if len(passcode) != otps.Digits.Length() {
		return false, ErrValidateInputInvalidLength
	}

	otp, err := GenerateCodeCustom(secret, counter, otps)
	if err != nil {
		return false, err
	}

	if subtle.ConstantTimeCompare([]byte(otp), []byte(passcode)) == 1 {
		return true, nil
	}

	return false, nil
}

type GenerateOtp struct {
	Issuer      string
	AccountName string
	SecretSize  uint
	Secret      []byte
	Digits      Digits
	Algorithm   Algorithm
	Rand        io.Reader
}

var b32NoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Gera uma nova chave HOTP baseada em mensagem
func Generate(otp GenerateOtp) (*Key, error) {
	if otp.Issuer == "" {
		return nil, ErrGenerateMissingIssuer
	}

	if otp.AccountName == "" {
		return nil, ErrGenerateMissingAccountName
	}

	if otp.SecretSize == 0 {
		otp.SecretSize = 10
	}

	if otp.Digits == 0 {
		otp.Digits = DigitsSix
	}

	if otp.Rand == nil {
		otp.Rand = rand.Reader
	}

	// otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example

	//​​retorna os parâmetros HOTP representados como url.Values.
	v := url.Values{}
	if len(otp.Secret) != 0 {
		v.Set("secret", b32NoPadding.EncodeToString(otp.Secret))
	} else {
		secret := make([]byte, otp.SecretSize)
		_, err := otp.Rand.Read(secret)
		if err != nil {
			return nil, err
		}
		v.Set("secret", b32NoPadding.EncodeToString(secret))
	}

	v.Set("issuer", otp.Issuer)
	v.Set("algorithm", otp.Algorithm.String())
	v.Set("digits", otp.Digits.String())

	u := url.URL{
		Scheme:   "otpauth",
		Host:     "hotp",
		Path:     "/" + otp.Issuer + ":" + otp.AccountName,
		RawQuery: v.Encode(),
	}

	return NewKeyFromURL(u.String())
}
