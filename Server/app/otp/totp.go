package app

import (
	"crypto/rand"
	"encoding/base32"
	"io"
	"math"
	"net/url"
	"strconv"
	"time"
)

// Valida um TOTP usando a hora atual.
func Validates(passcode string, secret string) bool {
	rv, _ := ValidateCustoms(
		passcode,
		secret,
		time.Now().UTC(),
		ValidateOtp{
			Period:    30,
			Skew:      1,
			Digits:    DigitsSix,
			Algorithm: AlgorithmSHA1,
		},
	)
	return rv
}

// GenerateCode cria um token TOTP usando a hora atual.
func GenerateCodes(secret string, t time.Time) (string, error) {
	return GenerateCodeCustoms(secret, t, ValidateOtp{
		Period:    30,
		Skew:      1,
		Digits:    DigitsSix,
		Algorithm: AlgorithmSHA1,
	})
}

// ValidateOpts fornece opções para ValidateCustom().
type ValidateOtp struct {
	Period    uint
	Skew      uint
	Digits    Digits
	Algorithm Algorithm
}

// GenerateCodeCustom pega um ponto de tempo e produz uma senha usando um secret e os opts fornecido.
func GenerateCodeCustoms(secret string, t time.Time, otp ValidateOtp) (passcode string, err error) {
	if otp.Period == 0 {
		otp.Period = 30
	}

	//retorna um contador válido baseado no timestamp fornecido.
	counter := uint64(math.Floor(float64(t.Unix()) / float64(otp.Period)))

	passcode, err = GenerateCodeCustom(secret, counter, ValidateOtps{
		Digits:    otp.Digits,
		Algorithm: otp.Algorithm,
	})
	if err != nil {
		return "", err
	}
	return passcode, nil
}

// ValidateCustom valida um TOTP dado um tempo especificado pelo usuário e opções personalizadas.
func ValidateCustoms(passcode string, secret string, t time.Time, otp ValidateOtp) (bool, error) {
	if otp.Period == 0 {
		otp.Period = 30
	}

	counters := []uint64{}
	counter := int64(math.Floor(float64(t.Unix()) / float64(otp.Period)))

	counters = append(counters, uint64(counter))
	for i := 1; i <= int(otp.Skew); i++ {
		counters = append(counters, uint64(counter+int64(i)))
		counters = append(counters, uint64(counter-int64(i)))
	}

	for _, counter := range counters {
		rv, err := ValidateCustom(passcode, counter, secret, ValidateOtps{
			Digits:    otp.Digits,
			Algorithm: otp.Algorithm,
		})

		if err != nil {
			return false, err
		}

		if rv == true {
			return true, nil
		}
	}

	return false, nil
}

// GenerateOpts fornece opções para Generate(). Os valores padrão
type GeneratesOtp struct {
	Issuer      string // Nome da organização
	AccountName string // Nome da conta do usuário
	Period      uint   // Número de segundos que um hash TOTP é válido. O padrão é 30 segundos.
	SecretSize  uint
	Secret      []byte // Dígitos a serem solicitados. O padrão é 6.
	Digits      Digits
	Algorithm   Algorithm
	Rand        io.Reader
}

var b32NoPaddings = base32.StdEncoding.WithPadding(base32.NoPadding)

// Gera uma nova chave TOTP baseada em tempo
func Generates(otp GeneratesOtp) (*Key, error) {
	if otp.Issuer == "" {
		return nil, ErrGenerateMissingIssuer
	}

	if otp.AccountName == "" {
		return nil, ErrGenerateMissingAccountName
	}

	if otp.Period == 0 {
		otp.Period = 30
	}

	if otp.SecretSize == 0 {
		otp.SecretSize = 20 // 20 bytes
	}

	if otp.Digits == 0 {
		otp.Digits = DigitsSix
	}

	if otp.Rand == nil {
		otp.Rand = rand.Reader
	}

	// otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example

	//​​retorna os parâmetros TOTP representados como url.Values.
	params := url.Values{}
	if len(otp.Secret) != 0 {
		params.Set("secret", b32NoPadding.EncodeToString(otp.Secret))
	} else {
		secret := make([]byte, otp.SecretSize)
		_, err := otp.Rand.Read(secret)
		if err != nil {
			return nil, err
		}
		params.Set("secret", b32NoPadding.EncodeToString(secret))
	}

	params.Set("issuer", otp.Issuer)
	params.Set("period", strconv.FormatUint(uint64(otp.Period), 10))
	params.Set("algorithm", otp.Algorithm.String())
	params.Set("digits", otp.Digits.String())

	u := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/" + otp.Issuer + ":" + otp.AccountName,
		RawQuery: params.Encode(),
	}

	return NewKeyFromURL(u.String())
}
