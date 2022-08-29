package app

import (
	"encoding/base32"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type otp struct {
	TS     int64
	TOTP   string
	Mode   Algorithm
	Secret string
}

var (
	secSha1   = base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	secSha256 = base32.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	secSha512 = base32.StdEncoding.EncodeToString([]byte("1234567890123456789012345678901234567890123456789012345678901234"))

	rfcMatrixTCs = []otp{
		{59, "94287082", AlgorithmSHA1, secSha1},
		{59, "46119246", AlgorithmSHA256, secSha256},
		{59, "90693936", AlgorithmSHA512, secSha512},
		{1111111109, "07081804", AlgorithmSHA1, secSha1},
		{1111111109, "68084774", AlgorithmSHA256, secSha256},
		{1111111109, "25091201", AlgorithmSHA512, secSha512},
		{1111111111, "14050471", AlgorithmSHA1, secSha1},
		{1111111111, "67062674", AlgorithmSHA256, secSha256},
		{1111111111, "99943326", AlgorithmSHA512, secSha512},
		{1234567890, "89005924", AlgorithmSHA1, secSha1},
		{1234567890, "91819424", AlgorithmSHA256, secSha256},
		{1234567890, "93441116", AlgorithmSHA512, secSha512},
		{2000000000, "69279037", AlgorithmSHA1, secSha1},
		{2000000000, "90698825", AlgorithmSHA256, secSha256},
		{2000000000, "38618901", AlgorithmSHA512, secSha512},
		{20000000000, "65353130", AlgorithmSHA1, secSha1},
		{20000000000, "77737706", AlgorithmSHA256, secSha256},
		{20000000000, "47863826", AlgorithmSHA512, secSha512},
	}
)

func TestGenerate(t *testing.T) {
	k, err := Generates(GeneratesOtp{
		Issuer:      "Brisa",
		AccountName: "matiasdias@gmail.com",
	})
	require.NoError(t, err, "Gerar TOTP basico")
	require.Equal(t, "Brisa", k.Issuer(), "Extraindo nome da organização")
	require.Equal(t, "matiasdias@gmail.com", k.AccountName(), "Extraindo nome do usuario")
	require.Equal(t, 32, len(k.Secret()), "Segredo tem 32 bytes de comprimento com base32.")

	k1, err := Generates(GeneratesOtp{
		Issuer:      "MovelEletro",
		AccountName: "fernando@gmail.com",
		SecretSize:  20,
	})
	require.NoError(t, err, "Gerar TOTP maior")
	require.Equal(t, 32, len(k1.Secret()), "O segredo tem 32 bytes de comprimento como base32.")

	k2, err := Generates(GeneratesOtp{
		Issuer:      "Zenir",
		AccountName: "mateus@gmail.com",
		SecretSize:  13,
	})
	require.NoError(t, err, "O tamanho do segredo é válido quando o comprimento não é divisível por 5.")
	require.NotContains(t, k2.Secret(), "=", "O segredo não tem caracteres de escape.")
}

func TestGoogleLowerCaseSecret(t *testing.T) {
	w, err := NewKeyFromURL(`otpauth://totp/Google%3Afoo%40example.com?secret=qlt6vmy6svfx4bt4rpmisaiyol6hihca&issuer=Google`)
	require.NoError(t, err)
	sec := w.Secret()
	require.Equal(t, "qlt6vmy6svfx4bt4rpmisaiyol6hihca", sec)

	n := time.Now().UTC()
	code, err := GenerateCodes(w.Secret(), n)
	require.NoError(t, err)

	valid := Validates(code, w.Secret())
	require.True(t, valid)
}
