package app

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidatePadding(t *testing.T) {
	valid, err := ValidateCustom("831097", 0, "JBSWY3DPEHPK3PX",
		ValidateOtps{
			Digits:    DigitsSix,
			Algorithm: AlgorithmSHA1})
	require.NoError(t, err, "Nenhum erro esperado.")
	require.Equal(t, true, valid, "Válido deve ser verdadeiro.")
}

func TestValidateLowerCaseSecret(t *testing.T) {
	valid, err := ValidateCustom("831097", 0, "jbswy3dpehpk3px",
		ValidateOtps{
			Digits:    DigitsSix,
			Algorithm: AlgorithmSHA1,
		})
	require.NoError(t, err, "Nenhum erro esperado.")
	require.Equal(t, true, valid, "Válido deve ser verdadeiro.")
}

func TestGenerates(t *testing.T) {
	//HOTP basico
	k, err := Generate(GenerateOtp{
		Issuer:      "Brisanet Telecomunicações",
		AccountName: "flavia@gmail.com",
	})
	require.NoError(t, err, "gerar HOTP básico")
	require.Equal(t, "Brisanet Telecomunicações", k.Issuer(), "Extraindo nome da organização")
	require.Equal(t, "flavia@gmail.com", k.AccountName(), "Extraindo nome do usuário")
	require.Equal(t, 16, len(k.Secret()), "O segredo tem 16 bytes de comprimento como base32.")

	//HOTP maior
	k, err = Generate(GenerateOtp{
		Issuer:      "Brisa",
		AccountName: "amatiasdias0102@gmail.com",
		SecretSize:  20,
	})
	require.NoError(t, err, "Gerar HOTP maior")
	require.Equal(t, 32, len(k.Secret()), "O segredo tem 32 bytes e o comprimento com base32.")

	//sem nome da organziação
	k, err = Generate(GenerateOtp{
		Issuer:      "",
		AccountName: "Suziane@gmail.com",
	})
	require.Equal(t, ErrGenerateMissingIssuer, err, "gerar nome da organização ausente")
	require.Nil(t, k, "chave deve ser nula em caso de erro.")

	//HOTP com nome do usuario ausente
	k, err = Generate(GenerateOtp{
		Issuer:      "Aamazom",
		AccountName: "",
	})
	require.Equal(t, ErrGenerateMissingAccountName, err, "Gerar nome do usuario ausente.")
	require.Nil(t, k, "Chave deve ser nula em caso de erro.")

	k, err = Generate(GenerateOtp{
		Issuer:      "Zenir",
		AccountName: "Flavio@gmail.com",
		SecretSize:  17,
	})
	require.NoError(t, err, "O tamanho do segredo é válido quando o comprimento não é divisível por 5.")
	require.NotContains(t, k.Secret(), "=", "O segredo não tem caracteres de escape.")

	k, err = Generate(GenerateOtp{
		Issuer:      "Boticario",
		AccountName: "maria@gmail.com",
		Secret:      []byte("helloworld"),
	})
	require.NoError(t, err, "Falha na geração secreta")
	sec, err := b32NoPadding.DecodeString(k.Secret())
	require.NoError(t, err, "Segredo não era válido base32")
	require.Equal(t, sec, []byte("helloworld"), "Segredo especificado não foi mantido")
}
