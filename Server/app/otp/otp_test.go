package app

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKey(t *testing.T) {
	k, err := NewKeyFromURL(`otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=sha256&digits=8`)
	require.NoError(t, err, "Falha ao analisar a url:")
	require.Equal(t, "totp", k.Type(), "Tipo de extração")
	require.Equal(t, "Example", k.Issuer(), "Emissor extrator")
	require.Equal(t, "alice@google.com", k.AccountName(), "extraindo nome do usuario")
	require.Equal(t, "JBSWY3DPEHPK3PXP", k.Secret(), "extraindo segredo")
	require.Equal(t, AlgorithmSHA256, k.Algorithm())
	require.Equal(t, DigitsEight, k.Digits())
}

func TestKeyIssuerOnlyInPath(t *testing.T) {
	k, err := NewKeyFromURL(`otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP`)
	require.NoError(t, err, "Falha ao analisar a url")
	require.Equal(t, "Example", k.Issuer(), "Nome da organização")
	require.Equal(t, "alice@google.com", k.AccountName(), "Extraindo nome do usuário")
}

func TestNoIssuer(t *testing.T) {
	k, err := NewKeyFromURL(`otpauth://totp/matiasdias@gmail.com?secret=JBSWY3DPEHPK3PXP`)
	require.NoError(t, err, "Falha ao analisar a url")
	require.Equal(t, "", k.Issuer(), "Nome da organização")
	require.Equal(t, "matiasdias@gmail.com", k.AccountName(), "Extraindo nome do usuário")
}

func TestNoAccountName(t *testing.T) {
	k1, err := NewKeyFromURL(`otpauth://totp/Example:?secret=JBSWY3DPEHPK3PXP`)
	require.NoError(t, err, "Falha ao analisar a url")
	require.Equal(t, "", k1.AccountName(), "Exatraindo nome do cliente")
	require.Equal(t, "Example", k1.Issuer(), "Nome da organização")
}

func TestKeyWithNewLine(t *testing.T) {
	w, err := NewKeyFromURL(`otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP`)
	require.NoError(t, err)
	sec := w.Secret()
	require.Equal(t, "JBSWY3DPEHPK3PXP", sec)
}
