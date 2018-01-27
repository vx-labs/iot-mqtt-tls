package signer

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/rand"
	"github.com/sirupsen/logrus"
	"crypto/x509/pkix"
	"time"
	"math/big"
)

type LocalSigner struct {
	key      *rsa.PrivateKey
	cert     *x509.Certificate
	template *x509.Certificate
}

func NewLocalSigner() *LocalSigner {
	const rsaKeySize = 2048
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		logrus.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         "CA",
			Country:            []string{"FR"},
			Organization:       []string{"Default CA"},
			OrganizationalUnit: []string{"Default"},
		},
		NotAfter:     time.Now().Add(time.Hour * 24 * 30 * 3),
		SerialNumber: big.NewInt(1),
	}
	b, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, privateKey.Public(), privateKey)
	if err != nil {
		logrus.Fatal(err)
	}
	cert, err := x509.ParseCertificate(b)
	if err != nil {
		logrus.Fatal(err)
	}
	l := &LocalSigner{}
	l.template = caTemplate
	l.key = privateKey
	l.cert = cert
	return l
}
func (l *LocalSigner) Sign(pub *rsa.PublicKey, cn string) ([]byte, error){
	logrus.Infof("signing cert for %s", cn)
	l.template.SerialNumber.Add(big.NewInt(1), big.NewInt(0))
	template := *l.template
	cert, err := x509.CreateCertificate(rand.Reader, &template, l.cert, pub, l.key)
	if err != nil {
		return nil, err
	}
	return cert, nil
}
