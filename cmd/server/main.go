package main

import (
	"os"
	"google.golang.org/grpc/reflection"
	"net"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"github.com/vx-labs/iot-mqtt-tls/types"
	"github.com/vx-labs/iot-mqtt-tls/state"
	"golang.org/x/net/context"
	"github.com/vx-labs/iot-mqtt-tls/signer"
	"crypto/rsa"
	"math/big"
)

type SignProvider interface {
	Sign(pub *rsa.PublicKey, cn string) ([]byte, error)
}
type StateProvider interface {
}

type CertificateProvider struct {
	state  StateProvider
	signer SignProvider
}

func (c *CertificateProvider) GetCertificate(ctx context.Context, in *types.GetCertificateRequest) (*types.GetCertificateReply, error) {
	pub := &rsa.PublicKey{
		N: big.NewInt(0),
		E: int(in.Exponent),
	}
	pub.N.SetBytes(in.Modulus)
	cert, err := c.signer.Sign(pub, in.Domain)
	if err != nil {
		return nil, err
	}
	return &types.GetCertificateReply{Certificate: cert}, nil
}

func main() {
	port := ":7995"
	lis, err := net.Listen("tcp", port)
	if err != nil {
		logrus.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	store := &CertificateProvider{
		signer: signer.NewLocalSigner(),
	}
	switch os.Getenv("BACKEND") {
	default:
		store.state = state.NewLocalProvider()
	}
	types.RegisterTLSServiceServer(s, store)
	reflection.Register(s)
	logrus.Infof("serving certificates provider on %v", port)
	if err := s.Serve(lis); err != nil {
		logrus.Fatalf("failed to serve: %v", err)
	}

}
