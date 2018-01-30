package main

import (
	"google.golang.org/grpc/reflection"
	"net"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"github.com/vx-labs/iot-mqtt-tls/types"
	"golang.org/x/net/context"
	"github.com/vx-labs/iot-mqtt-tls/signer"
	"crypto/rsa"
	"math/big"
	"github.com/vx-labs/iot-mqtt-tls/cache"
	"fmt"
)

type SignProvider interface {
	Sign(pub *rsa.PublicKey, cn string) ([]byte, error)
}

type CacheProvider interface {
	Get(ctx context.Context, cn string) ([]byte, error)
	Put(ctx context.Context, cn string, cert []byte) (error)
}

type CertificateProvider struct {
	signer SignProvider
	cache CacheProvider
}

func (c *CertificateProvider) GetCertificate(ctx context.Context, in *types.GetCertificateRequest) (*types.GetCertificateReply, error) {
	cert, err := c.cache.Get(ctx, in.Domain)
	if err != nil {
		pub := &rsa.PublicKey{
			N: big.NewInt(0),
			E: int(in.Exponent),
		}
		pub.N.SetBytes(in.Modulus)
		cert, err = c.signer.Sign(pub, in.Domain)
		if err != nil {
			return nil, err
		}
		err = c.cache.Put(ctx, in.Domain, cert)
		if err != nil {
			logrus.Errorf("unable to save cert to cache store: %v", err)
			return nil, fmt.Errorf("unable to persit certificate to store")
		}
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
		cache: cache.NewEtcdProvider(),
	}
	types.RegisterTLSServiceServer(s, store)
	reflection.Register(s)
	logrus.Infof("serving certificates provider on %v", port)
	if err := s.Serve(lis); err != nil {
		logrus.Fatalf("failed to serve: %v", err)
	}

}
