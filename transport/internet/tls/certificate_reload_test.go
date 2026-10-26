package tls_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	gotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

func TestCertificateReloadConcurrentSelection(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	makeCert := func(serial int64) []byte {
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "fixture.test"}, DNSNames: []string{"fixture.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	certA, certB := makeCert(1), makeCert(2)
	directory := t.TempDir()
	certFile, keyFile := filepath.Join(directory, "cert.pem"), filepath.Join(directory, "key.pem")
	if err = os.WriteFile(certFile, certA, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	entry := &xtls.Certificate{Certificate: certA, Key: keyPEM, CertificatePath: certFile, KeyPath: keyFile, OcspStapling: 1}
	config := &xtls.Config{Certificate: []*xtls.Certificate{entry}, RejectUnknownSni: true}
	configs := []*gotls.Config{config.GetTLSConfig(), config.GetTLSConfig()}
	hello := &gotls.ClientHelloInfo{ServerName: "fixture.test"}
	first, err := configs[0].GetCertificate(hello)
	if err != nil {
		t.Fatal(err)
	}
	if first.Leaf.SerialNumber.Int64() != 1 {
		t.Fatal("initial certificate mismatch")
	}
	var stop, seenNew atomic.Bool
	var wg sync.WaitGroup
	failures := make(chan error, 4)
	for i := range 4 {
		wg.Go(func() {
			for !stop.Load() {
				certificate, err := configs[i%2].GetCertificate(hello)
				if err != nil {
					failures <- err
					return
				}
				serial := certificate.Leaf.SerialNumber.Int64()
				if serial != 1 && serial != 2 {
					failures <- fmt.Errorf("invalid certificate serial %d", serial)
					return
				}
				_ = len(certificate.OCSPStaple)
				if serial == 2 {
					seenNew.Store(true)
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
	updated := filepath.Join(directory, "updated.pem")
	if err = os.WriteFile(updated, certB, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(updated, certFile); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(5 * time.Second)
	for !seenNew.Load() && time.Now().Before(until) {
		time.Sleep(10 * time.Millisecond)
	}
	stop.Store(true)
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	if !seenNew.Load() {
		t.Fatal("hot reload never selected the new certificate")
	}
	if first.Leaf.SerialNumber.Int64() != 1 {
		t.Fatal("published certificate snapshot was mutated")
	}
	if !bytes.Equal(entry.Certificate, certA) {
		t.Fatal("watcher mutated the shared protobuf configuration")
	}
}
