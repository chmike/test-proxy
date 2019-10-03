package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/ayllon/go-proxy"
	"github.com/pkg/errors"
)

var (
	proxyCertInfoOid = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 14}
	diracGroupOid    = asn1.ObjectIdentifier{1, 2, 42, 42}

	serverFlag = flag.String("s", "", "server: listen address")
	clientFlag = flag.String("c", "", "client: server address")
)

// DiracGroupName returns the dirac group name if present, or an empty string.
func DiracGroupName(p *proxy.X509Proxy) string {
	for _, e := range p.Certificate.Extensions {
		if e.Id.Equal(diracGroupOid) && len(e.Value) > 2 && e.Value[0] == 22 && int(e.Value[1]) == len(e.Value)-2 {
			return string(e.Value[2:])
		}
	}
	return ""
}

// CaCerts loads the CA certificates from the file into a CertPool.
func CaCerts(filename string) *x509.CertPool {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatalln(err)
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(data) {
		log.Fatalf("failed to parse rootCA certificates '%s'\n", filename)
	}
	return certPool
}

// ProxyCaCerts loads the CA certificates from the file into a ProxyCertPool.
func ProxyCaCerts(filename string) (*proxy.CertPool, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	roots := &proxy.CertPool{
		CertPool: x509.NewCertPool(),
		Crls:     make(map[string]*pkix.CertificateList),
		CaByHash: make(map[string]*x509.Certificate),
	}
	if err := roots.AppendFromPEM(data, false); err != nil {
		return nil, err
	}
	return roots, nil
}

func decodeFromFile(filename string) {
	var p proxy.X509Proxy
	if e := p.DecodeFromFile(filename); e != nil {
		log.Fatal(e)
	}
	log.Println("Subject:", proxy.NameRepr(&p.Certificate.Subject))
	log.Println("Issuer:", proxy.NameRepr(&p.Issuer))
	log.Println("DiracGroup:", DiracGroupName(&p))
	for _, v := range p.VomsAttributes {
		log.Print(v.Vo)
		log.Print(v.Fqan)
	}
}

// VerifiedProxyCert returns the first verified proxy certificate in certs, or nil if none.
func VerifiedProxyCert(certs []*x509.Certificate, caCertPool *proxy.CertPool) (*proxy.X509Proxy, error) {
	p := &proxy.X509Proxy{}
	if err := p.InitFromCertificates(certs); err != nil {
		return nil, errors.Wrap(err, "convert to proxy")
	}
	if err := p.Verify(proxy.VerifyOptions{Roots: caCertPool}); err != nil {
		return nil, errors.Wrap(err, "verify proxy")
	}

	return p, nil
}

func main() {
	flag.Parse()

	listenAddr := flag.Arg(0)
	caCertPool := CaCerts("cas.pem")
	proxyCaCertPool, err := ProxyCaCerts("cas.pem")
	if err != nil {
		log.Fatal("failed loading ca certs: ", err)
	}

	server := &http.Server{
		Addr: listenAddr,
		TLSConfig: &tls.Config{
			// ClientAuth: tls.RequireAndVerifyClientCert, : verify proxy certificate fails
			ClientAuth: tls.RequireAnyClientCert, // may be as well RequestClientCert
			RootCAs:    caCertPool,
		},
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		p, err := VerifiedProxyCert(r.TLS.PeerCertificates, proxyCaCertPool)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, "Error: %s", err)
			return
		}
		fmt.Println("Group:", DiracGroupName(p))

		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Hi there, I love %s!\n", r.URL.Path[1:])
		fmt.Fprintf(w, "Your group %s!\n", DiracGroupName(p))
	})
	log.Fatal(server.ListenAndServeTLS("marc-crt.pem", "marc-key.pem"))
}
