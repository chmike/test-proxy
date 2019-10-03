package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/ayllon/go-proxy"
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
func VerifiedProxyCert(certs []*x509.Certificate) *proxy.X509Proxy {
	for i := range certs {

	}
	return nil
}

// DiracGroup returns the first dirac group found in a certificate, or return an empty string.
func DiracGroup(certs []*x509.Certificate) string {
	return ""
}

func main() {
	flag.Parse()

	listenAddr := flag.Arg(0)
	caCertPool := CaCerts("cas.pem")

	server := &http.Server{
		Addr: listenAddr,
		TLSConfig: &tls.Config{
			// ClientAuth: tls.RequireAndVerifyClientCert, : verify proxy certificate fails
			ClientAuth: tls.RequireAnyClientCert, // may be as well RequestClientCert
			RootCAs:    caCertPool,
		},
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		DiracGroup(r.TLS.PeerCertificates)

		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Hi there, I love %s!", r.URL.Path[1:])
	})
	log.Fatal(server.ListenAndServeTLS("marc-crt.pem", "marc-key.pem"))
}
