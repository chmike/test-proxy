package main

import (
	"crypto/x509"
	"encoding/asn1"
	"flag"
	"fmt"
	"go-proxy"
	"io/ioutil"
	"log"
	"net/http"
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

// CaCerts loads CA certificates.
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

func main() {
	flag.Parse()

	// decodeFromFile(flag.Arg(0))
	// certPool := CaCerts("cas.pem")

	if *serverFlag != "" {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "Hi there, I love %s!", r.URL.Path[1:])
		})
		log.Fatal(http.ListenAndServe(*serverFlag, nil))
	}
	if *clientFlag != "" {
		res, err := http.Get("http://" + *clientFlag + "/toto")
		if err != nil {
			log.Fatalln("http get error:", err)
		}
		defer res.Body.Close()
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			log.Fatalln("read response body error:", err)
		}
		log.Println(string(body))
	}
}
