package aeletsencrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	// golang.org/x/crypto/acme uses context features from Go 1.7 but
	// AppEngine is still on Go 1.6 as of 2017-06-15.
	// The following package is a fork with a compatibility patch for Go 1.6.
	// It can be removed once AppEngine updates to Go 1.7 or above.
	"github.com/StalkR/golang-crypto/acme"
	"golang.org/x/net/context"
	"google.golang.org/appengine"
	"google.golang.org/appengine/memcache"
	"google.golang.org/appengine/urlfetch"
)

func init() {
	http.HandleFunc("/.well-known/acme-challenge/", challengeHandler)
}

// challengeHandler responds to the http-01 challenge for domain validation.
func challengeHandler(w http.ResponseWriter, r *http.Request) {
	ctx := appengine.NewContext(r)
	item, err := memcache.Get(ctx, r.URL.Path)
	switch err {
	case nil:
		fmt.Fprint(w, string(item.Value))
	case memcache.ErrCacheMiss:
		http.NotFound(w, r)
	default:
		http.Error(w, fmt.Sprintf("memcache get: %v", err), http.StatusInternalServerError)
	}
}

// obtainCert creates a key and obtains a signed certificate.
// It returns the signed certificate with chain and the key, both PEM encoded.
// A temporary account key is created and domain validation done over http.
func obtainCert(ctx context.Context, domain string) (cert, key string, err error) {
	// "Private keys must use RSA encryption."
	// "Maximum allowed key modulus: 2048 bits"
	// https://cloud.google.com/appengine/docs/standard/python/using-custom-domains-and-ssl#app_engine_support_for_ssl_certificates
	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("cert key: %v", err)
	}

	req := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: domain},
	}
	req.DNSNames = []string{domain}
	csr, err := x509.CreateCertificateRequest(rand.Reader, req, certKey)
	if err != nil {
		return "", "", fmt.Errorf("csr: %v", err)
	}

	accountKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("account key: %v", err)
	}
	client := &acme.Client{
		Key:          accountKey,
		HTTPClient:   urlfetch.Client(ctx),
		DirectoryURL: acme.LetsEncryptURL,
	}
	if _, err = client.Register(ctx, &acme.Account{}, acme.AcceptTOS); err != nil {
		return "", "", fmt.Errorf("register: %v", err)
	}

	if err := authorize(ctx, client, domain); err != nil {
		return "", "", err
	}

	const expiry = 90 * 24 * time.Hour // 90 days, desired
	const bundle = true
	certDER, _, err := client.CreateCert(ctx, csr, expiry, bundle)
	if err != nil {
		return "", "", fmt.Errorf("create cert: %v", err)
	}

	var certPEM []byte
	for _, b := range certDER {
		b = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})
		certPEM = append(certPEM, b...)
	}
	certKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certKey)})

	return string(certPEM), string(certKeyPEM), nil
}

// authorize authorizes the client to issue certificates for this domain
// by going through the http-01 challenge.
func authorize(ctx context.Context, client *acme.Client, domain string) error {
	authorization, err := client.Authorize(ctx, domain)
	if err != nil {
		return fmt.Errorf("authorize: %v", err)
	}
	if authorization.Status == acme.StatusValid {
		return nil
	}

	var challenge *acme.Challenge
	for _, c := range authorization.Challenges {
		if c.Type == "http-01" {
			challenge = c
			break
		}
	}
	if challenge == nil {
		return fmt.Errorf("no http-01 challenge offered")
	}

	response, err := client.HTTP01ChallengeResponse(challenge.Token)
	if err != nil {
		return fmt.Errorf("challenge response: %v", err)
	}
	if err := memcache.Set(ctx, &memcache.Item{
		Key:   client.HTTP01ChallengePath(challenge.Token),
		Value: []byte(response),
	}); err != nil {
		return fmt.Errorf("memcache set: %v", err)
	}

	if _, err := client.Accept(ctx, challenge); err != nil {
		return fmt.Errorf("accept challenge: %v", err)
	}
	if _, err = client.WaitAuthorization(ctx, authorization.URI); err != nil {
		return fmt.Errorf("authorization: %v", err)
	}
	return nil
}
