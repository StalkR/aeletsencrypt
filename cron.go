package aeletsencrypt

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2/google"
	api "google.golang.org/api/appengine/v1beta"
	"google.golang.org/appengine"
	"google.golang.org/appengine/user"
)

// updateBefore is the delay to update certificates before expiration.
const updateBefore = 30 * 24 * time.Hour // 30 days

func init() {
	http.HandleFunc("/.well-known/letsencrypt", cronHandler)
}

// cronHandler is the cron job handler to create and update certificates.
func cronHandler(w http.ResponseWriter, r *http.Request) {
	ctx := appengine.NewContext(r)
	if r.Header.Get("X-Appengine-Cron") == "" && !user.IsAdmin(ctx) {
		http.Error(w, "unauthorized", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	if err := createUpdate(ctx, w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// createUpdate creates and updates certificates as needed.
// It uses the AppEngine Admin API as the AppEngine default service
// account to list custom domains, creating certificates when missing, and to
// list certificates, updating them before they expire.
func createUpdate(ctx context.Context, w http.ResponseWriter) error {
	appID := appengine.AppID(ctx)
	client, err := google.DefaultClient(ctx, api.CloudPlatformScope)
	if err != nil {
		return fmt.Errorf("default client: %v", err)
	}
	svc, err := api.New(client)
	if err != nil {
		return fmt.Errorf("api client: %v", err)
	}

	dm, err := svc.Apps.DomainMappings.List(appID).Do()
	if err != nil {
		return addTip(ctx, fmt.Errorf("list domains: %v", err))
	}
	fmt.Fprintf(w, "Found %v custom domains:\n", len(dm.DomainMappings))
	for _, e := range dm.DomainMappings {
		domain := e.Id
		if e.SslSettings != nil {
			fmt.Fprintf(w, " - %v: has certificate, nothing to do\n", domain)
			continue
		}
		fmt.Fprintf(w, " - %v: no certificate, creating\n", domain)

		cert, key, err := obtainCert(ctx, domain)
		if err != nil {
			return fmt.Errorf("obtain cert for %v: %v", domain, err)
		}

		created, err := svc.Apps.AuthorizedCertificates.Create(appID, &api.AuthorizedCertificate{
			CertificateRawData: &api.CertificateRawData{
				PrivateKey:        key,
				PublicCertificate: cert,
			},
			DisplayName: domain,
		}).Do()
		if err != nil {
			return addTip(ctx, fmt.Errorf("create cert for %v: %v", domain, err))
		}

		_, err = svc.Apps.DomainMappings.Patch(appID, domain, &api.DomainMapping{
			SslSettings: &api.SslSettings{
				CertificateId: created.Id,
			},
		}).UpdateMask("ssl_settings.certificate_id").Do()
		if err != nil {
			return addTip(ctx, fmt.Errorf("update mapping for %v: %v", domain, err))
		}
	}
	fmt.Fprintln(w)

	ac, err := svc.Apps.AuthorizedCertificates.List(appID).Do()
	if err != nil {
		return addTip(ctx, fmt.Errorf("list certificates: %v", err))
	}
	fmt.Fprintf(w, "Found %v certificates:\n", len(ac.Certificates))
	for _, c := range ac.Certificates {
		domain := c.DomainNames[0]
		expire, err := time.Parse(time.RFC3339, c.ExpireTime)
		if err != nil {
			return fmt.Errorf("invalid expiry for %v: %v", domain, err)
		}
		if time.Now().Add(updateBefore).Before(expire) {
			fmt.Fprintf(w, " - %v: expires on %v, nothing to do\n", domain, expire)
			continue
		}
		fmt.Fprintf(w, " - %v: expires on %v, updating\n", domain, expire)

		cert, key, err := obtainCert(ctx, domain)
		if err != nil {
			return fmt.Errorf("obtain cert for %v: %v", domain, err)
		}

		_, err = svc.Apps.AuthorizedCertificates.Patch(appID, c.Id, &api.AuthorizedCertificate{
			CertificateRawData: &api.CertificateRawData{
				PrivateKey:        key,
				PublicCertificate: cert,
			},
		}).UpdateMask("certificate_raw_data").Do()
		if err != nil {
			return addTip(ctx, fmt.Errorf("update cert for %v: %v", domain, err))
		}
	}
	fmt.Fprintln(w)
	return nil
}

func addTip(ctx context.Context, err error) error {
	appID := appengine.AppID(ctx)
	serviceAccount, errz := appengine.ServiceAccount(ctx)
	if errz != nil {
		serviceAccount = "n/a"
	}
	switch {
	case strings.Contains(err.Error(), "Quota configuration not found"),
		strings.Contains(err.Error(), "Google App Engine Admin API has not been used"):
		return fmt.Errorf("%v\nTip: enable Google App Engine Admin API on "+
			"https://console.cloud.google.com/apis/api/appengine.googleapis.com/overview?project=%s",
			err, appID)
	case strings.Contains(err.Error(), "Operation not allowed, forbidden"):
		return fmt.Errorf("%v\nTip: add AppEngine default service account (%s) to role App Engine Admin "+
			"https://console.cloud.google.com/iam-admin/iam/project?project=%s",
			err, serviceAccount, appID)
	case strings.Contains(err.Error(), "Caller is not authorized to administer this certificate"):
		return fmt.Errorf("%v\nTip: add AppEngine default service account (%s) as verified owner for the domain"+
			"https://www.google.com/webmasters/verification/details",
			err, serviceAccount)
	}
	return err
}
