/*
Package aeletsencrypt manages Let's Encrypt certificates for AppEngine.

How it works

Package initialization registers an HTTP handler at /.well-known/letsencrypt
restricted to app admins and AppEngine cron, which calls it daily.
This handler uses the AppEngine Admin API as the AppEngine default service
account to list custom domains, creating certificates when missing, and to
list certificates, updating them 30 days before they expire.
To create and update certificates with LetsEncrypt it creates a temporary
account key, resolves the http-01 challenge for domain validation,
creates a certificate key and request, receives the signed certificate with
its chain and uploads it to AppEngine along with the key.
Nothing is saved in the app itself.

Setup

In the Google Cloud Console, configure custom domains
(https://console.cloud.google.com/appengine/settings/domains),
enable the AppEngine Admin API
(https://console.cloud.google.com/apis/api/appengine.googleapis.com/overview)
and grant the AppEngine default service account the AppEngine admin role
(https://console.cloud.google.com/iam-admin/iam/project).
In the Google Webmaster Console, add the AppEngine default service account
as verified owner for the domains
(https://www.google.com/webmasters/verification/details).

Import this package anywhere in your app for its side-effect: during
initialization it registers its handlers.

	import (
		...
		_ "github.com/StalkR/aeletsencrypt"
	)

Add the following handlers to your app.yaml:

	handlers:
	# Cron job handler to create and update certificates
	- url: /.well-known/letsencrypt
	  script: _go_app
	  secure: optional
	  login: admin
	# Challenge handler for domain validation
	- url: /.well-known/acme-challenge/.*
	  script: _go_app
	  secure: optional

Handlers order matter, so insert above more generic handlers (e.g /.*).
The "secure: optional" is to avoid https redirect, which might not work yet.

Add the following cron jobs to your cron.yaml, creating it if necessary:

	cron:
	- description: create and update certificates
	  url: /.well-known/letsencrypt
	  schedule: every 24 hours

At this point you are done, certificates for all custom domains will be created
next time the cron job runs. To create certificates immediately, run the cron
job now by visiting http://<any custom domain>/.well-known/letsencrypt.

If you have several domains be mindful of
Let's Encrypt rate-limits (https://letsencrypt.org/docs/rate-limits/) in
particular 20 domains per week. If you hit this limit, just wait a week and
let the cron job resume certificate creation for the remaining domains.

If you add new custom domains later, the cron job will automatically create
certificates next time it runs.
*/
package aeletsencrypt
