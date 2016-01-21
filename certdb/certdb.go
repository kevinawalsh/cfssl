package certdb

import (
	"database/sql"
	"time"
)

// CertificateRecord encodes a certificate and its metadata
// that will be recorded in a database.
type CertificateRecord struct {
	Serial    string    `sql:"serial"`
	CALabel   string    `sql:"ca_label"`
	Status    string    `sql:"status"`
	Reason    int       `sql:"reason"`
	Expiry    time.Time `sql:"expiry"`
	RevokedAt time.Time `sql:"revoked_at"`
	PEM       string    `sql:"pem"`
}

// OCSPRecord encodes a OCSP response body and its metadata
// that will be recorded in a database.
type OCSPRecord struct {
	Serial string    `sql:"serial"`
	Body   string    `sql:"body"`
	Expiry time.Time `sql:"expiry"`
}

// DBAccessor abstracts the CRUD of certdb objects from a DB.
type DBAccessor interface {
	InsertCertificate(db *sql.DB, cr *CertificateRecord) error
	GetCertificate(db *sql.DB, serial string) (*CertificateRecord, error)
	GetUnexpiredCertificates(db *sql.DB) (crs []*CertificateRecord, err error)
	RevokeCertificate(db *sql.DB, serial string, reasonCode int) error
	InsertOCSP(db *sql.DB, rr *OCSPRecord) error
	GetOCSP(db *sql.DB, serial string) (rr *OCSPRecord, err error)
	GetUnexpiredOCSPs(db *sql.DB) (rrs []*OCSPRecord, err error)
	UpdateOCSP(db *sql.DB, serial, body string, expiry time.Time) error
	UpsertOCSP(db *sql.DB, serial, body string, expiry time.Time) error
}
