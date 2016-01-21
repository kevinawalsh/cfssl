package cloudflare

import (
	"database/sql"
	"fmt"
	"github.com/cloudflare/cfssl/certdb"
	"time"

	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/kisielk/sqlstruct"
)

const (
	insertSQL = `
INSERT INTO certificates (serial, ca_label, status, reason, expiry, revoked_at, pem)
	VALUES ($1, $2, $3, $4, $5, $6, $7);`

	selectSQL = `
SELECT %s FROM certificates
	WHERE (serial = $1);`

	selectAllSQL = `
SELECT %s FROM certificates;`

	selectAllUnexpiredSQL = `
SELECT %s FROM certificates
WHERE CURRENT_TIMESTAMP < expiry;`

	updateRevokeSQL = `
UPDATE certificates
	SET status='revoked', revoked_at=CURRENT_TIMESTAMP, reason=$1
	WHERE (serial = $2);`

	insertOCSPSQL = `
INSERT INTO ocsp_responses (serial, body, expiry)
    VALUES ($1, $2, $3);`

	updateOCSPSQL = `
UPDATE ocsp_responses
    SET expiry=$3, body=$2
	WHERE (serial = $1);`

	selectAllUnexpiredOCSPSQL = `
SELECT %s FROM ocsp_responses
WHERE CURRENT_TIMESTAMP < expiry;`

	selectOCSPSQL = `
SELECT %s FROM ocsp_responses
    WHERE (serial = $1);`
)

// CertDBAccessor implements certdb.DBAccessor interface.
type CertDBAccessor struct {
}

// StdCertDB is the standard certdb DBAccessor.
var StdCertDB = &CertDBAccessor{}

func wrapCertStoreError(err error) error {
	if err != nil {
		return cferr.Wrap(cferr.CertStoreError, cferr.Unknown, err)
	}
	return nil
}

// InsertCertificate puts a certdb.CertificateRecord into db.
func (d *CertDBAccessor) InsertCertificate(db *sql.DB, cr *certdb.CertificateRecord) error {
	res, err := db.Exec(
		insertSQL,
		cr.Serial,
		cr.CALabel,
		cr.Status,
		cr.Reason,
		cr.Expiry.UTC(),
		cr.RevokedAt,
		cr.PEM,
	)
	if err != nil {
		return wrapCertStoreError(err)
	}

	numRowsAffected, _ := res.RowsAffected()

	if numRowsAffected == 0 {
		return cferr.Wrap(cferr.CertStoreError, cferr.InsertionFailed, fmt.Errorf("failed to insert the certificate record"))
	}

	if numRowsAffected != 1 {
		return wrapCertStoreError(fmt.Errorf("%d rows are affected, should be 1 row", numRowsAffected))
	}

	return nil
}

// GetCertificate gets a certdb.CertificateRecord indexed by serial.
func (d *CertDBAccessor) GetCertificate(db *sql.DB, serial string) (*certdb.CertificateRecord, error) {
	cr := new(certdb.CertificateRecord)
	rows, err := db.Query(fmt.Sprintf(selectSQL, sqlstruct.Columns(*cr)), serial)
	if err != nil {
		return nil, wrapCertStoreError(err)
	}
	defer rows.Close()

	if rows.Next() {
		return cr, wrapCertStoreError(sqlstruct.Scan(cr, rows))
	}
	return nil, nil
}

// GetUnexpiredCertificates gets all unexpired certificate from db.
func (d *CertDBAccessor) GetUnexpiredCertificates(db *sql.DB) (crs []*certdb.CertificateRecord, err error) {
	cr := new(certdb.CertificateRecord)
	rows, err := db.Query(fmt.Sprintf(selectAllUnexpiredSQL, sqlstruct.Columns(*cr)))
	if err != nil {
		return nil, wrapCertStoreError(err)
	}
	defer rows.Close()

	for rows.Next() {
		err = sqlstruct.Scan(cr, rows)
		if err != nil {
			return nil, wrapCertStoreError(err)
		}
		crs = append(crs, cr)
	}

	return crs, nil
}

// RevokeCertificate updates a certificate with a given serial number and marks it revoked.
func (d *CertDBAccessor) RevokeCertificate(db *sql.DB, serial string, reasonCode int) error {
	result, err := db.Exec(updateRevokeSQL, reasonCode, serial)

	if err != nil {
		return wrapCertStoreError(err)
	}

	numRowsAffected, _ := result.RowsAffected()

	if numRowsAffected == 0 {
		return cferr.Wrap(cferr.CertStoreError, cferr.RecordNotFound, fmt.Errorf("failed to revoke the certificate: certificate not found"))
	}

	if numRowsAffected != 1 {
		return wrapCertStoreError(fmt.Errorf("%d rows are affected, should be 1 row", numRowsAffected))
	}

	return nil
}

// InsertOCSP puts a new certdb.OCSPRecord into the db.
func (d *CertDBAccessor) InsertOCSP(db *sql.DB, rr *certdb.OCSPRecord) error {
	res, err := db.Exec(
		insertOCSPSQL,
		rr.Serial,
		rr.Body,
		rr.Expiry.UTC(),
	)
	if err != nil {
		return wrapCertStoreError(err)
	}

	numRowsAffected, _ := res.RowsAffected()

	if numRowsAffected == 0 {
		return cferr.Wrap(cferr.CertStoreError, cferr.InsertionFailed, fmt.Errorf("failed to insert the OCSP record"))
	}

	if numRowsAffected != 1 {
		return wrapCertStoreError(fmt.Errorf("%d rows are affected, should be 1 row", numRowsAffected))
	}

	return nil
}

// GetOCSP retrieves a certdb.OCSPRecord from db by serial.
func (d *CertDBAccessor) GetOCSP(db *sql.DB, serial string) (rr *certdb.OCSPRecord, err error) {
	rr = new(certdb.OCSPRecord)
	rows, err := db.Query(fmt.Sprintf(selectOCSPSQL, sqlstruct.Columns(*rr)), serial)
	if err != nil {
		return nil, wrapCertStoreError(err)
	}
	defer rows.Close()

	if rows.Next() {
		return rr, sqlstruct.Scan(rr, rows)
	}
	return nil, nil
}

// GetUnexpiredOCSPs retrieves all unexpired certdb.OCSPRecord from db.
func (d *CertDBAccessor) GetUnexpiredOCSPs(db *sql.DB) (rrs []*certdb.OCSPRecord, err error) {
	rr := new(certdb.OCSPRecord)
	rows, err := db.Query(fmt.Sprintf(selectAllUnexpiredOCSPSQL, sqlstruct.Columns(*rr)))
	if err != nil {
		return nil, wrapCertStoreError(err)
	}
	defer rows.Close()

	for rows.Next() {
		err = sqlstruct.Scan(rr, rows)
		if err != nil {
			return nil, wrapCertStoreError(err)
		}
		rrs = append(rrs, rr)
	}

	return rrs, nil
}

// UpdateOCSP updates a ocsp response record with a given serial number.
func (d *CertDBAccessor) UpdateOCSP(db *sql.DB, serial, body string, expiry time.Time) error {
	result, err := db.Exec(updateOCSPSQL, serial, body, expiry)

	if err != nil {
		return wrapCertStoreError(err)
	}

	numRowsAffected, err := result.RowsAffected()

	if numRowsAffected == 0 {
		return cferr.Wrap(cferr.CertStoreError, cferr.RecordNotFound, fmt.Errorf("failed to update the OCSP record"))
	}

	if numRowsAffected != 1 {
		return wrapCertStoreError(fmt.Errorf("%d rows are affected, should be 1 row", numRowsAffected))
	}
	return err
}

// UpsertOCSP update a ocsp response record with a given serial number,
// or insert the record if it doesn't yet exist in the db
// Implementation note:
// We didn't implement 'upsert' with SQL statement and we lost race condition
// prevention provided by underlying DMBS.
// Reasoning:
// 1. it's diffcult to support multiple DBMS backends in the same time, the
// SQL syntax differs from one to another.
// 2. we don't need a strict simultaneous consistency between OCSP and certificate
// status. It's OK that a OCSP response still shows 'good' while the
// corresponding certificate is being revoked seconds ago, as long as the OCSP
// response catches up to be eventually consistent (within hours to days).
// Write race condition between OCSP writers on OCSP table is not a problem,
// since we don't have write race condition on Certificate table and OCSP
// writers should periodically use Certificate table to update OCSP table
// to catch up.
func (d *CertDBAccessor) UpsertOCSP(db *sql.DB, serial, body string, expiry time.Time) error {
	result, err := db.Exec(updateOCSPSQL, serial, body, expiry)

	if err != nil {
		return wrapCertStoreError(err)
	}

	numRowsAffected, err := result.RowsAffected()

	if numRowsAffected == 0 {
		return d.InsertOCSP(db, &certdb.OCSPRecord{Serial: serial, Body: body, Expiry: expiry})
	}

	if numRowsAffected != 1 {
		return wrapCertStoreError(fmt.Errorf("%d rows are affected, should be 1 row", numRowsAffected))
	}
	return err
}
