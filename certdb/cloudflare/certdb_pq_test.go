// +build postgresql

package cloudflare

import (
	"testing"

	"github.com/cloudflare/cfssl/certdb/testdb"
)

func TestPostgreSQL(t *testing.T) {
	db := testdb.PostgreSQLDB()
	testEverything(db, t)
}
