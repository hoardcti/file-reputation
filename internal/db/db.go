package db

import (
	"os"

	"github.com/hoardcti/file-reputation/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func Init() (*gorm.DB, error) {

	host := os.Getenv("PGHOST")
	user := os.Getenv("PGUSER")
	pass := os.Getenv("PGPASSWORD")
	name := os.Getenv("PGDATABASE")
	port := os.Getenv("PGPORT")
	sslm := os.Getenv("PGSSLMODE")
	time := os.Getenv("PGTIMEZONE")

	// https://github.com/go-gorm/postgres/tree/1a2d67b91586ce34c989a2b2be91f9c37c0cfb86#configuration
	db, err := gorm.Open(postgres.New(postgres.Config{
		DSN:                  "host=" + host + " user=" + user + " password=" + pass + " dbname=" + name + " port=" + port + " sslmode=" + sslm + " TimeZone=" + time, // data source name, refer https://github.com/jackc/pgx
		PreferSimpleProtocol: true,                                                                                                                                    // disables implicit prepared statement usage. By default pgx automatically uses the extended protocol
	}), &gorm.Config{})

	return db, err
}
