module github.com/danhunsaker/gorm-crypto

go 1.16

require (
	golang.org/x/crypto v0.0.0-20211215153901-e495a2d5b3d3
	gorm.io/driver/bigquery v1.0.16
	gorm.io/driver/clickhouse v0.2.2
	gorm.io/driver/mysql v1.2.2
	gorm.io/driver/postgres v1.2.3
	gorm.io/driver/sqlite v1.2.6
	gorm.io/driver/sqlserver v1.2.1
	gorm.io/gorm v1.22.4
)

replace gorm.io/driver/bigquery => github.com/danhunsaker/bigquery v0.0.0-20211228052622-cc499511c872
