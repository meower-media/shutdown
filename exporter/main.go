package main

import (
	"context"
	"database/sql"
	"log"
	"os"
	"sync"

	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var mongoDb *mongo.Database
var uploadsS3 *minio.Client

var exportsDb *sql.DB
var exportsS3 *minio.Client

func main() {
	// Load .env
	godotenv.Load()

	// Connect to the main MongoDB database
	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
	opts := options.Client().ApplyURI(os.Getenv("MONGO_URI")).SetServerAPIOptions(serverAPI)
	client, err := mongo.Connect(context.TODO(), opts)
	if err != nil {
		log.Fatalln(err)
	}
	defer client.Disconnect(context.TODO())
	mongoDb = client.Database(os.Getenv("MONGO_DB"))

	// Test the main MongoDB database connection
	var result bson.M
	if err := mongoDb.RunCommand(context.TODO(), bson.M{"ping": 1}).Decode(&result); err != nil {
		log.Fatalln(err)
	}

	// Connect to the exports SQLite database
	exportsDb, err = sql.Open("sqlite3", os.Getenv("EXPORTS_SQLITE_DB"))
	if err != nil {
		log.Fatalln(err)
	}
	if err := exportsDb.Ping(); err != nil {
		log.Fatalln(err)
	}

	// Create exports SQLite tables
	exportsDb.Exec(`CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		username TEXT,
		lower_username TEXT,
		legacy_avatar INTEGER,
		password TEXT,
		totp_tokens TEXT,
		mfa_recovery_code TEXT,
		created_at INTEGER,
		last_seen_at INTEGER,
		exported_at INTEGER
	);`)
	exportsDb.Exec(`CREATE TABLE IF NOT EXISTS auth_ratelimits (
		ip TEXT PRIMARY KEY,
		remaining INTEGER,
		reset_at INTEGER
	);`)
	exportsDb.Exec("PRAGMA journal_mode=WAL")

	// Connect to S3
	uploadsS3, err = minio.New(os.Getenv("UPLOADS_S3_ENDPOINT"), &minio.Options{
		Creds:  credentials.NewStaticV4(os.Getenv("UPLOADS_S3_ACCESS"), os.Getenv("UPLOADS_S3_SECRET"), ""),
		Secure: os.Getenv("UPLOADS_S3_SECURE") == "1",
	})
	if err != nil {
		log.Fatalln(err)
	}
	exportsS3, err = minio.New(os.Getenv("EXPORTS_S3_ENDPOINT"), &minio.Options{
		Creds:  credentials.NewStaticV4(os.Getenv("EXPORTS_S3_ACCESS"), os.Getenv("EXPORTS_S3_SECRET"), ""),
		Secure: os.Getenv("EXPORTS_S3_SECURE") == "1",
	})
	if err != nil {
		log.Fatalln(err)
	}

	// Get users for export
	var users []User
	cur, err := mongoDb.Collection("usersv0").Find(
		context.TODO(),
		bson.M{"flags": bson.M{"$bitsAllClear": 3}},
		options.Find().SetProjection(bson.M{"uuid": 1, "_id": 1, "pfp_data": 1, "pswd": 1, "mfa_recovery_code": 1, "created": 1, "last_seen": 1}),
	)
	if err != nil {
		log.Fatalln(err)
	}
	if err := cur.All(context.TODO(), &users); err != nil {
		log.Fatalln(err)
	}
	log.Println(users)
	log.Println(len(users))

	// Export users
	var wg sync.WaitGroup
	wg.Add(len(users))
	for _, user := range users {
		go func(user User) {
			defer wg.Done()
			if err := RunExport(user); err != nil {
				log.Printf("Error while exporting %s: %s", user.Username, err)
			}
		}(user)
	}
	wg.Wait()
}
