package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func RunExport(u User) error {
	// Init context, cursor and error
	var ctx = context.TODO()
	var cur *mongo.Cursor
	var f io.Writer
	var csvWriter *csv.Writer
	var err error

	// Make sure user hasn't already been exported
	var rowCount int
	exportsDb.QueryRow("SELECT COUNT(*) FROM users WHERE id = ? AND last_seen_at = ?", u.Id, u.LastSeenAt).Scan(&rowCount)
	if rowCount > 0 {
		fmt.Printf("Skipping %s\n", u.Username)
		return nil
	} else {
		fmt.Printf("Exporting %s\n", u.Username)
	}

	// Create ZIP file
	archive, err := os.Create(os.Getenv("OUTPUT_DIR") + "/" + u.Id + ".zip")
	if err != nil {
		return err
	}
	defer archive.Close()

	// Create ZIP writer
	zipWriter := zip.NewWriter(archive)
	defer zipWriter.Close()

	// Export user, authenticators, settings, and relationships to user.json
	fmt.Printf("(%s) Exporting user\n", u.Username)
	var user map[string]interface{}
	cur, err = mongoDb.Collection("usersv0").Aggregate(ctx, bson.A{
		bson.M{"$match": bson.M{"_id": u.Username, "uuid": u.Id}},
		bson.M{"$lookup": bson.M{
			"from":         "authenticators",
			"localField":   "_id",
			"foreignField": "user",
			"as":           "authenticators",
		}},
		bson.M{"$lookup": bson.M{
			"from":         "user_settings",
			"localField":   "_id",
			"foreignField": "_id",
			"as":           "settings",
		}},
		bson.M{"$lookup": bson.M{
			"from":         "relationships",
			"localField":   "_id",
			"foreignField": "_id.from",
			"as":           "relationships",
		}},
		bson.M{"$unwind": bson.M{
			"path":                       "$settings",
			"preserveNullAndEmptyArrays": true,
		}},
		bson.M{"$project": bson.M{
			"pswd":              0,
			"tokens":            0,
			"mfa_recovery_code": 0,

			"authenticators.user":        0,
			"authenticators.totp_secret": 0,

			"settings._id": 0,

			"relationships._id.from": 0,
		}},
	})
	if err != nil {
		return err
	}
	defer cur.Close(ctx)
	cur.Next(ctx)
	if err := cur.Decode(&user); err != nil {
		return err
	}
	marshaledUser, err := json.MarshalIndent(user, "", "\t")
	if err != nil {
		return err
	}
	f, err = zipWriter.Create("user.json")
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, bytes.NewReader(marshaledUser)); err != nil {
		return err
	}
	zipWriter.Flush()

	// Export reports
	fmt.Printf("(%s) Exporting reports\n", u.Username)
	cur, err = mongoDb.Collection("reports").Find(ctx, bson.M{"reports.user": u.Username})
	if err != nil {
		return err
	}
	defer cur.Close(ctx)
	f, err = zipWriter.Create("reports.csv")
	if err != nil {
		return err
	}
	csvWriter = csv.NewWriter(f)
	csvWriter.Write([]string{
		"id",
		"type",
		"content_id",
		"status",
		"ip",
		"reason",
		"comment",
		"time",
	})
	for cur.Next(ctx) {
		var report Report
		if err := cur.Decode(&report); err != nil {
			return err
		}
		for _, reporter := range report.Reporters {
			if reporter.User == u.Username {
				csvWriter.Write([]string{
					report.Id,
					report.Type,
					report.ContentId,
					report.Status,
					reporter.IP,
					reporter.Reason,
					reporter.Comment,
					strconv.FormatInt(reporter.Time, 10),
				})
				break
			}
		}
	}
	csvWriter.Flush()
	zipWriter.Flush()

	// Export chats and posts
	chatIds, err := mongoDb.Collection("posts").Distinct(ctx, "post_origin", bson.M{"u": u.Username})
	if err != nil {
		return err
	}
	for _, chatId := range chatIds {
		fmt.Printf("(%s) Exporting %s\n", u.Username, chatId)

		// Export posts
		cur, err = mongoDb.Collection("posts").Find(
			ctx,
			bson.M{"u": u.Username, "post_origin": chatId},
			options.Find().SetProjection(bson.M{"u": 0, "post_origin": 0, "isDeleted": 0}),
		)
		if err != nil {
			return err
		}
		defer cur.Close(ctx)
		f, err = zipWriter.Create(fmt.Sprint("chats/", chatId, "/posts.csv"))
		if err != nil {
			return err
		}
		csvWriter = csv.NewWriter(f)
		csvWriter.Write([]string{
			"id",
			"time",
			"reply_to",
			"content",
			"attachments",
			"emojis",
			"stickers",
			"pinned",
			"reactions",
		})
		for cur.Next(ctx) {
			var post Post
			if err := cur.Decode(&post); err != nil {
				return err
			}

			replyTo, _ := json.Marshal(post.ReplyTo)
			attachments, _ := json.Marshal(post.Attachments)
			emojis, _ := json.Marshal(post.Emojis)
			stickers, _ := json.Marshal(post.Stickers)
			reactions, _ := json.Marshal(post.Reactions)

			csvWriter.Write([]string{
				post.Id,
				strconv.FormatInt(post.Time.Unix, 10),
				string(replyTo),
				post.Content,
				string(attachments),
				string(emojis),
				string(stickers),
				strconv.FormatBool(post.Pinned),
				string(reactions),
			})
		}
		csvWriter.Flush()

		// Export chat
		var chat map[string]interface{}
		cur, err = mongoDb.Collection("chats").Aggregate(ctx, bson.A{
			bson.M{"$match": bson.M{"_id": chatId, "members": u.Username}},
			bson.M{"$lookup": bson.M{
				"from":         "chat_emojis",
				"localField":   "_id",
				"foreignField": "chat_id",
				"as":           "emojis",
			}},
			bson.M{"$lookup": bson.M{
				"from":         "chat_stickers",
				"localField":   "_id",
				"foreignField": "chat_id",
				"as":           "stickers",
			}},
			bson.M{"$project": bson.M{
				"emojis.chat_id":   0,
				"stickers.chat_id": 0,
			}},
		})
		if err != nil {
			return err
		}
		defer cur.Close(ctx)
		if cur.Next(ctx) {
			if err := cur.Decode(&chat); err != nil {
				return err
			}
			marshaledChat, err := json.MarshalIndent(chat, "", "\t")
			if err != nil {
				return err
			}
			f, err = zipWriter.Create(fmt.Sprint("chats/", chatId, "/chat.json"))
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, bytes.NewReader(marshaledChat)); err != nil {
				return err
			}
		}

		zipWriter.Flush()
	}

	// Export post reactions
	fmt.Printf("(%s) Exporting post reactions\n", u.Username)
	var reactions []map[string]interface{}
	cur, err = mongoDb.Collection("post_reactions").Find(
		ctx,
		bson.M{"_id.user": u.Username},
		options.Find().SetProjection(bson.M{"_id.user": 0}),
	)
	if err != nil {
		return err
	}
	defer cur.Close(ctx)
	if err := cur.All(ctx, &reactions); err != nil {
		return err
	}
	marshaledReactions, err := json.MarshalIndent(reactions, "", "\t")
	if err != nil {
		return err
	}
	f, err = zipWriter.Create("post_reactions.json")
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, bytes.NewReader(marshaledReactions)); err != nil {
		return err
	}

	// Export files
	fmt.Printf("(%s) Exporting files\n", u.Username)
	var files []map[string]interface{}
	cur, err = mongoDb.Collection("files").Find(ctx, bson.M{"uploaded_by": u.Username})
	if err != nil {
		return err
	}
	defer cur.Close(ctx)
	if err := cur.All(ctx, &files); err != nil {
		return err
	}
	marshaledFiles, err := json.MarshalIndent(files, "", "\t")
	if err != nil {
		return err
	}
	f, err = zipWriter.Create("files.json")
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, bytes.NewReader(marshaledFiles)); err != nil {
		return err
	}
	for _, file := range files {
		fmt.Printf("(%s) Exporting file %s\n", u.Username, file["_id"].(string))
		fWriter, err := zipWriter.Create(fmt.Sprintf("files/(%s) %s", file["_id"].(string), file["filename"].(string)))
		if err != nil {
			log.Println(err)
			continue
		}
		obj, err := uploadsS3.GetObject(ctx, file["bucket"].(string), file["hash"].(string), minio.GetObjectOptions{})
		if err != nil {
			log.Println(err)
			continue
		}
		io.Copy(fWriter, obj)
		zipWriter.Flush()
	}

	// Flush and close ZIP
	zipWriter.Flush()
	zipWriter.Close()
	archive.Close()

	// Upload ZIP to exports S3
	if _, err := exportsS3.FPutObject(
		ctx,
		os.Getenv("EXPORTS_S3_BUCKET"),
		u.Id+".zip",
		os.Getenv("OUTPUT_DIR")+"/"+u.Id+".zip",
		minio.PutObjectOptions{},
	); err != nil {
		return err
	}

	// Get TOTP tokens
	var totpSecrets []string
	cur, err = mongoDb.Collection("authenticators").Find(ctx, bson.M{"user": u.Username})
	if err != nil {
		return err
	}
	for cur.Next(ctx) {
		var authenticator map[string]interface{}
		if err := cur.Decode(&authenticator); err != nil {
			return err
		}
		totpSecrets = append(totpSecrets, authenticator["totp_secret"].(string))
	}

	// Add to exports DB
	if _, err := exportsDb.Exec(
		"INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		u.Id,
		u.Username,
		strings.ToLower(u.Username),
		u.LegacyAvatar,
		u.Password,
		strings.Join(totpSecrets, ";"),
		u.MFARecoveryCode,
		u.CreatedAt,
		u.LastSeenAt,
		time.Now().Unix(),
	); err != nil {
		return err
	}

	return nil
}
