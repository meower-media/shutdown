package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/pquerna/otp/totp"
	"github.com/rs/cors"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Id              string   `json:"uuid"`
	Username        string   `json:"_id"`
	LowerUsername   string   `json:"lower_username"`
	LegacyAvatar    int8     `json:"pfp_data"`
	Avatar          string   `json:"avatar"`
	AvatarColor     string   `json:"avatar_color"`
	Flags           int64    `json:"flags"`
	Permissions     int64    `json:"permissions"`
	Level           int8     `json:"lvl"`
	Quote           string   `json:"quote"`
	Password        string   `json:"-"`
	TOTPTokens      []string `json:"-"`
	MFARecoveryCode string   `json:"-"`
	CreatedAt       int64    `json:"created"`
	LastSeenAt      int64    `json:"last_seen"`
	Ban             *UserBan `json:"ban,omitempty"`
	Banned          bool     `json:"banned"`

	*UserSettings
}

type UserBan struct {
	State        string `json:"state"`
	Restrictions int64  `json:"restrictions"`
	Reason       string `json:"reason"`
	ExpiresAt    int64  `json:"expires"`
}

type UserSettings struct {
	Theme            string   `json:"theme"`
	Layout           string   `json:"layout"`
	Mode             bool     `json:"mode"`
	Bgm              bool     `json:"bgm"`
	BgmSong          int8     `json:"bgm_song"`
	Sfx              bool     `json:"sfx"`
	ActiveDMs        []string `json:"active_dms"`
	FavoritedChats   []string `json:"favorited_chats"`
	UnreadInbox      bool     `json:"unread_inbox"`
	HideBlockedUsers bool     `json:"hide_blocked_users"`
	Debug            bool     `json:"debug"`
}

type Post struct {
	Id             string        `json:"_id"`
	PostId         string        `json:"post_id"`
	PostOrigin     string        `json:"post_origin"`
	Author         *User         `json:"author"`
	AuthorUsername string        `json:"u"`
	Content        string        `json:"p"`
	ReplyTo        []interface{} `json:"reply_to"`
	Attachments    []interface{} `json:"attachments"`
	Emojis         []interface{} `json:"emojis"`
	Stickers       []interface{} `json:"stickers"`
	Reactions      []interface{} `json:"reactions"`
	Time           *Timestamp    `json:"t"`
	Pinned         bool          `json:"pinned"`
	Deleted        bool          `json:"isDeleted"`
}

type Timestamp struct {
	UnixSeconds int64 `json:"e"`
}

type LoginRequest struct {
	Username        string `json:"username"`
	Password        string `json:"password"`
	TOTPCode        string `json:"totp_code"`
	MFARecoveryCode string `json:"mfa_recovery_code"`
}

func getUser(userId string) *User {
	var user User
	var totpTokensString string
	err = db.QueryRow(`
		SELECT
		id,
		username,
		lower_username,
		legacy_avatar,
		password,
		totp_tokens,
		mfa_recovery_code,
		created_at,
		last_seen_at
		FROM users WHERE id=?`, userId).Scan(
		&user.Id,
		&user.Username,
		&user.LowerUsername,
		&user.LegacyAvatar,
		&user.Password,
		&totpTokensString,
		&user.MFARecoveryCode,
		&user.CreatedAt,
		&user.LastSeenAt,
	)
	if err == sql.ErrNoRows {
		return nil
	}
	if totpTokensString != "" {
		user.TOTPTokens = strings.Split(totpTokensString, ";")
	} else {
		user.TOTPTokens = []string{}
	}
	user.Ban = &UserBan{State: "none"}
	user.UserSettings = userSettings
	return &user
}

func getUserByUsername(username string) *User {
	var userId string
	db.QueryRow("SELECT id FROM users WHERE lower_username = ?", strings.ToLower(username)).Scan(&userId)
	return getUser(userId)
}

func getUserByToken(signedToken string) *User {
	token, err := jwt.Parse(signedToken, func(t *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})
	if err != nil {
		return nil
	}
	userId, _ := token.Claims.GetSubject()
	return getUser(userId)
}

func (u *User) CheckPassword(password string) error {
	return bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
}

func (u *User) CheckTOTPCode(code string) bool {
	for _, totpToken := range u.TOTPTokens {
		if totp.Validate(code, totpToken) {
			return true
		}
	}
	return false
}

func (u *User) GetToken() (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": u.Id,
		"iss": "Meower",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour * 24).Unix(),
	}).SignedString([]byte(os.Getenv("JWT_SECRET")))
}

func (u *User) Delete() error {
	if err := s3.RemoveObject(
		context.TODO(),
		os.Getenv("S3_BUCKET"),
		u.Id+".zip",
		minio.RemoveObjectOptions{},
	); err != nil {
		return err
	}
	if _, err := db.Exec("DELETE FROM users WHERE id = ?", u.Id); err != nil {
		return err
	}
	return nil
}

var (
	err error

	db *sql.DB
	s3 *minio.Client

	userSettings = &UserSettings{
		Theme:          "orange",
		Layout:         "new",
		ActiveDMs:      []string{},
		FavoritedChats: []string{},
	}

	systemUser = &User{
		Id:       "10000000-0000-0000-0000-000000000000",
		Username: "Meower",
	}

	shutdownPostTimestamp = &Timestamp{
		UnixSeconds: 1733011200,
	}
)

func main() {
	// Load .env
	godotenv.Load()

	// Check JWT_SECRET
	if os.Getenv("JWT_SECRET") == "" {
		log.Fatalln("Please set the 'JWT_SECRET' environment variable.")
	}

	// Connect to SQLite database
	db, err = sql.Open("sqlite3", os.Getenv("SQLITE_DB"))
	if err != nil {
		log.Fatalln(err)
	}
	if err := db.Ping(); err != nil {
		log.Fatalln(err)
	}

	// Connect to S3
	s3, err = minio.New(os.Getenv("S3_ENDPOINT"), &minio.Options{
		Creds:  credentials.NewStaticV4(os.Getenv("S3_ACCESS"), os.Getenv("S3_SECRET"), ""),
		Secure: os.Getenv("S3_SECURE") == "1",
	})
	if err != nil {
		log.Fatalln(err)
	}

	// Create router
	r := chi.NewRouter()

	// CORS middleware
	r.Use(cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"OPTIONS", "GET", "POST", "PATCH", "PUT", "DELETE"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	}).Handler)

	// Use Cf-Connecting-Ip
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.RemoteAddr = r.Header.Get("Cf-Connecting-Ip")
			next.ServeHTTP(w, r)
		})
	})

	// robots.txt
	r.Get("/robots.txt", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("User-agent: *\nDisallow: /"))
	})

	// REST API
	r.Get("/", func(w http.ResponseWriter, _ *http.Request) {
		marshaled, _ := json.Marshal(map[string]interface{}{
			"captcha": map[string]interface{}{
				"enabled": false,
				"sitekey": nil,
			},
		})
		w.Write(marshaled)
	})
	r.Get("/statistics", func(w http.ResponseWriter, r *http.Request) {
		marshaled, _ := json.Marshal(map[string]interface{}{
			"error": false,
			"users": 0,
			"chats": 0,
			"posts": 0,
		})
		w.Write(marshaled)
	})
	r.Post("/auth/login", func(w http.ResponseWriter, r *http.Request) {
		// Ratelimit (10 requests per 15 minutes)
		var rtlRemaining int8
		var rtlResetAt int64
		db.QueryRow("SELECT remaining, reset_at FROM auth_ratelimits WHERE ip = ?", r.RemoteAddr).Scan(&rtlRemaining, &rtlResetAt)
		if rtlResetAt == 0 || time.Now().Unix() >= rtlResetAt {
			rtlRemaining = 10
			rtlResetAt = time.Now().Add(time.Minute * 15).Unix()
		}
		rtlRemaining -= 1
		if rtlRemaining < 0 {
			marshaled, _ := json.Marshal(map[string]interface{}{
				"error": true,
				"type":  "tooManyRequests",
			})
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write(marshaled)
			return
		}
		db.Exec("DELETE FROM auth_ratelimits WHERE ip = ?", r.RemoteAddr)
		db.Exec("INSERT INTO auth_ratelimits (ip, remaining, reset_at) VALUES (?, ?, ?)", r.RemoteAddr, rtlRemaining, rtlResetAt)

		// Decode body
		var body LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			marshaled, _ := json.Marshal(map[string]interface{}{
				"error": true,
				"type":  "badRequest",
			})
			w.WriteHeader(http.StatusBadRequest)
			w.Write(marshaled)
			return
		}

		// Pre-existing token auth
		user := getUserByToken(body.Password)
		if user != nil {
			marshaled, _ := json.Marshal(map[string]interface{}{
				"error":   false,
				"account": &user,
				"token":   body.Password,
			})
			w.Write(marshaled)
			return
		}

		// Get user
		user = getUserByUsername(body.Username)
		if user == nil {
			marshaled, _ := json.Marshal(map[string]interface{}{
				"error": true,
				"type":  "Unauthorized",
			})
			w.WriteHeader(http.StatusUnauthorized)
			w.Write(marshaled)
			return
		}

		// Check password
		if err := user.CheckPassword(body.Password); err != nil {
			marshaled, _ := json.Marshal(map[string]interface{}{
				"error": true,
				"type":  "Unauthorized",
			})
			w.WriteHeader(http.StatusUnauthorized)
			w.Write(marshaled)
			return
		}

		// Check MFA
		if len(user.TOTPTokens) > 0 {
			if body.TOTPCode != "" {
				if !user.CheckTOTPCode(body.TOTPCode) {
					marshaled, _ := json.Marshal(map[string]interface{}{
						"error": true,
						"type":  "Unauthorized",
					})
					w.WriteHeader(http.StatusUnauthorized)
					w.Write(marshaled)
					return
				}
			} else if body.MFARecoveryCode != "" {
				if user.MFARecoveryCode != body.MFARecoveryCode {
					marshaled, _ := json.Marshal(map[string]interface{}{
						"error": true,
						"type":  "Unauthorized",
					})
					w.WriteHeader(http.StatusUnauthorized)
					w.Write(marshaled)
					return
				}
			} else {
				marshaled, _ := json.Marshal(map[string]interface{}{
					"error":       true,
					"type":        "mfaRequired",
					"mfa_methods": []string{"totp"},
				})
				w.WriteHeader(http.StatusUnauthorized)
				w.Write(marshaled)
				return
			}
		}

		// Create token
		token, err := user.GetToken()
		if err != nil {
			marshaled, _ := json.Marshal(map[string]interface{}{
				"error": true,
				"type":  "Internal",
			})
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(marshaled)
			return
		}

		// Return account and token
		marshaled, _ := json.Marshal(map[string]interface{}{
			"error":   false,
			"account": &user,
			"token":   token,
		})
		w.Write(marshaled)
	})
	r.Delete("/me", func(w http.ResponseWriter, r *http.Request) {
		user := getUserByToken(r.Header.Get("token"))
		if user == nil {
			marshaled, _ := json.Marshal(map[string]interface{}{
				"error": true,
				"type":  "Unauthorized",
			})
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(marshaled)
			return
		}
		if err := user.Delete(); err != nil {
			marshaled, _ := json.Marshal(map[string]interface{}{
				"error": true,
				"type":  "Internal",
			})
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(marshaled)
			return
		}
		marshaled, _ := json.Marshal(map[string]interface{}{
			"error": false,
		})
		w.Write(marshaled)
	})
	r.Get("/{origin:home|inbox}", func(w http.ResponseWriter, r *http.Request) {
		// Get authenticated user
		user := getUserByToken(r.Header.Get("token"))

		// Get presigned data export URL
		var exportUrl *url.URL
		if user != nil {
			exportUrl, _ = s3.PresignedGetObject(context.TODO(), os.Getenv("S3_BUCKET"), user.Id+".zip", time.Minute*30, url.Values{})
		}

		// Construct posts
		posts := []Post{{
			Id:             "20000000-0000-0000-0000-000000000000",
			PostId:         "20000000-0000-0000-0000-000000000000",
			PostOrigin:     chi.URLParam(r, "origin"),
			Author:         systemUser,
			AuthorUsername: systemUser.Username,
			Content:        "Meower ended service on December 1st, 2024 due to challenges in development and moderation. If you would like to stay in touch with the Meower community, you may join our Discord server at https://discord.gg/pHpMHtu8WZ. Thank you to everyone who had a hand in this project <3",
			ReplyTo:        []interface{}{},
			Attachments:    []interface{}{},
			Emojis:         []interface{}{},
			Stickers:       []interface{}{},
			Reactions:      []interface{}{},
			Time:           shutdownPostTimestamp,
		}}
		if exportUrl == nil {
			posts = append(posts, Post{
				Id:             "30000000-0000-0000-0000-000000000000",
				PostId:         "30000000-0000-0000-0000-000000000000",
				PostOrigin:     chi.URLParam(r, "origin"),
				Author:         systemUser,
				AuthorUsername: systemUser.Username,
				Content:        "To get a download of your data, please log in.",
				ReplyTo:        []interface{}{},
				Attachments:    []interface{}{},
				Emojis:         []interface{}{},
				Stickers:       []interface{}{},
				Reactions:      []interface{}{},
				Time:           shutdownPostTimestamp,
			})
		} else {
			posts = append(posts, Post{
				Id:             "30000000-0000-0000-0000-000000000000",
				PostId:         "30000000-0000-0000-0000-000000000000",
				PostOrigin:     chi.URLParam(r, "origin"),
				Author:         systemUser,
				AuthorUsername: systemUser.Username,
				Content:        "You may download your data here: " + exportUrl.String() + "\n\nPlease do not share this link!",
				ReplyTo:        []interface{}{},
				Attachments:    []interface{}{},
				Emojis:         []interface{}{},
				Stickers:       []interface{}{},
				Reactions:      []interface{}{},
				Time:           shutdownPostTimestamp,
			})
		}

		// Return posts
		marshaled, _ := json.Marshal(map[string]interface{}{
			"error":   false,
			"autoget": posts,
			"page#":   1,
			"pages":   1,
		})
		w.Write(marshaled)
	})

	// Cloudlink
	r.Get("/v0/cloudlink", func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Get version
		var version int
		version, _ = strconv.Atoi(r.URL.Query().Get("v"))

		// Automatic auth
		if r.URL.Query().Has("token") && version == 1 {
			u := getUserByToken(r.URL.Query().Get("token"))
			if u != nil {
				token, _ := u.GetToken()
				p := map[string]interface{}{
					"username":      u.Username,
					"token":         token,
					"account":       u,
					"relationships": []interface{}{},
					"chats":         []interface{}{},
				}
				if version == 0 {
					p = map[string]interface{}{
						"cmd": "direct",
						"val": map[string]interface{}{
							"mode":    "auth",
							"payload": p,
						},
					}
				} else if version == 1 {
					p = map[string]interface{}{
						"cmd": "auth",
						"val": p,
					}
				}
				conn.WriteJSON(p)

				var exportUrl *url.URL
				exportUrl, err = s3.PresignedGetObject(context.TODO(), os.Getenv("S3_BUCKET"), u.Id+".zip", time.Minute*30, url.Values{})
				if err != nil {
					log.Println(err)
					marshaled, _ := json.Marshal(Post{
						Id:             "30000000-0000-0000-0000-000000000000",
						PostId:         "30000000-0000-0000-0000-000000000000",
						PostOrigin:     chi.URLParam(r, "origin"),
						Author:         systemUser,
						AuthorUsername: systemUser.Username,
						Content:        "We failed getting your data package. Please try again later or send an email to support@meower.org.",
						ReplyTo:        []interface{}{},
						Attachments:    []interface{}{},
						Emojis:         []interface{}{},
						Stickers:       []interface{}{},
						Reactions:      []interface{}{},
						Time:           shutdownPostTimestamp,
					})
					json.Unmarshal(marshaled, &p)
				} else {
					marshaled, _ := json.Marshal(Post{
						Id:             "30000000-0000-0000-0000-000000000000",
						PostId:         "30000000-0000-0000-0000-000000000000",
						PostOrigin:     chi.URLParam(r, "origin"),
						Author:         systemUser,
						AuthorUsername: systemUser.Username,
						Content:        "You may download your data here: " + exportUrl.String() + "\n\nPlease do not share this link!",
						ReplyTo:        []interface{}{},
						Attachments:    []interface{}{},
						Emojis:         []interface{}{},
						Stickers:       []interface{}{},
						Reactions:      []interface{}{},
						Time:           shutdownPostTimestamp,
					})
					json.Unmarshal(marshaled, &p)
				}
				if version == 0 {
					p = map[string]interface{}{
						"cmd": "direct",
						"val": map[string]interface{}{
							"mode":    "update_post",
							"payload": p,
						},
					}
				} else if version == 1 {
					p = map[string]interface{}{
						"cmd": "update_post",
						"val": p,
					}
				}
				conn.WriteJSON(p)
			} else {
				conn.WriteJSON(map[string]string{
					"cmd": "statuscode",
					"val": "I:011 | Invalid Password",
				})
			}
		}

		for {
			// Parse msg
			var msg map[string]interface{}
			if err := conn.ReadJSON(&msg); err != nil {
				conn.WriteJSON(map[string]string{
					"cmd": "statuscode",
					"val": "E:101 | Syntax",
				})
				continue
			}

			// Get listener
			listener, _ := msg["listener"].(string)

			// Unwrap direct
			if msg["cmd"] == "direct" {
				var ok bool
				msg, ok = msg["val"].(map[string]interface{})
				if !ok {
					conn.WriteJSON(map[string]string{
						"cmd":      "statuscode",
						"val":      "E:101 | Syntax",
						"listener": listener,
					})
					continue
				}
			}

			switch msg["cmd"] {
			case "ping":
				conn.WriteJSON(map[string]string{
					"cmd":      "statuscode",
					"val":      "I:100 | OK",
					"listener": listener,
				})
			case "authpswd":
				val, ok := msg["val"].(map[string]interface{})
				if !ok {
					conn.WriteJSON(map[string]string{
						"cmd":      "statuscode",
						"val":      "E:101 | Syntax",
						"listener": listener,
					})
					continue
				}

				username, _ := val["username"].(string)
				password, _ := val["pswd"].(string)

				u := getUserByToken(password)
				if u == nil {
					u := getUserByUsername(username)
					if u == nil {
						conn.WriteJSON(map[string]string{
							"cmd":      "statuscode",
							"val":      "E:103 | ID not found",
							"listener": listener,
						})
						continue
					}
					if u.CheckPassword(password) != nil {
						conn.WriteJSON(map[string]string{
							"cmd":      "statuscode",
							"val":      "I:011 | Invalid Password",
							"listener": listener,
						})
						continue
					}
					if len(u.TOTPTokens) > 0 {
						conn.WriteJSON(map[string]string{
							"cmd":      "statuscode",
							"val":      "I:016 | 2FA Required",
							"listener": listener,
						})
						continue
					}
				}

				token, _ := u.GetToken()
				p := map[string]interface{}{
					"username":      u.Username,
					"token":         token,
					"account":       u,
					"relationships": []interface{}{},
					"chats":         []interface{}{},
				}
				if version == 0 {
					p = map[string]interface{}{
						"cmd": "direct",
						"val": map[string]interface{}{
							"mode":    "auth",
							"payload": p,
						},
						"listener": listener,
					}
				} else if version == 1 {
					p = map[string]interface{}{
						"cmd":      "auth",
						"val":      p,
						"listener": listener,
					}
				}
				conn.WriteJSON(p)

				var exportUrl *url.URL
				exportUrl, err = s3.PresignedGetObject(context.TODO(), os.Getenv("S3_BUCKET"), u.Id+".zip", time.Minute*30, url.Values{})
				if err != nil {
					log.Println(err)
					marshaled, _ := json.Marshal(Post{
						Id:             "30000000-0000-0000-0000-000000000000",
						PostId:         "30000000-0000-0000-0000-000000000000",
						PostOrigin:     chi.URLParam(r, "origin"),
						Author:         systemUser,
						AuthorUsername: systemUser.Username,
						Content:        "We failed getting your data package. Please try again later or send an email to support@meower.org.",
						ReplyTo:        []interface{}{},
						Attachments:    []interface{}{},
						Emojis:         []interface{}{},
						Stickers:       []interface{}{},
						Reactions:      []interface{}{},
						Time:           shutdownPostTimestamp,
					})
					json.Unmarshal(marshaled, &p)
				} else {
					marshaled, _ := json.Marshal(Post{
						Id:             "30000000-0000-0000-0000-000000000000",
						PostId:         "30000000-0000-0000-0000-000000000000",
						PostOrigin:     chi.URLParam(r, "origin"),
						Author:         systemUser,
						AuthorUsername: systemUser.Username,
						Content:        "You may download your data here: " + exportUrl.String() + "\n\nPlease do not share this link!",
						ReplyTo:        []interface{}{},
						Attachments:    []interface{}{},
						Emojis:         []interface{}{},
						Stickers:       []interface{}{},
						Reactions:      []interface{}{},
						Time:           shutdownPostTimestamp,
					})
					json.Unmarshal(marshaled, &p)
				}
				if version == 0 {
					p = map[string]interface{}{
						"cmd": "direct",
						"val": map[string]interface{}{
							"mode":    "update_post",
							"payload": p,
						},
					}
				} else if version == 1 {
					p = map[string]interface{}{
						"cmd": "update_post",
						"val": p,
					}
				}
				conn.WriteJSON(p)
			default:
				conn.WriteJSON(map[string]string{
					"cmd":      "statuscode",
					"val":      "E:118 | Invalid command",
					"listener": listener,
				})
			}
		}
	})

	http.ListenAndServe(":3000", r)
}
