package main

type Post struct {
	Id   string `bson:"_id"`
	Time struct {
		Unix int64 `bson:"e"`
	} `bson:"t"`
	ReplyTo     []string                 `bson:"reply_to"`
	Content     string                   `bson:"p"`
	Attachments []string                 `bson:"attachments"`
	Emojis      []string                 `bson:"emojis"`
	Stickers    []string                 `bson:"stickers"`
	Pinned      bool                     `bson:"pinned"`
	Reactions   []map[string]interface{} `bson:"reactions"`
}
