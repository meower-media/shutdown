package main

type Report struct {
	Id        string `bson:"_id"`
	Type      string `bson:"type"`
	ContentId string `bson:"content_id"`
	Status    string `bson:"status"`
	Reporters []struct {
		User    string `bson:"user"`
		IP      string `bson:"ip"`
		Reason  string `bson:"reason"`
		Comment string `bson:"comment"`
		Time    int64  `bson:"time"`
	} `bson:"reports"`
}
