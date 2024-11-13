package main

type User struct {
	Id              string `bson:"uuid"`
	Username        string `bson:"_id"`
	LegacyAvatar    int64  `bson:"pfp_data"`
	Password        string `bson:"pswd"`
	MFARecoveryCode string `bson:"mfa_recovery_code"`
	CreatedAt       int64  `bson:"created"`
	LastSeenAt      int64  `bson:"last_seen"`
}
