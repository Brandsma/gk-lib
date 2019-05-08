package models

// User is the struct that determines what users look like in the database
type User struct {
	UserID        string   `json:"userId" bson:"userId"`
	FirstName     string   `json:"firstName" bson:"firstName"`
	LastName      string   `json:"lastName" bson:"lastName"`
	ImageURL      string   `json:"imageUrl" bson:"imageUrl"`
	Email         string   `json:"email" bson:"email"`
	Password      string   `json:"password" bson:"password"`
	Groups        []string `json:"groups" bson:"groups"`
	InvitedGroups []string `json:"invitedGroups" bson:"invitedGroups"`
}
