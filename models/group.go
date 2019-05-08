package models

// Group is the struct that determines what a group looks like
type Group struct {
	GroupID    string   `json:"groupId,omitempty" bson:"groupId,omitempty"`
	GroupName  string   `json:"groupName" bson:"groupName"`
	UserIDs    []string `json:"userIds" bson:"userIds"`
	InvitedIDs []string `json:"invitedIds" bson:"invitedIds"`
}
