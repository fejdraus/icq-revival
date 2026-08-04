package types

import "time"

// ConversationData is a conversation event payload: an operation and the
// conversations it applies to.
type ConversationData struct {
	Operation     string                  `json:"operation" xml:"operation"`
	Conversations []ConversationEntryData `json:"conversations" xml:"conversations>conversation"`
}

// ConversationEntryData is one conversation in the client's list.
type ConversationEntryData struct {
	AimID string `json:"aimId" xml:"aimId"`
	// Active is always sent, zero included, because the client reads it
	// unconditionally.
	Active      int `json:"active" xml:"active"`
	UnreadCount int `json:"unreadCount" xml:"unreadCount"`
	// DisplayID is omitted when empty rather than sent blank: the client falls
	// back to the name it already has for aimID, whereas any value present here
	// replaces it.
	DisplayID string  `json:"displayId,omitempty" xml:"displayId,omitempty"`
	LastIM    *LastIM `json:"lastIM,omitempty" xml:"lastIM,omitempty"`
}

// LastIM is the most recent message in a conversation.
//
// Timestamp is a float because AMF3 encodes whole numbers in 29 bits, which a
// Unix timestamp overflows.
type LastIM struct {
	Message   string  `json:"message" xml:"message"`
	MsgID     string  `json:"msgId" xml:"msgId"`
	Sender    string  `json:"sender" xml:"sender"`
	Sent      bool    `json:"sent" xml:"sent"`
	Timestamp float64 `json:"timestamp" xml:"timestamp"`
}

// ConversationEventData builds a conversation fetchEvents payload.
func ConversationEventData(operation string, conversations []ConversationEntryData) *ConversationData {
	if conversations == nil {
		conversations = []ConversationEntryData{}
	}
	return &ConversationData{
		Operation:     operation,
		Conversations: conversations,
	}
}

// ConversationEntry builds one conversation object for the Web AIM client.
func ConversationEntry(aimID, displayID, message, msgID, sender string, sent bool, unread int) ConversationEntryData {
	entry := ConversationEntryData{
		AimID:       aimID,
		Active:      0,
		UnreadCount: unread,
		DisplayID:   displayID,
	}
	if message != "" {
		entry.LastIM = &LastIM{
			Message:   message,
			MsgID:     msgID,
			Sender:    sender,
			Sent:      sent,
			Timestamp: float64(time.Now().Unix()),
		}
	}
	return entry
}
