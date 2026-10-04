package foodgroup

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/patrickmn/go-cache"
	"golang.org/x/net/html"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

const (
	evilDelta         = uint16(100)
	evilDeltaAnon     = uint16(30)
	warningDecayPct   = -50
	rateDecayInterval = 5 * time.Minute
)

// NewICBMService returns a new instance of ICBMService.
func NewICBMService(bartItemManager BARTItemManager, messageRelayer MessageRelayer, offlineMessageSaver OfflineMessageManager, relationshipFetcher RelationshipFetcher, sessionRetriever SessionRetriever, userManager UserManager, feedbagManager FeedbagManager, contactPreAuthorizer ContactPreAuthorizer, snacRateLimits wire.SNACRateLimits, logger *slog.Logger) *ICBMService {
	return &ICBMService{
		relationshipFetcher:   relationshipFetcher,
		buddyBroadcaster:      newBuddyNotifier(bartItemManager, relationshipFetcher, messageRelayer, sessionRetriever),
		messageRelayer:        messageRelayer,
		offlineMessageSaver:   offlineMessageSaver,
		offlineMessageManager: offlineMessageSaver,
		userManager:           userManager,
		feedbagManager:        feedbagManager,
		contactPreAuthorizer:  contactPreAuthorizer,
		timeNow:               time.Now,
		sessionRetriever:      sessionRetriever,
		snacRateLimits:        snacRateLimits,
		convoTracker:          newConvoTracker(),
		logger:                logger,
		interval:              rateDecayInterval,
		forwardICQAuthEvents: func(ctx context.Context, sender state.IdentScreenName, recipient state.IdentScreenName, authMsg wire.ICBMCh4Message) error {
			return errors.New("forwardICQAuthEvents not implemented")
		},
	}
}

// ICBMService provides functionality for the ICBM food group, which is
// responsible for sending and receiving instant messages and associated
// functionality such as warning, typing events, etc.
type ICBMService struct {
	relationshipFetcher   RelationshipFetcher
	buddyBroadcaster      buddyBroadcaster
	messageRelayer        MessageRelayer
	offlineMessageSaver   OfflineMessageManager
	userManager           UserManager
	feedbagManager        FeedbagManager
	contactPreAuthorizer  ContactPreAuthorizer
	timeNow               func() time.Time
	sessionRetriever      SessionRetriever
	snacRateLimits        wire.SNACRateLimits
	convoTracker          *convoTracker
	logger                *slog.Logger
	interval              time.Duration
	offlineMessageManager OfflineMessageManager
	forwardICQAuthEvents  func(ctx context.Context, sender state.IdentScreenName, recipient state.IdentScreenName, authMsg wire.ICBMCh4Message) error
}

// BridgeFeedbagService enables the ICBMService to forward legacy ICQ events to
// the ICBM service.
func (s *ICBMService) BridgeFeedbagService(service *FeedbagService) {
	s.forwardICQAuthEvents = service.ForwardICQAuthEvents
}

// maxICBMLen is the largest ICBM the server relays, and what it announces as
// MaxIncomingICBMLen. What AOL's servers gave, and the top of the range the
// OSCAR specification allows (80 to 8000). A SIP message of an ICQ 6 call is
// several kilobytes and goes over ICBM too.
const maxICBMLen uint16 = 8000

// minICBMLen is the bottom of the range the OSCAR specification allows for
// MaxIncomingICBMLen.
const minICBMLen uint16 = 80

// AddParameters records the ICBM parameters a client sets for itself. Of
// them the server honours MaxIncomingICBMLen: it relays no ICBM longer than
// that to the client. A value of 0 leaves the previous one; the rest is
// brought into the range 80 to 8000.
func (s *ICBMService) AddParameters(_ context.Context, instance *state.SessionInstance, inBody wire.SNAC_0x04_0x02_ICBMAddParameters) {
	if inBody.MaxIncomingICBMLen == 0 {
		return
	}
	instance.SetMaxIncomingICBMLen(inBody.Channel, max(inBody.MaxIncomingICBMLen, minICBMLen))
}

// ParameterQuery returns ICBM service parameters.
func (s *ICBMService) ParameterQuery(_ context.Context, inFrame wire.SNACFrame) wire.SNACMessage {
	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.ICBM,
			SubGroup:  wire.ICBMParameterReply,
			RequestID: inFrame.RequestID,
		},
		Body: wire.SNAC_0x04_0x05_ICBMParameterReply{
			MaxSlots:             100,
			ICBMFlags:            3,
			MaxIncomingICBMLen:   maxICBMLen,
			MaxSourceEvil:        999,
			MaxDestinationEvil:   999,
			MinInterICBMInterval: 0,
		},
	}
}

// ChannelMsgToHost relays the instant message SNAC wire.ICBMChannelMsgToHost
// from the sender to the intended recipient. It returns wire.ICBMHostAck if
// the wire.ICBMChannelMsgToHost message contains a request acknowledgement
// flag.
func (s *ICBMService) ChannelMsgToHost(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x04_0x06_ICBMChannelMsgToHost) (*wire.SNACMessage, error) {
	recip := state.NewIdentScreenName(inBody.ScreenName)

	msgLen := icbmMessageLen(inBody)
	if msgLen > int(maxICBMLen) {
		return newICBMErr(inFrame.RequestID, wire.ErrorCodeRequestDenied), nil
	}

	rel, err := s.relationshipFetcher.Relationship(ctx, instance.IdentScreenName(), recip)
	if err != nil {
		return nil, err
	}

	switch {
	case rel.BlocksYou:
		return newICBMErr(inFrame.RequestID, wire.ErrorCodeNotLoggedOn), nil
	case rel.YouBlock:
		return newICBMErr(inFrame.RequestID, wire.ErrorCodeInLocalPermitDeny), nil
	}

	recipSess := s.sessionRetriever.RetrieveSession(recip)
	if recipSess == nil {
		// check for TLV that indicates that the message should be saved offline.
		// For AIM 6/7, this is only set if the sender has the recipient on
		// their buddy list and they've seen them online at least once.
		if _, saveOffline := inBody.Bytes(wire.ICBMTLVStore); !saveOffline {
			return newICBMErr(inFrame.RequestID, wire.ErrorCodeNotLoggedOn), nil
		}
		canSend, err := s.canSendOfflineMessage(ctx, inBody)
		if err != nil {
			return nil, err
		}
		if !canSend {
			return newICBMErr(inFrame.RequestID, wire.ErrorCodeNotLoggedOn), nil
		}
		msg, err := s.sendOfflineMessage(ctx, instance, inFrame, inBody)
		if errors.Is(err, state.ErrNoUser) {
			return newICBMErr(inFrame.RequestID, wire.ErrorCodeNotLoggedOn), nil
		}
		return msg, err
	}

	for _, recipInstance := range recipSess.Instances() {
		if msgLen > int(recipInstance.MaxIncomingICBMLen(inBody.ChannelID, maxICBMLen)) {
			// longer than one of the recipient's clients said it takes
			return newICBMErr(inFrame.RequestID, wire.ErrorCodeRefusedByClient), nil
		}
	}

	if inBody.ChannelID == wire.ICBMChannelSIP {
		// The signalling of an ICQ 6 call, relayed as it is. Logged by its
		// method or status and its size, to see a call through when it fails -
		// not its URIs nor its SDP body, the peers' addresses (sipLogAttrs).
		sip, _ := inBody.Bytes(0x0005)
		s.logger.InfoContext(ctx, "call signalling", append([]any{"to", recip.String()}, sipLogAttrs(sip)...)...)
	}

	if inBody.ChannelID == wire.ICBMChannelICQ {
		if b, ok := inBody.Bytes(wire.ICBMTLVData); ok {
			authMsg := wire.ICBMCh4Message{}
			if err = wire.UnmarshalLE(&authMsg, bytes.NewReader(b)); err != nil {
				return nil, fmt.Errorf("failed to unmarshal ICBM authMsg: %w", err)
			}
			if authMsg.MessageType == wire.ICBMMsgTypeAuthReq ||
				authMsg.MessageType == wire.ICBMMsgTypeAuthDeny ||
				authMsg.MessageType == wire.ICBMMsgTypeAuthOK ||
				authMsg.MessageType == wire.ICBMMsgTypeAdded {
				if recipSess.UsesFeedbag() {
					return nil, s.forwardICQAuthEvents(ctx, instance.IdentScreenName(), recipSess.IdentScreenName(), authMsg)
				} else if authMsg.MessageType == wire.ICBMMsgTypeAuthOK {
					if err := s.contactPreAuthorizer.RecordPreAuth(ctx, instance.IdentScreenName(), recipSess.IdentScreenName()); err != nil {
						return nil, fmt.Errorf("RecordPreAuth: %w", err)
					}
				}
			}
		}
	}

	clientIM := wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
		Cookie:       inBody.Cookie,
		ChannelID:    inBody.ChannelID,
		TLVUserInfo:  recipSess.UserInfoFor(instance.Session().TLVUserInfo()),
		TLVRestBlock: wire.TLVRestBlock{},
	}

	relayTLVs := inBody.TLVList
	if channel, tlv, rebuilt, err := tzerForRecipient(inBody, recipSess); err != nil {
		return nil, fmt.Errorf("tzerForRecipient: %w", err)
	} else if rebuilt {
		// a tZer goes in the form the recipient plays, or as a message saying
		// what it was
		clientIM.ChannelID = channel
		clientIM.Append(tlv)
		relayTLVs = nil
	}

	for _, tlv := range relayTLVs {
		if tlv.Tag == wire.ICBMTLVRequestHostAck {
			// Exclude this TLV, because its presence breaks chat invitations
			// on macOS client v4.0.9.
			continue
		}
		if tlv.Tag == wire.ICBMTLVStore {
			// Strip the store message directive.
			continue
		}
		if tlv.Tag == wire.ICBMTLVSendTime {
			// Only the server stamps a send time, and only on a message replayed
			// out of the offline store. Forwarding the sender's would let them
			// pass a live message off as a stored one and date it at will.
			continue
		}
		if clientIM.ChannelID == wire.ICBMChannelRendezvous && tlv.Tag == wire.ICBMTLVData {
			if tlv, err = s.addExternalIP(ctx, instance, recipSess, tlv); err != nil {
				return nil, fmt.Errorf("addExternalIP: %w", err)
			}
		}
		// Strip HTML from ICQ messages if recipient doesn't read it.
		// AIM clients send HTML formatted messages that should be preserved.
		if instance.UIN() > 0 &&
			(clientIM.ChannelID == wire.ICBMChannelIM || clientIM.ChannelID == wire.ICBMChannelMIME) &&
			tlv.Tag == wire.ICBMTLVAOLIMData {
			if !ReadsHTML(recipSess) {
				if transformedTLV, err := stripHTMLFromICBMTLV(tlv); err == nil {
					tlv = transformedTLV
				}
			}
		}
		clientIM.Append(tlv)
	}

	if instance.TypingEventsEnabled() && clientIM.ChannelID == inBody.ChannelID &&
		(inBody.ChannelID == wire.ICBMChannelIM || inBody.ChannelID == wire.ICBMChannelMIME) {
		// tell the receiver that we want to receive their typing events
		clientIM.Append(wire.NewTLVBE(wire.ICBMTLVWantEvents, []byte{}))
	}

	if recipSess.Inactive() {
		s.messageRelayer.RelayToScreenName(ctx, recipSess.IdentScreenName(), wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.ICBM,
				SubGroup:  wire.ICBMChannelMsgToClient,
				RequestID: wire.ReqIDFromServer,
			},
			Body: clientIM,
		})
	} else {
		s.messageRelayer.RelayToScreenNameActiveOnly(ctx, recipSess.IdentScreenName(), wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.ICBM,
				SubGroup:  wire.ICBMChannelMsgToClient,
				RequestID: wire.ReqIDFromServer,
			},
			Body: clientIM,
		})
	}

	s.convoTracker.trackConvo(time.Now(), instance.IdentScreenName(), recipSess.IdentScreenName())

	if _, requestedConfirmation := inBody.Bytes(wire.ICBMTLVRequestHostAck); !requestedConfirmation {
		// don't ack message
		return nil, nil
	}

	// ack message back to sender
	return &wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.ICBM,
			SubGroup:  wire.ICBMHostAck,
			RequestID: inFrame.RequestID,
		},
		Body: wire.SNAC_0x04_0x0C_ICBMHostAck{
			Cookie:     inBody.Cookie,
			ChannelID:  inBody.ChannelID,
			ScreenName: inBody.ScreenName,
		},
	}, nil
}

// icbmMessageLen returns the length of what an ICBM carries, the part
// MaxIncomingICBMLen limits: the message TLV of channels 1 and 3 (fragments,
// text and all), the data TLV of the others.
func icbmMessageLen(inBody wire.SNAC_0x04_0x06_ICBMChannelMsgToHost) int {
	tag := wire.ICBMTLVData
	if inBody.ChannelID == wire.ICBMChannelIM || inBody.ChannelID == wire.ICBMChannelMIME {
		tag = wire.ICBMTLVAOLIMData
	}
	b, _ := inBody.Bytes(tag)
	return len(b)
}

// canSendOfflineMessage returns true if the user can send an offline message.
//
//	For ICQ users, always return true. Todo: Check ICQ recipient's preferences.
//
//	For AIM users, only return false if the recipient has specifically opted out
//	of receiving offline messages or they do not have a stored buddy list.
func (s *ICBMService) canSendOfflineMessage(ctx context.Context, inBody wire.SNAC_0x04_0x06_ICBMChannelMsgToHost) (bool, error) {
	bag, err := s.feedbagManager.Feedbag(ctx, state.NewIdentScreenName(inBody.ScreenName))
	if err != nil {
		return false, fmt.Errorf("get feedbag failed: %w", err)
	}

	for _, item := range bag {
		if item.ClassID == wire.FeedbagClassIdBuddyPrefs {
			// wire.BuddyPref defaults AcceptOfflineIM to true when the bit is
			// absent, matching AIM 6.0+ behavior: the preference did not exist
			// prior to AIM 6, so users who never ran a capable client are
			// assumed to accept stored offline messages.
			return wire.BuddyPref(item.TLVList, wire.FeedbagBuddyPrefsAcceptOfflineIM), nil
		}
	}

	return true, nil
}

func (s *ICBMService) sendOfflineMessage(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x04_0x06_ICBMChannelMsgToHost) (*wire.SNACMessage, error) {
	recip := state.NewIdentScreenName(inBody.ScreenName)

	offlineMsg := state.OfflineMessage{
		Message:   inBody,
		Recipient: recip,
		Sender:    instance.IdentScreenName(),
		Sent:      s.timeNow().UTC(),
	}
	if _, err := s.offlineMessageSaver.SaveMessage(ctx, offlineMsg); err != nil {
		if errors.Is(err, state.ErrOfflineInboxFull) {
			return newICBMErr(
				inFrame.RequestID,
				wire.ErrorCodeNotLoggedOn,
				wire.NewTLVBE(wire.ErrorTLVErrorSubcode, wire.ICBMSubErrOfflineIMExceedMax),
			), nil
		}
		return nil, fmt.Errorf("save ICBM offline message failed: %w", err)
	}

	if _, requestedConfirmation := inBody.Bytes(wire.ICBMTLVRequestHostAck); requestedConfirmation {
		// ack message back to sender
		return &wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.ICBM,
				SubGroup:  wire.ICBMHostAck,
				RequestID: inFrame.RequestID,
			},
			Body: wire.SNAC_0x04_0x0C_ICBMHostAck{
				Cookie:     inBody.Cookie,
				ChannelID:  inBody.ChannelID,
				ScreenName: inBody.ScreenName,
			},
		}, nil
	}
	return nil, nil
}

// sipLogAttrs describes a SIP message of an ICQ 6 call for the log: the
// method of a request ("INVITE") or the status of a response ("200 OK"), its
// size and the size of its SDP body - not the URIs, the headers or the SDP,
// which name the peers and their addresses.
func sipLogAttrs(sip []byte) []any {
	first, _, _ := strings.Cut(string(sip), "\r\n")
	_, sdp, _ := strings.Cut(string(sip), "\r\n\r\n")
	what, rest, _ := strings.Cut(first, " ")
	if strings.HasPrefix(what, "SIP/") {
		what = rest
	}
	return []any{"what", what, "bytes", len(sip), "sdp_bytes", len(sdp)}
}

// rendezvousLogAttrs describes a rendezvous proposal for the log without
// anything that identifies the transfer or the people in it: the capability,
// the sequence number, which tags it has (not their values), whether it asks
// for the proxy, the kind of the proposed address and how many bytes of
// service data it carries - and, for a file transfer, how many files. Not
// the cookie, the addresses, the port, the file names or the sizes.
func rendezvousLogAttrs(frag wire.ICBMCh2Fragment, proposed []byte, port uint16, sameNetwork bool) []any {
	tags := make([]string, 0, len(frag.TLVList))
	for _, t := range frag.TLVList {
		tags = append(tags, fmt.Sprintf("%04X", t.Tag))
	}
	seq, _ := frag.Uint16BE(wire.ICBMRdvTLVTagsSeqNum)
	svc, _ := frag.Bytes(wire.ICBMRdvTLVTagsSvcData)
	attrs := []any{
		"capability", fmt.Sprintf("%X", frag.Capability),
		"seq", seq,
		"tags", strings.Join(tags, " "),
		"use_ars", frag.HasTag(wire.ICBMRdvTLVTagsUseARS),
		"proposed_addr", addrClass(proposed),
		"has_port", port != 0,
		"service_data_bytes", len(svc),
		"same_network", sameNetwork,
	}
	// File transfer service data: u16 multiple-files flag, u16 file count,
	// u32 total size, then the name.
	if frag.Capability == wire.CapFileTransfer && len(svc) >= 4 {
		attrs = append(attrs, "files", binary.BigEndian.Uint16(svc[2:4]))
	}
	return attrs
}

// addrClass names the kind of an IPv4 address without giving it.
func addrClass(b []byte) string {
	addr, ok := netip.AddrFromSlice(b)
	switch {
	case !ok:
		return "none"
	case addr.IsUnspecified():
		return "unspecified"
	case addr.IsLoopback():
		return "loopback"
	case addr.IsPrivate(), addr.IsLinkLocalUnicast():
		return "private"
	default:
		return "public"
	}
}

// addExternalIP sets the proposing client's address in an ICBM rendezvous
// proposal: file transfer, and the voice and video calls of ICQ 6.
//
// A client behind NAT proposes its LAN address, useless to a peer on the
// Internet, so the server puts in the address it sees instead - unlike AOL,
// which left it and only added the verified one. But two clients behind the
// same NAT would then be sent to their router's outside address, which many
// routers do not loop back, and the call fails one way or both. For them the
// LAN address is kept, and the outside one goes in the verified tag, as AOL
// did: a client that finds its peer's verified address equal to its own knows
// they share a network and uses the proposed one.
func (s *ICBMService) addExternalIP(ctx context.Context, instance *state.SessionInstance, recip *state.Session, tlv wire.TLV) (wire.TLV, error) {
	frag := wire.ICBMCh2Fragment{}
	if err := wire.UnmarshalBE(&frag, bytes.NewReader(tlv.Value)); err != nil {
		return tlv, fmt.Errorf("wire.UnmarshalBE: %w", err)
	}
	if frag.Type != wire.ICBMRdvMessagePropose {
		return tlv, nil
	}
	if !frag.HasTag(wire.ICBMRdvTLVTagsRequesterIP) || instance.RemoteAddr() == nil || !instance.RemoteAddr().Addr().Is4() {
		return tlv, nil
	}
	ip := instance.RemoteAddr().Addr()
	proposed, _ := frag.Bytes(wire.ICBMRdvTLVTagsRequesterIP)
	port, _ := frag.Uint16BE(wire.ICBMRdvTLVTagsPort)
	sameNetwork := false
	for _, ri := range recip.Instances() {
		if ra := ri.RemoteAddr(); ra != nil && ra.Addr() == ip {
			sameNetwork = true
			break
		}
	}
	s.logger.InfoContext(ctx, "rendezvous proposal", rendezvousLogAttrs(frag, proposed, port, sameNetwork)...)
	if !sameNetwork {
		frag.Set(wire.NewTLVBE(wire.ICBMRdvTLVTagsRequesterIP, ip.AsSlice()))
	}
	// The address as the server sees it. Required by the clients, which
	// compare it with the proposed one.
	frag.Append(wire.NewTLVBE(wire.ICBMRdvTLVTagsVerifiedIP, ip.AsSlice()))
	return wire.NewTLVBE(tlv.Tag, frag), nil
}

// ReadsHTML reports whether recip reads HTML in ICQ messages: it announces
// XHTML, or it is ICQ 6 or 7, which send and read HTML without announcing it.
// Their smileys ride in the HTML (<FONT sml="...">, naming the set that draws
// them), and ICQ 7 draws none from plain text.
func ReadsHTML(recip *state.Session) bool {
	return recip.HasCap(wire.CapXHTMLIM) || recip.HasCap(wire.CapICQ6HTML) || wire.HasICQ7Caps(recip.Caps())
}

// stripHTML extracts plaintext from HTML content.
func stripHTML(text []byte) []byte {
	if len(text) == 0 {
		return text
	}

	var result strings.Builder
	tok := html.NewTokenizer(strings.NewReader(string(text)))

	for {
		tt := tok.Next()
		switch tt {
		case html.TextToken:
			result.Write(tok.Text())
		case html.SelfClosingTagToken, html.StartTagToken:
			tn, _ := tok.TagName()
			if string(tn) == "br" {
				result.WriteByte('\n')
			}
		case html.ErrorToken:
			if tok.Err() == io.EOF {
				return []byte(result.String())
			}
			// on error return what we have
			return []byte(result.String())
		}
	}
}

// stripHTMLFromICBMTLV transforms an ICBMTLVAOLIMData TLV by stripping HTML
// from the message text for clients that don't support XHTML.
func stripHTMLFromICBMTLV(tlv wire.TLV) (wire.TLV, error) {
	var frags []wire.ICBMCh1Fragment
	if err := wire.UnmarshalBE(&frags, bytes.NewBuffer(tlv.Value)); err != nil {
		return tlv, fmt.Errorf("unmarshal ICBM fragments: %w", err)
	}

	modified := false
	for i, frag := range frags {
		if frag.ID == 1 { // 1 = message text
			msg := wire.ICBMCh1Message{}
			if err := wire.UnmarshalBE(&msg, bytes.NewBuffer(frag.Payload)); err != nil {
				continue
			}

			// Strip HTML from message text. UCS-2 text is stripped as text:
			// its markup is not ASCII bytes the tokenizer can see.
			var strippedText []byte
			if msg.Charset == wire.ICBMMessageEncodingUnicode {
				strippedText = encodeUTF16BE(string(stripHTML([]byte(decodeUTF16BE(msg.Text)))))
			} else {
				strippedText = stripHTML(msg.Text)
			}
			if !bytes.Equal(strippedText, msg.Text) {
				msg.Text = strippedText

				// Remarshal the message
				msgBuf := bytes.Buffer{}
				if err := wire.MarshalBE(msg, &msgBuf); err != nil {
					continue
				}
				frags[i].Payload = msgBuf.Bytes()
				modified = true
			}
		}
	}

	if !modified {
		return tlv, nil
	}

	// Remarshal the fragments
	newValue, err := wire.MarshalICBMFragmentList(frags)
	if err != nil {
		return tlv, err
	}

	return wire.NewTLVBE(tlv.Tag, newValue), nil
}

// ClientEvent relays SNAC wire.ICBMClientEvent typing events from the
// sender to the recipient.
func (s *ICBMService) ClientEvent(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x04_0x14_ICBMClientEvent) error {
	blocked, err := s.relationshipFetcher.Relationship(ctx, instance.IdentScreenName(), state.NewIdentScreenName(inBody.ScreenName))

	switch {
	case err != nil:
		return err
	case blocked.BlocksYou || blocked.YouBlock:
		return nil
	default:
		recipient := state.NewIdentScreenName(inBody.ScreenName)
		s.messageRelayer.RelayToScreenNameActiveOnly(ctx, recipient, wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.ICBM,
				SubGroup:  wire.ICBMClientEvent,
				RequestID: inFrame.RequestID,
			},
			Body: wire.SNAC_0x04_0x14_ICBMClientEvent{
				Cookie:     inBody.Cookie,
				ChannelID:  inBody.ChannelID,
				ScreenName: string(instance.DisplayScreenName()),
				Event:      inBody.Event,
			},
		})

		return nil
	}
}

func (s *ICBMService) ClientErr(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x04_0x0B_ICBMClientErr) error {
	s.messageRelayer.RelayToScreenName(ctx, state.NewIdentScreenName(inBody.ScreenName), wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.ICBM,
			SubGroup:  wire.ICBMClientErr,
			RequestID: inFrame.RequestID,
		},
		Body: wire.SNAC_0x04_0x0B_ICBMClientErr{
			Cookie:     inBody.Cookie,
			ChannelID:  inBody.ChannelID,
			ScreenName: instance.DisplayScreenName().String(),
			Code:       inBody.Code,
			ErrInfo:    inBody.ErrInfo,
		},
	})
	return nil
}

// EvilRequest handles user warning (a.k.a evil) notifications. It receives
// wire.ICBMEvilRequest warning SNAC, increments the warned user's warning
// level, and sends the warned user a notification informing them that they
// have been warned. The user may choose to warn anonymously or
// non-anonymously. It returns SNAC wire.ICBMEvilReply to confirm that the
// warning was sent. Users may not warn themselves or warn users they have
// blocked or are blocked by.
func (s *ICBMService) EvilRequest(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x04_0x08_ICBMEvilRequest) (wire.SNACMessage, error) {
	identScreenName := state.NewIdentScreenName(inBody.ScreenName)

	// don't let users warn themselves, it causes the AIM client to go into a
	// weird state.
	if identScreenName == instance.IdentScreenName() {
		return *newICBMErr(inFrame.RequestID, wire.ErrorCodeNotSupportedByHost), nil
	}

	blocked, err := s.relationshipFetcher.Relationship(ctx, instance.IdentScreenName(), identScreenName)
	if err != nil {
		return wire.SNACMessage{}, err
	}
	if blocked.BlocksYou || blocked.YouBlock {
		// user or target is blocked
		return *newICBMErr(inFrame.RequestID, wire.ErrorCodeNotLoggedOn), nil
	}

	recipSess := s.sessionRetriever.RetrieveSession(identScreenName)
	if recipSess == nil {
		// target user is offline
		return *newICBMErr(inFrame.RequestID, wire.ErrorCodeNotLoggedOn), nil
	}

	if recipSess.AllUserInfoBitmask(wire.OServiceUserFlagBot) {
		// target user is a bot, bots can't be warned
		return *newICBMErr(inFrame.RequestID, wire.ErrorCodeRequestDenied), nil
	}

	canWarn := s.convoTracker.trackWarn(time.Now(), instance.IdentScreenName(), recipSess.IdentScreenName())
	if !canWarn {
		// user has warned target too many times or not enough messages have
		// been received from target
		return *newICBMErr(inFrame.RequestID, wire.ErrorCodeRequestDenied), nil
	}

	increase := evilDelta
	if inBody.SendAs == 1 {
		increase = evilDeltaAnon
	}

	// get the rate class for sending IMs, which gets limited when the user gets warned
	classID, ok := s.snacRateLimits.RateClassLookup(wire.ICBM, wire.ICBMChannelMsgToHost)
	if !ok {
		panic("failed to retrieve rate class for ICBMChannelMsgToHost")
	}

	ok, newLevel := recipSess.ScaleWarningAndRateLimit(int16(increase), classID)
	if !ok {
		// target's warning is at 100%
		return *newICBMErr(inFrame.RequestID, wire.ErrorCodeRequestDenied), nil
	}

	notif := wire.SNAC_0x01_0x10_OServiceEvilNotification{
		NewEvil: newLevel,
	}

	// append info about user who sent the warning
	if inBody.SendAs == 0 {
		notif.Snitcher = &struct {
			wire.TLVUserInfo
		}{
			TLVUserInfo: wire.TLVUserInfo{
				ScreenName:   instance.DisplayScreenName().String(),
				WarningLevel: instance.Warning(),
			},
		}
	}

	s.messageRelayer.RelayToScreenName(ctx, recipSess.IdentScreenName(), wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.OService,
			SubGroup:  wire.OServiceEvilNotification,
		},
		Body: notif,
	})

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.ICBM,
			SubGroup:  wire.ICBMEvilReply,
			RequestID: inFrame.RequestID,
		},
		Body: wire.SNAC_0x04_0x09_ICBMEvilReply{
			EvilDeltaApplied: increase,
			UpdatedEvilValue: newLevel,
		},
	}, nil
}

func (s *ICBMService) OfflineRetrieve(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame) (wire.SNACMessage, error) {
	msgList, err := s.offlineMessageManager.RetrieveMessages(ctx, instance.IdentScreenName())
	if err != nil {
		return wire.SNACMessage{}, fmt.Errorf("retrieving messages: %w", err)
	}

	for _, event := range msgList {
		clientIM := wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
			Cookie:    event.Message.Cookie,
			ChannelID: event.Message.ChannelID,
			TLVUserInfo: wire.TLVUserInfo{
				ScreenName: event.Sender.String(),
			},
			TLVRestBlock: wire.TLVRestBlock{},
		}

		storedTLVs := event.Message.TLVList
		// a stored tZer goes in the form the recipient plays, as a live one does
		if channel, tlv, rebuilt, err := tzerForRecipient(event.Message, instance.Session()); err != nil {
			return wire.SNACMessage{}, fmt.Errorf("tzerForRecipient: %w", err)
		} else if rebuilt {
			clientIM.ChannelID = channel
			storedTLVs = wire.TLVList{tlv}
		}

		for _, tlv := range storedTLVs {
			// The stored SNAC is whatever the sender sent. A send time it carries
			// is not ours, and TLVList lookups return the first match, so it would
			// shadow the stamp appended below.
			if tlv.Tag == wire.ICBMTLVSendTime {
				continue
			}
			clientIM.Append(tlv)
		}
		clientIM.Append(wire.NewTLVBE(wire.ICBMTLVSendTime, uint32(event.Sent.Unix())))

		// Retrieval answers the instance that asked for it. Relaying to the screen
		// name would hand this reply to every other instance of the account, which
		// never requested it and cannot tell it apart from a live message.
		s.messageRelayer.RelayToSelf(ctx, instance, wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.ICBM,
				SubGroup:  wire.ICBMChannelMsgToClient,
				RequestID: wire.ReqIDFromServer,
			},
			Body: clientIM,
		})
	}

	if len(msgList) > 0 {
		if err := s.offlineMessageManager.DeleteMessages(ctx, instance.IdentScreenName()); err != nil {
			return wire.SNACMessage{}, fmt.Errorf("offlineMessageManager.DeleteMessages: %w", err)
		}
	}

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.ICBM,
			SubGroup:  wire.ICBMOfflineRetrieveReply,
			RequestID: inFrame.RequestID,
		},
		Body: wire.SNAC_0x04_0x17_ICBMOfflineRetrieveReply{},
	}, nil
}

// RestoreWarningLevel restores the warning level from the last stored value at login time,
// accounting for time passed between logins.
func (s *ICBMService) RestoreWarningLevel(ctx context.Context, instance *state.SessionInstance) error {
	u, err := s.userManager.User(ctx, instance.IdentScreenName())
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if u == nil {
		return state.ErrNoUser
	}

	if u.LastWarnLevel == 0 {
		// user had no warning at the end of last session
		return nil
	}

	// get the rate class for sending IMs, which gets limited when the user gets warned
	classID, ok := s.snacRateLimits.RateClassLookup(wire.ICBM, wire.ICBMChannelMsgToHost)
	if !ok {
		panic("failed to retrieve rate class for ICBMChannelMsgToHost")
	}

	// increment warning level by the amount of time that has passed since last
	// login, proportionally increasing the warning level
	warnDelta := calcElapsedWarningLevel(u.LastWarnUpdate, s.timeNow(), s.interval)
	newWarning := int16(u.LastWarnLevel) + warnDelta
	instance.Session().SetWarning(0)
	instance.Session().ScaleWarningAndRateLimit(newWarning, classID)

	if instance.Warning() > 0 {
		s.logger.DebugContext(ctx, "restored warning level with time decay applied since last login",
			"stored_level", u.LastWarnLevel,
			"time_since_update", s.timeNow().Sub(u.LastWarnUpdate),
			"decay_delta", warnDelta,
			"final_level", instance.Warning(),
		)
	} else {
		s.logger.DebugContext(ctx, "warning level decayed to zero since last login",
			"stored_level", u.LastWarnLevel,
			"time_since_update", s.timeNow().Sub(u.LastWarnUpdate),
			"decay_delta", warnDelta,
		)
	}

	return nil
}

// UpdateWarnLevel periodically updates the warning level relative to time
// elapsed between warnings.
func (s *ICBMService) UpdateWarnLevel(ctx context.Context, instance *state.SessionInstance) {
	var inProgress bool
	var ticker *time.Ticker
	var tickC <-chan time.Time // nil when idle, enables/disables the select case
	var doReset bool

	stopTicker := func() {
		if ticker != nil {
			ticker.Stop()
			ticker = nil
		}
		tickC = nil
		inProgress = false
		s.logger.DebugContext(ctx, "warning decay stopped")
	}

	startTicker := func(interval time.Duration) {
		ticker = time.NewTicker(interval)
		tickC = ticker.C
		inProgress = true
		s.logger.DebugContext(ctx, "warning decay started")
	}

	if instance.Warning() > 0 {
		u, err := s.userManager.User(ctx, instance.IdentScreenName())
		if err != nil {
			s.logger.ErrorContext(ctx, "failed to get user", "err", err)
			return
		}
		newInterval := timeTillNextInterval(u.LastWarnUpdate, s.timeNow(), s.interval)
		interval := s.interval
		if newInterval > 0 {
			interval = newInterval
		}
		s.logger.DebugContext(ctx, "starting warning level update with interval adjusted to next boundary",
			"user", instance.IdentScreenName(),
			"adjusted_interval", interval,
			"default_interval", s.interval,
			"time_since_last_update", s.timeNow().Sub(u.LastWarnUpdate),
		)
		startTicker(interval)
		doReset = true
	}

	// get the rate class for sending IMs, which gets limited when the user gets warned
	classID, ok := s.snacRateLimits.RateClassLookup(wire.ICBM, wire.ICBMChannelMsgToHost)
	if !ok {
		panic("failed to retrieve rate class for ICBMChannelMsgToHost")
	}

	warnCh := make(chan struct{}, 1)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(warnCh)
		for {
			select {
			case <-instance.Closed():
				return
			case <-ctx.Done():
				return
			case warning := <-instance.WarningCh():
				if warning > 0 {
					warnCh <- struct{}{}
				}
				if err := s.userManager.SetWarnLevel(ctx, instance.IdentScreenName(), s.timeNow(), warning); err != nil {
					s.logger.ErrorContext(ctx, "failed to set warn level", "err", err)
				}

				info := instance.Session().TLVUserInfo()
				// lock in the current warning level to avoid race conditions
				// where the warning level might change during this broadcast
				// operation
				info.WarningLevel = warning
				if err := s.buddyBroadcaster.BroadcastBuddyArrived(ctx, instance.IdentScreenName(), info); err != nil {
					s.logger.ErrorContext(ctx, "BroadcastBuddyArrived failed", "err", err)
				} else {
					s.logger.DebugContext(ctx, "warning lowered", "remaining", warning)
				}
			}
		}
	}()

	defer wg.Wait()

	for {
		select {
		case <-instance.Closed():
			stopTicker()
			return
		case <-ctx.Done():
			stopTicker()
			return

		case <-warnCh:
			if inProgress {
				s.logger.DebugContext(ctx, "warning decay already in progress")
				continue
			}
			startTicker(s.interval)

		case <-tickC:
			if doReset {
				ticker.Reset(s.interval)
				doReset = false
			}

			ok, warning := instance.Session().ScaleWarningAndRateLimit(warningDecayPct, classID)
			if !ok {
				s.logger.ErrorContext(ctx, "warning increment out of rage", "level", warning)
				stopTicker()
				return
			}

			if warning == 0 {
				s.logger.DebugContext(ctx, "warning decay complete")
				stopTicker()
			}
		}
	}
}

func newICBMErr(requestID uint32, errCode uint16, tlvs ...wire.TLV) *wire.SNACMessage {
	body := wire.SNACError{
		Code: errCode,
	}
	if len(tlvs) > 0 {
		body.AppendList(tlvs)
	}
	return &wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.ICBM,
			SubGroup:  wire.ICBMErr,
			RequestID: requestID,
		},
		Body: body,
	}
}

func calcElapsedWarningLevel(lastWarnUpdate time.Time, now time.Time, interval time.Duration) int16 {
	// time passed since last signoff
	since := now.Sub(lastWarnUpdate)

	// how many times warning decayed since last signoff
	decayPeriods := int(since / interval)
	// total amount warning decreased since last signoff
	warnDelta := decayPeriods * warningDecayPct

	return int16(warnDelta)
}

func timeTillNextInterval(lastWarned time.Time, now time.Time, interval time.Duration) time.Duration {
	return interval - (now.Sub(lastWarned) % interval)
}

// convoTracker keeps track of messages initiated from a sender to a recipient.
// A user (the warner) can only warn another user (the warnee) only if the
// warner has received a message from the warnee. The warner may only warn 1
// time per message received from warnee. The warner may only warn the warnee
// up to 3 times per warn window.
type convoTracker struct {
	convos *cache.Cache
	warns  *cache.Cache
	window time.Duration
}

func newConvoTracker() *convoTracker {
	window := 1 * time.Hour
	return &convoTracker{
		convos: cache.New(window, window),
		warns:  cache.New(window, window),
		window: window,
	}
}

// trackConvo records a conversation from sender to recipient at the given time.
func (w *convoTracker) trackConvo(now time.Time, sender, recip state.IdentScreenName) {
	k := w.key(sender, recip)

	buf, found := w.convos.Get(k)
	if !found {
		buf = &ringBuffer{}
		w.convos.Set(k, buf, time.Hour)
	}

	buf.(*ringBuffer).set(now)
}

// trackWarn attempts to record a warning from warner to warnee.
// It returns true if the warning is allowed (warnee has sent more messages
// than warnings in the current window), or false if the warning limit has been
// reached or no conversation exists in the current window.
func (w *convoTracker) trackWarn(now time.Time, warner, warnee state.IdentScreenName) bool {
	key := w.key(warnee, warner)

	convos, found := w.convos.Get(key)
	if !found {
		// no convos tracked, can't warn
		return false
	}

	windowStart := now.Add(-w.window)

	// get convo count during window
	var convoCt int
	for _, v := range convos.(*ringBuffer).vals {
		if v.After(windowStart) {
			convoCt++
		}
	}

	warns, found := w.warns.Get(key)
	if !found {
		warns = &ringBuffer{}
		w.warns.Set(key, warns, time.Hour)
	}

	// get warn count during window
	var warnCount int
	for _, v := range warns.(*ringBuffer).vals {
		if v.After(windowStart) {
			warnCount++
		}
	}

	if convoCt <= warnCount {
		return false
	}

	warns.(*ringBuffer).set(now)

	return true
}

func (w *convoTracker) key(sender state.IdentScreenName, recip state.IdentScreenName) string {
	return sender.String() + recip.String()
}

// ringBuffer is a fixed-size circular buffer with 3 slots for storing time values.
type ringBuffer struct {
	cur  int          // Current cursor position (0, 1, or 2)
	vals [3]time.Time // Fixed-size array to store time values
}

// val returns the time at the current cursor position.
func (r *ringBuffer) val() time.Time {
	return r.vals[r.cur]
}

// set stores the given time at the current cursor position and advances the cursor.
func (r *ringBuffer) set(v time.Time) {
	r.vals[r.cur] = v
	r.cur = (r.cur + 1) % len(r.vals)
}
