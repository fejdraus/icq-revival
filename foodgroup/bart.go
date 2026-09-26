package foodgroup

import (
	"bytes"
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"log/slog"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// blankGIF is a blank, transparent 50x50p GIF that takes the place of a
// cleared buddy icon.
var blankGIF = []byte{
	0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x32, 0x00, 0x32, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
	0x32, 0x00, 0x32, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
}

func NewBARTService(
	logger *slog.Logger,
	bartItemManager BARTItemManager,
	messageRelayer MessageRelayer,
	relationshipFetcher RelationshipFetcher,
	sessionRetriever SessionRetriever,
) BARTService {
	return BARTService{
		bartItemManager:        bartItemManager,
		buddyUpdateBroadcaster: newBuddyNotifier(bartItemManager, relationshipFetcher, messageRelayer, sessionRetriever),
		messageRelayer:         messageRelayer,
		logger:                 logger,
	}
}

type BARTService struct {
	bartItemManager        BARTItemManager
	buddyUpdateBroadcaster buddyBroadcaster
	messageRelayer         MessageRelayer
	logger                 *slog.Logger
}

func (s BARTService) UpsertItem(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x10_0x02_BARTUploadQuery) (wire.SNACMessage, error) {
	h := md5.New()
	if _, err := h.Write(inBody.Data); err != nil {
		return wire.SNACMessage{}, err
	}
	hash := h.Sum(nil)

	if err := s.bartItemManager.InsertBARTItem(ctx, hash, inBody.Data, inBody.Type); err != nil {
		if !errors.Is(err, state.ErrBARTItemExists) {
			return wire.SNACMessage{}, fmt.Errorf("failed to insert BART item: %w", err)
		}
	}

	s.logger.DebugContext(ctx, "successfully uploaded BART item", "hash", fmt.Sprintf("%x", hash))

	// the session item this upload completes, if any: an ICQ avatar item of
	// the uploaded type, otherwise the buddy icon
	var bartID wire.BARTID
	var hasItem bool
	if wire.IsRelayedAvatarBARTType(inBody.Type) {
		bartID, hasItem = instance.Session().AvatarItem(inBody.Type)
	} else {
		bartID, hasItem = instance.Session().BuddyIcon()
	}
	if hasItem && bytes.Equal(hash, bartID.Hash) {
		// unset unknown flag
		bartID.Flags &^= wire.BARTFlagsUnknown
		setSessionBARTItem(instance.Session(), bartID)

		sendUserInfoUpdateToAll(ctx, s.messageRelayer, instance)

		if err := s.buddyUpdateBroadcaster.BroadcastBuddyArrived(ctx, instance.IdentScreenName(), instance.Session().TLVUserInfo()); err != nil {
			return wire.SNACMessage{}, err
		}
	} else {
		bartID = wire.BARTID{
			Type: inBody.Type,
			BARTInfo: wire.BARTInfo{
				Flags: wire.BARTFlagsCustom,
				Hash:  hash,
			},
		}
	}

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.BART,
			SubGroup:  wire.BARTUploadReply,
			RequestID: inFrame.RequestID,
		},
		Body: wire.SNAC_0x10_0x03_BARTUploadReply{
			Code: wire.BARTReplyCodesSuccess,
			ID:   bartID,
		},
	}, nil
}

// RetrieveItem fetches a BART item from the data store. The item is selected
// based on inBody.Hash. It's unclear what effect inBody.Flags is supposed to
// have on the request.
func (s BARTService) RetrieveItem(ctx context.Context, inFrame wire.SNACFrame, inBody wire.SNAC_0x10_0x04_BARTDownloadQuery) (wire.SNACMessage, error) {
	var item []byte
	if inBody.HasClearIconHash() {
		item = blankGIF
	} else {
		var err error
		if item, err = s.bartItemManager.BARTItem(ctx, inBody.Hash); err != nil {
			return wire.SNACMessage{}, err
		}
	}

	// This reply has no result code: an item that doesn't exist comes back
	// with no data.
	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.BART,
			SubGroup:  wire.BARTDownloadReply,
			RequestID: inFrame.RequestID,
		},
		Body: wire.SNAC_0x10_0x05_BARTDownloadReply{
			ScreenName: inBody.ScreenName,
			BARTID:     inBody.BARTID,
			Data:       item,
		},
	}, nil
}

// RetrieveItemV2 implements the SNAC handler for SNAC(0x10,0x06) BARTDownload2Query.
func (s BARTService) RetrieveItemV2(ctx context.Context, inFrame wire.SNACFrame, inBody wire.SNAC_0x10_0x06_BARTDownload2Query) ([]wire.SNACMessage, error) {
	var result []wire.SNACMessage

	for _, id := range inBody.IDs {
		var item []byte

		if id.Type == wire.BARTTypesBuddyIcon && id.HasClearIconHash() {
			item = blankGIF
		} else {
			var err error
			if item, err = s.bartItemManager.BARTItem(ctx, id.Hash); err != nil {
				return nil, err
			}
		}

		code := wire.BARTReplyCodesSuccess
		if len(item) == 0 {
			code = wire.BARTReplyCodesNotfound
		}

		result = append(result, wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.BART,
				SubGroup:  wire.BARTDownload2Reply,
				RequestID: inFrame.RequestID,
			},
			Body: wire.SNAC_0x10_0x07_BARTDownload2Reply{
				ScreenName: inBody.ScreenName,
				ReplyID: wire.BartQueryReplyID{
					QueryID: id,
					Code:    code,
					ReplyID: wire.BARTID{
						Type:     id.Type,
						BARTInfo: id.BARTInfo,
					},
				},
				Data: item,
			},
		})
	}

	return result, nil
}
