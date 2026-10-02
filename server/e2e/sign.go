// Package e2e is the server side of the end-to-end encryption add-on for ICQ
// 6.5 and 7.2: a directory of public keys and a relay for device linking,
// served over HTTP under /e2e/v1/. The API is specified in
// docs/e2e/KEY-DIRECTORY-API.md.
//
// The server is an untrusted but available directory. It stores and hands out
// public keys and relays opaque blobs; it never sees a private key or a
// plaintext message. What stops it from slipping in a key of its own is that
// every key is signed and clients check the signatures themselves:
//
//   - each account (screen name; the UIN for ICQ) has one account key,
//     Ed25519, shared by all of its devices;
//   - each device's Olm keys (Curve25519 identity key and Ed25519 signing
//     key, as vodozemac makes them) are signed by the account key;
//   - each device's fallback and one-time Curve25519 keys are signed by the
//     device's Ed25519 key.
//
// The server checks the same signatures on the way in, so a buggy client
// cannot store material that no real device vouched for.
//
// # Signed messages
//
// A signature is plain Ed25519 (RFC 8032, 64 bytes) over a message built by
// one of the functions in this file. A message is the 12 ASCII bytes
// "OSCAR-E2E-v1" followed by its fields, each written as a 16-bit big-endian
// length and then the field's bytes. The first field names the purpose, the
// second is the account's screen name in its ident form (lower case, no
// spaces; the UIN in decimal for ICQ). Device ids are 4 bytes big-endian,
// keys the 32 raw public key bytes, key ids their ASCII string.
package e2e

import (
	"crypto/ed25519"
	"encoding/binary"

	"github.com/mk6i/open-oscar-server/state"
)

// signatureContext starts every signed message, so no signature made for this
// protocol is valid anywhere else, and the other way round.
const signatureContext = "OSCAR-E2E-v1"

// AccountMessage is what an account key signs about itself when it is
// published, rotated to or reset to: proof that the publisher holds its
// private key.
//
//	"account" | screen name | account key
func AccountMessage(screenName state.IdentScreenName, accountKey []byte) []byte {
	return signedMessage("account", screenName, accountKey)
}

// RotateMessage is what the current account key signs to hand over to a new
// one.
//
//	"rotate" | screen name | old account key | new account key
func RotateMessage(screenName state.IdentScreenName, oldKey, newKey []byte) []byte {
	return signedMessage("rotate", screenName, oldKey, newKey)
}

// DeviceMessage is what the account key signs to vouch for a device.
//
//	"device" | screen name | device id | Curve25519 key | Ed25519 key
func DeviceMessage(screenName state.IdentScreenName, deviceID uint32, curve25519Key, ed25519Key []byte) []byte {
	return signedMessage("device", screenName, deviceIDBytes(deviceID), curve25519Key, ed25519Key)
}

// OneTimeKeyMessage is what a device's Ed25519 key signs for each of its
// one-time keys.
//
//	"one-time-key" | screen name | device id | key id | Curve25519 key
func OneTimeKeyMessage(screenName state.IdentScreenName, deviceID uint32, keyID string, key []byte) []byte {
	return signedMessage("one-time-key", screenName, deviceIDBytes(deviceID), []byte(keyID), key)
}

// FallbackKeyMessage is what a device's Ed25519 key signs for its fallback
// key.
//
//	"fallback-key" | screen name | device id | key id | Curve25519 key
func FallbackKeyMessage(screenName state.IdentScreenName, deviceID uint32, keyID string, key []byte) []byte {
	return signedMessage("fallback-key", screenName, deviceIDBytes(deviceID), []byte(keyID), key)
}

// RevokeMessage is what the account key signs to revoke one of its devices,
// with the time the request was made (Unix seconds): the server takes it
// only within revokeWindow of its own clock, and only once.
//
//	"revoke" | screen name | device id | issued at (8 bytes big endian)
func RevokeMessage(screenName state.IdentScreenName, deviceID uint32, issuedAt int64) []byte {
	return signedMessage("revoke", screenName, deviceIDBytes(deviceID), binary.BigEndian.AppendUint64(nil, uint64(issuedAt)))
}

// verify reports whether sig is publicKey's signature over msg. A key or
// signature of the wrong size does not verify.
func verify(publicKey, msg, sig []byte) bool {
	return len(publicKey) == ed25519.PublicKeySize &&
		len(sig) == ed25519.SignatureSize &&
		ed25519.Verify(publicKey, msg, sig)
}

func signedMessage(purpose string, screenName state.IdentScreenName, fields ...[]byte) []byte {
	msg := []byte(signatureContext)
	msg = appendField(msg, []byte(purpose))
	msg = appendField(msg, []byte(screenName.String()))
	for _, f := range fields {
		msg = appendField(msg, f)
	}
	return msg
}

func appendField(msg, field []byte) []byte {
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(field)))
	return append(msg, field...)
}

func deviceIDBytes(deviceID uint32) []byte {
	return binary.BigEndian.AppendUint32(nil, deviceID)
}
