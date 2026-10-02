package e2e

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Cosignatures over the key log's checkpoints (c2sp.org/tlog-cosignature,
// Ed25519): what an auditor signs once it has checked that the log only grew
// and that every entry keeps the directory's rules (docs/e2e/KEY-TRANSPARENCY.md,
// stage 2).
//
// The signed message is "cosignature/v1\ntime <T>\n" and the checkpoint body;
// the signature line is "— <name> base64(key ID || T as u64 BE || signature)"
// with the key ID the first four bytes of SHA-256(name || "\n" || 0x04 ||
// public key). A cosigner's verifier key is "<name>+<key ID hex>+base64(0x04
// || public key)".

const cosigType = 0x04

// Cosigner is an auditor's public key.
type Cosigner struct {
	Name string
	ID   uint32
	Key  ed25519.PublicKey
}

func cosigKeyID(name string, pub ed25519.PublicKey) uint32 {
	h := sha256.Sum256(append(append([]byte(name+"\n"), cosigType), pub...))
	return binary.BigEndian.Uint32(h[:4])
}

// CosignerKey is the verifier key of an auditor's public key.
func CosignerKey(name string, pub ed25519.PublicKey) string {
	return fmt.Sprintf("%s+%08x+%s", name, cosigKeyID(name, pub),
		base64.StdEncoding.EncodeToString(append([]byte{cosigType}, pub...)))
}

// ParseCosigner reads an auditor's verifier key and checks its key ID.
func ParseCosigner(vkey string) (Cosigner, error) {
	parts := strings.SplitN(strings.TrimSpace(vkey), "+", 3)
	if len(parts) != 3 || parts[0] == "" {
		return Cosigner{}, errors.New("auditor key is not name+id+key")
	}
	id, err := strconv.ParseUint(parts[1], 16, 32)
	if err != nil || len(parts[1]) != 8 {
		return Cosigner{}, errors.New("auditor key id is not 8 hex digits")
	}
	raw, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(raw) != 1+ed25519.PublicKeySize || raw[0] != cosigType {
		return Cosigner{}, errors.New("auditor key is not an Ed25519 cosignature key")
	}
	c := Cosigner{Name: parts[0], ID: uint32(id), Key: ed25519.PublicKey(raw[1:])}
	if cosigKeyID(c.Name, c.Key) != c.ID {
		return Cosigner{}, errors.New("auditor key id does not match the key")
	}
	return c, nil
}

func cosigMessage(body string, t uint64) []byte {
	return []byte(fmt.Sprintf("cosignature/v1\ntime %d\n%s", t, body))
}

// Cosign signs a checkpoint body (with its final newline, without signature
// lines) at time t and returns the signature line, without a newline.
func Cosign(name string, priv ed25519.PrivateKey, body string, t uint64) string {
	pub := priv.Public().(ed25519.PublicKey)
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, cosigKeyID(name, pub))
	_ = binary.Write(&b, binary.BigEndian, t)
	b.Write(ed25519.Sign(priv, cosigMessage(body, t)))
	return "— " + name + " " + base64.StdEncoding.EncodeToString(b.Bytes())
}

// VerifyCosignature checks a signature line over a checkpoint body and
// returns its time.
func (c Cosigner) VerifyCosignature(body, line string) (uint64, error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(line), "— ")
	if !ok {
		return 0, errors.New("not a signature line")
	}
	name, sig, ok := strings.Cut(rest, " ")
	if !ok || name != c.Name {
		return 0, errors.New("signature line names another auditor")
	}
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil || len(raw) != 4+8+ed25519.SignatureSize {
		return 0, errors.New("signature line is not a cosignature")
	}
	if binary.BigEndian.Uint32(raw) != c.ID {
		return 0, errors.New("cosignature is by another key")
	}
	t := binary.BigEndian.Uint64(raw[4:])
	if !ed25519.Verify(c.Key, cosigMessage(body, t), raw[12:]) {
		return 0, errors.New("cosignature does not verify")
	}
	return t, nil
}

// checkpointBody is the text of a checkpoint of the log named origin.
func checkpointBody(origin string, size int64, root []byte) string {
	return fmt.Sprintf("%s\n%d\n%s\n", origin, size, base64.StdEncoding.EncodeToString(root))
}

// parseCheckpointBody reads origin, size and root out of a checkpoint body.
func parseCheckpointBody(body string) (string, int64, []byte, error) {
	lines := strings.Split(body, "\n")
	if len(lines) < 4 || lines[len(lines)-1] != "" {
		return "", 0, nil, errors.New("checkpoint body is not origin, size, root")
	}
	size, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil || size < 0 {
		return "", 0, nil, errors.New("checkpoint size is not a number")
	}
	root, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || len(root) != sha256.Size {
		return "", 0, nil, errors.New("checkpoint root is not a hash")
	}
	return lines[0], size, root, nil
}
