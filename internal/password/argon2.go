package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/bengobox/auth-service/internal/config"
	"golang.org/x/crypto/argon2"
)

// ErrInvalidHash indicates the stored hash cannot be parsed.
var ErrInvalidHash = errors.New("invalid password hash")

// Hasher wraps Argon2id hashing with configurable parameters.
type Hasher struct {
	cfg config.SecurityConfig
}

// NewHasher constructs a Hasher.
func NewHasher(cfg config.SecurityConfig) *Hasher {
	return &Hasher{cfg: cfg}
}

// Hash creates a new Argon2id hash for the supplied plain text password.
func (h *Hasher) Hash(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		h.cfg.Argon2Time,
		h.cfg.Argon2Memory,
		h.cfg.Argon2Threads,
		h.cfg.Argon2KeyLength,
	)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	formatted := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		h.cfg.Argon2Memory,
		h.cfg.Argon2Time,
		h.cfg.Argon2Threads,
		b64Salt,
		b64Hash,
	)
	return formatted, nil
}

// Compare verifies that the specified password matches the stored hash.
func (h *Hasher) Compare(hash string, password string) error {
	params, salt, expected, err := parseHash(hash)
	if err != nil {
		return err
	}

	calculated := argon2.IDKey(
		[]byte(password),
		salt,
		params.time,
		params.memory,
		params.threads,
		uint32(len(expected)),
	)

	calculatedB64 := base64.RawStdEncoding.EncodeToString(calculated)
	expectedB64 := base64.RawStdEncoding.EncodeToString(expected)
	if subtle.ConstantTimeCompare([]byte(calculatedB64), []byte(expectedB64)) == 1 {
		return nil
	}
	return errors.New("password mismatch")
}

type argon2Params struct {
	memory  uint32
	time    uint32
	threads uint8
}

func parseHash(hash string) (*argon2Params, []byte, []byte, error) {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		return nil, nil, nil, ErrInvalidHash
	}

	var memory uint32
	var time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return nil, nil, nil, ErrInvalidHash
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, ErrInvalidHash
	}
	hashBytes, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, ErrInvalidHash
	}

	return &argon2Params{
		memory:  memory,
		time:    time,
		threads: threads,
	}, salt, hashBytes, nil
}
