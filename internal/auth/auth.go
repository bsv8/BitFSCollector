package auth

import (
	"crypto/sha256"
	"crypto/subtle"

	collector "github.com/bsv8/BitFSCollectorProtocol/collector"
)

// Verifier 校验 v2 拉取 Bearer（支持双 Token 轮换，只比哈希）。
// Verifier checks the v2 pull bearer with rotation support.
type Verifier struct {
	hashes [][32]byte
}

// New 构造校验器（空 token 自动忽略）。
// New builds a verifier from configured tokens.
func New(tokens []string) *Verifier {
	v := &Verifier{}
	for _, t := range tokens {
		if t == "" {
			continue
		}
		v.hashes = append(v.hashes, sha256.Sum256([]byte(t)))
	}
	return v
}

// Valid 报告 Authorization 头是否携带有效 Token。
// Valid reports whether the header carries a configured token.
func (v *Verifier) Valid(header string) bool {
	token, err := collector.ParseBearer(header)
	if err != nil {
		return false
	}
	sum := sha256.Sum256([]byte(token))
	for _, h := range v.hashes {
		if subtle.ConstantTimeCompare(sum[:], h[:]) == 1 {
			return true
		}
	}
	return false
}

// Configured 报告是否配置了至少一个 Token。
// Configured reports whether any token is configured.
func (v *Verifier) Configured() bool { return len(v.hashes) > 0 }
