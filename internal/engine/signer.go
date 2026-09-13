package engine

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/gob"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/signer"
	"github.com/rs/xid"
)

// localIdentifier 自签名证书 CommonName，用于在验证器链中标识本地签名器。
const localIdentifier = "gobas-local"

// LocalSigner 本地 code 模板签名器：
// 程序化生成自签名密钥对（无交互），注册到 nuclei DefaultTemplateVerifiers，
// 使未官方签名的 code 模板经本地重签后通过验证。
type LocalSigner struct {
	signer   *signer.TemplateSigner // nuclei 验证器（用于注册到 DefaultTemplateVerifiers）
	ecdsaKey *ecdsa.PrivateKey       // 原始私钥（签名用）
	fragment string                  // md5(pubkey x-coord)，签名末尾标识
}

var (
	initOnce sync.Once
	instance *LocalSigner
	initErr  error
)

// Init 初始化本地签名器（幂等）：
// 读取 workspace/.gobas-keys/ 下的密钥对，不存在则生成并持久化，
// 随后注册到 nuclei DefaultTemplateVerifiers 验证器链。
func Init(workspace string) error {
	initOnce.Do(func() {
		keysDir := filepath.Join(workspace, ".gobas-keys")
		instance, initErr = loadOrCreate(keysDir)
		if initErr != nil {
			return
		}
		// 注册验证器：nuclei Verify 遍历 DefaultTemplateVerifiers，
		// 官方证书验证失败后会尝试本地验证器。
		_ = signer.AddSignerToDefault(instance.signer)
		// 同步初始化 SignatureStats：nuclei init() 仅预初始化了官方验证器的 key，
		// 后注册的本地验证器需手动加入，否则 loader 加载已验证模板时
		// SignatureStats[identifier] 返回 nil，.Add(1) 空指针 panic。
		id := instance.signer.Identifier()
		if templates.SignatureStats[id] == nil {
			templates.SignatureStats[id] = &atomic.Uint64{}
		}
	})
	return initErr
}

// Instance 返回已初始化的本地签名器（未 Init 则返回 nil）。
func Instance() *LocalSigner { return instance }

func loadOrCreate(keysDir string) (*LocalSigner, error) {
	certPath := filepath.Join(keysDir, "nuclei-user.crt")
	keyPath := filepath.Join(keysDir, "nuclei-user-private-key.pem")

	certPEM, keyPEM, err := readKeys(certPath, keyPath)
	if err != nil {
		// 密钥不存在或损坏：重新生成
		certPEM, keyPEM, privKey, genErr := generateKeyPair()
		if genErr != nil {
			return nil, fmt.Errorf("generate local signer keypair: %w", genErr)
		}
		if mkErr := os.MkdirAll(keysDir, 0o700); mkErr != nil {
			return nil, fmt.Errorf("create keys dir: %w", mkErr)
		}
		if wErr := os.WriteFile(certPath, certPEM, 0o600); wErr != nil {
			return nil, fmt.Errorf("write cert: %w", wErr)
		}
		if wErr := os.WriteFile(keyPath, keyPEM, 0o600); wErr != nil {
			return nil, fmt.Errorf("write private key: %w", wErr)
		}
		return newLocalSigner(certPEM, keyPEM, privKey)
	}

	// 从 PEM 解析私钥
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("decode private key PEM block failed")
	}
	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ECDSA private key: %w", err)
	}
	return newLocalSigner(certPEM, keyPEM, privKey)
}

func newLocalSigner(certPEM, keyPEM []byte, privKey *ecdsa.PrivateKey) (*LocalSigner, error) {
	// 创建 nuclei 验证器（用于注册到 DefaultTemplateVerifiers）
	s, err := signer.NewTemplateSigner(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("create template signer: %w", err)
	}
	fragment := s.GetUserFragment()
	return &LocalSigner{
		signer:   s,
		ecdsaKey: privKey,
		fragment: fragment,
	}, nil
}

func readKeys(certPath, keyPath string) (cert, key []byte, err error) {
	cert, err = os.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	key, err = os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// generateKeyPair 程序化生成自签名 ECDSA P-256 密钥对（不加密私钥）。
func generateKeyPair() (certPEM, keyPEM []byte, privKey *ecdsa.PrivateKey, err error) {
	privKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	serial := big.NewInt(xid.New().Time().Unix())
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: localIdentifier},
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		PublicKey:             &privKey.PublicKey,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  false,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "PD NUCLEI USER CERTIFICATE", Bytes: derBytes})

	keyData, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PD NUCLEI USER PRIVATE KEY", Bytes: keyData})

	return certPEM, keyPEM, privKey, nil
}

// SignTemplate 对模板内容签名，返回追加签名后的完整模板字节。
// 签名前去除旧签名（社区贡献者签名），避免 nuclei Sign 的 re-signing 限制。
// 用于让未验证的 code 模板通过本地签名器验证。
func (ls *LocalSigner) SignTemplate(data []byte) ([]byte, error) {
	_, content := signer.ExtractSignatureAndContent(data)
	signature, err := ls.signContent(content)
	if err != nil {
		return nil, err
	}
	result := make([]byte, 0, len(content)+len(signature)+2)
	result = append(result, content...)
	result = append(result, '\n')
	result = append(result, signature...)
	return result, nil
}

// signContent 直接对内容签名，复现 nuclei TemplateSigner.sign 的内部逻辑：
// normalizeContent(\r\n→\n) → sha256 → ecdsa.SignASN1 → gob encode → "# digest: %x:%fragment"
func (ls *LocalSigner) signContent(content []byte) (string, error) {
	normalized := bytes.ReplaceAll(content, []byte("\r\n"), []byte("\n"))
	dataHash := sha256.Sum256(normalized)

	ecdsaSig, err := ecdsa.SignASN1(rand.Reader, ls.ecdsaKey, dataHash[:])
	if err != nil {
		return "", err
	}

	var sigBuf bytes.Buffer
	if err := gob.NewEncoder(&sigBuf).Encode(ecdsaSig); err != nil {
		return "", err
	}

	return fmt.Sprintf("# digest: %x:%s", sigBuf.Bytes(), ls.fragment), nil
}

// SignFile 对指定路径的模板文件原地重签（覆盖写入）。
// 已有本地签名的模板跳过（幂等）。
func (ls *LocalSigner) SignFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read template: %w", err)
	}
	// 已有本地签名则跳过
	if ls.hasLocalSignature(data) {
		return nil
	}
	signed, err := ls.SignTemplate(data)
	if err != nil {
		return fmt.Errorf("sign template %s: %w", path, err)
	}
	return os.WriteFile(path, signed, 0o644)
}

// hasLocalSignature 检查模板是否已含本地签名器 fragment。
func (ls *LocalSigner) hasLocalSignature(data []byte) bool {
	return strings.Contains(string(data), ":"+ls.fragment)
}

// Fragment 返回本地签名器的 fragment 标识。
func (ls *LocalSigner) Fragment() string { return ls.fragment }

// simpleSignable 实现 signer.SignableTemplate 接口，用于无文件导入的模板验证。
type simpleSignable struct{}

func (s simpleSignable) GetFileImports() []string { return nil }
func (s simpleSignable) HasCodeProtocol() bool     { return false }

// Verify 用本地签名器验证模板数据（无文件导入场景）。
func (ls *LocalSigner) Verify(data []byte) bool {
	ok, _ := ls.signer.Verify(data, simpleSignable{})
	return ok
}
