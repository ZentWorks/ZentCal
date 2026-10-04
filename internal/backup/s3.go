package backup

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

type S3Config struct {
	Endpoint, Region, Bucket, AccessKey, SecretKey, Prefix string
	TLSVerify                                              bool
}

func (c S3Config) objectURL(key string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(c.Endpoint, "/"))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("Ungültiger S3 Endpoint.")
	}
	clean := strings.TrimLeft(path.Join(c.Prefix, key), "/")
	u.Path = strings.TrimRight(u.Path, "/") + "/" + c.Bucket
	if clean != "" {
		u.Path += "/" + clean
	}
	return u, nil
}
func sha256HexBytes(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func hmacSHA(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(data))
	return h.Sum(nil)
}
func (c S3Config) client() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: !c.TLSVerify}
	return &http.Client{Timeout: 5 * time.Minute, Transport: tr}
}
func (c S3Config) request(ctx context.Context, method, key string, body io.Reader, payloadHash string) (*http.Request, error) {
	u, err := c.objectURL(key)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	amz := now.Format("20060102T150405Z")
	date := now.Format("20060102")
	req.Header.Set("x-amz-date", amz)
	req.Header.Set("x-amz-content-sha256", payloadHash)
	canonicalURI := u.EscapedPath()
	canonicalHeaders := "host:" + u.Host + "\n" + "x-amz-content-sha256:" + payloadHash + "\n" + "x-amz-date:" + amz + "\n"
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"
	canonical := method + "\n" + canonicalURI + "\n\n" + canonicalHeaders + "\n" + signedHeaders + "\n" + payloadHash
	scope := date + "/" + c.Region + "/s3/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + amz + "\n" + scope + "\n" + sha256HexBytes([]byte(canonical))
	kDate := hmacSHA([]byte("AWS4"+c.SecretKey), date)
	kRegion := hmacSHA(kDate, c.Region)
	kService := hmacSHA(kRegion, "s3")
	kSign := hmacSHA(kService, "aws4_request")
	sig := hex.EncodeToString(hmacSHA(kSign, toSign))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+c.AccessKey+"/"+scope+", SignedHeaders="+signedHeaders+", Signature="+sig)
	return req, nil
}
func fileHash(name string) (string, int64, error) {
	f, err := os.Open(name)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
func (c S3Config) Put(ctx context.Context, key, file string) error {
	hash, size, err := fileHash(file)
	if err != nil {
		return err
	}
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	req, err := c.request(ctx, http.MethodPut, key, f, hash)
	if err != nil {
		return err
	}
	req.ContentLength = size
	resp, err := c.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("S3 Upload antwortete mit HTTP %d", resp.StatusCode)
	}
	return nil
}
func (c S3Config) Get(ctx context.Context, key, file string) error {
	empty := sha256HexBytes(nil)
	req, err := c.request(ctx, http.MethodGet, key, nil, empty)
	if err != nil {
		return err
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("S3 Download antwortete mit HTTP %d", resp.StatusCode)
	}
	out, err := os.OpenFile(file, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	return err
}
func (c S3Config) Delete(ctx context.Context, key string) error {
	empty := sha256HexBytes(nil)
	req, err := c.request(ctx, http.MethodDelete, key, nil, empty)
	if err != nil {
		return err
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 204 && resp.StatusCode != 200 && resp.StatusCode != 404 {
		return fmt.Errorf("S3 Delete antwortete mit HTTP %d", resp.StatusCode)
	}
	return nil
}
func (c S3Config) Test(ctx context.Context) error {
	key := ".zentcal-connection-test"
	tmp, err := os.CreateTemp("", "zentcal-s3-test-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, _ = tmp.WriteString("zentcal")
	_ = tmp.Close()
	defer os.Remove(name)
	if err = c.Put(ctx, key, name); err != nil {
		return err
	}
	return c.Delete(ctx, key)
}
