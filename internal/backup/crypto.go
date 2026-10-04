package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"os"

	"crypto/sha256"
	"golang.org/x/crypto/pbkdf2"
)

var backupMagic = []byte("ZCBK001\n")

func encryptFile(src, dst, password string) error {
	if len(password) < 10 {
		return errors.New("Backup-Verschlüsselungspasswort muss mindestens 10 Zeichen lang sein.")
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = out.Close()
		if !ok {
			_ = os.Remove(dst)
		}
	}()
	salt := make([]byte, 16)
	if _, err = io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}
	key := pbkdf2.Key([]byte(password), salt, 250000, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	if _, err = out.Write(backupMagic); err != nil {
		return err
	}
	if _, err = out.Write(salt); err != nil {
		return err
	}
	buf := make([]byte, 1<<20)
	for {
		n, rerr := in.Read(buf)
		if n > 0 {
			nonce := make([]byte, gcm.NonceSize())
			if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
				return err
			}
			sealed := gcm.Seal(nil, nonce, buf[:n], nil)
			var lenbuf [4]byte
			binary.BigEndian.PutUint32(lenbuf[:], uint32(len(sealed)))
			if _, err = out.Write(lenbuf[:]); err != nil {
				return err
			}
			if _, err = out.Write(nonce); err != nil {
				return err
			}
			if _, err = out.Write(sealed); err != nil {
				return err
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	var end [4]byte
	if _, err = out.Write(end[:]); err != nil {
		return err
	}
	if err = out.Sync(); err != nil {
		return err
	}
	ok = true
	return nil
}

func decryptFile(src, dst, password string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	magic := make([]byte, len(backupMagic))
	if _, err = io.ReadFull(in, magic); err != nil {
		return err
	}
	if string(magic) != string(backupMagic) {
		return errors.New("Unbekanntes Backup-Format.")
	}
	salt := make([]byte, 16)
	if _, err = io.ReadFull(in, salt); err != nil {
		return err
	}
	key := pbkdf2.Key([]byte(password), salt, 250000, 32, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = out.Close()
		if !ok {
			_ = os.Remove(dst)
		}
	}()
	for {
		var lenbuf [4]byte
		if _, err = io.ReadFull(in, lenbuf[:]); err != nil {
			return err
		}
		n := binary.BigEndian.Uint32(lenbuf[:])
		if n == 0 {
			break
		}
		if n > (1<<20)+uint32(gcm.Overhead()) {
			return errors.New("Backup-Chunk ist ungültig.")
		}
		nonce := make([]byte, gcm.NonceSize())
		if _, err = io.ReadFull(in, nonce); err != nil {
			return err
		}
		sealed := make([]byte, n)
		if _, err = io.ReadFull(in, sealed); err != nil {
			return err
		}
		plain, err := gcm.Open(nil, nonce, sealed, nil)
		if err != nil {
			return errors.New("Backup-Passwort ist falsch oder das Backup ist beschädigt.")
		}
		if _, err = out.Write(plain); err != nil {
			return err
		}
	}
	if err = out.Sync(); err != nil {
		return err
	}
	ok = true
	return nil
}
