package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"

	"github.com/BradLugo/dialogue"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/alecthomas/kong"
)

var cli struct {
	Lock struct {
		Path string `arg:"" required:"" help:"Path to file or directory to lock"`
	} `cmd:"" help:"Encrypt journal or journal entry"`

	Unlock struct {
		Path string `arg:"" required:"" help:"Path to file or directory to unlock"`
	} `cmd:"" help:"Decrypt journal or journal entry"`
}

func main() {
	logger, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}
	defer logger.Sync()

	ctx := kong.Parse(&cli,
		kong.Description("Journaling CLI"),
		kong.UsageOnError(),
	)
	switch ctx.Command() {
	case "lock <path>":
		passwd, err := getPassword()
		if err != nil {
			logger.Error("error while getting password", zap.Error(err))
		}

		if err := lock(cli.Lock.Path, passwd, false, logger); err != nil {
			logger.Error("error while encrypting", zap.Error(err))
		}
	case "unlock <path>":
		passwd, err := getPassword()
		if err != nil {
			logger.Error("error while getting password", zap.Error(err))
		}

		if err := unlock(cli.Unlock.Path, passwd, logger); err != nil {
			logger.Error("error while decrypting", zap.Error(err))
		}
	default:
		panic(ctx.Command())
	}
}

func lock(src string, passwd []byte, compress bool, logger *zap.Logger) error {
	var pt []byte
	if fi, err := os.Stat(src); err != nil {
		return err
	} else if fi.IsDir() {
		b := &bytes.Buffer{}
		if err := archive(src, compress, logger, b); err != nil {
			return err
		}

		pt = b.Bytes()
	} else {
		pt, err = ioutil.ReadFile(src)
		if err != nil {
			return err
		}
	}

	ct, err := dialogue.Encrypt(pt, passwd, rand.Reader)
	if err != nil {
		return err
	}

	f, err := os.Create(src)
	if err != nil {
		return err
	}

	_, err = io.Copy(f, bytes.NewReader(ct))
	if err != nil {
		return err
	}

	return nil
}

func unlock(src string, passwd []byte, logger *zap.Logger) error {
	if _, err := os.Stat(src); os.IsNotExist(err) {
		return err
	}

	ct, err := ioutil.ReadFile(src)
	if err != nil {
		return err
	}

	pt, err := dialogue.Decrypt(ct, passwd)
	if err != nil {
		return err
	}

	pt, err = tryExtract(pt, strings.Replace(src, ".locked", ".unlocked", 1), logger)
	if err != nil {
		return err
	}

	// Files are created in `tryExtract`
	if pt == nil {
		return nil
	}

	f, err := os.Create(strings.Replace(src, ".locked", ".unlocked", 1))
	if err != nil {
		return err
	}

	_, err = io.Copy(f, bytes.NewReader(pt))
	if err != nil {
		return err
	}

	return nil
}

func getPassword() ([]byte, error) {
	fmt.Print("Enter password:")
	passwd, err := terminal.ReadPassword(syscall.Stdin)
	if err != nil {
		return nil, err
	}

	fmt.Println()
	fmt.Print("Retype password:")
	cp, err := terminal.ReadPassword(syscall.Stdin)
	if err != nil {
		return nil, err
	}
	fmt.Println()

	if !reflect.DeepEqual(passwd, cp) {
		return nil, errors.New("passwords do not match")
	}

	return bytes.TrimSpace(passwd), nil
}

func archive(src string, compress bool, logger *zap.Logger, writers ...io.Writer) error {
	if _, err := os.Stat(src); err != nil {
		return err
	}

	mw := io.MultiWriter(writers...)

	var tw *tar.Writer
	if compress {
		gzw := gzip.NewWriter(mw)
		defer func() {
			if err := gzw.Close(); err != nil {
				logger.Error("error while closing gzip writer", zap.Error(err))
			}
		}()
		tw = tar.NewWriter(gzw)
	} else {
		tw = tar.NewWriter(mw)
	}

	defer func() {
		if err := tw.Close(); err != nil {
			logger.Error("error while closing tar writer", zap.Error(err))
		}
	}()

	return filepath.Walk(src, func(file string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		header, err := tar.FileInfoHeader(fi, fi.Name())
		if err != nil {
			return err
		}

		header.Name = strings.TrimPrefix(strings.Replace(file, src, "", 1), string(filepath.Separator))

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		if !fi.IsDir() {
			f, err := os.Open(file)
			if err != nil {
				return err
			}

			if _, err := io.Copy(tw, f); err != nil {
				return err
			}

			if err := f.Close(); err != nil {
				return err
			}
		}

		return nil
	})
}

func tryExtract(pt []byte, dst string, logger *zap.Logger) ([]byte, error) {
	br := bytes.NewReader(pt)
	var tr *tar.Reader
	if pt[0] == 31 && pt[1] == 139 {
		gzr, err := gzip.NewReader(br)
		if err != nil {
			return nil, err
		}

		defer func() {
			if err := gzr.Close(); err != nil {
				logger.Error("error while closing gzip reader", zap.Error(err))
			}
		}()

		tr = tar.NewReader(gzr)
	} else {
		ttr := tar.NewReader(br)
		_, err := ttr.Next()
		if err == nil {
			// Determined this was not an archived file
			return pt, nil
		}

		tr = tar.NewReader(br)
	}

	if err := extract(tr, dst); err != nil {
		return nil, err
	}

	return nil, nil
}

func extract(tr *tar.Reader, dst string) error {
	if _, err := os.Stat(dst); os.IsNotExist(err) {
		if err := os.MkdirAll(dst, 0755); err != nil {
			return err
		}
	} else {
		return err
	}

	for {
		h, err := tr.Next()

		switch {
		case err == io.EOF:
			return nil

		case err != nil:
			return err

		case h == nil:
			continue
		}

		target := filepath.Join(dst, h.Name)

		switch h.Typeflag {
		case tar.TypeDir:
			if _, err := os.Stat(target); err != nil {
				if err := os.MkdirAll(target, 0755); err != nil {
					return err
				}
			}

		case tar.TypeReg:
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(h.Mode))
			if err != nil {
				return err
			}

			if _, err := io.Copy(f, tr); err != nil {
				return err
			}

			if err := f.Close(); err != nil {
				return err
			}
		}
	}
}
