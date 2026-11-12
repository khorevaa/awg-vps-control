//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
)

// safeDirectoryPath проверяет владельцев и права всех предков без символических ссылок.
func safeDirectoryPath(path string) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return fmt.Errorf("unsafe directory path")
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect directory ancestor: %w", err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
			return fmt.Errorf("unsafe directory ancestor ownership")
		}
		rootSticky := stat.Uid == 0 && info.Mode()&os.ModeSticky != 0
		if info.Mode().Perm()&0o022 != 0 && !rootSticky {
			return fmt.Errorf("unsafe writable directory ancestor")
		}
		if current == filepath.Dir(current) {
			break
		}
	}
	return nil
}

// ownedDirectory проверяет собственный каталог без символических ссылок.
func ownedDirectory(path string) error {
	if err := safeDirectoryPath(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect directory: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm() != 0o700 || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("unsafe directory ownership or permissions")
	}
	return nil
}

// closeFile закрывает файл и безопасно сообщает об ошибке без содержимого файла.
func closeFile(file *os.File) {
	if err := file.Close(); err != nil {
		slog.Error("не удалось закрыть файл")
	}
}

// secureRead читает ограниченный обычный файл без следования ссылкам.
func secureRead(path string, maximum int64, secret bool) ([]byte, error) {
	directory := filepath.Dir(path)
	if err := safeDirectoryPath(directory); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open protected file: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer closeFile(file)
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect protected file: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	ownerOK := ok && stat.Uid == uint32(os.Geteuid())
	if secret {
		ownerOK = ownerOK || (ok && stat.Uid == 0)
	}
	modeOK := info.Mode().Perm() == 0o600 || (secret && info.Mode().Perm() == 0o400)
	if !info.Mode().IsRegular() || !ownerOK || !modeOK || stat.Nlink != 1 || info.Size() > maximum {
		return nil, fmt.Errorf("unsafe protected file")
	}
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, fmt.Errorf("read protected file: %w", err)
	}
	if int64(len(content)) > maximum {
		return nil, fmt.Errorf("protected file exceeds limit")
	}
	return content, nil
}

// atomicWrite заменяет защищённый state-файл с синхронизацией файла и каталога.
func atomicWrite(path string, content []byte) error {
	directory := filepath.Dir(path)
	if err := ownedDirectory(directory); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		if _, err = secureRead(path, 2*1024*1024, false); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect state: %w", err)
	}
	file, err := os.CreateTemp(directory, ".state_*")
	if err != nil {
		return fmt.Errorf("create state candidate: %w", err)
	}
	name := file.Name()
	defer func() {
		if err := os.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			slog.Error("не удалось убрать временный state")
		}
	}()
	if err = file.Chmod(0o600); err == nil {
		_, err = file.Write(content)
	}
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		return fmt.Errorf("persist state candidate: %w", err)
	}
	if err = os.Rename(name, path); err != nil {
		return fmt.Errorf("replace state: %w", err)
	}
	dir, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open state directory: %w", err)
	}
	return errors.Join(dir.Sync(), dir.Close())
}
