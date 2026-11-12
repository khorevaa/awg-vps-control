//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// verifyDirectoryPath проверяет всю цепочку каталогов без перехода по symlink.
func verifyDirectoryPath(path string, create bool, mode os.FileMode) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("ненормализованный путь каталога")
	}
	current := "/"
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) && create {
			if err = os.Mkdir(current, mode); err != nil {
				return err
			}
			info, err = os.Lstat(current)
		}
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("путь содержит небезопасный каталог")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
			return errors.New("недопустимый владелец каталога")
		}
		stickyRoot := stat.Uid == 0 && info.Mode()&os.ModeSticky != 0 && current != path
		if info.Mode().Perm()&0022 != 0 && !stickyRoot {
			return errors.New("каталог доступен посторонним для записи")
		}
		if current == path && create && (stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm() != mode) {
			return errors.New("неверные права или владелец рабочего каталога")
		}
	}
	return nil
}

// openPrivateFile открывает файл без следования symlink и проверяет его владельца.
func openPrivateFile(path string, flags int) (*os.File, error) {
	fd, err := syscall.Open(path, flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm() != 0600 || stat.Nlink != 1 {
		_ = file.Close()
		return nil, errors.New("небезопасный файл состояния")
	}
	return file, nil
}

// readPrivateFile ограниченно читает обычный приватный файл.
func readPrivateFile(path string, limit int64) ([]byte, error) {
	file, err := openPrivateFile(path, syscall.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(content)) > limit {
		return nil, errors.New("невозможно безопасно прочитать состояние")
	}
	return content, nil
}

// atomicPrivateFile сохраняет файл через fsync и замену в доверенном каталоге.
func atomicPrivateFile(path string, content []byte) error {
	directory := filepath.Dir(path)
	if err := verifyDirectoryPath(directory, true, 0700); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		file, openErr := openPrivateFile(path, syscall.O_RDONLY)
		if openErr != nil {
			return openErr
		}
		_ = file.Close()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".control_state_*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	defer temporary.Close()
	if err := temporary.Chmod(0600); err != nil {
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// peerUID получает UID ядра, а не переданный пользователем идентификатор.
func peerUID(connection *net.UnixConn) (uint32, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, err
	}
	var credentials *syscall.Ucred
	var socketErr error
	err = raw.Control(func(fd uintptr) {
		credentials, socketErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil {
		return 0, err
	}
	if socketErr != nil || credentials == nil {
		return 0, errors.New("не удалось проверить учётные данные Unix-сокета")
	}
	return credentials.Uid, nil
}

// listenControl создаёт socket только в доверенном каталоге и не заменяет живой процесс.
func listenControl(config Config) (*net.UnixListener, error) {
	if err := verifyDirectoryPath(filepath.Dir(config.SocketPath), true, 0750); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(config.SocketPath); err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || info.Mode()&os.ModeSocket == 0 || stat.Uid != uint32(os.Geteuid()) {
			return nil, errors.New("на месте socket найден посторонний объект")
		}
		connection, dialErr := net.DialTimeout("unix", config.SocketPath, 200*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			return nil, errors.New("Control socket уже обслуживается")
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("невозможно проверить прежний socket: %w", dialErr)
		}
		if err := os.Remove(config.SocketPath); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: config.SocketPath, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chown(config.SocketPath, os.Geteuid(), config.WebGID); err != nil {
		_ = listener.Close()
		return nil, err
	}
	if err := os.Chmod(config.SocketPath, 0660); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}
