//go:build linux

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

var version = "dev"

// healthcheck проверяет готовность Control и host bridge без проб AWG или WARP.
func healthcheck(socketPath string) error {
	connection, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return err
	}
	request := Request{RequestID: "healthcheck", Action: "health", Payload: json.RawMessage(`{}`)}
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return err
	}
	line, err := readLine(connection)
	if err != nil {
		return err
	}
	var response Response
	if decodeStrict(line, &response) != nil || !response.OK || response.RequestID != request.RequestID {
		return fmt.Errorf("Control не подтвердил готовность сервиса")
	}
	return nil
}

// run подготавливает защищённый журнал, listener и последовательный исполнитель.
func run() error {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "adapter":
			return runAdapter(os.Args[2:])
		case "warp":
			return runWarp(os.Args[2:])
		case "install-tools":
			return runInstallTools(os.Args[2:])
		case "manual":
			return runManual(os.Args[2:])
		}
	}
	config, err := loadConfig()
	if err != nil {
		return err
	}
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "healthcheck":
			return healthcheck(config.SocketPath)
		case "version":
			fmt.Println(version)
			return nil
		default:
			return fmt.Errorf("доступны команды healthcheck и version")
		}
	}
	store, err := openStore(config.StatePath)
	if err != nil {
		return err
	}
	defer store.Close()
	listener, err := listenControl(config)
	if err != nil {
		return err
	}
	service := newService(config, store, &HostClient{socketPath: config.HostSocket})
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	workerContext, cancelWorker := context.WithCancel(ctx)
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		service.RunWorker(workerContext)
	}()
	server := &Server{service: service, listener: listener, connections: make(chan struct{}, 32)}
	log.Printf("Control %s запущен", version)
	err = server.Run(ctx)
	cancelWorker()
	workers.Wait()
	return err
}

// main завершает процесс с ненулевым кодом при небезопасной конфигурации или ошибке запуска.
func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)
	if err := run(); err != nil {
		log.Printf("Control: %v", err)
		os.Exit(1)
	}
}
