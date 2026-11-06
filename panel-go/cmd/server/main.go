// Paylater Monitor — единая панель мониторинга (Go-порт).
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"paylater-mon/internal/config"
	"paylater-mon/internal/web"
)

func main() {
	configPath := flag.String("config", "config.yaml", "путь к YAML-конфигурации")
	flag.Parse()

	store, err := config.NewStore(*configPath)
	if err != nil {
		log.Fatalf("ошибка загрузки конфигурации: %v", err)
	}

	app := web.NewApp(store)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	app.Start(ctx)

	// Ожидание сигнала остановки.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("остановка панели...")
	app.Stop()
}
