package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/SmidraClawd/cvebridge/internal/bridge"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			fmt.Println(version)
			return
		case "render":
			if e := render(os.Args[2:]); e != nil {
				log.Fatal(e)
			}
			return
		default:
			log.Fatal("usage: cvebridge [render|version]")
		}
	}
	c, e := bridge.ConfigFromEnv()
	if e != nil {
		log.Fatal(e)
	}
	svc, e := bridge.NewServices(c)
	if e != nil {
		log.Fatal(e)
	}
	store, e := bridge.OpenStore(c.Get("STATE_FILE", "/data/requests.sqlite3"))
	if e != nil {
		log.Fatal("state database unavailable")
	}
	defer store.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	app := bridge.NewApp(ctx, svc, store)
	done := make(chan struct{})
	go func() { app.Loop(); close(done) }()
	server := &http.Server{Addr: c.Get("LISTEN_ADDR", ":8001"), Handler: app, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	log.Printf("CVEBridge %s: Mattermost listener %s", version, server.Addr)
	if e = server.ListenAndServe(); e != nil && e != http.ErrServerClosed {
		log.Fatal("HTTP listener failed")
	}
	<-done
	<-shutdownDone
	app.Wait()
}
func render(args []string) error {
	f := flag.NewFlagSet("render", flag.ContinueOnError)
	env := f.String("env-file", ".env", "configuration file")
	part := f.String("part", "deployment", "deployment or bootstrap")
	image := f.String("image", "", "deployment image supplied by the build helper")
	if e := f.Parse(args); e != nil {
		return e
	}
	file, e := os.Open(*env)
	if e != nil {
		return e
	}
	defer file.Close()
	values, e := bridge.ReadEnv(file)
	if e != nil {
		return e
	}
	if *image != "" {
		values["APP_IMAGE"] = *image
	}
	return bridge.Render(os.Stdout, values, *part)
}
