package socketguard

import (
	"context"
	"fmt"
	"io"
	"testing"

	"github.com/benburkert/socketguard-go/internal/must"
)

var (
	cliPriv, cliPub = must.GenerateKeyPair()
	srvPriv, srvPub = must.GenerateKeyPair()
)

func TestGoConn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cliConf, srvConf := mustConfigPair()
	cliConf.PreferGo, srvConf.PreferGo = true, true

	ln, err := Listen(ctx, "tcp", ":0", srvConf)
	if err != nil {
		t.Fatal(err)
	}

	errc := make(chan error, 2)
	go func() {
		conn, err := Dial(ctx, "tcp", ln.Addr().String(), cliConf)
		if err != nil {
			errc <- fmt.Errorf("client: %w", err)
			return
		}

		if _, err := conn.Write([]byte("ping!")); err != nil {
			errc <- fmt.Errorf("client: %w", err)
			return
		}

		buf := make([]byte, 5)
		if _, err := io.ReadFull(conn, buf); err != nil {
			errc <- fmt.Errorf("client: %w", err)
			return
		}

		if want, got := "pong!", string(buf); want != got {
			errc <- fmt.Errorf("client: want response %q, got %q", want, got)
			return
		}

		errc <- nil
	}()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errc <- fmt.Errorf("server: %w", err)
			return
		}

		buf := make([]byte, 5)
		if _, err := io.ReadFull(conn, buf); err != nil {
			errc <- fmt.Errorf("server: %w", err)
			return
		}

		if want, got := "ping!", string(buf); want != got {
			errc <- fmt.Errorf("server: want request %q, got %q", want, got)
			return
		}

		if _, err := conn.Write([]byte("pong!")); err != nil {
			errc <- fmt.Errorf("server: %w", err)
			return
		}

		errc <- nil
	}()

	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

func mustConfigPair() (cli, srv *Config) {
	srv, cli = new(Config), new(Config)
	srv.StaticPrivate, srv.StaticPublic = must.GenerateKeyPair()
	cli.StaticPrivate, cli.StaticPublic = must.GenerateKeyPair()
	cli.PeerPublic = srv.StaticPublic
	return
}
