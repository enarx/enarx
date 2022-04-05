package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
)

func handle(conn net.Conn) error {
	defer conn.Close()

	var b [128]byte
	n, err := conn.Read(b[:])
	if err != nil {
		if err == io.EOF {
			return nil
		}
		return fmt.Errorf("failed to read from connection: %s", err)
	}
	log.Printf("Read '%s'\n", b[:n])

	res := fmt.Sprintf("Hello, %s", b[:n])
	n, err = conn.Write([]byte(res))
	if err != nil {
		return fmt.Errorf("failed to write to connection: %s", err)
	}
	log.Printf("Wrote '%s'\n", res[:n])
	return nil
}

func run() error {
	fds, err := strconv.Atoi(os.Getenv("FD_COUNT"))
	if err != nil {
		return fmt.Errorf("failed to parse FD_COUNT: %w", err)
	}
	if fds < 4 {
		return fmt.Errorf("FD_COUNT must be at least 4, got %d", fds)
	}

	ln, err := net.FileListener(os.NewFile(uintptr(3), "socket"))
	if err != nil {
		return fmt.Errorf("failed to listen on fd 3: %w", err)
	}

	for {
		log.Println("Waiting for connection...")
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %s", err)
            continue
		}
		log.Println("Accepted connection")

		if err := handle(conn); err != nil {
			log.Printf("Failed to handle connection: %s", err)
            continue
		}
		log.Println("---")
	}
}

func init() {
	log.SetOutput(os.Stderr)
	log.SetFlags(0)
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("Failed to run: %s", err)
	}
}
