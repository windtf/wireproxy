package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage:")
		fmt.Println("  Server: go run wireworm_chat.go server <port>")
		fmt.Println("  Client: go run wireworm_chat.go client <addr:port>")
		return
	}

	mode := os.Args[1]
	target := os.Args[2]

	var conn net.Conn
	var err error

	if mode == "server" {
		fmt.Printf("Chat Server listening on 127.0.0.1:%s...\n", target)
		ln, err := net.Listen("tcp", "127.0.0.1:"+target)
		if err != nil {
			log.Fatal(err)
		}
		conn, err = ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Peer connected! Start typing (Ctrl+C to quit).")
	} else {
		fmt.Printf("Connecting to Chat Server at %s...\n", target)
		conn, err = net.Dial("tcp", target)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Connected to peer! Start typing (Ctrl+C to quit).")
	}

	defer conn.Close()

	// 2-way communication
	go func() {
		_, _ = io.Copy(os.Stdout, conn)
		fmt.Println("\nPeer disconnected.")
		os.Exit(0)
	}()

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		text := scanner.Text()
		if strings.TrimSpace(text) == "" {
			continue
		}
		_, err := fmt.Fprintln(conn, "Peer: "+text)
		if err != nil {
			break
		}
	}
}
