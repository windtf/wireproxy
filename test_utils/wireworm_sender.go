package main

import (
"fmt"
"net/http"
"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run sender_server.go <file_to_send>")
		return
	}
	fileName := os.Args[1]
	
	http.HandleFunc("/download", func(w http.ResponseWriter, r *http.Request) {
fmt.Printf("Receiver connected! Sending %s...\n", fileName)
http.ServeFile(w, r, fileName)
})

	fmt.Println("File server internal listening on 127.0.0.1:8080")
	fmt.Println("Endpoint: http://10.0.0.1:9000/download (via WireGuard)")
	http.ListenAndServe("127.0.0.1:8080", nil)
}
