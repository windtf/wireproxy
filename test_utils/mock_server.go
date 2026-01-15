package main
import (
    "fmt"
    "net"
)
func main() {
    l, err := net.Listen("tcp", "127.0.0.1:8080")
    if err != nil {
        panic(err)
    }
    fmt.Println("Mock server listening on 8080")
    for {
        conn, err := l.Accept()
        if err != nil {
            continue
        }
        go func(c net.Conn) {
            defer c.Close()
            buf := make([]byte, 1024)
            n, _ := c.Read(buf)
            fmt.Printf("Received: %s\n", string(buf[:n]))
            c.Write([]byte("PONG"))
        }(conn)
    }
}
