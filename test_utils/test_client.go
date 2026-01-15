package main
import (
    "fmt"
    "net"
    "time"
)
func main() {
    var conn net.Conn
    var err error
    for i := 0; i < 15; i++ {
        conn, err = net.Dial("tcp", "127.0.0.1:25565")
        if err == nil {
            break
        }
        fmt.Printf("Retrying connection... (%d/15)\n", i+1)
        time.Sleep(1 * time.Second)
    }
    
    if err != nil {
        fmt.Printf("Connection failed: %v\n", err)
        return
    }
    defer conn.Close()
    conn.Write([]byte("PING"))
    buf := make([]byte, 1024)
    n, err := conn.Read(buf)
    if err != nil {
        fmt.Printf("Read failed: %v\n", err)
        return
    }
    fmt.Printf("Response: %s\n", string(buf[:n]))
}
