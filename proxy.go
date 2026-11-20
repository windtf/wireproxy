package wireproxy

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
)

const copyBufferSize = 32 * 1024

// copyBufferPool holds the buffers used by proxyCopy, so that each connection
// does not allocate a new buffer per direction.
var copyBufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, copyBufferSize)
		return &b
	},
}

// closeWriter is implemented by connections that can shut down only their
// write side (*net.TCPConn, *tls.Conn, gonet.TCPConn).
type closeWriter interface {
	CloseWrite() error
}

// readerOnly and writerOnly hide the WriterTo and ReaderFrom methods of the
// wrapped value so that io.CopyBuffer always uses the supplied buffer.
type readerOnly struct{ io.Reader }
type writerOnly struct{ io.Writer }

func copyPooled(dst io.Writer, src io.Reader) (int64, error) {
	bp := copyBufferPool.Get().(*[]byte)
	defer copyBufferPool.Put(bp)
	return io.CopyBuffer(writerOnly{dst}, readerOnly{src}, *bp)
}

// copyHalf copies src to dst. When src reaches EOF it shuts down the write side
// of dst so the other end sees EOF while the reverse direction keeps going.
// If that is not possible, or the copy failed, both connections are closed.
func copyHalf(dst, src io.ReadWriteCloser) {
	_, err := copyPooled(dst, src)
	if err != nil && !errors.Is(err, net.ErrClosed) {
		errorLogger.Printf("Cannot forward traffic: %s\n", err.Error())
	}
	if err == nil {
		if cw, ok := dst.(closeWriter); ok && cw.CloseWrite() == nil {
			return
		}
	}
	_ = dst.Close()
	_ = src.Close()
}

// proxyCopy copies data in both directions between a and b, honouring
// half-close, and closes both once both directions are finished (or one fails).
// It blocks until then.
func proxyCopy(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		copyHalf(a, b)
	}()
	go func() {
		defer wg.Done()
		copyHalf(b, a)
	}()
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}

// readerConn reads from r instead of the embedded connection, for a connection
// that was partly consumed through a buffer. Writes and closes go to the
// connection.
type readerConn struct {
	net.Conn
	r io.Reader
}

func (c readerConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c readerConn) CloseWrite() error {
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return errors.ErrUnsupported
}

// stdioConn presents a stdin/stdout pair as a single connection.
type stdioConn struct {
	in  *os.File
	out *os.File
}

func (c stdioConn) Read(p []byte) (int, error)  { return c.in.Read(p) }
func (c stdioConn) Write(p []byte) (int, error) { return c.out.Write(p) }
func (c stdioConn) Close() error                { return errors.Join(c.in.Close(), c.out.Close()) }
