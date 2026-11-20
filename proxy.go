package wireproxy

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
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

// proxyIdleTimeout bounds how long a half-closed proxyCopy, or a plain-HTTP
// response relay, waits for more data from the other side.
var proxyIdleTimeout = 2 * time.Minute

// activityReader calls onRead after every read that returned data.
type activityReader struct {
	io.Reader
	onRead func()
}

func (r activityReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if n > 0 {
		r.onRead()
	}
	return n, err
}

// idleConn calls reset after every read or write that moved data.
type idleConn struct {
	net.Conn
	reset func()
}

func (c idleConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.reset()
	}
	return n, err
}

func (c idleConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.reset()
	}
	return n, err
}

type proxyState struct {
	a, b io.ReadWriteCloser
	idle *time.Timer
	d    time.Duration
	// closing is set before we close the connections ourselves, so errors that
	// our own Close causes in the other direction are not logged.
	closing    atomic.Bool
	halfClosed atomic.Bool
}

func (s *proxyState) closeBoth() {
	s.closing.Store(true)
	_ = s.a.Close()
	_ = s.b.Close()
}

// copyHalf copies src to dst. When src reaches EOF it shuts down the write side
// of dst so the other end sees EOF while the reverse direction keeps going,
// bounded by the idle timeout. If that is not possible, or the copy failed,
// both connections are closed.
func (s *proxyState) copyHalf(dst, src io.ReadWriteCloser) {
	_, err := copyPooled(dst, activityReader{src, func() {
		if s.halfClosed.Load() {
			s.idle.Reset(s.d)
		}
	}})
	if err != nil && !s.closing.Load() && !errors.Is(err, net.ErrClosed) {
		errorLogger.Printf("Cannot forward traffic: %s\n", err.Error())
	}
	if err == nil {
		if cw, ok := dst.(closeWriter); ok && cw.CloseWrite() == nil {
			s.halfClosed.Store(true)
			s.idle.Reset(s.d)
			return
		}
	}
	s.closeBoth()
}

// proxyCopy copies data in both directions between a and b, honouring
// half-close, and closes both once both directions are finished (or one fails,
// or the remaining direction is idle for proxyIdleTimeout after the other
// finished). It blocks until then.
func proxyCopy(a, b io.ReadWriteCloser) {
	s := &proxyState{a: a, b: b, d: proxyIdleTimeout}
	s.idle = time.AfterFunc(s.d, s.closeBoth)
	s.idle.Stop()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		s.copyHalf(a, b)
	}()
	go func() {
		defer wg.Done()
		s.copyHalf(b, a)
	}()
	wg.Wait()
	s.idle.Stop()
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
