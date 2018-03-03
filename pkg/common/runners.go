package common

import (
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
)

// Params type defines the parameters required by the runners
type Params struct {
	Conn       net.Conn
	Proxy      string
	ExecuteCmd string
}

// Router routes a connection based on provided parameters
func (c *Params) Router() {

	if c.Proxy != "" {
		c.proxyConn()
	} else if c.ExecuteCmd != "" {
		c.executeCmd()
	} else {
		c.handleIO(os.Stdout, os.Stdin)
	}
}

func (c *Params) proxyConn() {
	pConn, err := net.Dial("tcp", c.Proxy)
	if err != nil {
		l.Fatalf("Can't connect to remote host: %s", err)
	}
	w, r := pConn, pConn
	c.handleIO(w, r)
}

func (c *Params) executeCmd() {
	defer func() {
		c.Conn.Close()
	}()
	cmdParse := strings.Split(c.ExecuteCmd, " ")
	cmdName := cmdParse[0]
	var cmdArgs []string
	if len(cmdParse[1:]) > 0 {
		cmdArgs = cmdParse[1:]
	}
	cmd := exec.Command(cmdName, cmdArgs...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = c.Conn, c.Conn, c.Conn
	if err := cmd.Run(); err != nil {
		l.Fatalf("Can't execute command: %s", err)
	}
}

func (c *Params) handleIO(w io.WriteCloser, r io.ReadCloser) {
	channel := make(chan Progress)

	copyIO := func(writer io.WriteCloser, reader io.ReadCloser, dir string) {
		defer func() {
			reader.Close()
			writer.Close()
		}()
		numBytes, _ := io.Copy(writer, reader)
		channel <- Progress{Bytes: numBytes, Dir: dir}
	}

	go copyIO(c.Conn, r, "SNT")
	go copyIO(w, c.Conn, "RCV")

	for i := 0; i < 2; i++ {
		s := <-channel
		l.Verb("%s: %d", s.Dir, s.Bytes)
	}
}
