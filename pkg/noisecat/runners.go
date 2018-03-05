package noisecat

import (
	"io"
	"log"
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
	Log        Verbose
}

// Router routes a connection based on provided parameters
func (c *Params) Router() {
	defer c.Conn.Close()

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
		c.Log.Fatalf("Can't connect to remote host: %s", err)
	}
	c.handleIO(pConn, pConn)
}

func (c *Params) executeCmd() {
	cmdParse := strings.Split(c.ExecuteCmd, " ")
	cmdName := cmdParse[0]
	var cmdArgs []string
	if len(cmdParse[1:]) > 0 {
		cmdArgs = cmdParse[1:]
	}
	cmd := exec.Command(cmdName, cmdArgs...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = c.Conn, c.Conn, c.Conn
	cmd.Run()
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
		log.Printf("%s: %d", s.Dir, s.Bytes)
	}
}
