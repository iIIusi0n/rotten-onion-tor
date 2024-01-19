package utils

import (
	"bytes"
	"net"
	"net/url"
)

func DownloadStringFromURL(addr string) (string, error) {
	parsed, err := url.Parse(addr)
	if err != nil {
		return "", err
	}

	host := parsed.Hostname()
	port := parsed.Port()

	conn, err := net.Dial("tcp", host+":"+port)
	if err != nil {
		return "", err
	}

	_, err = conn.Write([]byte("GET " + parsed.Path + " HTTP/1.0\r\nHost: " + host + "\r\n\r\n"))
	if err != nil {
		return "", err
	}

	body := make([]byte, 0)
	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}

		body = append(body, buf[:n]...)
	}

	body = body[bytes.Index(body, []byte("\r\n\r\n"))+4:]

	return string(body), nil
}
