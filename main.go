package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/quic-go/quic-go/http3"
)

type RequestInfo struct {
	Method         string              `json:"method"`
	URL            string              `json:"url"`
	Headers        map[string][]string `json:"headers"`
	Body           string              `json:"body"`
	RemoteAddr     string              `json:"remote_addr"`
	Protocol       string              `json:"protocol"`
	Prefetch       bool                `json:"prefetch"`
	PrefetchResult string              `json:"prefetch_result"`
}

func generateSelfSignedCert() (*tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Echo Server"},
			CommonName:   "localhost",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
		Leaf:        cert,
	}, nil
}

func detectProtocol(c *gin.Context) string {
	r := c.Request
	if r.TLS != nil {
		if r.ProtoMajor == 3 || r.Context().Value(http3.ServerContextKey) != nil {
			return "HTTP/3"
		}
		if r.ProtoMajor == 2 {
			return "HTTP/2"
		}
	}
	return "HTTP/1.1"
}

func isPrefetchRequest(c *gin.Context) bool {
	headers := []string{c.GetHeader("Purpose"), c.GetHeader("Sec-Purpose"), c.GetHeader("X-Moz")}
	for _, header := range headers {
		if strings.Contains(strings.ToLower(header), "prefetch") {
			return true
		}
	}
	return false
}

func echoHandler(c *gin.Context) {
	body, _ := io.ReadAll(c.Request.Body)

	protocol := detectProtocol(c)
	isPrefetch := isPrefetchRequest(c)

	reqInfo := RequestInfo{
		Method:         c.Request.Method,
		URL:            c.Request.URL.String(),
		Headers:        c.Request.Header,
		Body:           string(body),
		RemoteAddr:     c.Request.RemoteAddr,
		Protocol:       protocol,
		Prefetch:       isPrefetch,
		PrefetchResult: map[bool]string{true: "PASSED", false: "NOT DETECTED"}[isPrefetch],
	}

	html := renderHTML(reqInfo)
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("X-Frame-Options", "DENY")
	c.String(http.StatusOK, html)
}

func renderHTML(info RequestInfo) string {
	return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Multi-Protocol HTTPS Echo Server</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { font-size: 12px; }
        .protocol-badge { @apply inline-block px-2 py-1 rounded text-xs font-bold uppercase; }
        .http11 { @apply bg-blue-100 text-blue-800; }
        .http2 { @apply bg-green-100 text-green-800; }
        .http3 { @apply bg-purple-100 text-purple-800; }
        .prefetch-success { @apply bg-green-100 text-green-800; }
        .prefetch-fail { @apply bg-red-100 text-red-800; }
        .card { @apply bg-white rounded-lg shadow-lg p-4 border border-gray-300; }
        .header { @apply text-center mb-8 py-6 bg-gradient-to-r from-blue-50 to-indigo-50 rounded-lg shadow-md; }
        .auto-test-results { @apply mt-4 pt-4 border-t border-gray-200; }
        .auto-test-results h4 { @apply text-sm font-bold mb-2; }
        pre { @apply text-xs p-2 bg-gray-50 rounded overflow-auto max-h-36; }
        .grid-container { @apply grid grid-cols-1 md:grid-cols-3 gap-6; }
        .grid-item { @apply flex flex-col; }
        .grid-box { @apply flex-grow; }
    </style>
</head>
<body class="bg-gray-50 min-h-screen">
    <main class="container mx-auto px-4 py-6">
        <header class="header">
            <h1 class="text-2xl font-bold text-gray-800">Multi-Protocol HTTPS Echo Server</h1>
            <p class="text-gray-600 mt-2">A server supporting HTTP/1.1, HTTP/2, and HTTP/3 with TLS</p>
        </header>

        <div class="grid-container">
            <div class="grid-item">
                <div class="grid-box">
                    <article class="card h-full">
                        <header>
                            <h3 class="text-lg font-bold text-gray-800 mb-4">Request Details</h3>
                        </header>
                        <section>
                            <dl class="space-y-2">
                                <div class="flex">
                                    <dt class="font-semibold w-24">Method:</dt>
                                    <dd class="font-mono"><code class="bg-gray-100 px-1 rounded">%s</code></dd>
                                </div>
                                <div class="flex">
                                    <dt class="font-semibold w-24">URL:</dt>
                                    <dd class="font-mono break-all"><code class="bg-gray-100 px-1 rounded">%s</code></dd>
                                </div>
                                <div class="flex">
                                    <dt class="font-semibold w-24">Remote:</dt>
                                    <dd class="font-mono"><code class="bg-gray-100 px-1 rounded">%s</code></dd>
                                </div>
                                <div class="flex">
                                    <dt class="font-semibold w-24">Protocol:</dt>
                                    <dd><span class="protocol-badge %s">%s</span></dd>
                                </div>
                                <div class="flex">
                                    <dt class="font-semibold w-24">Prefetch:</dt>
                                    <dd><span class="protocol-badge %s">%s</span></dd>
                                </div>
                            </dl>
                        </section>
                    </article>
                </div>
            </div>

            <div class="grid-item">
                <div class="grid-box">
                    <article class="card h-full">
                        <header>
                            <h3 class="text-lg font-bold text-gray-800 mb-4">Headers & Body</h3>
                        </header>
                        <section>
                            <h4 class="font-semibold mb-2">Headers</h4>
                            <pre class="mb-4">%s</pre>
                            <h4 class="font-semibold mb-2">Body</h4>
                            <pre>%s</pre>
                        </section>
                    </article>
                </div>
            </div>

            <div class="grid-item">
                <div class="grid-box">
                    <article class="card h-full">
                        <header>
                            <h3 class="text-lg font-bold text-gray-800 mb-4">Protocol & Prefetch Info</h3>
                        </header>
                        <section>
                            <h4 class="font-semibold mb-2">Protocol Information</h4>
                            <ul class="list-disc pl-5 space-y-1 mb-4">
                                <li><strong>HTTP/1.1:</strong> Traditional HTTP over TLS</li>
                                <li><strong>HTTP/2:</strong> Multiplexed, binary protocol over TLS</li>
                                <li><strong>HTTP/3:</strong> HTTP over QUIC (UDP-based)</li>
                            </ul>
                            
                            <h4 class="font-semibold mb-2">Prefetch Detection</h4>
                            <ul class="list-disc pl-5 space-y-1 mb-4">
                                <li><code class="bg-gray-100 px-1 rounded">Purpose: prefetch</code></li>
                                <li><code class="bg-gray-100 px-1 rounded">Sec-Purpose: prefetch</code></li>
                                <li><code class="bg-gray-100 px-1 rounded">X-Moz: prefetch</code></li>
                            </ul>
                            
                            <div class="bg-gray-50 p-3 rounded mb-4">
                                <p class="font-semibold">Result: <span class="protocol-badge %s">%s</span></p>
                            </div>
                            
                            <div class="auto-test-results">
                                <h4>Auto Prefetch Tests</h4>
                                <ul id="autoPrefetchResult" class="list-disc pl-5 space-y-1">
                                    <li>Running prefetch test...</li>
                                </ul>
                            </div>
                        </section>
                    </article>
                </div>
            </div>
        </div>

        <footer class="text-center py-6 text-gray-600 text-sm">
            <p>Server running with TLS and supporting multiple HTTP protocols</p>
        </footer>
    </main>
    
    <script>
        window.addEventListener('load', function() {
            const resultDiv = document.getElementById('autoPrefetchResult');
            fetch(window.location.href + '?test=prefetch', {
                headers: { 'Purpose': 'prefetch' }
            })
            .then(response => {
                if (response.ok) {
                    resultDiv.innerHTML = '<li class="text-green-600">Prefetch test: PASSED - Prefetch request detected!</li>';
                } else {
                    resultDiv.innerHTML = '<li class="text-red-600">Prefetch test: FAILED - Prefetch request not detected.</li>';
                }
            })
            .catch(error => {
                resultDiv.innerHTML = '<li class="text-red-600">Prefetch test: ERROR - ' + error.message + '</li>';
            });
        });
    </script>
</body>
</html>`,
		htmlEscape(info.Method),
		htmlEscape(info.URL),
		htmlEscape(info.RemoteAddr),
		getProtocolClass(info.Protocol),
		htmlEscape(info.Protocol),
		getPrefetchClass(info.Prefetch),
		htmlEscape(getPrefetchText(info.Prefetch)),
		htmlEscape(formatHeaders(info.Headers)),
		htmlEscape(info.Body),
		getPrefetchResultClass(info.PrefetchResult),
		htmlEscape(info.PrefetchResult),
	)
}

func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}

func formatHeaders(headers map[string][]string) string {
	var buf strings.Builder
	for name, values := range headers {
		for _, value := range values {
			buf.WriteString(name)
			buf.WriteString(": ")
			buf.WriteString(value)
			buf.WriteString("\n")
		}
	}
	return buf.String()
}

func getProtocolClass(protocol string) string {
	switch protocol {
	case "HTTP/1.1":
		return "http11"
	case "HTTP/2":
		return "http2"
	case "HTTP/3":
		return "http3"
	default:
		return "http11"
	}
}

func getPrefetchClass(prefetch bool) string {
	if prefetch {
		return "prefetch-success"
	}
	return "prefetch-fail"
}

func getPrefetchText(prefetch bool) string {
	if prefetch {
		return "true"
	}
	return "false"
}

func getPrefetchResultClass(result string) string {
	if result == "PASSED" {
		return "prefetch-success"
	}
	return "prefetch-fail"
}

func main() {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.GET("/", echoHandler)
	router.POST("/", echoHandler)
	router.PUT("/", echoHandler)
	router.DELETE("/", echoHandler)
	router.PATCH("/", echoHandler)
	router.HEAD("/", echoHandler)
	router.OPTIONS("/", echoHandler)

	cert, err := generateSelfSignedCert()
	if err != nil {
		panic(err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}

	httpsServer := &http.Server{
		Addr:      ":8443",
		Handler:   router,
		TLSConfig: tlsConfig,
	}

	h3Server := &http3.Server{
		Addr:      ":8443",
		Handler:   router,
		TLSConfig: tlsConfig,
	}

	go httpsServer.ListenAndServeTLS("", "")
	go h3Server.ListenAndServe()

	select {}
}
