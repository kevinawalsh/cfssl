// Package serve implements the serve command for CFSSL's API.
package serve

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"text/tabwriter"
	"time"

	linuxproc "github.com/c9s/goprocinfo/linux"
	"github.com/davecheney/junk/clock"

	rice "github.com/GeertJohan/go.rice"
	"github.com/cloudflare/cfssl/api/bundle"
	"github.com/cloudflare/cfssl/api/certinfo"
	"github.com/cloudflare/cfssl/api/crl"
	"github.com/cloudflare/cfssl/api/generator"
	"github.com/cloudflare/cfssl/api/info"
	"github.com/cloudflare/cfssl/api/initca"
	apiocsp "github.com/cloudflare/cfssl/api/ocsp"
	"github.com/cloudflare/cfssl/api/revoke"
	"github.com/cloudflare/cfssl/api/scan"
	"github.com/cloudflare/cfssl/api/signhandler"
	"github.com/cloudflare/cfssl/bundler"
	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/cli"
	ocspsign "github.com/cloudflare/cfssl/cli/ocspsign"
	"github.com/cloudflare/cfssl/cli/sign"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/ocsp"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/ubiquity"
)

// Usage text of 'cfssl serve'
var serverUsageText = `cfssl serve -- set up a HTTP server handles CF SSL requests

Usage of serve:
        cfssl serve [-address address] [-ca cert] [-ca-bundle bundle] \
                    [-ca-key key] [-int-bundle bundle] [-int-dir dir] [-port port] \
                    [-metadata file] [-remote remote_host] [-config config] \
                    [-responder cert] [-responder-key key] [-tls-cert cert] [-tls-key key] \
                    [-client-auth] [-trust-anchors pemfile] \
                    [-db-config db-config] [-stats n]

Flags:
`

// Flags used by 'cfssl serve'
var serverFlags = []string{"address", "port", "ca", "ca-key", "ca-bundle", "int-bundle", "int-dir", "metadata",
	"remote", "config", "responder", "responder-key", "client-auth", "trust-anchors", "tls-key", "tls-cert", "db-config", "stats"}

var (
	conf       cli.Config
	s          signer.Signer
	ocspSigner ocsp.Signer
	db         *sql.DB
)

// V1APIPrefix is the prefix of all CFSSL V1 API Endpoints.
var V1APIPrefix = "/api/v1/cfssl/"

// v1APIPath prepends the V1 API prefix to endpoints not beginning with "/"
func v1APIPath(path string) string {
	if !strings.HasPrefix(path, "/") {
		path = V1APIPrefix + path
	}
	return (&url.URL{Path: path}).String()
}

// httpBox implements http.FileSystem which allows the use of Box with a http.FileServer.
// Atempting to Open an API endpoint will result in an error.
type httpBox struct {
	*rice.Box
	redirects map[string]string
}

func (hb *httpBox) findStaticBox() (err error) {
	hb.Box, err = rice.FindBox("static")
	return
}

// Open returns a File for non-API enpoints using the http.File interface.
func (hb *httpBox) Open(name string) (http.File, error) {
	if strings.HasPrefix(name, V1APIPrefix) {
		return nil, os.ErrNotExist
	}

	if location, ok := hb.redirects[name]; ok {
		return hb.Box.Open(location)
	}

	return hb.Box.Open(name)
}

// staticBox is the box containing all static assets.
var staticBox = &httpBox{
	redirects: map[string]string{
		"/scan":   "/index.html",
		"/bundle": "/index.html",
	},
}

var errBadSigner = errors.New("signer not initialized")
var errNoCertDBConfigured = errors.New("cert db not configured (missing -db-config)")

var endpoints = map[string]func() (http.Handler, error){
	"sign": func() (http.Handler, error) {
		if s == nil {
			return nil, errBadSigner
		}
		return signhandler.NewHandlerFromSigner(s)
	},

	"authsign": func() (http.Handler, error) {
		if s == nil {
			return nil, errBadSigner
		}
		return signhandler.NewAuthHandlerFromSigner(s)
	},

	"info": func() (http.Handler, error) {
		if s == nil {
			return nil, errBadSigner
		}
		return info.NewHandler(s)
	},

	"gencrl": func() (http.Handler, error) {
		if s == nil {
			return nil, errBadSigner
		}
		return crl.NewHandler(), nil
	},

	"newcert": func() (http.Handler, error) {
		if s == nil {
			return nil, errBadSigner
		}
		return generator.NewCertGeneratorHandlerFromSigner(generator.CSRValidate, s), nil
	},

	"bundle": func() (http.Handler, error) {
		return bundle.NewHandler(conf.CABundleFile, conf.IntBundleFile)
	},

	"newkey": func() (http.Handler, error) {
		return generator.NewHandler(generator.CSRValidate)
	},

	"init_ca": func() (http.Handler, error) {
		return initca.NewHandler(), nil
	},

	"scan": func() (http.Handler, error) {
		return scan.NewHandler(conf.CABundleFile)
	},

	"scaninfo": func() (http.Handler, error) {
		return scan.NewInfoHandler(), nil
	},

	"certinfo": func() (http.Handler, error) {
		return certinfo.NewHandler(), nil
	},

	"ocspsign": func() (http.Handler, error) {
		if ocspSigner == nil {
			return nil, errBadSigner
		}
		return apiocsp.NewHandler(ocspSigner), nil
	},

	"revoke": func() (http.Handler, error) {
		if db == nil {
			return nil, errNoCertDBConfigured
		}
		return revoke.NewHandler(db), nil
	},

	"/": func() (http.Handler, error) {
		if err := staticBox.findStaticBox(); err != nil {
			return nil, err
		}

		return http.FileServer(staticBox), nil
	},
}

type StatsResponse struct {
	StatusCode int
	r          http.ResponseWriter
}

func (w *StatsResponse) Header() http.Header {
	return w.r.Header()
}

func (w *StatsResponse) Write(data []byte) (int, error) {
	return w.r.Write(data)
}

func (w *StatsResponse) WriteHeader(code int) {
	w.StatusCode = code
	w.r.WriteHeader(code)
}

type Stats struct {
	nok, nerr, tok, terr uint64
}

func (s *Stats) AtomicCopy(t *Stats) {
	s.nok = atomic.LoadUint64(&t.nok)
	s.tok = atomic.LoadUint64(&t.tok)
	s.nerr = atomic.LoadUint64(&t.nerr)
	s.terr = atomic.LoadUint64(&t.terr)
}

func (s Stats) Sub(t Stats) Stats {
	var d Stats
	d.nok = s.nok - t.nok
	d.tok = s.tok - t.tok
	d.nerr = s.nerr - t.nerr
	d.terr = s.terr - t.terr
	return d
}

type StatsHandler struct {
	path    string
	handler http.Handler
	Stats
}

func NewStatsHandler(path string, handler http.Handler) *StatsHandler {
	return &StatsHandler{path: path, handler: handler}
}

func (s *StatsHandler) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	r := &StatsResponse{200, resp}
	start := clock.Monotonic.Now()
	s.handler.ServeHTTP(r, req)
	end := clock.Monotonic.Now()
	elapsed := end.Sub(start)
	if r.StatusCode == 200 {
		atomic.AddUint64(&s.nok, 1)
		atomic.AddUint64(&s.tok, (uint64)(elapsed.Nanoseconds()))
	} else {
		atomic.AddUint64(&s.nerr, 1)
		atomic.AddUint64(&s.terr, (uint64)(elapsed.Nanoseconds()))
	}
}

func showStats(handlers []*StatsHandler, delay string) {

	d, err := time.ParseDuration(delay)
	if err != nil {
		fmt.Printf("Unrecognized duration '%s', using '1s' instead\n", delay)
		d = 1 * time.Second
	}

	n := len(handlers)
	prev := make([]Stats, n)
	curr := make([]Stats, n)
	diff := make([]Stats, n)
	var w tabwriter.Writer
	w.Init(os.Stdout, 5, 0, 2, ' ', tabwriter.AlignRight)

	first := true
	start := clock.Monotonic.Now()
	for {
		time.Sleep(d)
		for i := 0; i < n; i++ {
			curr[i].AtomicCopy(&handlers[i].Stats)
		}
		end := clock.Monotonic.Now()
		elapsed := end.Sub(start)
		start = end

		if first {
			first = false
			fmt.Printf("Endpoints:\n")
			for i := 0; i < n; i++ {
				fmt.Printf(" [%d] %s\n", i, handlers[i].path)
			}
			fmt.Fprintf(&w, "\t")
			for i := 0; i < n; i++ {
				fmt.Fprintf(&w, "[%d]\t", i)
			}
			fmt.Fprintf(&w, "\n")
		}
		for i := 0; i < n; i++ {
			diff[i] = curr[i].Sub(prev[i])
		}
		fmt.Fprintf(&w, "ok\t")
		for i := 0; i < n; i++ {
			fmt.Fprintf(&w, "%d\t", diff[i].nok)
		}
		fmt.Fprintf(&w, "\n")
		fmt.Fprintf(&w, "\t")
		for i := 0; i < n; i++ {
			fmt.Fprintf(&w, "%0.2f/sec\t", (float64)(diff[i].nok)/elapsed.Seconds())
		}
		fmt.Fprintf(&w, "\n")
		fmt.Fprintf(&w, "\t")
		for i := 0; i < n; i++ {
			if diff[i].nok == 0 {
				fmt.Fprintf(&w, "%s\t", "-")
			} else {
				fmt.Fprintf(&w, "%s\t", time.Duration(diff[i].tok/diff[i].nok))
			}
		}
		fmt.Fprintf(&w, "\n")

		fmt.Fprintf(&w, "err\t")
		for i := 0; i < n; i++ {
			fmt.Fprintf(&w, "%d\t", diff[i].nerr)
		}
		fmt.Fprintf(&w, "\n")
		fmt.Fprintf(&w, "\t")
		for i := 0; i < n; i++ {
			fmt.Fprintf(&w, "%0.2f/sec\t", (float64)(diff[i].nerr)/elapsed.Seconds())
		}
		fmt.Fprintf(&w, "\n")
		fmt.Fprintf(&w, "\t")
		for i := 0; i < n; i++ {
			if diff[i].nerr == 0 {
				fmt.Fprintf(&w, "%s\t", "-")
			} else {
				fmt.Fprintf(&w, "%s\t", time.Duration(diff[i].terr/diff[i].nerr))
			}
		}
		fmt.Fprintf(&w, "\n")
		w.Flush()

		for i := 0; i < n; i++ {
			prev[i] = curr[i]
		}
	}
}

func cpustatsub(B *linuxproc.CPUStat, A linuxproc.CPUStat) {
	B.User -= A.User
	B.Nice -= A.Nice
	B.System -= A.System
	B.Idle -= A.Idle
	B.IOWait -= A.IOWait
	B.IRQ -= A.IRQ
	B.SoftIRQ -= A.SoftIRQ
	B.Steal -= A.Steal
	B.Guest -= A.Guest
	B.GuestNice -= A.GuestNice
}

func cpustatprint(w io.Writer, name string, B linuxproc.CPUStat) {
	ticks := B.User + B.Nice + B.System + B.Idle + B.IOWait + B.IRQ + B.SoftIRQ + B.Steal + B.Guest + B.GuestNice
	d := 100.0 / (float64)(ticks)
	fmt.Fprintf(w, "%s\t%d\t%0.2f %%\t%0.2f %%\t%0.2f %%\t%0.2f %%\t%0.2f %%\t%0.2f %%\t%0.2f %%\t%0.2f %%\t%0.2f %%\t%0.2f %%\t\n",
		name, ticks,
		(float64)(B.User)*d,
		(float64)(B.Nice)*d,
		(float64)(B.System)*d,
		(float64)(B.Idle)*d,
		(float64)(B.IOWait)*d,
		(float64)(B.IRQ)*d,
		(float64)(B.SoftIRQ)*d,
		(float64)(B.Steal)*d,
		(float64)(B.Guest)*d,
		(float64)(B.GuestNice)*d)
}

func showstat(B, A *linuxproc.Stat) {
	var D linuxproc.Stat
	D.CPUStatAll = B.CPUStatAll
	cpustatsub(&D.CPUStatAll, A.CPUStatAll)
	for i, _ := range B.CPUStats {
		D.CPUStats = append(D.CPUStats, B.CPUStats[i])
		cpustatsub(&D.CPUStats[i], A.CPUStats[i])
	}
	D.Interrupts = B.Interrupts - A.Interrupts
	D.ContextSwitches = B.ContextSwitches - A.ContextSwitches

	fmt.Printf("CPU Load:\n")
	var w tabwriter.Writer
	w.Init(os.Stdout, 5, 0, 2, ' ', tabwriter.AlignRight)
	fmt.Fprintf(&w, "cpu\tticks\tuser\tnice\tsys\tidle\tiowait\tirq\tsirq\tsteal\tguest\tnguest\t\n")
	cpustatprint(&w, "total", D.CPUStatAll)
	for _, s := range D.CPUStats {
		cpustatprint(&w, s.Id, s)
	}
	w.Flush()
	fmt.Printf("CPU Statistics:\n")
	fmt.Printf("  elapsed: %s\n", B.BootTime.Sub(A.BootTime))
	fmt.Printf("  processes: %d .. %d\n", A.Processes, B.Processes)
	fmt.Printf("  procs running: %d .. %d\n", A.ProcsRunning, B.ProcsRunning)
	fmt.Printf("  procs blocked: %d .. %d\n", A.ProcsBlocked, B.ProcsBlocked)
}

func showOneStats(handlers []*StatsHandler, delay string, path string) {

	d, err := time.ParseDuration(delay)
	if err != nil {
		fmt.Printf("Unrecognized duration '%s', using '1s' instead\n", delay)
		d = 1 * time.Second
	}

	var handler *StatsHandler
	for _, h := range handlers {
		if h.path == path {
			handler = h
			break
		}
	}
	if handler == nil {
		fmt.Printf("No such handler: %s\n", path)
		return
	}

	var prev, curr, diff Stats

	var w tabwriter.Writer
	w.Init(os.Stdout, 5, 0, 2, ' ', tabwriter.AlignRight)

	start := clock.Monotonic.Now()
	A, _ := linuxproc.ReadStat("/proc/stat")
	for {
		time.Sleep(d)
		curr.AtomicCopy(&handler.Stats)
		B, _ := linuxproc.ReadStat("/proc/stat")
		end := clock.Monotonic.Now()
		elapsed := end.Sub(start)
		start = end

		showstat(B, A)
		A = B

		diff = curr.Sub(prev)
		fmt.Printf("Load statistics for %s\n", path)
		fmt.Fprintf(&w, "\tops\tops/sec\tsec/op\terrs\t\n")
		fmt.Fprintf(&w, "\t")
		fmt.Fprintf(&w, "%d\t", diff.nok)
		fmt.Fprintf(&w, "%0.2f/sec\t", (float64)(diff.nok)/elapsed.Seconds())
		if diff.nok == 0 {
			fmt.Fprintf(&w, "%s\t", "-")
		} else {
			fmt.Fprintf(&w, "%s\t", time.Duration(diff.tok/diff.nok))
		}
		fmt.Fprintf(&w, "%d\t\n", diff.nerr)
		w.Flush()

		prev = curr
	}
}

// registerHandlers instantiates various handlers and associate them to corresponding endpoints.
func registerHandlers(statsdelay string) {
	var stats []*StatsHandler
	for path, getHandler := range endpoints {
		path = v1APIPath(path)
		log.Infof("Setting up '%s' endpoint", path)
		if handler, err := getHandler(); err != nil {
			log.Warningf("endpoint '%s' is disabled: %v", path, err)
		} else if statsdelay != "" {
			h := NewStatsHandler(path, handler)
			stats = append(stats, h)
			http.Handle(path, h)
		} else {
			http.Handle(path, handler)
		}
	}
	if statsdelay != "" {
		// go showStats(stats, statsdelay)
		go showOneStats(stats, statsdelay, "/api/v1/cfssl/authsign")
	}

	log.Info("Handler set up complete.")
}

// serverMain is the command line entry point to the API server. It sets up a
// new HTTP server to handle sign, bundle, and validate requests.
func serverMain(args []string, c cli.Config) error {
	conf = c
	// serve doesn't support arguments.
	if len(args) > 0 {
		return errors.New("argument is provided but not defined; please refer to the usage by flag -h")
	}

	bundler.IntermediateStash = conf.IntDir
	var err error

	if err = ubiquity.LoadPlatforms(conf.Metadata); err != nil {
		return err
	}

	if c.DBConfigFile != "" {
		db, err = certdb.DBFromConfig(c.DBConfigFile)
		if err != nil {
			return err
		}
	}

	log.Info("Initializing signer")

	if s, err = sign.SignerFromConfigAndDB(c, db); err != nil {
		log.Warningf("couldn't initialize signer: %v", err)
	}

	if ocspSigner, err = ocspsign.SignerFromConfig(c); err != nil {
		log.Warningf("couldn't initialize ocsp signer: %v", err)
	}

	registerHandlers(conf.Stats)

	addr := net.JoinHostPort(conf.Address, strconv.Itoa(conf.Port))

	if conf.TLSCertFile == "" || conf.TLSKeyFile == "" {
		log.Info("Now listening on ", addr)
		return http.ListenAndServe(addr, nil)
	}

	log.Info("Now listening on https://", addr)

	if !conf.RequireClientTLSCertificates {
		fmt.Printf("Client certificates are not required.\n")
		return http.ListenAndServeTLS(addr, conf.TLSCertFile, conf.TLSKeyFile, nil)
	} else {
		server := &http.Server{
			Addr: addr,
			TLSConfig: &tls.Config{
				ClientAuth: tls.RequireAndVerifyClientCert,
			},
		}
		fmt.Printf("Client certificates are required.\n")
		if conf.TrustAnchorFile != "" {
			fmt.Printf("  tls trust anchors: %s\n", conf.TrustAnchorFile)
			pem, err := ioutil.ReadFile(conf.TrustAnchorFile)
			if err != nil {
				return err
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return fmt.Errorf("Failed to load: %s\n", conf.TrustAnchorFile)
			}
			server.TLSConfig.ClientCAs = pool
		} else {
			fmt.Printf("  tls trust anchors: <from system>\n")
		}
		return server.ListenAndServeTLS(conf.TLSCertFile, conf.TLSKeyFile)
	}
}

// Command assembles the definition of Command 'serve'
var Command = &cli.Command{UsageText: serverUsageText, Flags: serverFlags, Main: serverMain}
