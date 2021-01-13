package main

import (
	"fmt"
	"html/template"
	"io/ioutil"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"strings"

	"github.com/gorilla/mux"
	"github.com/markbates/pkger"
	"github.com/oschwald/geoip2-golang"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"golang.org/x/net/publicsuffix"
)

var db *geoip2.Reader
var templates map[string]*template.Template

func fakeip(h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if fakeIp := r.Form.Get("ip"); fakeIp != "" {
			r.RemoteAddr = fmt.Sprintf("%s:12345", fakeIp)
		}
		h.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func whoisIp(w http.ResponseWriter, r *http.Request) {
	whois(w, r, parseRemoteAddr(r).String())
}

func whoisHost(w http.ResponseWriter, r *http.Request) {
	addr := parseRemoteAddr(r)
	names, err := net.LookupAddr(addr.String())
	if err == nil && len(names) > 0 {
		name := strings.TrimSuffix(names[0], ".")
		name, err = publicsuffix.EffectiveTLDPlusOne(name)
		if err == nil {
			whois(w, r, name)
		}
	}
}

func whois(w http.ResponseWriter, r *http.Request, arg string) {
	data := make(map[string]interface{})
	out, _ := exec.Command("whois", arg).CombinedOutput()
	data["Whois"] = string(out)
	templates["whois.html"].Execute(w, data)
}

func ipInfo(w http.ResponseWriter, r *http.Request) {
	ua := r.Header.Get("User-Agent")
	accept := r.Header.Get("Accept")
	if strings.HasPrefix(ua, "curl") || accept == "text/plain" {
		ipInfoPlain(w, r)
	} else {
		ipInfoHtml(w,r)
	}
}

func parseRemoteAddr(r *http.Request) net.IP {
	addr := r.RemoteAddr[:strings.LastIndex(r.RemoteAddr, ":")]
	if addr[0] == '[' && addr[len(addr)-1] == ']' {
		addr = addr[1:len(addr)-1]
	}
	return net.ParseIP(addr)
}

func ipInfoPlain(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(parseRemoteAddr(r)))
}

func ipInfoHtml(w http.ResponseWriter, r *http.Request) {
	data := make(map[string]interface{})
	addr := parseRemoteAddr(r)
	data["IpAddress"] = addr
	names, err := net.LookupAddr(addr.String())
	if err == nil && len(names) > 0 {
		data["Hostname"] = names[0]
	}
	if asn, err := db.ASN(addr); err == nil && asn != nil {
		data["ASN"] = asn
	}
	if city, err := db.City(addr); err == nil && city != nil && city.City.GeoNameID != 0 {
		data["City"] = city
	}
	if proxy := r.Header.Get("Via"); proxy != "" {
		data["Proxy"] = strings.Split(proxy, " ")
	}
	if localIp := r.Header.Get("X-Forwarded-For"); localIp != "" {
		data["LocalIp"] = localIp
	}
	templates["index.html"].Execute(w, data)
}

func main() {
	var dbPath string
	pflag.StringVar(&dbPath, "db", dbPath, "Path to the GeoIP database")
	pflag.Parse()

	var err error
	db, err = geoip2.Open(dbPath)
	if err != nil {
		logrus.WithFields(logrus.Fields{"err": err, "db": dbPath}).Fatal("Unable to open database")
	}

	pkger.Include("/templates/")
	templates = make(map[string]*template.Template)
	for _, tn := range []string{"index.html", "whois.html"} {
		r, err := pkger.Open(fmt.Sprintf("/templates/%s", tn))
		if err != nil {
			logrus.WithFields(logrus.Fields{"err": err, "template": tn}).Fatal("Unable to open template")
		}
		data, _ := ioutil.ReadAll(r)
		tmpl := template.New(tn)
		tmpl.Funcs(template.FuncMap{"linkify": linkify})
		if _, err := tmpl.Parse(string(data)); err != nil {
			logrus.WithFields(logrus.Fields{"err": err, "template": tn}).Fatal("Unable to parse template")
		}
		templates[tn] = tmpl
	}

	r := mux.NewRouter()
	r.HandleFunc("/", ipInfo)
	r.HandleFunc("/whois", whoisHost)
	r.HandleFunc("/whois-ip", whoisIp)
	logrus.Info("Waiting...")
	http.ListenAndServe(":8081", fakeip(r))
}

var linkRx = regexp.MustCompile("(?P<link>https?://[-a-zA-Z0-9._/&%=?;]+)")
var mailRx = regexp.MustCompile("(?P<addr>[-a-zA-Z0-9_.+]+@[-a-zA-Z0-9.]+)")
func linkify(data string) template.HTML {
	data = template.HTMLEscapeString(data)
	data = linkRx.ReplaceAllString(data, "<a href=\"$link\">$link</a>")
	data = mailRx.ReplaceAllString(data, "<a href=\"mailto:$addr\">$addr</a>")
	return template.HTML(data)
}
