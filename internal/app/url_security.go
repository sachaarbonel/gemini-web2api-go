package app

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Credential-bearing requests only use these exact HTTPS hosts. Never match a
// hostname in a path, query, userinfo, or suffix controlled by another domain.
func trustedGoogleURL(raw string, hosts ...string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" ||
		u.Fragment != "" || (u.Port() != "" && u.Port() != "443") {
		return nil, fmt.Errorf("untrusted Google URL")
	}
	for _, host := range hosts {
		if strings.EqualFold(u.Hostname(), host) {
			return u, nil
		}
	}
	return nil, fmt.Errorf("untrusted Google URL host")
}

func trustedMediaURL(raw string) (*url.URL, error) {
	return trustedGoogleURL(raw, "lh3.googleusercontent.com",
		"work.fife.usercontent.google.com", "contribution.usercontent.google.com")
}

func publicMediaURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") ||
		u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.Fragment != "" {
		return nil, fmt.Errorf("media URL must be an HTTP(S) URL without credentials or a fragment")
	}
	if port := u.Port(); port != "" && port != "80" && port != "443" {
		return nil, fmt.Errorf("media URL must use port 80 or 443")
	}
	if strings.Contains(u.Hostname(), "%") {
		return nil, fmt.Errorf("media URL cannot contain an IP zone")
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil && !publicMediaIP(ip) {
		return nil, fmt.Errorf("media URL must resolve to public internet addresses")
	}
	return u, nil
}

var nonPublicMediaNetworks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/32"), // Teredo can encode private IPv4 destinations.
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"), // 6to4 can encode private IPv4 destinations.
}

func publicMediaIP(addr netip.Addr) bool {
	if !addr.IsValid() || addr.Zone() != "" {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return false
	}
	// Only currently assigned global IPv6 unicast space; excludes local NAT64
	// prefixes, unspecified/compatible IPv4 forms and other special-use ranges.
	if addr.Is6() && !netip.MustParsePrefix("2000::/3").Contains(addr) {
		return false
	}
	for _, prefix := range nonPublicMediaNetworks {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

type mediaResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

// Resolve once, reject mixed public/private answers, and dial the checked IP.
// Validating the hostname and then letting a transport resolve again permits
// DNS rebinding. This transport deliberately never uses environment proxies.
func publicMediaDialer(resolver mediaResolver, dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := resolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("media host DNS lookup failed")
		}
		for _, ip := range ips {
			if !publicMediaIP(ip) {
				return nil, fmt.Errorf("media URL must resolve to public internet addresses")
			}
		}
		for _, ip := range ips {
			var conn net.Conn
			conn, err = dial(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
		}
		return nil, err
	}
}

var publicMediaClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		DialContext:           publicMediaDialer(net.DefaultResolver, (&net.Dialer{Timeout: 10 * time.Second}).DialContext),
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		MaxIdleConns:          20,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       30 * time.Second,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("too many media redirects")
		}
		_, err := publicMediaURL(req.URL.String())
		return err
	},
}
