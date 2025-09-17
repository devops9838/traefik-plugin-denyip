// Package denyip - middleware for denying request based on IP.
// Supports both IPv4 and IPv6 addresses in both single IP and CIDR notation.
package denyip

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
)

const (
	xForwardedFor = "X-Forwarded-For"
)

// Checker allows to check that addresses are in a denied IPs.
type Checker struct {
	denyIPs    []*net.IP
	denyIPsNet []*net.IPNet
}

// Config the plugin configuration.
type Config struct {
	IPDenyList []string `json:"ipDenyList,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// DenyIP plugin.
type denyIP struct {
	next    http.Handler
	checker *Checker
	name    string
}

// New creates a new DenyIP plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	checker, err := NewChecker(config.IPDenyList)
	if err != nil {
		return nil, err
	}

	return &denyIP{
		checker: checker,
		next:    next,
		name:    name,
	}, nil
}

func (a *denyIP) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	reqIPAddr := a.GetRemoteIP(req)
	reqIPAddrLenOffset := len(reqIPAddr) - 1

	for i := reqIPAddrLenOffset; i >= 0; i-- {
		isBlocked, err := a.checker.Contains(reqIPAddr[i])
		if err != nil {
			log.Printf("%v", err)
		}

		if isBlocked {
			log.Printf("denyIP: request denied [%s]", reqIPAddr[i])
			rw.WriteHeader(http.StatusForbidden)

			return
		}
	}

	a.next.ServeHTTP(rw, req)
}

// GetRemoteIP returns a list of IPs that are associated with this request.
// Handles both IPv4 and IPv6 addresses from X-Forwarded-For header and RemoteAddr.
func (a *denyIP) GetRemoteIP(req *http.Request) []string {
	var ipList []string

	xff := req.Header.Get(xForwardedFor)
	xffs := strings.Split(xff, ",")

	for i := len(xffs) - 1; i >= 0; i-- {
		xffsTrim := strings.TrimSpace(xffs[i])
		// Remove IPv6 brackets if present
		xffsTrim = strings.Trim(xffsTrim, "[]")

		if len(xffsTrim) > 0 {
			ipList = append(ipList, xffsTrim)
		}
	}

	// Handle RemoteAddr which may contain port number
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		// If SplitHostPort fails, try to use the address as is
		// This handles cases where the address might not have a port
		remoteAddrTrim := strings.TrimSpace(req.RemoteAddr)
		if len(remoteAddrTrim) > 0 {
			// Remove IPv6 brackets if present
			remoteAddrTrim = strings.Trim(remoteAddrTrim, "[]")
			ipList = append(ipList, remoteAddrTrim)
		}
	} else {
		ipTrim := strings.TrimSpace(ip)
		if len(ipTrim) > 0 {
			// Remove IPv6 brackets if present
			ipTrim = strings.Trim(ipTrim, "[]")
			ipList = append(ipList, ipTrim)
		}
	}

	return ipList
}

// NewChecker builds a new Checker given a list of CIDR-Strings to denied IPs.
func NewChecker(deniedIPs []string) (*Checker, error) {
	if len(deniedIPs) == 0 {
		return nil, errors.New("no denied IPs provided")
	}

	checker := &Checker{}

	for _, ipMask := range deniedIPs {
		// Remove IPv6 brackets if present
		ipMask = strings.Trim(ipMask, "[]")
		
		// Try parsing as CIDR first
		_, ipNet, err := net.ParseCIDR(ipMask)
		if err == nil {
			checker.denyIPsNet = append(checker.denyIPsNet, ipNet)
			continue
		}

		// If not a CIDR, try parsing as a single IP
		if ipAddr := net.ParseIP(ipMask); ipAddr != nil {
			checker.denyIPs = append(checker.denyIPs, &ipAddr)
		} else {
			return nil, fmt.Errorf("parsing denied IPs %s: invalid IP or CIDR format", ipMask)
		}
	}

	return checker, nil
}

// Contains checks if provided address is in the denied IPs.
func (ip *Checker) Contains(addr string) (bool, error) {
	if len(addr) == 0 {
		return false, errors.New("empty IP address")
	}

	ipAddr, err := parseIP(addr)
	if err != nil {
		return false, fmt.Errorf("unable to parse address: %s: %w", addr, err)
	}

	return ip.ContainsIP(ipAddr), nil
}

// ContainsIP checks if provided address is in the denied IPs.
func (ip *Checker) ContainsIP(addr net.IP) bool {
	for _, deniedIP := range ip.denyIPs {
		if deniedIP.Equal(addr) {
			return true
		}
	}

	for _, denyNet := range ip.denyIPsNet {
		if denyNet.Contains(addr) {
			return true
		}
	}

	return false
}

func parseIP(addr string) (net.IP, error) {
	// Remove IPv6 brackets if present
	addr = strings.Trim(addr, "[]")
	
	userIP := net.ParseIP(addr)
	if userIP == nil {
		return nil, fmt.Errorf("unable to parse IP from address %s", addr)
	}

	return userIP, nil
}
