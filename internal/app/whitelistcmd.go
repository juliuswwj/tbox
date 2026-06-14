package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

func adminURL(adminAddr string) string {
	return "http://" + adminAddr + "/whitelist"
}

var adminClient = &http.Client{Timeout: 10 * time.Second}

// WhitelistShow prints the current allow lists from a running client's admin API.
func WhitelistShow(adminAddr string) error {
	resp, err := adminClient.Get(adminURL(adminAddr))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var entries []AdminWhitelistEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return err
	}
	if len(entries) == 0 {
		fmt.Println("(no published services)")
		return nil
	}
	for _, e := range entries {
		if len(e.Allow) == 0 {
			fmt.Printf("%s\tallow-all\n", e.Service)
		} else {
			fmt.Printf("%s\t%v\n", e.Service, e.Allow)
		}
	}
	return nil
}

// WhitelistSet replaces a service's allow list.
func WhitelistSet(adminAddr, service string, allow []string) error {
	return postWhitelist(adminAddr, AdminWhitelistRequest{Service: service, Allow: allow})
}

// WhitelistAdd adds CIDRs to a service's current allow list.
func WhitelistAdd(adminAddr, service string, add []string) error {
	cur, err := fetchAllow(adminAddr, service)
	if err != nil {
		return err
	}
	set := map[string]bool{}
	var merged []string
	for _, c := range append(cur, add...) {
		if !set[c] {
			set[c] = true
			merged = append(merged, c)
		}
	}
	return postWhitelist(adminAddr, AdminWhitelistRequest{Service: service, Allow: merged})
}

// WhitelistRemove removes CIDRs from a service's current allow list.
func WhitelistRemove(adminAddr, service string, remove []string) error {
	cur, err := fetchAllow(adminAddr, service)
	if err != nil {
		return err
	}
	drop := map[string]bool{}
	for _, c := range remove {
		drop[c] = true
	}
	var kept []string
	for _, c := range cur {
		if !drop[c] {
			kept = append(kept, c)
		}
	}
	return postWhitelist(adminAddr, AdminWhitelistRequest{Service: service, Allow: kept})
}

func fetchAllow(adminAddr, service string) ([]string, error) {
	resp, err := adminClient.Get(adminURL(adminAddr))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var entries []AdminWhitelistEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.Service == service {
			return e.Allow, nil
		}
	}
	return nil, fmt.Errorf("service %q not found", service)
}

func postWhitelist(adminAddr string, req AdminWhitelistRequest) error {
	body, _ := json.Marshal(req)
	resp, err := adminClient.Post(adminURL(adminAddr), "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("admin error: %s", bytes.TrimSpace(data))
	}
	return nil
}
