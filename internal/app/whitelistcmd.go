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
		fmt.Println("(no published domains)")
		return nil
	}
	for _, e := range entries {
		if len(e.Allow) == 0 {
			fmt.Printf("%s\tallow-all\n", e.Domain)
		} else {
			fmt.Printf("%s\t%v\n", e.Domain, e.Allow)
		}
	}
	return nil
}

// WhitelistSet replaces a domain's allow list.
func WhitelistSet(adminAddr, domain string, allow []string) error {
	return postWhitelist(adminAddr, AdminWhitelistRequest{Domain: domain, Allow: allow})
}

// WhitelistAdd adds CIDRs to a domain's current allow list.
func WhitelistAdd(adminAddr, domain string, add []string) error {
	cur, err := fetchAllow(adminAddr, domain)
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
	return postWhitelist(adminAddr, AdminWhitelistRequest{Domain: domain, Allow: merged})
}

// WhitelistRemove removes CIDRs from a domain's current allow list.
func WhitelistRemove(adminAddr, domain string, remove []string) error {
	cur, err := fetchAllow(adminAddr, domain)
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
	return postWhitelist(adminAddr, AdminWhitelistRequest{Domain: domain, Allow: kept})
}

func fetchAllow(adminAddr, domain string) ([]string, error) {
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
		if e.Domain == domain {
			return e.Allow, nil
		}
	}
	return nil, fmt.Errorf("domain %q not found", domain)
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
