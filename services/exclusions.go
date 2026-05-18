/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package services

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/amnezia-vpn/amneziawg-windows/conf"
)

// ExclusionList represents the split-tunneling exclusion rules for a tunnel.
// Domains are resolved via public DNS and their resolved IPs are bypassed.
// IPRanges are CIDR ranges that are excluded from the tunnel.
type ExclusionList struct {
	Domains  []string `json:"domains"`
	IPRanges []string `json:"ip_ranges"`
}

// ExclusionsPath returns the path to the exclusions JSON file for the given tunnel name.
func ExclusionsPath(tunnelName string) (string, error) {
	root, err := conf.RootDirectory(false)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "Configurations", tunnelName+".exclusions.json"), nil
}

// LoadExclusions loads the exclusion list for the given tunnel name.
// Returns an empty list if the file does not exist yet.
func LoadExclusions(tunnelName string) (*ExclusionList, error) {
	path, err := ExclusionsPath(tunnelName)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &ExclusionList{}, nil
		}
		return nil, err
	}

	var list ExclusionList
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	if list.Domains == nil {
		list.Domains = []string{}
	}
	if list.IPRanges == nil {
		list.IPRanges = []string{}
	}
	return &list, nil
}

// SaveExclusions saves the exclusion list for the given tunnel name.
func SaveExclusions(tunnelName string, list *ExclusionList) error {
	path, err := ExclusionsPath(tunnelName)
	if err != nil {
		return err
	}

	// Ensure the Configurations directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// DeleteExclusions removes the exclusions file for the given tunnel name.
func DeleteExclusions(tunnelName string) error {
	path, err := ExclusionsPath(tunnelName)
	if err != nil {
		return err
	}
	err = os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
