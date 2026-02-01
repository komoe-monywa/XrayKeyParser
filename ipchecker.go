package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

func isIpValid(site string, ip string, keyName string, value []string, blacklist bool) bool {
	// check if ip is domain or ip
	_ip := net.ParseIP(ip)
	if _ip == nil { //domain
		ips, err := net.LookupIP(ip)
		if err != nil {
			fmt.Println("Unable to resolve server name:", err)
			return false
		} else {
			if ips[0] != nil {
				ip = ips[0].To16().String()
				if ip == "" {
					fmt.Println("Unable to convert server name:", err)
					return false
				}
			}
		}
	} //ip
	request := strings.Builder{}
	request.WriteString(site)
	request.WriteString(ip)
	resp, err := http.Get(request.String())
	if err != nil {
		fmt.Println("Unable to connect to ip checker server:", err)
		return false
	} else if resp.StatusCode == 200 {
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("Unable to read ip info:", err)
			return false
		} else {
			var answer map[string]interface{}
			err := json.Unmarshal([]byte(body), &answer)
			if err != nil {
				fmt.Println("Error while unmarshalling JSON:", err)
				return false
			}
			for key, val := range answer {
				if key == keyName {
					j := len(value)
					for i := range j {
						if val == value[i] {
							if blacklist {
								return false
							} else {
								fmt.Println("Country ", val)
								return true
							}
						}
					}
					if blacklist {
						fmt.Println("Country ", val)
						return true
					} else {
						return false
					}
				}
			}
		}
	} else {
		fmt.Println("Service unavailable, response code - ", resp.StatusCode)
	}
	return false
}
