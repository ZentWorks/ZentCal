package web

import (
	"bufio"
	"os"
	"sort"
	"strings"
)

func availableTimezones() []string {
	seen := map[string]bool{"UTC": true, "Etc/UTC": true, "Etc/GMT": true}
	for _, path := range []string{"/usr/share/zoneinfo/zone1970.tab", "/usr/share/zoneinfo/zone.tab"} {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		s := bufio.NewScanner(f)
		for s.Scan() {
			line := strings.TrimSpace(s.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				seen[fields[2]] = true
			}
		}
		_ = f.Close()
	}
	// Useful fixed-offset IANA zones are not listed in zone.tab.
	for i := 1; i <= 14; i++ {
		seen["Etc/GMT+"+itoa(i)] = true
		seen["Etc/GMT-"+itoa(i)] = true
	}
	if len(seen) < 20 {
		for _, z := range []string{"Europe/Berlin", "Europe/London", "Europe/Paris", "Europe/Vienna", "Europe/Zurich", "America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles", "Asia/Tokyo", "Asia/Singapore", "Australia/Sydney"} {
			seen[z] = true
		}
	}
	out := make([]string, 0, len(seen))
	for z := range seen {
		seenOK := true
		if _, err := os.Stat("/usr/share/zoneinfo/" + z); err != nil && z != "UTC" {
			seenOK = false
		}
		if seenOK {
			out = append(out, z)
		}
	}
	sort.Strings(out)
	return out
}

func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return "1" + string(rune('0'+(n-10)))
}
