package main

// Scanner holds the metadata for the malware scan procedure, including the
// original URL requested by the user, some optional parameters for the HTTP
// request and the JSON-decoded data obtained from the scan results.
type Scanner struct {
	Domain    string
	FromCache bool
	Report    Result
}

// Result contains the JSON-decoded data from the API call.
type Result struct {
	Scan            ResultScan                            `json:"scan"`
	Site            Site                                  `json:"site"`
	Software        Software                              `json:"software"`
	TLS             map[string]string                     `json:"tls"`
	Recommendations map[string]map[string]Recommendations `json:"recommendations"`
	Links           map[string][]string                   `json:"links"`
	Ratings         map[string]Rating                     `json:"ratings"`
}

// ResultScan contains the details for the scan target.
type ResultScan struct {
	DbDate   string  `json:"db_date"`
	Version  string  `json:"version"`
	Duration float32 `json:"duration"`
	LastScan string  `json:"last_scan"`
}

// Site contains details for the scanned Site
type Site struct {
	RunningOn   []string `json:"running_on"`
	Input       string   `json:"input"`
	PoweredBy   []string `json:"powered_by"`
	RedirectsTo []string `json:"redirects_to"`
	Domain      string   `json:"domain"`
	FinalURL    string   `json:"final_url"`
	IP          []string `json:"ip"`
	CDN         []string `json:"cdn"`
}

// Software contains details on the site's software
type Software struct {
	Language []SoftwareLanguage `json:"language"`
	CMS      []SoftwareCMS      `json:"cms"`
	Server   []SoftwareLanguage `json:"server"`
}

// SoftwareLanguage abstracts the name/version component for languages and servers used.
type SoftwareLanguage struct {
	Version string `json:"version"`
	Name    string `json:"name"`
}

// SoftwareCMS contains details on the site's CMS
type SoftwareCMS struct {
	Version   string `json:"version"`
	InfoURL   string `json:"info_url"`
	Name      string `json:"name"`
	BasedOn   string `json:"based_on"`
	Theme     string `json:"theme"`
	Directory string `json:"directory"`
}

// Recommendations contains additional details on security recommendations
type Recommendations struct {
	Details string   `json:"details"`
	Pages   []string `json:"pages"`
}

// Rating contains details on each individual audit rating.
type Rating struct {
	Rating string `json:"rating"`
	Passed string `json:"passed"`
}
