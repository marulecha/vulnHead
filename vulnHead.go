package main

import (
	"flag"
	"fmt"
	"net/http"

	"github.com/gookit/color"
)

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func main() {

	color.Cyan.Println("\n              :|      ::| ::|::::::| ::::\\ ::::::\n    :\\:| :\\:| :| :::\\ ::::::|:::>   ::|,::|::| ::|\n     :/  `::| :| :|:| ::| ::|::::::|::| ::|::::::/\n\n")
	targetUrlFlag := flag.String("u", "https://google.com", "Target URL, -u http(s)://<IP>:<PORT> ")
	flag.Parse()

	resp, err := http.Get(*targetUrlFlag)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	//numbersArray := [10]string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"}
	respHeaderSliceKey := []string{}
	respHeaderSliceValue := [][]string{}

	missingHeaderList := []string{"Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options", "Content-Security-Policy", "Referrer-Policy", "Permissions-Policy"}
	targetMissingHeaders := []string{}
	//missingHeadersRecomm := []string{}

	recommendations := make(map[string]string) //for loops declare like this.
	recommendations = map[string]string{
		"Strict-Transport-Security": "Strict-Transport-Security: max-age=31536000; includeSubDomains",
		"X-Frame-Options":           "X-Frame-Options: DENY",
		"X-Content-Type-Options":    "X-Content-Type-Options: nosniff",
		"Content-Security-Policy":   "Content-Security-Policy: script-src 'self'",
		"Referrer-Policy":           "Referrer-Policy: strict-origin  ||  Referrer-Policy: strict-origin-when-cross-origin",
		"Permissions-Policy":        "Permissions-Policy: fullscreen=(self \"https://example.com\" \"https://another.example.com\"), geolocation=*, camera=()",
	}
	references := make(map[string]string) //for loops declare like this.
	references = map[string]string{
		"Strict-Transport-Security": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
		"X-Frame-Options":           "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
		"X-Content-Type-Options":    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
		"Content-Security-Policy":   "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
		"Referrer-Policy":           "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
		"Permissions-Policy":        "https://github.com/w3c/webappsec-permissions-policy/blob/main/permissions-policy-explainer.md",
	}

	//okHeaders := []string{}
	ischeckFurtherHeader := []string{}
	checkFurtherHeaders := []string{"Server", "Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"}
	allHeaderList := []string{"Feature-Policy", "Expect-CT", "Public-Key-Pins", "X-XSS-Protection"}
	warningHeader := []string{}
	iswarningHeader := make(map[string]string) //for loops declare like this.
	iswarningHeader = map[string]string{
		"Feature-Policy":   "Feature-Policy:  ALMOST DEPRECATED",
		"Expect-CT":        "Expect-CT:  ALMOST DEPRECATED",
		"Public-Key-Pins":  "Public-Key-Pins:  DEPRECATED",
		"X-XSS-Protection": "X-XSS-Protection:  DEPRECATED",
	}

	// Print Response Headers
	color.Cyan.Printf("[SCAN] ")
	color.Yellow.Println(*targetUrlFlag, "\n")
	color.New(color.FgCyan, color.BgMagenta).Println("       Response Headers                            ")
	for k, v := range resp.Header {
		respHeaderSliceKey = append(respHeaderSliceKey, k)
		respHeaderSliceValue = append(respHeaderSliceValue, v)
	}

	// Identify Warning & Check Headers
	for i, v1 := range respHeaderSliceKey {
		for _, v2 := range allHeaderList {
			if v1 == v2 {
				color.Red.Println("[ -> ]", v1, " : ", respHeaderSliceValue[i])
				warningHeader = append(warningHeader, v1)
				break
			} else {
				checkFurtherHeaders = append(checkFurtherHeaders, v1)
				break
			}
		}
		for _, v3 := range checkFurtherHeaders {
			if v1 == v3 {
				color.Red.Println("[ -> ]", v1, " : ", respHeaderSliceValue[i])
				ischeckFurtherHeader = append(ischeckFurtherHeader, v1)
				break
			} else {
				color.Green.Printf("[ OK ] ")
				color.Cyan.Println(v1, " : ", respHeaderSliceValue[i])
				break
			}
		}
	}

	// Print Warning Headers.
	fmt.Println()
	for _, v1 := range warningHeader {
		if contains(warningHeader, v1) == true {
			color.Danger.Printf("[Warn] ")
			color.Warn.Println(iswarningHeader[v1])
		}
	}
	// Print Missing Headers
	fmt.Println()
	color.New(color.FgMagenta, color.BgYellow).Println("       Missing Headers                            ")
	for _, v1 := range missingHeaderList {
		if contains(respHeaderSliceKey, v1) == false {
			color.Yellow.Printf("[ MH ] ")
			color.Cyan.Println(v1)
			targetMissingHeaders = append(targetMissingHeaders, v1)
		}
	}

	// Print Recommendations for Missing Headers
	fmt.Println()
	color.New(color.FgYellow, color.BgCyan).Println("       Recommendations                            ")
	for _, v1 := range targetMissingHeaders {
		if contains(targetMissingHeaders, v1) == true {
			color.Green.Printf("[Reco] ")
			color.Yellow.Println(recommendations[v1])

			color.Magenta.Printf("[Refe] ")
			color.Cyan.Println(references[v1])
		}
	}

	fmt.Println()
	color.New(color.FgMagenta, color.BgCyan).Println("           Tips                                   ")
	color.Cyan.Printf("[Tip ] ")
	color.HEX("#ef7a82").Printf("Make Sure all your session cookies have the\n       'Secure' & 'httpOnly' flags enabled!\n")
}
