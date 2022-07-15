package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"syscall/js"
	"time"

	"github.com/miekg/dns"
)

// Accept: application/dns-json or Accept: application/json
type DOHJsonQuestion struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
}

type DOHJsonAnswer struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
	TTL  int64  `json:"TTL"`
	Data string `json:"data"`
}

// rfc: https://datatracker.ietf.org/doc/html/rfc1035
// some flags associate with rfc1035
type DOHJson struct {
	Status    int               `json:"Status"`              // required, dns.MsgHdr.Rcode
	TC        bool              `json:"TC"`                  // required, dns.MsgHdr.Truncated
	RD        bool              `json:"RD"`                  // required, dns.MsgHdr.RecursionDesired
	RA        bool              `json:"RA"`                  // required, dns.MsgHdr.RecursionAvailable
	AD        bool              `json:"AD"`                  // required, dns.MsgHdr.AuthenticatedData
	CD        bool              `json:"CD"`                  // required, dns.MsgHdr.CheckingDisabled
	Question  []DOHJsonQuestion `json:"Question"`            // required, dns.Msg.Question
	Answer    []DOHJsonAnswer   `json:"Answer"`              // required, dns.Msg.Answer
	Authority []DOHJsonAnswer   `json:"Authority,omitempty"` // optional, dns.Msg.Ns
	//Aditional []string          `json:"Aditional,omitempty"`          // optional, dns.Msg.Extra
	//ECS       string            `json:"edns_client_subnet,omitempty"` // optional
	//Comment   string            `json:"Comment,omitempty"`            // optional
}

func generateDnsMsgBytes(name string, qtype string, qclass string) ([]byte, error) {
	r := new(dns.Msg)

	qname := dns.Fqdn(name)
	qtypeInt := dns.StringToType[strings.ToUpper(qtype)]
	qclassInt := dns.StringToClass[strings.ToUpper(qclass)]

	r.Id = dns.Id()
	r.RecursionDesired = true
	r.Question = make([]dns.Question, 1)
	r.Question[0] = dns.Question{
		Name:   qname,
		Qtype:  qtypeInt,
		Qclass: qclassInt,
	}

	bmsg, err := r.Pack()
	if err != nil {
		return nil, err
	}
	return bmsg, err
}

func newRequest(method string, server string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, server, body)

	return req, err
}

func queryDohServer(method string, server string, name string, qtype string, qclass string, format string) (string, error) {

	method = strings.ToUpper(method)
	if method != http.MethodGet && method != http.MethodPost {
		return "", fmt.Errorf("method %s not support", method)
	}
	name = dns.Fqdn(name)
	qtype = strings.ToUpper(qtype)
	url := server
	var body io.Reader = nil

	headers := make(map[string]string)
	switch format {
	case "JSON":
		url = fmt.Sprintf("%s?name=%s&type=%s", server, name, qtype)
		headers["Accept"] = "application/dns-json"
		if method == http.MethodPost {
			headers["Content-Type"] = "application/dns-json"
		}
	case "RFC8484":
		headers["Accept"] = "application/dns-message"
		bmsg, err := generateDnsMsgBytes(name, qtype, qclass)
		if err != nil {
			return "", err
		}
		if method == http.MethodGet {
			url = fmt.Sprintf("%s?dns=%s", server, base64.RawURLEncoding.EncodeToString(bmsg))
		} else {
			body = bytes.NewReader(bmsg)
			headers["Content-Type"] = "application/dns-message"
		}
	default:
		return "", fmt.Errorf("doh format %s not support", format)
	}
	req, err := newRequest(method, url, body)
	if err != nil {
		return "", err
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := query(req)

	if err != nil {
		return "", err
	}

	// parse
	switch format {
	case "JSON":
		var dohJson DOHJson
		err = json.Unmarshal(resp, &dohJson)
		if err != nil {
			return "", err
		}
		bs, err := json.MarshalIndent(dohJson, "", "\t")
		if err != nil {
			return "", err
		}
		return string(bs), nil
	case "RFC8484":
		rmsg := new(dns.Msg)
		if err := rmsg.Unpack(resp); err != nil {
			return "", err
		}

		return rmsg.String(), err
	}

	return "", err
}

func query(req *http.Request) ([]byte, error) {
	c := http.Client{
		Timeout: 10 * time.Second,
	}
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return nil
	}
	c.Transport = &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{
			//InsecureSkipVerify: true,
		},
	}

	// https://github.com/golang/go/blob/2580d0e08d5e9f979b943758d3c49877fb2324cb/src/net/http/roundtrip_js.go#L76
	// https://developer.mozilla.org/en-US/docs/Web/API/fetch
	// disable cors
	// must enable cors, or will not enable to read response, only send data (or disable base on browser)
	//req.Header.Set("js.fetch:mode", "no-cors")

	// show in browser console
	fmt.Printf("%s %s\n", req.Method, req.URL)
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("response status code %d not 200", resp.StatusCode)
	}

	bs, err := ioutil.ReadAll(resp.Body)
	return bs, err
}

// require:
// 1. doh server support cors and enable this domain access
// 2. [optional] doh server must support preflight request, "OPTIONS" method, return CORS rules
// 3. [must] doh server response must contain header: 'Access-Control-Allow-Origin: *' or 'Access-Control-Allow-Origin: <this_site_url>'
//
// if client set CORS mode as "no-cors", some browser can send request, some disallow, but all of them are disable read response.
//
// in order to get fetch() (which http request do) response, we must use async func (Promise Object)
func AsyncDohQuery() js.Func {
	return js.FuncOf(func(this js.Value, args []js.Value) any {
		// func(v_method, v_server, v_name, v_qtype, v_doh_format)
		var err error
		v_method, v_server, v_name, v_qtype, v_doh_format := "", "", "", "", ""
		if len(args) < 5 {
			err = fmt.Errorf("require argument size 5, given %d", len(args))
		} else {
			v_method = args[0].String()
			v_server = args[1].String()
			v_name = args[2].String()
			v_qtype = args[3].String()
			v_doh_format = args[4].String()
		}

		// Promise handler
		handler := js.FuncOf(func(this js.Value, args []js.Value) any {
			resolve := args[0]
			reject := args[1]

			if err != nil {
				js.Global().Get("ans_doh").Set("innerHTML", fmt.Sprintf("Error: %s", err.Error()))
				reject.Invoke(err.Error())
				return nil
			}

			// in js, async/await make sure this code returen
			go func() {
				// if server response dosen't contain valid "access-control-allow-origin" to permit CORS
				// error occur
				resp, err := queryDohServer(v_method, v_server, v_name, v_qtype, "IN", v_doh_format)
				if err != nil {
					js.Global().Get("ans_doh").Set("innerHTML", fmt.Sprintf("Error: %s", err.Error()))
					reject.Invoke(err.Error())
					return
				}
				fmt.Printf("%s\n", resp)

				// html add style="white-space: pre;",
				js.Global().Get("ans_doh").Set("innerHTML", resp)

				// Resolve the Promise
				resolve.Invoke(resp)
			}()

			// Promise handler always return nil
			return nil
		})

		js.Global().Get("ans_doh").Set("innerHTML", "doh request has been sent, waiting for response ...")

		// return Promise object about the handler
		// in js, use async/await to make sure handler(promise) execute
		return js.Global().Get("Promise").New(handler)
	})
}

func main() {
	js.Global().Set("AsyncDohQuery", AsyncDohQuery())
	select {}
}
