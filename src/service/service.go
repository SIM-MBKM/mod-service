package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/SIM-MBKM/mod-service/src/helpers"
)

type Service struct {
	BaseURI      string
	AsyncURIs    []string
	Client       *http.Client
	HTTPResponse *http.Response
}

func NewService(baseURI string, asyncURIs []string) *Service {
	return &Service{
		BaseURI:   strings.TrimRight(baseURI, "/") + "/",
		AsyncURIs: asyncURIs,
		Client:    &http.Client{Timeout: 30 * time.Second},
	}
}

// getHeaders generates the headers for the request.
func (s *Service) getHeaders(token string) (map[string]string, error) {
	security := helpers.NewSecurity(
		"sha256",
		helpers.GetEnv("APP_KEY", "secret"),
		"aes",
	)

	// Mengambil waktu saat ini
	currentTime := time.Now()

	// Mengubah waktu ke timestamp Unix (jumlah detik sejak epoch)
	timestamp := currentTime.Unix()

	// Mengonversi timestamp ke string
	timestampString := strconv.Itoa(int(timestamp))

	accessKey, err := security.Encrypt(
		helpers.GetEnv("APP_KEY", "secret") + "@" + timestampString,
	)

	localeInstance := helpers.GetInstance()
	locale := localeInstance.GetLocale()

	if err != nil {
		return nil, err
	}

	var userToken string

	if token != "" {
		userToken = fmt.Sprintf("Bearer %s", token)
	} else {
		userToken = ""
	}

	headers := map[string]string{
		"Accept":        "application/json",
		"Authorization": userToken,
		"Access-From":   "service",
		"Access-Key":    accessKey,
		"App-Locale":    locale,
	}

	return headers, nil
}

// Request sends an HTTP request.
func (s *Service) Request(method, uri string, opts map[string]interface{}, token string) (map[string]interface{}, error) {
	url := s.BaseURI + uri
	var body []byte
	var err error

	if opts != nil {
		body, err = json.Marshal(opts)
		if err != nil {
			return nil, err
		}
	}

	headers, err := s.getHeaders(token)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	if s.isAsync(uri) {
		go func() {
			s.HTTPResponse, _ = s.Client.Do(req)

		}()
		return nil, nil
	} else {
		s.HTTPResponse, err = s.Client.Do(req)

		if err != nil {
			return nil, err
		}
		// return s.HTTPResponse, nil
		jsonResponse, err := s.Response()

		if err != nil {
			return nil, err
		}

		return jsonResponse, nil
	}
}

// Response processes the HTTP response.
func (s *Service) Response() (map[string]interface{}, error) {
	if s.HTTPResponse == nil {
		return map[string]interface{}{
			"status": "success",
			"data":   nil,
		}, nil
	}

	defer s.HTTPResponse.Body.Close()
	body, err := io.ReadAll(s.HTTPResponse.Body)
	if err != nil {
		return nil, err
	}

	if s.HTTPResponse.StatusCode != http.StatusOK {
		var errorResponse map[string]interface{}
		_ = json.Unmarshal(body, &errorResponse)

		return map[string]interface{}{
			"status":  "error",
			"code":    s.HTTPResponse.StatusCode,
			"message": s.HTTPResponse.Status,
			"errors":  errorResponse["errors"],
		}, errors.New(s.HTTPResponse.Status)
	}

	var jsonResponse map[string]interface{}
	if err := json.Unmarshal(body, &jsonResponse); err != nil {
		return nil, err
	}

	return jsonResponse, nil
}

// isAsync checks if the URI is asynchronous.
func (s *Service) isAsync(uri string) bool {
	for _, asyncURI := range s.AsyncURIs {
		if strings.Contains(uri, asyncURI) {
			return true
		}
	}
	return false
}
