package main

import (
	"bytes"
	"cmp"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/sethvargo/go-githubactions"
	"golang.org/x/crypto/nacl/box"
)

var (
	apiURL, token, repo, environment string
	delete                           bool
	publicKey                        PublicKeyResponse
	secretsMap, variablesMap         = make(map[string]string), make(map[string]string)
)

type PublicKeyResponse struct {
	Key   string `json:"key"`
	KeyID string `json:"key_id"`
}

type HttpConfig struct {
	BaseURL, Token string
	Client         *http.Client
}

func GetHttpConfig() *HttpConfig {
	return &HttpConfig{
		BaseURL: fmt.Sprintf("%s/repos/%s/environments/%s", apiURL, repo, environment),
		Token:   token,
		Client:  &http.Client{},
	}
}

func HttpRequest(c *HttpConfig, method, url string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.Token))
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}

	return resp, nil
}

func HttpStatusOK(m string, c int) bool {
	status := map[string]int{
		http.MethodDelete: http.StatusNoContent,
		http.MethodGet:    http.StatusOK,
		http.MethodPatch:  http.StatusNoContent,
		http.MethodPost:   http.StatusCreated,
		http.MethodPut:    http.StatusCreated,
	}
	return status[m] == c
}

func GetPublicKey(c *HttpConfig) (PublicKeyResponse, error) {
	var pk PublicKeyResponse
	method := http.MethodGet
	pkURL := fmt.Sprintf("%s/secrets/public-key", c.BaseURL)

	resp, err := HttpRequest(c, method, pkURL, nil)
	if err != nil {
		return pk, fmt.Errorf("failed to get public key: %w", err)
	}

	if !HttpStatusOK(method, resp.StatusCode) {
		return pk, fmt.Errorf("failed to get public key: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return pk, fmt.Errorf("failed to read public key response: %w", err)
	}

	err = json.Unmarshal(data, &pk)
	if err != nil {
		return pk, fmt.Errorf("failed to unmarshal public key response: %w", err)
	}

	return pk, nil
}

func EncryptPlaintext(plaintext, pkBase64 string) ([]byte, error) {
	pkBytes, err := base64.StdEncoding.DecodeString(pkBase64)
	if err != nil {
		return []byte{}, err
	}

	var pkBytes32 [32]byte
	copiedLen := copy(pkBytes32[:], pkBytes)
	if copiedLen == 0 {
		return []byte{}, fmt.Errorf("could not convert public key to byte array")
	}

	plaintextBytes := []byte(plaintext)
	var ciphertextBytes []byte

	ciphertext, err := box.SealAnonymous(ciphertextBytes, plaintextBytes, &pkBytes32, nil)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to encrypt plaintext: %w", err)
	}

	return ciphertext, nil
}

func SetValues(c *HttpConfig, m *map[string]string, endpoint string) error {
	for k, v := range *m {
		endpoints := map[string]map[string]string{
			"secret": {
				http.MethodGet: fmt.Sprintf("%s/secrets/%s", c.BaseURL, k),
				http.MethodPut: fmt.Sprintf("%s/secrets/%s", c.BaseURL, k),
			},
			"variable": {
				http.MethodGet:   fmt.Sprintf("%s/variables/%s", c.BaseURL, k),
				http.MethodPatch: fmt.Sprintf("%s/variables/%s", c.BaseURL, k),
				http.MethodPost:  fmt.Sprintf("%s/variables", c.BaseURL),
			},
		}

		method := http.MethodGet
		lookupResp, err := HttpRequest(c, method, endpoints[endpoint][method], nil)
		if err != nil {
			return fmt.Errorf("failed to lookup %s %s: %w", endpoint, k, err)
		}

		method = http.MethodPatch
		if !HttpStatusOK(http.MethodGet, lookupResp.StatusCode) {
			method = http.MethodPost
			log.Printf("%s '%s' not found, creating it", endpoint, k)
		}

		data := map[string]string{"name": k, "value": v}

		if endpoint == "secret" {
			method = http.MethodPut
			ciphertext, err := EncryptPlaintext(v, publicKey.Key)
			if err != nil {
				return fmt.Errorf("failed to encrypt secret %s: %w", k, err)
			}
			cipherB64 := base64.StdEncoding.EncodeToString(ciphertext)
			data = map[string]string{"encrypted_value": cipherB64, "key_id": publicKey.KeyID}
		}

		jsonData, err := json.Marshal(data)
		if err != nil {
			return fmt.Errorf("failed to marshal JSON for %s %s: %w", endpoint, k, err)
		}

		log.Printf("setting %s '%s' via %s at URL: %s", endpoint, k, method, endpoints[endpoint][method])

		resp, err := HttpRequest(c, method, endpoints[endpoint][method], bytes.NewBuffer(jsonData))
		if err != nil {
			return fmt.Errorf("failed to set %s %s: %w", endpoint, k, err)
		}

		if !HttpStatusOK(method, resp.StatusCode) {
			return fmt.Errorf("failed to set %s '%s' with status code: %d", endpoint, k, resp.StatusCode)
		}

		log.Printf("successfully set %s '%s' with status code: %d", endpoint, k, resp.StatusCode)
	}
	return nil
}

func init() {
	apiURL = cmp.Or(
		githubactions.GetInput("base_url"),
		os.Getenv("GITHUB_API_URL"),
		"https://api.github.com",
	)

	token = cmp.Or(
		githubactions.GetInput("token"),
		os.Getenv("GH_TOKEN"),
		os.Getenv("GITHUB_TOKEN"),
	)

	repo = cmp.Or(
		githubactions.GetInput("repository"),
		os.Getenv("GITHUB_REPOSITORY"),
	)

	environment = cmp.Or(
		githubactions.GetInput("environment"),
		os.Getenv("GITHUB_ENVIRONMENT"),
		"",
	)

	variablesData := []byte(githubactions.GetInput("variables"))
	err := json.Unmarshal(
		variablesData,
		&variablesMap,
	)
	if err != nil {
		githubactions.Fatalf("failed to unmarshal variables: %v", err)
	}

	secretsData := []byte(githubactions.GetInput("secrets"))
	err = json.Unmarshal(
		secretsData,
		&secretsMap,
	)
	if err != nil {
		githubactions.Fatalf("failed to unmarshal secrets: %v", err)
	}
}

func main() {
	config := GetHttpConfig()

	log.Printf("requesting environment URL: %s", config.BaseURL)

	getResp, err := HttpRequest(config, http.MethodGet, config.BaseURL, nil)
	if err != nil {
		githubactions.Fatalf("failed %s request to %s: %v", http.MethodGet, config.BaseURL, err)
	}

	if getResp.StatusCode == http.StatusNotFound {
		if delete {
			log.Printf("environment '%s' not found, nothing to delete", environment)
			return
		}
		log.Printf("environment '%s' not found, creating it", environment)

		createEnvResp, err := HttpRequest(config, http.MethodPut, config.BaseURL, nil)
		if err != nil {
			githubactions.Fatalf("failed %s request to %s: %v", http.MethodPut, config.BaseURL, err)
		}

		if createEnvResp.StatusCode != http.StatusOK {
			githubactions.Fatalf("failed to create environment '%s' with status code: %d", environment, createEnvResp.StatusCode)
		}

		log.Printf("successfully created environment '%s' with status code: %d", environment, createEnvResp.StatusCode)
	}

	log.Printf("environment '%s' found", environment)

	if delete {
		log.Printf("deleting environment '%s'", environment)
		deleteResp, _ := HttpRequest(config, http.MethodDelete, config.BaseURL, nil)
		if !HttpStatusOK(http.MethodDelete, deleteResp.StatusCode) {
			githubactions.Fatalf("failed to delete environment %s: %d", config.BaseURL, deleteResp.StatusCode)
		}

		log.Printf("successfully deleted environment '%s'", environment)
		return
	}
}
