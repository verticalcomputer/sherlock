package config

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

const localEnvMaximumBytes = 64 << 10

// loadLocalEnv loads a repository-local .env as data, never as shell code.
// Explicit process environment values, including explicitly empty values,
// always win over file values.
func loadLocalEnv() error { return loadEnvFile(".env") }

func loadEnvFile(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect local environment file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("local environment file must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("local environment file permissions must be 0600 or stricter")
	}
	if info.Size() > localEnvMaximumBytes {
		return fmt.Errorf("local environment file exceeds %d bytes", localEnvMaximumBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open local environment file: %w", err)
	}
	defer file.Close()
	values, err := parseEnv(file)
	if err != nil {
		return err
	}
	for name, value := range values {
		if _, exists := os.LookupEnv(name); exists {
			continue
		}
		if err := os.Setenv(name, value); err != nil {
			return fmt.Errorf("set local environment variable %s: %w", name, err)
		}
	}
	return nil
}

func parseEnv(reader io.Reader) (map[string]string, error) {
	values := make(map[string]string)
	scanner := bufio.NewScanner(io.LimitReader(reader, localEnvMaximumBytes+1))
	scanner.Buffer(make([]byte, 4096), localEnvMaximumBytes)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		name, encoded, found := strings.Cut(line, "=")
		name = strings.TrimSpace(name)
		if !found || !validEnvName(name) {
			return nil, fmt.Errorf("local environment file line %d is invalid", lineNumber)
		}
		if _, duplicate := values[name]; duplicate {
			return nil, fmt.Errorf("local environment file repeats %s", name)
		}
		value, err := decodeEnvValue(strings.TrimSpace(encoded))
		if err != nil {
			return nil, fmt.Errorf("local environment file value for %s is invalid", name)
		}
		values[name] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read local environment file: %w", err)
	}
	return values, nil
}

func validEnvName(name string) bool {
	if !strings.HasPrefix(name, "SHERLOCK_") || len(name) == len("SHERLOCK_") {
		return false
	}
	for _, character := range name {
		if character != '_' && (character < 'A' || character > 'Z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func decodeEnvValue(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if value[0] == '\'' {
		if len(value) < 2 || value[len(value)-1] != '\'' || strings.Contains(value[1:len(value)-1], "'") {
			return "", errors.New("invalid single-quoted value")
		}
		return value[1 : len(value)-1], nil
	}
	if value[0] == '"' {
		decoded, err := strconv.Unquote(value)
		if err != nil {
			return "", err
		}
		return decoded, nil
	}
	if strings.ContainsAny(value, "\x00\r\n") {
		return "", errors.New("invalid control character")
	}
	return value, nil
}
