package telemetry

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"
)

// DecodeNodeBatch accepts one bounded identity-encoded strict JSON object.
// Duplicate keys are rejected before unmarshaling, avoiding parser-dependent
// identity/signature interpretation. Signature and authority validation follow.
func DecodeNodeBatch(body []byte, contentEncoding string) (NodeBatch, error) {
	var batch NodeBatch
	if len(body) > MaxNodeBatchBytes {
		return batch, ErrInvalid
	}
	if err := DecodeStrictJSON(body, contentEncoding, &batch); err != nil {
		return NodeBatch{}, err
	}
	if _, err := CanonicalDigest(batch); err != nil {
		return NodeBatch{}, err
	}
	return batch, nil
}

// DecodeStrictJSON applies the same bounded, exact-key schema rules to cloud
// envelopes and lifecycle messages. encoding/json's case-insensitive field
// matching is deliberately excluded: distinct wire keys cannot alias identity.
func DecodeStrictJSON(body []byte, contentEncoding string, target any) error {
	t := reflect.TypeOf(target)
	if t == nil || t.Kind() != reflect.Pointer || reflect.ValueOf(target).IsNil() {
		return ErrInvalid
	}
	if len(body) == 0 || len(body) > MaxBatchBytes || !utf8.Valid(body) || (contentEncoding != "" && !strings.EqualFold(contentEncoding, "identity")) {
		return ErrInvalidBatch
	}
	tokens := json.NewDecoder(bytes.NewReader(body))
	tokens.UseNumber()
	if err := uniqueJSON(tokens, 0); err != nil {
		return ErrInvalidBatch
	}
	if _, err := tokens.Token(); err != io.EOF {
		return ErrInvalidBatch
	}
	if err := exactJSONShape(body, t.Elem(), 0); err != nil {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrInvalid
	}
	return nil
}

func exactJSONShape(body []byte, t reflect.Type, depth int) error {
	if depth > 16 {
		return ErrInvalid
	}
	body = bytes.TrimSpace(body)
	if t.Kind() == reflect.Pointer {
		if bytes.Equal(body, []byte("null")) {
			return nil
		}
		return exactJSONShape(body, t.Elem(), depth)
	}
	if t == reflect.TypeOf(time.Time{}) {
		if len(body) == 0 || body[0] != '"' {
			return ErrInvalid
		}
		return nil
	}
	switch t.Kind() {
	case reflect.Struct:
		var object map[string]json.RawMessage
		if len(body) == 0 || body[0] != '{' || json.Unmarshal(body, &object) != nil {
			return ErrInvalid
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = f.Name
			}
			fields[name] = f.Type
		}
		for key, value := range object {
			field, ok := fields[key]
			if !ok {
				return ErrInvalid
			}
			if err := exactJSONShape(value, field, depth+1); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		if t.Kind() == reflect.Slice && bytes.Equal(body, []byte("null")) {
			return nil
		}
		var array []json.RawMessage
		if len(body) == 0 || body[0] != '[' || json.Unmarshal(body, &array) != nil || len(array) > MaxRecords {
			return ErrInvalid
		}
		for _, v := range array {
			if err := exactJSONShape(v, t.Elem(), depth+1); err != nil {
				return err
			}
		}
	case reflect.String:
		if len(body) == 0 || body[0] != '"' {
			return ErrInvalid
		}
	case reflect.Bool:
		if !bytes.Equal(body, []byte("true")) && !bytes.Equal(body, []byte("false")) {
			return ErrInvalid
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64:
		if len(body) == 0 || body[0] != '-' && (body[0] < '0' || body[0] > '9') {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func uniqueJSON(d *json.Decoder, depth int) error {
	if depth > 16 {
		return ErrInvalidBatch
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		keys := map[string]bool{}
		for d.More() {
			t, err := d.Token()
			if err != nil {
				return err
			}
			key, ok := t.(string)
			if !ok || keys[key] || len(keys) >= 64 {
				return ErrInvalidBatch
			}
			keys[key] = true
			if err := uniqueJSON(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return ErrInvalidBatch
		}
	case '[':
		count := 0
		for d.More() {
			count++
			if count > MaxRecords {
				return ErrInvalidBatch
			}
			if err := uniqueJSON(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return ErrInvalidBatch
		}
	default:
		return ErrInvalidBatch
	}
	return nil
}
