package alertassessment

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var ErrInvalid = errors.New("invalid assessment contract")
var timeType = reflect.TypeFor[time.Time]()
var rawType = reflect.TypeFor[json.RawMessage]()

func parseJSON(data []byte) (any, error) {
	if !utf8.Valid(data) || !validEscapedUnicode(data) {
		return nil, ErrInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := readValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err = dec.Token(); err != io.EOF {
		return nil, ErrInvalid
	}
	return v, nil
}

// encoding/json replaces unmatched UTF-16 surrogates with U+FFFD. Reject them
// before decoding so invalid input cannot share the identity of a valid string.
func validEscapedUnicode(data []byte) bool {
	var quoted bool
	for i := 0; i < len(data); i++ {
		switch data[i] {
		case '"':
			quoted = !quoted
		case '\\':
			if !quoted || i+1 >= len(data) {
				return false
			}
			i++
			if data[i] != 'u' {
				continue
			}
			if i+5 > len(data) {
				return false
			}
			value, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
			if err != nil || value >= 0xdc00 && value <= 0xdfff {
				return false
			}
			i += 4
			if value < 0xd800 || value > 0xdbff {
				continue
			}
			if i+7 > len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}

// DecodeStrict checks exact field names and presence before decoding. Opaque
// RawMessage objects are structurally bounded here and typed by their owner.
func DecodeStrict(data []byte, dst any, limit int) error {
	if len(data) == 0 || len(data) > limit {
		return ErrInvalid
	}
	v, err := parseJSON(data)
	if err != nil {
		return err
	}
	target := reflect.ValueOf(dst)
	if !target.IsValid() || target.Kind() != reflect.Pointer || target.IsNil() {
		return ErrInvalid
	}
	if err = shape(v, target.Type().Elem()); err != nil {
		return err
	}
	typed := reflect.New(target.Type().Elem())
	if err := json.Unmarshal(data, typed.Interface()); err != nil {
		return err
	}
	target.Elem().Set(typed.Elem())
	return nil
}
func readValue(d *json.Decoder, depth int) (any, error) {
	if depth > 16 {
		return nil, ErrInvalid
	}
	tok, e := d.Token()
	if e != nil {
		return nil, ErrInvalid
	}
	switch x := tok.(type) {
	case json.Delim:
		if x == '{' {
			m := map[string]any{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return nil, ErrInvalid
				}
				s, ok := k.(string)
				if !ok || len(m) >= 64 {
					return nil, ErrInvalid
				}
				if _, ok = m[s]; ok {
					return nil, ErrInvalid
				}
				v, e := readValue(d, depth+1)
				if e != nil {
					return nil, e
				}
				m[s] = v
			}
			_, e = d.Token()
			return m, e
		}
		if x == '[' {
			a := []any{}
			for d.More() {
				v, e := readValue(d, depth+1)
				if e != nil {
					return nil, e
				}
				a = append(a, v)
			}
			_, e = d.Token()
			return a, e
		}
		return nil, ErrInvalid
	case nil:
		return nil, ErrInvalid
	case json.Number:
		f, e := strconv.ParseFloat(string(x), 64)
		if e != nil || math.IsInf(f, 0) || math.IsNaN(f) {
			return nil, ErrInvalid
		}
		return x, nil
	default:
		return tok, nil
	}
}
func shape(v any, t reflect.Type) error {
	if t.Kind() == reflect.Pointer {
		return shape(v, t.Elem())
	}
	if t == rawType {
		if _, ok := v.(map[string]any); !ok {
			return ErrInvalid
		}
		return nil
	}
	if t == timeType {
		s, ok := v.(string)
		if !ok || !strings.HasSuffix(s, "Z") || (len(s) != 20 && (len(s) < 22 || len(s) > 30 || s[19] != '.')) {
			return ErrInvalid
		}
		_, e := time.Parse(time.RFC3339Nano, s)
		return e
	}
	switch t.Kind() {
	case reflect.Struct:
		m, ok := v.(map[string]any)
		if !ok {
			return ErrInvalid
		}
		known := map[string]bool{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			tag := strings.Split(f.Tag.Get("json"), ",")
			name := tag[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = f.Name
			}
			known[name] = true
			value, exists := m[name]
			optional := len(tag) > 1 && tag[1] == "omitempty"
			if !exists {
				if !optional {
					return fmt.Errorf("%w: missing %s", ErrInvalid, name)
				}
				continue
			}
			if e := shape(value, f.Type); e != nil {
				return fmt.Errorf("%w: %s", ErrInvalid, name)
			}
		}
		for k := range m {
			if !known[k] {
				return fmt.Errorf("%w: unknown field", ErrInvalid)
			}
		}
	case reflect.Slice, reflect.Array:
		a, ok := v.([]any)
		if !ok {
			return ErrInvalid
		}
		if t.Kind() == reflect.Array && len(a) != t.Len() {
			return ErrInvalid
		}
		for _, x := range a {
			if e := shape(x, t.Elem()); e != nil {
				return e
			}
		}
	case reflect.String:
		if _, ok := v.(string); !ok {
			return ErrInvalid
		}
	case reflect.Bool:
		if _, ok := v.(bool); !ok {
			return ErrInvalid
		}
	case reflect.Int, reflect.Int64, reflect.Int32:
		n, ok := v.(json.Number)
		if !ok {
			return ErrInvalid
		}
		i, e := strconv.ParseInt(n.String(), 10, t.Bits())
		if e != nil || i < 0 {
			return ErrInvalid
		}
	case reflect.Uint64:
		n, ok := v.(json.Number)
		if !ok {
			return ErrInvalid
		}
		if _, err := strconv.ParseUint(n.String(), 10, 64); err != nil {
			return ErrInvalid
		}
	case reflect.Float64:
		if _, ok := v.(json.Number); !ok {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

// Canonical normalizes typed floats/timestamps, then sorts keys without losing
// int64 precision. RawMessage must already contain typed canonical JSON.
func Canonical(v any) ([]byte, error) {
	normalized, e := normalize(reflect.ValueOf(v), 0)
	if e != nil {
		return nil, e
	}
	return json.Marshal(normalized)
}
func normalize(v reflect.Value, depth int) (any, error) {
	if !v.IsValid() || depth > 16 {
		return nil, ErrInvalid
	}
	if v.Kind() == reflect.Interface || v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil, ErrInvalid
		}
		return normalize(v.Elem(), depth)
	}
	if v.Type() == timeType {
		t := normalizeTime(v.Interface().(time.Time))
		if t.Year() < 1 || t.Year() > 9999 {
			return nil, ErrInvalid
		}
		return t.Format(time.RFC3339Nano), nil
	}
	if v.Type() == rawType {
		x, e := parseJSON(v.Bytes())
		if _, ok := x.(map[string]any); e != nil || !ok {
			return nil, ErrInvalid
		}
		return x, nil
	}
	switch v.Kind() {
	case reflect.Struct:
		m := map[string]any{}
		t := v.Type()
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			parts := strings.Split(f.Tag.Get("json"), ",")
			name := parts[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = f.Name
			}
			fv := v.Field(i)
			if len(parts) > 1 && parts[1] == "omitempty" && emptyJSONField(fv) {
				continue
			}
			x, e := normalize(fv, depth+1)
			if e != nil {
				return nil, e
			}
			m[name] = x
		}
		return m, nil
	case reflect.Map:
		if v.Type().Key().Kind() != reflect.String || v.Len() > 64 {
			return nil, ErrInvalid
		}
		m := map[string]any{}
		it := v.MapRange()
		for it.Next() {
			if !utf8.ValidString(it.Key().String()) {
				return nil, ErrInvalid
			}
			x, e := normalize(it.Value(), depth+1)
			if e != nil {
				return nil, e
			}
			m[it.Key().String()] = x
		}
		return m, nil
	case reflect.Slice, reflect.Array:
		a := make([]any, v.Len())
		for i := range a {
			x, e := normalize(v.Index(i), depth+1)
			if e != nil {
				return nil, e
			}
			a[i] = x
		}
		return a, nil
	case reflect.Float64, reflect.Float32:
		f := v.Float()
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, ErrInvalid
		}
		if f == 0 {
			f = 0
		}
		return f, nil
	case reflect.String:
		if !utf8.ValidString(v.String()) {
			return nil, ErrInvalid
		}
		return v.Interface(), nil
	default:
		return v.Interface(), nil
	}
}

func emptyJSONField(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	default:
		return v.IsZero()
	}
}

func normalizeTime(t time.Time) time.Time { return t.UTC().Truncate(time.Microsecond) }

func durableTime(t time.Time) bool {
	return !t.IsZero() && t.Location() == time.UTC && t.Year() >= 1 && t.Year() <= 9999 && t.Nanosecond()%1000 == 0
}
func Hash(kind, category string, version int64, body []byte) string {
	h := sha256.New()
	h.Write([]byte("sherlock-assessment-v1\x00"))
	for _, b := range [][]byte{[]byte(kind), []byte(category), []byte(strconv.FormatInt(version, 10)), body} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))
}
func Identity(kind, category string, v any) (string, error) {
	b, e := Canonical(v)
	if e != nil {
		return "", e
	}
	return Hash(kind, category, 1, b), nil
}
func NewPayload(category, kind string, schema int64, v any) (Payload, error) {
	b, e := Canonical(v)
	if e != nil {
		return Payload{}, e
	}
	p := Payload{category, kind, schema, Hash(kind, category, schema, b), b}
	return p, ValidatePayload(p, category, kind, schema)
}
func ValidatePayload(p Payload, category, kind string, schema int64) error {
	var limit int
	switch kind {
	case "policy", "tracker", "candidate":
		limit = MaxPayloadBytes
	case "details":
		limit = MaxDetailsBytes
	default:
		return ErrInvalid
	}
	if !ValidID(category, 128) || p.Category != category || p.Kind != kind || p.Schema != schema || schema < 1 || len(p.Body) > limit || !ValidHash(p.Hash) {
		return ErrInvalid
	}
	x, e := parseJSON(p.Body)
	if e != nil {
		return ErrInvalid
	}
	if _, ok := x.(map[string]any); !ok {
		return ErrInvalid
	}
	b, e := json.Marshal(x)
	if e != nil || !bytes.Equal(b, p.Body) || Hash(kind, category, schema, b) != p.Hash {
		return ErrInvalid
	}
	return nil
}

func hashSet(xs []string, max int) error {
	if xs == nil || len(xs) > max {
		return ErrInvalid
	}
	for i, x := range xs {
		if !ValidHash(x) || i > 0 && xs[i-1] >= x {
			return ErrInvalid
		}
	}
	return nil
}
func ValidID(s string, max int) bool {
	return len(s) > 0 && len(s) <= max && utf8.ValidString(s) && strings.IndexFunc(s, unicode.IsControl) < 0
}
func ValidHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}
func Set(xs []string, max int) error {
	if xs == nil || len(xs) > max {
		return ErrInvalid
	}
	for i, s := range xs {
		if !ValidID(s, 128) || i > 0 && xs[i-1] >= s {
			return ErrInvalid
		}
	}
	return nil
}
func SortedUnique(xs []string) []string {
	r := append([]string{}, xs...)
	sort.Strings(r)
	out := r[:0]
	for _, s := range r {
		if len(out) == 0 || out[len(out)-1] != s {
			out = append(out, s)
		}
	}
	return out
}
func Clone[T any](v T) (T, error) {
	b, e := Canonical(v)
	var out T
	if e == nil {
		e = json.Unmarshal(b, &out)
	}
	return out, e
}
