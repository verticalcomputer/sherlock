package remediation

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

// RecipeReleaseSchemaVersion separates recipe signatures from every other
// signed Sherlock document.  A signature over a command pack can therefore
// never be replayed as a recipe release.
const RecipeReleaseSchemaVersion = "sherlock.remediation-recipe-release.v1"

var (
	ErrInvalidRecipeRelease = errors.New("invalid remediation recipe release")
	ErrUnknownRecipeRoot    = errors.New("unknown remediation recipe trust root")
	ErrInactiveRecipeRoot   = errors.New("inactive remediation recipe trust root")
	ErrBadRecipeSignature   = errors.New("invalid remediation recipe signature")
)

// RecipeTrustRoot is an offline-reviewed Ed25519 verification key.  Private
// keys never enter the catalog or executor APIs.
type RecipeTrustRoot struct {
	ID          string
	Issuer      string
	PublicKey   ed25519.PublicKey
	ActivatesAt time.Time
	RetiresAt   time.Time
}

// SignedRecipeRelease is the transport envelope for a complete recipe set.
// The signature covers the schema, selected root and every recipe's canonical
// bytes and digest.  It never covers a partially loaded subset.
type SignedRecipeRelease struct {
	SchemaVersion string
	TrustRootID   string
	Recipes       []Recipe
	Signature     []byte
}

// CanonicalReleaseBytes returns the exact preimage signed for a release.  It
// uses fixed-width counts and length-prefixed fields; no delimiter choice or
// JSON encoder setting participates in the trust decision.  Recipes are
// coordinate-sorted because their order is not meaningful to a catalog.
func CanonicalReleaseBytes(release SignedRecipeRelease) ([]byte, error) {
	if release.SchemaVersion != RecipeReleaseSchemaVersion || !domain.ValidRemediationToken(release.TrustRootID) {
		return nil, fmt.Errorf("%w: envelope identity is invalid", ErrInvalidRecipeRelease)
	}
	if len(release.Recipes) == 0 || len(release.Recipes) > maxRecipeCollection {
		return nil, fmt.Errorf("%w: recipe count is invalid", ErrInvalidRecipeRelease)
	}
	recipes := make([]Recipe, len(release.Recipes))
	for index, recipe := range release.Recipes {
		recipes[index] = cloneRecipe(recipe)
	}
	slices.SortFunc(recipes, func(left, right Recipe) int {
		leftKey, rightKey := catalogKey(left.ID, left.Version), catalogKey(right.ID, right.Version)
		if leftKey < rightKey {
			return -1
		}
		if leftKey > rightKey {
			return 1
		}
		return 0
	})
	payload := make([]byte, 0, 1024*len(recipes))
	payload = appendField(payload, []byte(RecipeReleaseSchemaVersion))
	payload = appendField(payload, []byte(release.TrustRootID))
	payload = appendCount(payload, len(recipes))
	previous := ""
	for _, recipe := range recipes {
		key := catalogKey(recipe.ID, recipe.Version)
		if key == previous {
			return nil, fmt.Errorf("%w: duplicate recipe coordinate", ErrInvalidRecipeRelease)
		}
		previous = key
		payload = appendField(payload, recipe.CanonicalBytes())
		payload = appendField(payload, recipe.Digest[:])
	}
	return payload, nil
}

// SignRecipeRelease signs a complete recipe set.  It is provided for the
// release-building side and test fixtures; a runtime has only RecipeTrustRoot
// public keys and Verify.
func SignRecipeRelease(recipes []Recipe, trustRootID string, privateKey ed25519.PrivateKey) (SignedRecipeRelease, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedRecipeRelease{}, fmt.Errorf("%w: signing key is invalid", ErrInvalidRecipeRelease)
	}
	release := SignedRecipeRelease{SchemaVersion: RecipeReleaseSchemaVersion, TrustRootID: trustRootID, Recipes: recipes}
	payload, err := CanonicalReleaseBytes(release)
	if err != nil {
		return SignedRecipeRelease{}, err
	}
	release.Signature = ed25519.Sign(privateKey, payload)
	return release, nil
}

// RecipeTrustStore contains only defensive copies of public trust roots.
type RecipeTrustStore struct{ roots map[string]RecipeTrustRoot }

func NewRecipeTrustStore(roots []RecipeTrustRoot) (*RecipeTrustStore, error) {
	if len(roots) == 0 {
		return nil, fmt.Errorf("recipe trust store requires a root")
	}
	store := &RecipeTrustStore{roots: make(map[string]RecipeTrustRoot, len(roots))}
	for _, root := range roots {
		if !domain.ValidRemediationToken(root.ID) || !domain.ValidRemediationToken(root.Issuer) || len(root.PublicKey) != ed25519.PublicKeySize || !canonicalRecipeTime(root.ActivatesAt) || !canonicalRecipeTime(root.RetiresAt) || !root.RetiresAt.After(root.ActivatesAt) {
			return nil, fmt.Errorf("recipe trust root %q is invalid", root.ID)
		}
		if _, exists := store.roots[root.ID]; exists {
			return nil, fmt.Errorf("duplicate recipe trust root %q", root.ID)
		}
		root.PublicKey = bytes.Clone(root.PublicKey)
		store.roots[root.ID] = root
	}
	return store, nil
}

// Verify checks the selected root, its validity at the server-causal instant,
// and the signature before admitting any executable catalog entry.  Catalog
// construction then performs digest, expiry and rollback-containment checks.
func (store *RecipeTrustStore) Verify(release SignedRecipeRelease, now time.Time) (*Catalog, error) {
	// now is an observation supplied by the local verifier, not signed release
	// data. It may carry sub-second precision from clock_timestamp and must not
	// make an otherwise valid release unusable.
	if store == nil || now.IsZero() {
		return nil, fmt.Errorf("%w: verification inputs are invalid", ErrInvalidRecipeRelease)
	}
	now = now.UTC()
	root, exists := store.roots[release.TrustRootID]
	if !exists {
		return nil, ErrUnknownRecipeRoot
	}
	if now.Before(root.ActivatesAt) || !now.Before(root.RetiresAt) {
		return nil, ErrInactiveRecipeRoot
	}
	payload, err := CanonicalReleaseBytes(release)
	if err != nil {
		return nil, err
	}
	if len(release.Signature) != ed25519.SignatureSize || !ed25519.Verify(root.PublicKey, payload, release.Signature) {
		return nil, ErrBadRecipeSignature
	}
	return newCatalog(release.Recipes, now, true, root.RetiresAt)
}

func canonicalRecipeTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond() == 0
}
