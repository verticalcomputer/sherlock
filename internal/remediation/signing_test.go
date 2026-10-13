package remediation

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func signedRecipeCatalog(t *testing.T) (*Catalog, SignedRecipeRelease, *RecipeTrustStore) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	release, err := SignRecipeRelease(BuiltinRecipes(testExpiry()), "recipe-root-1", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewRecipeTrustStore([]RecipeTrustRoot{{
		ID: "recipe-root-1", Issuer: "sherlock.release", PublicKey: publicKey,
		ActivatesAt: testInstant().Add(-time.Hour), RetiresAt: testInstant().Add(time.Hour),
	}})
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := store.Verify(release, testInstant())
	if err != nil {
		t.Fatal(err)
	}
	return catalog, release, store
}

func TestRecipeTrustStoreVerifiesReleaseBeforeCatalogAdmission(t *testing.T) {
	catalog, release, store := signedRecipeCatalog(t)
	if !catalog.Verified() || catalog.Len() != 2 {
		t.Fatal("verified release did not produce a verified complete catalog")
	}
	plain, err := NewCatalog(BuiltinRecipes(testExpiry()), testInstant())
	if err != nil || plain.Verified() {
		t.Fatalf("plain catalog verified=%v err=%v", plain.Verified(), err)
	}
	if _, err := store.Verify(release, testInstant().Add(time.Nanosecond)); err != nil {
		t.Fatalf("subsecond verifier instant rejected: %v", err)
	}
}

func TestRecipeReleaseSignatureCoversEveryRecipeFieldAndDigest(t *testing.T) {
	catalog, release, store := signedRecipeCatalog(t)
	if catalog == nil {
		t.Fatal("missing baseline catalog")
	}
	for _, mutate := range []func(*SignedRecipeRelease){
		func(r *SignedRecipeRelease) { r.Recipes[0].Operation = OperationEvidenceCollectionRestore },
		func(r *SignedRecipeRelease) { r.Recipes[0].Digest[0] ^= 0xff },
		func(r *SignedRecipeRelease) { r.TrustRootID = "other-root" },
	} {
		altered := release
		altered.Recipes = append([]Recipe(nil), release.Recipes...)
		mutate(&altered)
		if _, err := store.Verify(altered, testInstant()); err == nil {
			t.Fatal("tampered release reached catalog construction")
		}
	}
}

func TestRecipeTrustStoreRejectsInactiveUnknownAndBadSignature(t *testing.T) {
	_, release, _ := signedRecipeCatalog(t)
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewRecipeTrustStore([]RecipeTrustRoot{{ID: "recipe-root-1", Issuer: "sherlock.release", PublicKey: publicKey, ActivatesAt: testInstant().Add(-time.Hour), RetiresAt: testInstant().Add(time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Verify(release, testInstant()); !errors.Is(err, ErrBadRecipeSignature) {
		t.Fatalf("err=%v", err)
	}
	release.TrustRootID = "unknown"
	if _, err := store.Verify(release, testInstant()); !errors.Is(err, ErrUnknownRecipeRoot) {
		t.Fatalf("err=%v", err)
	}
}

func TestRecipeTrustStoreRejectsExpiredRecipeAfterSignatureVerification(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stale := BuiltinRecipes(testInstant().Add(-time.Second))
	release, err := SignRecipeRelease(stale, "recipe-root-1", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewRecipeTrustStore([]RecipeTrustRoot{{ID: "recipe-root-1", Issuer: "sherlock.release", PublicKey: publicKey, ActivatesAt: testInstant().Add(-time.Hour), RetiresAt: testInstant().Add(time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	if catalog, err := store.Verify(release, testInstant()); catalog != nil || err == nil {
		t.Fatal("expired signed recipe was admitted")
	}
}
