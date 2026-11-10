//go:build !linux

package controlplane

func readUploadServerKey(path string) ([]byte, error) {
	return ReadProtectedPrivateKey(path)
}
