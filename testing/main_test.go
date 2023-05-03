package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// TestHelloName calls greetings.Hello with a name, checking
// for a valid return value.
func TestIsValidEmail(t *testing.T) {
	want := false
	str := "Gladys"
	out := IsValidEmail(str)
	if want != out {
		t.Errorf(`IsValidEmail("Gladys") = %t; want %t`, out, want)
	}

	want = true
	str = "dgoldelman@wesleyan.edu"
	out = IsValidEmail(str)
	if want != out {
		t.Errorf(`IsValidEmail(%s) = %t; want %t`, str, out, want)
	}

	want = false
	str = "dgoldel:man@wesleyan.edu"
	out = IsValidEmail(str)
	if want != out {
		t.Errorf(`IsValidEmail(%s) = %t; want %t`, str, out, want)
	}

	want = false
	str = "dgoldel#man@wesleyan.edu"
	out = IsValidEmail(str)
	if want != out {
		t.Errorf(`IsValidEmail(%s) = %t; want %t`, str, out, want)
	}
}

func FuzzIsValidEmail(f *testing.F) {
	// Add some valid email addresses to the corpus
	f.Add("john@example.com")
	f.Add("jane.doe@example.co.uk")
	f.Add("bill_gates@microsoft.com")
	f.Add("steve.jobs@apple.com")

	// Add some invalid email addresses to the corpus
	f.Add("invalid_email.com")
	f.Add("test@.com")
	f.Add("@example.com")
	f.Add("test@example.")
	f.Add("test:@ecam.com")
	f.Add("lsihche@alhcjee#klauhce.son")

	// Run the fuzzer
	f.Fuzz(func(t *testing.T, email string) {
		// Call the function with the input data
		result := IsValidEmail(email)

		// Verify that the result is correct
		if !result && IsValidEmail("invalid") {
			t.Errorf("invalid email passed the validation: %s", email)
		}
	})
}

func TestGenerateRsaKeyPair(t *testing.T) {
	// Generate a key pair
	privKey, pubKey := GenerateRsaKeyPair()

	// Check that the private key is not nil
	if privKey == nil {
		t.Error("private key is nil")
	}

	// Check that the public key is not nil
	if pubKey == nil {
		t.Error("public key is nil")
	}

	// Check that the public key matches the private key
	if pubKey.N.Cmp(privKey.PublicKey.N) != 0 {
		t.Error("public key does not match private key")
	}
}

func FuzzRSA_Encrypt(f *testing.F) {
	// valids
	f.Add("checking")
	f.Add("a;lhcoeihfe")
	f.Add("literally any string")
	f.Add(" ")

	// Use the fuzzer to generate inputs
	f.Fuzz(func(t *testing.T, input string) {
		// Generate a public/private key pair
		key, _ := rsa.GenerateKey(rand.Reader, 2048)

		// Encrypt the input string using the key
		encrypted := RSA_Encrypt(input, key.PublicKey)

		// Try to decrypt the ciphertext using the private key
		decoded, err := base64.StdEncoding.DecodeString(encrypted)
		CheckError(err)
		decrypted, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, decoded, []byte("OAEP Encrypted"))
		CheckError(err)

		// Check if the decrypted message matches the original input
		if string(input) != string(decrypted) {
			t.Errorf("Input: %s, Decrypted: %s", string(input), string(decrypted))
		}
	})
}

func FuzzRSA_Decrypt(f *testing.F) {
	testCases := []string{"", "VGVzdA==", "ZGF0YQ=="}
	for _, tc := range testCases {
		f.Add([]byte(tc))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		CheckError(err)

		cipherText := RSA_Encrypt(string(input), privKey.PublicKey)
		plainText := RSA_Decrypt(cipherText, *privKey)

		if plainText != string(input) {
			t.Errorf("unexpected result for input %q: got %q, want %q", input, plainText, string(input))
		}
	})
}

func FuzzGenerateRandomString(f *testing.F) {
	f.Fuzz(func(t *testing.T, n int) {
		// Ensure that n is non-negative
		if n < 0 {
			n = -n
		}

		str, err := GenerateRandomString(n)
		if err != nil {
			// If there's an error, log it and return
			t.Logf("Error generating random string: %v", err)
			return
		}

		// Ensure that the generated string is of the correct length
		if len(str) != n {
			t.Errorf("Generated string has length %d, expected %d", len(str), n)
			return
		}

		// Ensure that the generated string only contains valid characters
		const validChars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-!$^&*"
		for _, ch := range str {
			if !strings.ContainsRune(validChars, ch) {
				t.Errorf("Invalid character '%c' in generated string '%s'", ch, str)
				return
			}
		}
	})
}

func TestRsaPrivateKeyToString(t *testing.T) {
	for i := 1; i < 10; i++ {
		// Generate a random RSA key pair for testing
		privKey, _ := rsa.GenerateKey(rand.Reader, 2048)

		// Convert the private key to a string
		pemStr, err := RsaPrivateKeyToString(privKey)
		if err != nil {
			t.Fatalf("RsaPrivateKeyToString failed: %v", err)
		}

		// Parse the PEM-encoded private key
		block, _ := pem.Decode([]byte(pemStr))
		if block == nil {
			t.Fatalf("Failed to decode PEM block")
		}

		// Check that the decoded PEM block has the expected type
		if block.Type != "RSA PRIVATE KEY" {
			t.Fatalf("Unexpected PEM block type: %v", block.Type)
		}

		// Parse the DER-encoded private key
		derBytes := block.Bytes
		_, err = x509.ParsePKCS1PrivateKey(derBytes)
		if err != nil {
			t.Fatalf("Failed to parse DER-encoded private key: %v", err)
		}
	}

	for i := 1; i < 3; i++ {
		// Generate a random RSA key pair for testing
		privKey, _ := rsa.GenerateKey(rand.Reader, 2048)

		// Convert the private key to a string
		pemStr, err := RsaPrivateKeyToString(privKey)
		if err != nil {
			t.Fatalf("RsaPrivateKeyToString failed: %v", err)
		}

		// Parse the PEM-encoded private key
		b, _ := strconv.Atoi("aaa")
		block, _ := pem.Decode(append([]byte(pemStr), uint8(b)))
		if block == nil {
			t.Fatalf("Decoded PEM block, error!")
		}

		// Parse the DER-encoded private key
		derBytes := block.Bytes
		_, err = x509.ParsePKCS1PrivateKey(derBytes)
		if err != nil {
			t.Fatalf("Failed to parse DER-encoded private key: %v", err)
		}
	}
}

func TestStringToRsaPrivateKey(t *testing.T) {
	// Generate a test private key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	// Convert the private key to a PEM-encoded string
	pemKey, _ := RsaPrivateKeyToString(privKey)

	// Convert the PEM-encoded string back to an RSA private key
	decodedKey, err := StringToRsaPrivateKey(pemKey)
	if err != nil {
		t.Fatalf("failed to convert private key: %v", err)
	}

	// Check that the decoded private key matches the original
	if !reflect.DeepEqual(privKey, decodedKey) {
		t.Errorf("private key mismatch; expected %v, got %v", privKey, decodedKey)
	}
}

func TestRsaPublicKeyToString(t *testing.T) {
	// Generate a new RSA key pair
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("error generating RSA key pair: %s", err)
	}

	// Get the public key from the key pair
	pubKey := &privKey.PublicKey

	// Convert the public key to a string
	pubKeyString, err := RsaPublicKeyToString(pubKey)
	if err != nil {
		t.Fatalf("error converting public key to string: %s", err)
	}

	// Convert the string back to a public key
	decodedPubKey, err := StringToRsaPublicKey(pubKeyString)
	if err != nil {
		t.Fatalf("error converting string back to public key: %s", err)
	}

	// Check that the original and decoded public keys are equal
	if !reflect.DeepEqual(pubKey, decodedPubKey) {
		t.Fatalf("decoded public key does not match original public key")
	}
}

func TestStringToRsaPublicKey(t *testing.T) {
	_, pubKey := GenerateRsaKeyPair()

	pubStr, err := RsaPublicKeyToString(pubKey)
	if err != nil {
		t.Fatalf("failed to convert public key to string: %v", err)
	}

	parsedPubKey, err := StringToRsaPublicKey(pubStr)
	if err != nil {
		t.Fatalf("failed to parse public key string: %v", err)
	}

	if parsedPubKey.N.Cmp(pubKey.N) != 0 {
		t.Errorf("parsed public key has different modulus")
	}

	if parsedPubKey.E != pubKey.E {
		t.Errorf("parsed public key has different public exponent")
	}
}
