/*
 *  Copyright IBM Corporation 2021
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package common

import (
	"os"
	"os/exec"
	"path/filepath"

	"github.com/sirupsen/logrus"
)

const ibmHyperProtectCert = `-----BEGIN CERTIFICATE-----
MIIF8TCCA9mgAwIBAgIQLKNAizePV1jGkvBknjjfOzANBgkqhkiG9w0BAQ0FADCB
0TELMAkGA1UEBhMCREUxGzAZBgNVBAgMEkJhZGVuLVfDvHJ0dGVtYmVyZzETMBEG
A1UEBwwKQsO2YmxpbmdlbjE0MDIGA1UECgwrSUJNIERldXRzY2hsYW5kIFJlc2Vh
cmNoICYgRGV2ZWxvcG1lbnQgR21iSDEkMCIGA1UECxMbSUJNIFogSHlicmlkIENs
b3VkIFBsYXRmb3JtMTQwMgYDVQQDDCtJQk0gRGV1dHNjaGxhbmQgUmVzZWFyY2gg
JiBEZXZlbG9wbWVudCBHbWJIMB4XDTIyMDkwMjE2NTc0N1oXDTQyMDkwMjE2NTc1
N1owgZYxCzAJBgNVBAYTAkRFMQswCQYDVQQIEwJCVzETMBEGA1UEBxMKQm9lYmxp
bmdlbjEhMB8GA1UECgwYSUJNIERldXRzY2hsYW5kIFImRCBHbWJIMSQwIgYDVQQL
ExtJQk0gWiBIeWJyaWQgQ2xvdWQgUGxhdGZvcm0xHDAaBgNVBAMTE2NvbnRyYWN0
LWRlY3J5cHRpb24wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDI9Jx9
NXPsbONFVqIsXfzB/4WI4Kj070AxveF8QHTMb8mQ8KOD5ZDs6Ug1fli2JbxFPfvK
oFD0v1FNsxBhjWHAkq8LpeIzrG0YVLmDcjQqEaJQd58YK8GygOLy7qoRMedsVr2X
+MIqxJda06tc/O3GrM4swZRQVh7I0BHB9cJ3mLbh7St3vmhBpNZt9EKIgTJUGFUH
gTpeZuh2AjOcKsdrbzfGcs+4q1CstVNZ9eECVc27JPAzzrfzS8ZRlLJPOVEVDj1Z
gs3rA36eTxRMC0XuJC+mgKASJsFKygYQmfbs1mzIN0oIzsewjHM6AywuJ21Srjaq
gMSaRKzfpnMELJqWpIKFDGjj+p6anp8zJPYQy9IrOG8ifgCg+LhVGQ6mx3xMgY3m
H9Mwcto/ox6mkLf/7JYWK2RoAZEJRuojuMpOfeOLEkkzkBgzgD2JLh2ps+Zc7YxE
I9O02vMHUHhamqLyjD1OOBUBbYQ+W+28svbMgr3m5F8ILzXVWTnT6+h6WStXhLbk
zUIsAWconRt6g3A6Y9UCeK252j3ITjKPlcduICZkkcnaj73VDACRmoOVBPrnb2Ex
YfXhibBlwPcGyUV+GwlZgs5IN+X8GIU0I6QFFUUh3+BhgbVu8Rei0CKl52aRyFTe
w9wo0abntwYLQlovZLNsPtMeZIGO/P37IMelGwIDAQABMA0GCSqGSIb3DQEBDQUA
A4ICAQAgBhbamlqQlOYNgyOOPnuDNRe/LEshv+yeHS5Yqjgb/o5WzhHQNla6kQpD
TgbYvF70Qkj3agSH6+M6C+mmdgzGNQOWhnPBPtDiySOn8BvlhIvcsOz/OQyIi0Se
4vqiKPQmGUJ9aZCmzmkKbzUIpWJZy8XOcG15a5lW1OIDIVl7qRehZDQ0MqhYk5yQ
hXG/0o50APhSJ3fN6ulcdP/BfMGQmHs3fRHiaOMxJvJC/obUSDCgDIrBodAk2GvW
8aKEu2yRS1RoespumrkB621eULWhTQ//M31JlvBSo5daulOcjfBeCmGcQGQFJs45
hsTkLfltYf6nkFxzrjPvaRMT9xGmXFUkMrr163P2f0ngDp2BopqAGaVT/yD4llOs
Li5o5ZEcSOhILypa141pGwDBK/7IGv35zicO39VlpKsF/sRej4xPMkZOSlBSAgQf
oDJ6NLx69TtmcDpz0nU9y4yjZQDWj2CiG8yK5Lr9ayq8ayOneJr3Krh0bJ43izD2
19UeNHaQrN94ylMNAyNB+2QrOtkAYuu0XKYuEDYaKx5V9w0Oodc2RJVZVt4PeHyY
BxB0v4gNdfr/ESjrmwHfQJh1wQYMG6mUUHseIGKwb7qLaHIp7Nxxc1bydlxEHqqB
bF0c1daNoz1JrAL6rrhMRMT8TQZTw+n/+R3HDbdIWG9alxtNbg==
-----END CERTIFICATE-----`

// RsaUtlEnc can be used to encrypt the data using RSA PKCS1v15 algorithm with certificate as key
func RsaUtlEnc(certificate string, data string) string {
	// if certificate == "" {
	// 	logrus.Info("using certificate from IBM Hyper Protect Container Runtime")
	// 	certificate = ibmHyperProtectCert
	// }
	// block, _ := pem.Decode([]byte(certificate))
	// cert, err := x509.ParseCertificate(block.Bytes)
	// if err != nil {
	// 	logrus.Error("invalid certificate : ", err)
	// }
	// rsaPublicKey := cert.PublicKey.(*rsa.PublicKey)
	// out, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPublicKey, []byte(data))
	// // out, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, rsaPublicKey, []byte(data), nil)

	// if err != nil {
	// 	logrus.Error("could not encrypt the data using RSA algorithm : ", err)
	// }
	// return base64.StdEncoding.EncodeToString(out)

	// read the whole file at once
	// b, err := os.ReadFile("input.txt")
	// if err != nil {
	// 	panic(err)
	// }

	// write the whole body at once
	dataLoc := filepath.Join(os.TempDir(), "rsadata.txt")
	certLoc := filepath.Join(os.TempDir(), "rsacert.crt")
	err := os.WriteFile(dataLoc, []byte(data), 0777)
	if err != nil {
		logrus.Error("unable to create temp data file to encrypt : ", err)
	}

	err = os.WriteFile(certLoc, []byte(ibmHyperProtectCert), 0777)
	if err != nil {
		logrus.Error("unable to create temp cert file : %s", err)
	}
	out, err := exec.Command("openssl", "rsautl", "-encrypt", "-inkey", certLoc, "-certin", "-in", dataLoc).CombinedOutput()
	if err != nil {
		logrus.Errorf("Error while running openssl rsautl: %s", err)
	}
	// err = os.Remove(dataLoc)
	// if err != nil {
	// 	logrus.Errorf("unable to delete rsa temp data file : %s", err)
	// }
	// err = os.Remove(certLoc)
	// if err != nil {
	// 	logrus.Errorf("unable to delete rsa temp cert file : %s", err)
	// }
	return string(out)
}

// func deriveKey(passphrase string, salt []byte) ([]byte, error) {
// 	s := "74B2D5262919A4DE"
// 	decoded, err := hex.DecodeString(s)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	// if salt == nil {
// 	// 	salt = make([]byte, 8)
// 	// 	_, err := rand.Read(salt)
// 	// 	if err != nil {
// 	// 		return []byte{}, err
// 	// 	}
// 	// }
// 	return pbkdf2.Key([]byte(passphrase), decoded, 10000, 48, sha256.New), nil
// }

// func pad(src []byte) []byte {
// 	padding := aes.BlockSize - len(src)%aes.BlockSize
// 	padtext := make([]byte, padding)
// 	return append(src, padtext...)
// }

// AesEncrypt can be used to encrypt the data using AES 256 CBC pbkdf2 algorithm with a textual key
func AesEncrypt(key string, data string) string {
	// logrus.Info(text)
	// logrus.Info(key)
	// keyandiv, err := deriveKey(key, nil)
	// if err != nil {
	// 	logrus.Error("failed to derive key with pbkdf2 : ", err)
	// }
	// iv := keyandiv[32:]
	// dKey := keyandiv[:32]
	// block, err := aes.NewCipher(dKey)
	// if err != nil {
	// 	logrus.Error("failed to create a new cipher : ", err)
	// }

	// msg := pad([]byte(text))
	// ciphertext := make([]byte, len(msg))

	// cfb := cipher.NewCBCEncrypter(block, iv)
	// cfb.CryptBlocks(ciphertext, msg)
	// return base64.StdEncoding.EncodeToString(ciphertext)
	dataLoc := filepath.Join(os.TempDir(), "aesdata.yaml")
	err := os.WriteFile(dataLoc, []byte(data), 0777)
	if err != nil {
		logrus.Error("unable to create temp data file to encrypt : ", err)
	}
	out, err := exec.Command("openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-pass", "pass:"+key, "-in", dataLoc).CombinedOutput()
	if err != nil {
		logrus.Errorf("Error while running openssl rsautl: %s", err)
	}
	// err = os.Remove(dataLoc)
	// if err != nil {
	// 	logrus.Errorf("unable to delete aes temo data file : %s", err)
	// }
	return string(out)
}
