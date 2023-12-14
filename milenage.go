package _5gAKA_go

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"strconv"
)

// LogicalXOR XOR for two hex string.
func LogicalXOR(hexStr1, hexStr2 string) string {
	var result string
	length := len(hexStr1)
	groupSize := 16
	for i := 0; i < length; i += groupSize {
		end := i + groupSize
		if end > length {
			end = length
		}
		subHexStr1 := hexStr1[i:end]
		subHexStr2 := hexStr2[i:end]
		num1, _ := strconv.ParseInt(subHexStr1, 16, 64)
		num2, _ := strconv.ParseInt(subHexStr2, 16, 64)
		xorResult := fmt.Sprintf("%X", num1^num2)
		if len(xorResult) != end-i {
			for j := 0; j < end-i-len(xorResult); j++ {
				xorResult = "0" + xorResult
			}
		}
		result += xorResult
	}
	return result
}

// Rotate Cycle right.
func Rotate(hexStr string, n int) string {
	num, _ := strconv.ParseInt(hexStr, 16, 64)
	binaryString := fmt.Sprintf("%064b", num)
	runes := []rune(binaryString)
	shiftedRunes := append(runes[len(runes)-n:], runes[:len(runes)-n]...)
	shiftedBinaryString := string(shiftedRunes)
	shiftedNum, _ := strconv.ParseUint(shiftedBinaryString, 2, 64)
	return fmt.Sprintf("%x", shiftedNum)
}

func AESEncrypt(key, plain string) string {
	newKey, _ := hex.DecodeString(key)
	newPlain, _ := hex.DecodeString(plain)
	block, _ := aes.NewCipher(newKey)
	iv := []byte("1234567812345678")
	//block, _ := aes.NewCipher(newKey)
	//cfb := cipher.NewCFBEncrypter(block, iv)
	//cfb.XORKeyStream(newPlain, newPlain)
	//return string(newPlain)
	ciphertext := make([]byte, aes.BlockSize+len(newPlain))
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], newPlain)
	return fmt.Sprintf("%x", ciphertext[aes.BlockSize:])
}

func MilenageGenOpc(ki, op string) string {
	opc := AESEncrypt(ki, op)
	//fmt.Println("op: " + op)
	//fmt.Println("不完整opc：" + opc)
	return LogicalXOR(opc, op)
}

// MilenageF1 F1 algorithm.
func MilenageF1(ki, opc, rand, sqn, amf string) (string, string) {
	tmp1 := LogicalXOR(opc, rand)
	//IN1 := sqn + amf + sqn + amf
	IN1 := sqn[:12] + amf[:4] + sqn[:12] + amf[:4]
	// 少循环移位
	result := LogicalXOR(AESEncrypt(ki, LogicalXOR(tmp1, LogicalXOR(IN1, opc))), opc)
	macA := result[:16]
	macS := result[16:32]
	return macA, macS
}

// MilenageF2345 F2345 algorithm,
func MilenageF2345(ki, opc, rand string) (res, ck, ik, ak string) {
	c2 := "00000000000000000000000000000001"
	c3 := "00000000000000000000000000000002"
	c4 := "00000000000000000000000000000004"
	c5 := "00000000000000000000000000000008"
	tmp1 := LogicalXOR(opc, rand)
	OUT2 := LogicalXOR(AESEncrypt(ki, LogicalXOR(LogicalXOR(tmp1, opc), c2)), opc)
	OUT3 := LogicalXOR(AESEncrypt(ki, LogicalXOR(LogicalXOR(tmp1, opc), c3)), opc)
	OUT4 := LogicalXOR(AESEncrypt(ki, LogicalXOR(LogicalXOR(tmp1, opc), c4)), opc)
	OUT5 := LogicalXOR(AESEncrypt(ki, LogicalXOR(LogicalXOR(tmp1, opc), c5)), opc)
	res = OUT2[16:32]
	ck = OUT3
	ik = OUT4
	ak = OUT5[:12]
	return res, ck, ik, ak
}

func Milenage(ki, opc, rand, sqn, amf string) (res, ck, ik, AUTN, ak string) {
	macA, _ := MilenageF1(ki, opc, rand, sqn, amf)
	res, ck, ik, ak = MilenageF2345(ki, opc, rand)
	AUTN = LogicalXOR(sqn[:12], ak) // ak 48bits
	AUTN += amf[:4] + macA
	return res, ck, ik, AUTN, ak
}
