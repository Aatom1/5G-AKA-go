package main

// HN端 接收SN发来的SUCI和SN_name，解密得到SUPI
// 生成5G_AV并发送给SN端
// 接收SN发送来的Res*并和xRes*比较，若相同则向SN返回认证成功

import (
	"_5gAKA_go"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"os"
	"time"
)

var (
	hostSN = "localhost"
	portSN = "8002"
	portHN  = "8003"
	xResStar string
)

// GetSUPI Get SUPI by decrypting SUCI.
func GetSUPI(SUCI string) string {
	mcc := SUCI[1:4]
	mnc := SUCI[4:6]
	msin := SUCI[11:]
	return mcc + mnc + msin
}

// GenerateRand Generate a 128-bit rand number.
func GenerateRand() (result string) {
	chars := "0123456789abcdef"
	for i := 1; i < 33; i++ {
		result += string(chars[rand.Intn(16)])
	}
	return result
}

// GenerateKausf Generate K_ausf.
func GenerateKausf(key, P0, L0, P1, L1 string) string {
	appSecret := []byte(key)
	s := []byte("6A" + P0 + L0 + P1 + L1)
	h := hmac.New(sha256.New, appSecret)
	h.Write(s)
	tmp := hex.EncodeToString(h.Sum(nil))
	ckNew := tmp[:32]
	ikNew := tmp[32:]
	keyNew := ckNew + ikNew
	h1 := hmac.New(sha256.New, []byte(keyNew))
	h1.Write(s)
	kAusf := hex.EncodeToString(h1.Sum(nil))
	return kAusf
}

// GenerateXResStar Generate xRes*.
func GenerateXResStar(key, P0, L0, P1, L1, P2, L2 string) string {
	appSecret := []byte(key)
	s := []byte("6B" + P0 + L0 + P1 + L1 + P2 + L2)
	h := hmac.New(sha256.New, appSecret)
	h.Write(s)
	tmp := hex.EncodeToString(h.Sum(nil))
	xResStar := tmp[32:]
	return xResStar
}

// GenerateHxResStar Generate hxRes* using xRes* by hash algorithm sha-256 after receiving HE_AV||SUPI from UDM.
func GenerateHxResStar(randNum, xResStar string) string {
	s := []byte(randNum + xResStar)
	h := sha256.New()
	h.Write(s)
	tmp := hex.EncodeToString(h.Sum(nil))
	hxResStar := tmp[32:]

	return hxResStar
}

func SendData(data, host, port string) {
	conn, err := net.Dial("tcp", host+":"+port)
	if err != nil {
		fmt.Println("Error connecting:", err.Error())
		return
	}

	_, err = conn.Write([]byte(data))
	if err != nil {
		fmt.Println("Error sending:", err.Error())
		return
	}

	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			fmt.Println("Error while closing connection:", err.Error())
		}
	}(conn)
}

func ReceiveData(port string) string {
	listen, err := net.Listen("tcp", "localhost:"+port)
	if err != nil {
		panic(err)
	}
	defer func(listen net.Listener) {
		err := listen.Close()
		if err != nil {
			fmt.Println("Error while closing connection:", err.Error())
		}
	}(listen)

	for {
		conn, err := listen.Accept()
		if err != nil {
			panic(err)
		}

		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err != nil {
			panic(err)
		}

		receivedData := string(buffer[:n])

		err = conn.Close()
		if err != nil {
			panic(err)
		}
		return receivedData
	}
}

func InitForUDM() (string, string, string, string, string) {
	ki := "000000012449900000000010123456d8"
	randNum := GenerateRand()
	sqn := "1234567888d8"
	amf := "8d00"
	op := "cda0c2852846d8eb63a387051cdd1fa5"
	return ki, randNum, sqn, amf, op
}

func main() {
	fmt.Println("HN:")
	file, _ := os.Create("HN.log")
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			panic(err)
		}
	}(file)

	data := ReceiveData(portHN) // data = SUCI||SN_name
	_, _ = file.WriteString(time.Now().Format("2006-01-02 15:04:05") + "  " + "Receive SUCI and SN_name from SN.")
	fmt.Println(time.Now().Format("2006-01-02 15:04:05") + "  " + "Receive SUCI and SN_name from SN.")

	SUCI, snName := data[:21], data[21:]
	SUPI := GetSUPI(SUCI)

	ki, randNum, sqn, amf, op := InitForUDM()
	opc := _5gAKA_go.MilenageGenOpc(ki, op)

	xRes, ck, ik, AUTN, ak := _5gAKA_go.Milenage(ki, opc, randNum, sqn, amf)

	key := ck + ik
	P0 := snName
	L0 := fmt.Sprintf("%x", len(P0))
	P1 := _5gAKA_go.LogicalXOR(sqn, ak)
	L1 := fmt.Sprintf("%x", len(P1))
	kAusf := GenerateKausf(key, P0, L0, P1, L1)

	P1 = randNum
	L1 = fmt.Sprintf("%x", len(P1))
	P2 := xRes
	L2 := fmt.Sprintf("%x", len(P2))

	xResStar = GenerateXResStar(key, P0, L0, P1, L1, P2, L2)
	hxResStar := GenerateHxResStar(randNum, xResStar)

	// heAV := randNum + AUTN + xResStar + kAusf	
	seAV := randNum + AUTN + hxResStar + kAusf

	SendData(seAV+SUPI, hostSN, portSN)
	fmt.Println(time.Now().Format("2006-01-02 15:04:05") + "  " + "Send 5G_AV and SUPI to SN.")
	_, _ = file.WriteString(time.Now().Format("2006-01-02 15:04:05") + "  " + "Send 5G_AV and SUPI to SN.")

	// 接收SN发送来的res*，并和xRes*比较，若相同则向SN返回"successful from HN"
	resStar := ReceiveData(portHN)
	fmt.Println(time.Now().Format("2006-01-02 15:04:05") + "  " + "Receive res* from SN.")
	_, _ = file.WriteString(time.Now().Format("2006-01-02 15:04:05") + "  " + "Receive res* from SN.")
	if resStar == xResStar {
		SendData("successful from HN", hostSN, portSN)
	}
}
