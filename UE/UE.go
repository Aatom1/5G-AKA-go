package main

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

	//"os"
	"strconv"
)

// UE端 产生SUPI并处理得到SUCI，把SUCI以及SN_name发送给SN
// 接收SEAF发送来的5G SE_AV，提取其中的各种值(randNum,AUTN),AUTN=xSQN^AK||amf||x_macA,处理后利用milenage算法计算得到macA
// 比较两个mac值是否相同，若相同则生成Res，进一步生成Res*并将其发送给SEAF

var (
	hostSEAF = "localhost"
	portSEAF = "8002"
	portUE   = "8001"
)

// GenerateSUPI Generate Subscription Permanent Identifier(SUPI).
func GenerateSUPI() string {
	//imsi := "46000"，IMSI是SUPI的一种类型，IMSI=MCC||MNC||MSIN, 3+2+10位十进制数字
	SUPI := "46000"
	for i := 0; i < 10; i++ {
		SUPI = SUPI + strconv.Itoa(rand.Intn(10))
	}
	return SUPI
}

// GenerateSUCI Generate Subscription Concealed Identifier(SUCI). (use null scheme)
func GenerateSUCI(SUPI string) string {
	// 对SUPI使用空保护策略
	// SUCI=SUPI类型取值(0表示imsi)||归属网络标识符(mcc+mnc)||路由标识符||SUPI保护算法ID(0表示null scheme)||归属网络公钥||msin
	mcc := SUPI[:3]
	mnc := SUPI[3:5]
	msin := SUPI[5:]
	SUCI := "0" + mcc + mnc + "678" + "0" + "0" + msin
	return SUCI
}

// ReceiveAuthReqFromSN Receive authReq(R, AUTN) from SN.
func ReceiveAuthReqFromSN(port string) string {
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
			fmt.Println("Error accepting:", err.Error())
			continue
		}

		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err != nil {
			panic(err)
		}

		receivedData := string(buffer[:n])
		//fmt.Println("Received:", receivedData)

		err = conn.Close()
		if err != nil {
			panic(err)
		}
		return receivedData
	}
}

// ResolveAUTN  Detach AUTN(sqn^AK||amf||mac_a) after receiving authReq(R, AUTN) from SEAF.
func ResolveAUTN(AUTN string) (string, string, string) {
	sqnAK := AUTN[:12]
	amf := AUTN[12:16]
	mac := AUTN[16:]
	return sqnAK, amf, mac
}

func CheckMac(xMacA, MacA string) int {
	if xMacA == MacA {
		return 1
	} else {
		return 0
	}
}

//func CheckSqn(sqn string) {
//	// pass
//}

func GenerateResStar(ck, ik, P0, L0, rand, res string) string {
	key := []byte(ck + ik)
	P1 := rand
	L1 := fmt.Sprintf("%x", len(P1))
	P2 := res
	L2 := fmt.Sprintf("%x", len(P2))
	s := []byte("6B" + P0 + L0 + P1 + L1 + P2 + L2)
	h := hmac.New(sha256.New, key)
	h.Write(s)
	resStar := hex.EncodeToString(h.Sum(nil))[32:]
	return resStar
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

func InitForUE() (string, string, string, string) {
	ki := "000000012449900000000010123456d8"
	op := "cda0c2852846d8eb63a387051cdd1fa5"
	//global sn_name
	snName := "123456789"
	sqnMax := "100000000000000000000000"
	return ki, op, snName, sqnMax
}

func main() {
	fmt.Println("UE")
	ki, op, snName, _ := InitForUE()
	opc := _5gAKA_go.MilenageGenOpc(ki, op)

	file, _ := os.Create("UE.log")
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			panic(err)
		}
	}(file)

	SUPI := GenerateSUPI()
	SUCI := GenerateSUCI(SUPI)

	SendData(SUCI+snName, hostSEAF, portSEAF)
	_, _ = file.WriteString(time.Now().Format("2006-01-02 15:04:05") + "  " + "Send SUCI and SN_name to SEAF.")
	fmt.Println(time.Now().Format("2006-01-02 15:04:05") + "  " + "Send SUCI and SN_name to SEAF")

	authReq := ReceiveAuthReqFromSN(portUE)
	fmt.Println(time.Now().Format("2006-01-02 15:04:05") + "  " + "Receive auth-request from SEAF.")
	_, _ = file.WriteString(time.Now().Format("2006-01-02 15:04:05") + "  " + "Receive auth-request from SEAF.")
	randNum, AUTN := authReq[:32], authReq[32:]
	sqnAK, amf, xMacA := ResolveAUTN(AUTN)

	res, ck, ik, ak := _5gAKA_go.MilenageF2345(ki, opc, randNum)

	xSqn := _5gAKA_go.LogicalXOR(ak, sqnAK)
	macA, _ := _5gAKA_go.MilenageF1(ki, opc, randNum, xSqn, amf)
	if CheckMac(xMacA, macA) == 1 {
		P0 := snName
		L0 := fmt.Sprintf("%x", len(snName))
		resStar := GenerateResStar(ck, ik, P0, L0, randNum, res)

		SendData(resStar, hostSEAF, portSEAF)
		fmt.Println(time.Now().Format("2006-01-02 15:04:05") + "  " + "Send res* to SEAF. Value:" + resStar)
		_, _ = file.WriteString(time.Now().Format("2006-01-02 15:04:05") + "  " + "Send res* to SEAF. Value:" + resStar)
	}
}
