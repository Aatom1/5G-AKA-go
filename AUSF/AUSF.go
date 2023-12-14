package main

// AUSF端 接收SEAF转发的来自UE的SUCI + SN_name，并将其发送给UDM
// 接收UDM发送来的认证向量5G HE_AV，据此存储xRes*并计算hxRes*，计算5G SE_AV并发送给SEAF
// 接收SEAF发送来的由UE生成的Res*，并将其与之前存储的xRes*比较，相同则认证成功

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"time"
)

var (
	hostSEAF = "localhost"
	hostUDM  = "localhost"
	portSEAF = "8002"
	portAUSF = "8003"
	portUDM  = "8004"
	P0       string
	L0       string
	xResStar string
)

// GenerateHxResStar Generate hxRes* using xRes* by hash algorithm sha-256 after receiving HE_AV||SUPI from UDM.
func GenerateHxResStar(randNum, xResStar string) string {
	s := []byte(randNum + xResStar)
	h := sha256.New()
	h.Write(s)
	tmp := hex.EncodeToString(h.Sum(nil))
	hxResStar := tmp[32:]

	return hxResStar
}

// GenerateKseaf Generate K_seaf after receiving HE_AV||SUPI from UDM.
func GenerateKseaf(kAusf, P0, L0 string) string {
	// P0 snName(serving network name)
	// L0 length of P0
	s := []byte("6C" + P0 + L0)
	h := hmac.New(sha256.New, []byte(kAusf))
	h.Write(s)
	kSeaf := hex.EncodeToString(h.Sum(nil))

	return kSeaf
}

// ResolveDataFromUDM Get HE_AV and SUPI by resolving the data(HE_AV||SUPI) received from UDM.
func ResolveDataFromUDM(data string) (string, string) {
	heAV := data[:160]
	SUPI := data[160:]
	return heAV, SUPI
}

// ResolveDataFromSEAF Get SUCI and snName by resolving the data(SUCI||snName) received from SEAF.
func ResolveDataFromSEAF(data string) (string, string) {
	SUCI := data[:21]
	snName := data[21:]
	return SUCI, snName
}

// ResolveHEAV Get (randNum,AUTN,hxRes*,K_seaf) by resolving HE_AV received from UDM.
func ResolveHEAV(heAV string) (string, string, string, string) {
	randNum := heAV[:32]
	AUTN := heAV[32:64]
	xResStarr := heAV[64:96]
	kAusf := heAV[96:]
	return randNum, AUTN, xResStarr, kAusf
}

// GenerateSEAV Compute SE_AV, which will be sent to SEAF
func GenerateSEAV(randNum, AUTN, hxResStar, kSeaf string) string {
	return randNum + AUTN + hxResStar + kSeaf
}

// SendData Send data to host:port by socket.
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

func ReceiveData(port string) {
	listen, err := net.Listen("tcp", "localhost:"+port)
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		return
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

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
		return
	}

	receivedData := string(buffer[:n])
	//fmt.Println("Received:", receivedData)

	// 根据消息长度做出不同反应
	file, _ := os.Create("AUSF.log")
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			panic(err)
		}
	}(file)
	length := len(receivedData)

	if length == 30 {
		// 消息长度为30，则为SEAF发来的SUCI + SN_name {SUCI---21, SN_name---9}
		// 把SUCI + SN_name发送给UDM
		_, snName := ResolveDataFromSEAF(receivedData)
		P0 = snName
		L0 = fmt.Sprintf("%x", len(snName))
		SendData(receivedData, hostUDM, portUDM)
		fmt.Println(time.Now().Format("2006-01-02 15:04:05") + "  " + "Send SUCI nd SN_name to UDM.")
		_, _ = file.WriteString(time.Now().Format("2006-01-02 15:04:05") + "  " + "Send SUCI nd SN_name to UDM.")

	} else if length >= 160 {
		// 消息长度>=160，则为UDM发来的HE_AV
		// HE_AV = rand + AUTN + xRes* + k_ausf {rand---32个十六进制字符串(128bits)，AUTN---32， xRes*---32, k_ausf---64}
		// 处理HE_AV，根据其中的xRes*计算哈希值hxRes*，根据其他数据计算5G SE_AV
		fmt.Println(time.Now().Format("2006-01-02 15:04:05") + "  " + "Receive 5G HE_AV and SUPI from UDM.")
		_, _ = file.WriteString(time.Now().Format("2006-01-02 15:04:05") + "  " + "Receive 5G HE_AV and SUPI from UDM.")
		heAV, SUPI := ResolveDataFromUDM(receivedData)
		randNum, AUTN, _, kAusf := ResolveHEAV(heAV)

		_, _, xResStar, _ = ResolveHEAV(heAV)
		kSeaf := GenerateKseaf(kAusf, P0, L0)
		hxResStar := GenerateHxResStar(randNum, xResStar)

		seAV := GenerateSEAV(randNum, AUTN, hxResStar, kSeaf)
		SendData(seAV+SUPI, hostSEAF, portSEAF)
		fmt.Println(time.Now().Format("2006-01-02 15:04:05") + "  " + "Send 5G SE_AV and SUPI to SEAF.")
		_, _ = file.WriteString(time.Now().Format("2006-01-02 15:04:05") + "  " + "Send 5G SE_AV and SUPI to SEAF.")
	} else if length == 32 {
		// 消息长度为32，则为SEAF发送来的Res*  {Res*---32}
		// 将SEAF发送来的Res*和之前从UDM接收的hRes*进行比较，相同则说明认证成功。
		if receivedData == xResStar {
			SendData("successful from AUSF", hostSEAF, portSEAF)
			fmt.Println(time.Now().Format("2006-01-02 15:04:05") + "  " + "Send Authentication Response to SEAF.")
			_, _ = file.WriteString(time.Now().Format("2006-01-02 15:04:05") + "  " + "Send Authentication Response to SEAF.")
		}
	}

	err = conn.Close()
	if err != nil {
		fmt.Println("Error while closing connection:", err.Error())
		return
	}
}

func main() {
	fmt.Println("AUSF:")
	ReceiveData(portAUSF)
}
