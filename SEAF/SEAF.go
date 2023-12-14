package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"time"
)

// SEAF端 监听SEAF对应端口，根据收到的不同信息做出不同处理
// 接收UE发送的SUCI+SN_name,并转发给AUSF
// 从AUSF端接收SE_AV(randNum||AUTN||hxResStar||kSeaf)
// 向UE端发送randNum||AUTN
// 从UE端接收Res*，并产生哈希值hRes*
// 验证计算的hRes*和从AUSF端接收处理得到的hxRes*是否相同，若相同，把Res*发送给AUSF

var (
	hostUE    = "localhost"
	hostAUSF  = "localhost"
	portUE    = "8001"
	portSEAF  = "8002"
	portAUSF  = "8003"
	randNum   string
	hxResStar string
	kSeaf     string
)

// GenerateHResStar Generate hRes* after receiving RES* from UE.
func GenerateHResStar(randNum, resStar string) string {
	s := []byte(randNum + resStar)
	h := sha256.New()
	h.Write(s)
	tmp := hex.EncodeToString(h.Sum(nil))
	hResStar := tmp[32:]
	return hResStar
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

// ResolveDataFromAusf Resolve data(SE_AV||SUPI) from AUSF.
func ResolveDataFromAusf(data string) (string, string) {
	AV := data[:160]
	SUPI := data[160:]
	return AV, SUPI
}

// ResolveAV Resolve SE_AV received from AUSF.
func ResolveAV(AV string) (string, string, string, string) {
	randNumber := AV[:32]
	AUTN := AV[32:64]
	hxResStar := AV[64:96]
	kSeaf := AV[96:]
	return randNumber, AUTN, hxResStar, kSeaf
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
	file, _ := os.Create("SEAF.log")
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			panic(err)
		}
	}(file)
	length := len(receivedData)
	if length == 30 {
		fmt.Println(time.Now().Format("2006-01-02 15:04:05") + "  " + "Receive SUCI and snName from UE.")
		_, _ = file.WriteString(time.Now().Format("2006-01-02 15:04:05") + "  " + "Receive SUCI and snName from UE.")
		SendData(receivedData, hostAUSF, portAUSF)
		fmt.Println(time.Now().Format("2006-01-02 15:04:05") + "  " + "Send SUCI and snName to AUSF.")
		_, _ = file.WriteString(time.Now().Format("2006-01-02 15:04:05") + "  " + "Send SUCI and snName to AUSF.")
	} else if length >= 160 {
		AV := receivedData
		fmt.Println(time.Now().Format("2006-01-02 15:04:05") + "  " + "Receive 5G_SE_AV and SUPI from AUSF.")
		_, _ = file.WriteString(time.Now().Format("2006-01-02 15:04:05") + "  " + "Receive 5G_SE_AV and SUPI from AUSF.")
		_, AUTN, _, _ := ResolveAV(AV)
		randNum, _, _, _ = ResolveAV(AV)
		_, _, hxResStar, kSeaf = ResolveAV(AV)

		authReq := randNum + AUTN
		SendData(authReq, hostUE, portUE)
		fmt.Println(time.Now().Format("2006-01-02 15:04:05") + "  " + "Send rand_num and AUTN to UE.")
		_, _ = file.WriteString(time.Now().Format("2006-01-02 15:04:05") + "  " + "Send rand_num and AUTN to UE.")
	} else if length == 32 {
		fmt.Println(time.Now().Format("2006-01-02 15:04:05") + "  " + "Receive res* from UE.")
		_, _ = file.WriteString(time.Now().Format("2006-01-02 15:04:05") + "  " + "Receive res* from UE.")
		resStar := receivedData
		hResStar := GenerateHResStar(randNum, resStar)

		// Judge
		if hResStar == hxResStar {
			fmt.Println(time.Now().Format("2006-01-02 15:04:05") + "  " + "SEAF Authentication Passed.")
			_, _ = file.WriteString(time.Now().Format("2006-01-02 15:04:05") + "  " + "SEAF Authentication Passed.")
			SendData(resStar, hostAUSF, portAUSF)
			fmt.Println(time.Now().Format("2006-01-02 15:04:05") + "  " + "Send res* to AUSF.")
			_, _ = file.WriteString(time.Now().Format("2006-01-02 15:04:05") + "  " + "Send res* to AUSF.")
		} else {
			fmt.Println(time.Now().Format("2006-01-02 15:04:05") + "  " + "SEAF Authentication Failed!")
			_, _ = file.WriteString(time.Now().Format("2006-01-02 15:04:05") + "  " + "SEAF Authentication Failed!")
		}
	} else if length == 48 {

	} else if receivedData == "successful from AUSF" {
		fmt.Println(time.Now().Format("2006-01-02 15:04:05") + "  " + "Receive authentication response from AUSF. AKA Successful!")
		_, _ = file.WriteString(time.Now().Format("2006-01-02 15:04:05") + "  " + "Receive authentication response from AUSF.\n AKA Successful!")
	}

	err = conn.Close()
	if err != nil {
		fmt.Println("Error while closing connection:", err.Error())
		return
	}
}

func main() {
	//	监听SEAF对应端口，根据监听到的消息长度做出不同反应
	fmt.Println("SEAF:")
	ReceiveData(portSEAF)
}
