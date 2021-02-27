package main

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"flag"
	"bufio"
	// "github.com/rs/zerolog"
	// "github.com/rs/zerolog/log"
)

// ws endpoint
var endpoints = [...]string{
	"wss://app.any.run/sockjs/158/r2jz998p/websocket",
	"wss://app.any.run/sockjs/479/eokzh54x/websocket",
	"wss://app.any.run/sockjs/937/thitlatz/websocket",
	"wss://app.any.run/sockjs/222/3_5u81il/websocket",
}

const (
	// handshake message
	connectMsg = `["{\"msg\":\"connect\",\"version\":\"1\",\"support\":[\"1\",\"pre2\",\"pre1\"]}"]`

	// public tasks
	//publicTasksUrlFormat        = `["{\"msg\":\"sub\",\"id\":\"vTWcZmngJ49BLcmsr\",\"name\":\"publicTasks\",\"params\":[%d,%d,{\"isPublic\":true,\"hash\":\"\",\"runtype\":[],\"verdict\":[],\"ext\":[],\"tag\":\"%s\",\"significant\":false,\"ip\":\"\",\"fileHash\":\"\",\"mitreId\":\"\",\"sid\":0,\"skip\":0}]}"]`
	//publicTasksCounterUrlFormat = `["{\"msg\":\"method\",\"method\":\"publicTasksCounter\",\"params\":[{\"isPublic\":true,\"hash\":\"\",\"runtype\":[],\"verdict\":[],\"ext\":[],\"tag\":\"%s\",\"significant\":false,\"ip\":\"\",\"fileHash\":\"\",\"mitreId\":\"\",\"sid\":0,\"skip\":0}],\"id\":\"4\"}"]`

	// PE EXE public tasks
	publicTasksUrlFormat        = `["{\"msg\":\"sub\",\"id\":\"qDA2CKe3Km4N9MPAE\",\"name\":\"publicTasks\",\"params\":[%d,%d,{\"isPublic\":true,\"hash\":\"\",\"runtype\":[],\"verdict\":[],\"ext\":[\"0\"],\"ip\":\"\",\"domain\":\"\",\"fileHash\":\"\",\"mitreId\":\"\",\"sid\":0,\"significant\":false,\"tag\":\"%s\",\"skip\":0}]}"]`
	publicTasksCounterUrlFormat = `["{\"msg\":\"method\",\"method\":\"publicTasksCounter\",\"params\":[{\"isPublic\":true,\"hash\":\"\",\"runtype\":[],\"verdict\":[],\"ext\":[\"0\"],\"ip\":\"\",\"domain\":\"\",\"fileHash\":\"\",\"mitreId\":\"\",\"sid\":0,\"significant\":false,\"tag\":\"%s\",\"skip\":0}],\"id\":\"7\"}"]`
	publicTasksDoneMsg          = `{"msg":"ready","subs":["qDA2CKe3Km4N9MPAE"]}`

	// File, PE EXE public tasks
	//publicTasksUrlFormat        = `["{\"msg\":\"sub\",\"id\":\"2ZYiGdXjJxY4QBvtb\",\"name\":\"publicTasks\",\"params\":[%d,%d,{\"isPublic\":true,\"hash\":\"\",\"runtype\":[\"1\"],\"verdict\":[],\"ext\":[\"0\"],\"ip\":\"\",\"domain\":\"\",\"fileHash\":\"\",\"mitreId\":\"\",\"sid\":0,\"significant\":false,\"tag\":\"%s\",\"skip\":0}]}"]`
	//publicTasksCounterUrlFormat = `["{\"msg\":\"method\",\"method\":\"publicTasksCounter\",\"params\":[{\"isPublic\":true,\"hash\":\"\",\"runtype\":[\"1\"],\"verdict\":[],\"ext\":[\"0\"],\"ip\":\"\",\"domain\":\"\",\"fileHash\":\"\",\"mitreId\":\"\",\"sid\":0,\"significant\":false,\"tag\":\"%s\",\"skip\":0}],\"id\":\"7\"}"]`
	//publicTasksDoneMsg          = `{"msg":"ready","subs":["2ZYiGdXjJxY4QBvtb"]}`

	// process tree
	processUrlFormat = `["{\"msg\":\"sub\",\"id\":\"ojEf2kD8Qo8Nt8aCg\",\"name\":\"process\",\"params\":[{\"taskID\":{\"$type\":\"oid\",\"$value\":\"%s\"},\"status\":100,\"important\":true}]}"]`
	processDoneMsg   = `{"msg":"ready","subs":["ojEf2kD8Qo8Nt8aCg"]}`

	// Mitre ATT&CK Mapping
	allIncidentsUrlFormat = `["{\"msg\":\"sub\",\"id\":\"xhR3rXWu4M8X6xFow\",\"name\":\"allIncidents\",\"params\":[{\"$type\":\"oid\",\"$value\":\"%s\"}]}"]`
	allIncidentsDoneMsg   = `{"msg":"ready","subs":["xhR3rXWu4M8X6xFow"]}`

	taskExistsUrlFormat = `["{\"msg\":\"sub\",\"id\":\"L6La59ezwZEf9qP2F\",\"name\":\"taskexists\",\"params\":[\"%s\"]}"]`
	taskExistsDoneMsg   = `["{\"msg\":\"ready\",\"subs\":[\"L6La59ezwZEf9qP2F\"]}"]`

	singleTaskUrlFormat = `["{\"msg\":\"sub\",\"id\":\"mkdKdJqprjPj98Z2e\",\"name\":\"singleTask\",\"params\":[{\"$type\":\"oid\",\"$value\":\"%s\"},true]}"]`
	singleTaskDoneMsg   = `["{\"msg\":\"ready\",\"subs\":[\"mkdKdJqprjPj98Z2e\"]}"]`


	dnsMsgFormat                = `["{\"msg\":\"sub\",\"id\":\"%s\",\"name\":\"dns\",\"params\":[{\"task\":{\"$type\":\"oid\",\"$value\":\"%s\"},\"searchParam\":\"\"},100]}"]`

    ipsMsgFormat                = `["{\"msg\":\"sub\",\"id\":\"%s\",\"name\":\"ips\",\"params\":[{\"taskId\":{\"$type\":\"oid\",\"$value\":\"%s\"},\"searchParam\":null},100]}"]`

    httpRequestsMsgFormat       = `["{\"msg\":\"sub\",\"id\":\"%s\",\"name\":\"reqs\",\"params\":[{\"taskId\":{\"$type\":\"oid\",\"$value\":\"%s\"},\"searchParam\":null},100]}"]`

	threatsMsgFormat 			= `["{\"msg\":\"sub\",\"id\":\"%s\",\"name\":\"threats\",\"params\":[{\"taskId\":{\"$type\":\"oid\",\"$value\":\"%s\"},\"uuid\":\"%s\",\"searchParam\":null}]}"]`

	registryMsgFormat			= `["{\"msg\":\"sub\",\"id\":\"%s\",\"name\":\"processRegistriesWrite\",\"params\":[{\"$type\":\"oid\",\"$value\":\"%s\"},{\"$type\":\"oid\",\"$value\":\"%s\"},70]}"]`
	dropFileMsgFormat			= `["{\"msg\":\"sub\",\"id\":\"%s\",\"name\":\"filesOfProcess\",\"params\":[{\"$type\":\"oid\",\"$value\":\"%s\"},50,{\"$type\":\"oid\",\"$value\":\"%s\"}]}"]`
	processConnectMsgFormat		= `["{\"msg\":\"sub\",\"id\":\"%s\",\"name\":\"processConnections\",\"params\":[{\"taskId\":{\"$type\":\"oid\",\"$value\":\"%s\"},\"processOID\":{\"$type\":\"oid\",\"$value\":\"%s\"},\"limit\":50}]}"]`
	processModuleMsgFormat 		= `["{\"msg\":\"sub\",\"id\":\"%s\",\"name\":\"processModules\",\"params\":[{\"$type\":\"oid\",\"$value\":\"%s\"},{\"$type\":\"oid\",\"$value\":\"%s\"},0]}"]`

	doneMsgFormat               = `{"msg":"ready","subs":["%s"]}`
	pingMsg                     = `{"msg":"ping"}`
	pongMsg                     = `["{\"msg\":\"pong\"}"]`

	LettersDigits = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

//--------------new add ---------------------//
var (
	inputFilePath  string
	outputFolderPath string
)

func init() {
	flag.StringVar(&inputFilePath, "file", "", "list of uuid")
	flag.StringVar(&outputFolderPath, "folder", "", "save folder")
}
//--------------new add ---------------------//

func getPublicTasksUrl(tag string, numOfEntries, index int) string {
	return fmt.Sprintf(publicTasksUrlFormat, numOfEntries, index, tag)
}

func getPublicTasksCounterUrl(tag string) string {
	return fmt.Sprintf(publicTasksCounterUrlFormat, tag)
}

func getProcessUrl(taskId string) string {
	return fmt.Sprintf(processUrlFormat, taskId)
}

func getAllIncidentsUrl(taskId string) string {
	return fmt.Sprintf(allIncidentsUrlFormat, taskId)
}

func getTaskExistsUrl(taskUuid string) string {
	return fmt.Sprintf(taskExistsUrlFormat, taskUuid)
}

func getSingleTaskUrl(taskId string) string {
	return fmt.Sprintf(singleTaskUrlFormat, taskId)
}

//them vao
func getDNSQueriesMsg(id string, taskId string) string {
	return fmt.Sprintf(dnsMsgFormat, id ,taskId)
}

func getIpsMsg(id string, taskId string) string {
	return fmt.Sprintf(ipsMsgFormat, id, taskId)
}

func getAllHttpRequestsMsg(id string, taskId string) string {
	return fmt.Sprintf(httpRequestsMsgFormat, id, taskId)
}

func getThreatsMsg(id string, taskId string, uuid string) string {
	return fmt.Sprintf(threatsMsgFormat, id, taskId, uuid)
}

func getRegistryMsg(id string, taskId string, proc string) string {
	return fmt.Sprintf(registryMsgFormat, id, taskId, proc)
}

func getDropFileMsg(id string, taskId string, proc string) string {
	return fmt.Sprintf(dropFileMsgFormat, id, taskId, proc)
}

func getProcessConnectMsg(id string, taskId string, proc string) string {
	return fmt.Sprintf(processConnectMsgFormat, id, taskId, proc)
}

func getProcessModuleMsg(id string, taskId string, proc string) string {
	return fmt.Sprintf(processModuleMsgFormat, id, taskId, proc)
}


func getDoneMsg(id string) string {
	return fmt.Sprintf(doneMsgFormat, id)
}

func generateRandStr(n int, letters string) string {
	randStr := make([]byte, n, n)
	for i := 0; i < n; i++ {
		randStr[i] = letters[rand.Intn(len(letters))]
	}
	return string(randStr)
}

//------------------------------//
func sendAll(conn *websocket.Conn, msg string) error {
	if err := conn.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
		return err
	}
	return nil
}

func readAll(conn *websocket.Conn) (string, error) {
	_, bytes, err := conn.ReadMessage()
	if err != nil {
		return "", err
	}
	if bytes[0] == 'a' && bytes[1] == '[' { // if the message in format a[payload]
		msg, err := strconv.Unquote(string(bytes[2 : len(bytes)-1]))
		if err != nil {
			return "", err
		}
		return msg, nil
	}
	return string(bytes), nil
}

func dumpProcessTree(conn *websocket.Conn, taskId string) ([]*Process, error) {
	processes := make([]*Process, 0)
	if err := sendAll(conn, getProcessUrl(taskId)); err != nil {
		return nil, err
	}
	for { // receive all
		rawProc := new(RawProcess)
		msg, err := readAll(conn)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(msg), &rawProc); err != nil {
			log.Println(msg)
			return nil, err
		}
		if rawProc.Fields.Pid == 0 && msg == processDoneMsg {
			break
		}
		processes = append(processes, NewProcess(rawProc))
	}
	return processes, nil
}

func dumpAllIncidents(conn *websocket.Conn, taskId string) ([]*Incident, error) {
	incidents := make([]*Incident, 0)
	if err := sendAll(conn, getAllIncidentsUrl(taskId)); err != nil {
		return nil, err
	}
	for { // receive all
		rawIncident := new(RawIncident)
		msg, err := readAll(conn)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(msg), &rawIncident); err != nil {
			return nil, err
		}
		if rawIncident.Collection == "" && msg == allIncidentsDoneMsg {
			break
		}
		incidents = append(incidents, NewIncident(rawIncident))
	}
	return incidents, nil
}

// GetDNSQueries returns a list of DSN queries as "DNS Queries" tab
func GetDNSQueries(conn *websocket.Conn, taskId string) ([]*DNSQueries, error) {
	dnsQueries := make([]*DNSQueries, 0)
	id := generateRandStr(len("4aYatF54JSoCNG94C"), LettersDigits)
	doneMsg := getDoneMsg(id)
	if err := sendAll(conn, getDNSQueriesMsg(id, taskId)); err != nil {
		return nil, err
	}
	for { // receive dns
		var dns *RawDNSQueries
		buffer, err := readAll(conn)
		if err != nil {
			return nil, fmt.Errorf("in recvMessage: %s", err)
		}
		if buffer == doneMsg {
			break
		}
		if err := json.Unmarshal([]byte(buffer), &dns); err != nil {
			return nil, fmt.Errorf("in Unmarshal: %s", err)
		}
		dnsQueries = append(dnsQueries, NewDNSQueries(dns))
	}
	return dnsQueries, nil
}

// GetIps returns a list of ips connections as "ips" tab
func GetIps(conn *websocket.Conn, taskId string) ([]*Ips, error) {
	ipsQuer := make([]*Ips, 0)
	id := generateRandStr(len("4aYatF54JSoCNG94C"), LettersDigits)
	doneMsg := getDoneMsg(id)
	if err := sendAll(conn, getIpsMsg(id, taskId)); err != nil {
		return nil, err
	}
	for { // receive dns
		var ips *RawIps
		buffer, err := readAll(conn)
		if err != nil {
			return nil, fmt.Errorf("in recvMessage: %s", err)
		}
		if buffer == doneMsg {
			break
		}
		if err := json.Unmarshal([]byte(buffer), &ips); err != nil {
			return nil, fmt.Errorf("in Unmarshal: %s", err)
		}
		ipsQuer = append(ipsQuer, NewIps(ips))
	}
	return ipsQuer, nil
}

// GetHttpRequests returns a list of HTTP requests as "HTTP Requests" tab
func GetHttpRequests(conn *websocket.Conn, taskId string) ([]*HttpRequests, error) {
	httpRequests := make([]*HttpRequests, 0)
	id := generateRandStr(len("6ehw2pycH63vBTmKe"), LettersDigits)
	doneMsg := getDoneMsg(id)

	if err := sendAll(conn, getAllHttpRequestsMsg(id, taskId)); err != nil {
		return nil, err
	}
	for { // receive http requests
		var http *RawHttpRequests
		buffer, err := readAll(conn)
		if err != nil {
			return nil, fmt.Errorf("in recvMessage: %s", err)
		}
		if buffer == doneMsg {
			break
		}
		if err := json.Unmarshal([]byte(buffer), &http); err != nil {
			return nil, fmt.Errorf("in Unmarshal: %s", err)
		}
		httpRequests = append(httpRequests, NewHttpRequests(http))
	}
	return httpRequests, nil
}

// GetGetThreats returns a list of Threats as "Threats" tab
func GetThreats(conn *websocket.Conn, taskId string, uuid string) ([]*Threats, error) {
	threats := make([]*Threats, 0)
	id := generateRandStr(len("4aYatF54JSoCNG94C"), LettersDigits)

	doneMsg := getDoneMsg(id)

	if err := sendAll(conn, getThreatsMsg(id, taskId, uuid)); err != nil {
		return nil, err
	}
	for { // receive threats
		var threat *RawThreats
		buffer, err := readAll(conn)
		if err != nil {
			return nil, fmt.Errorf("in recvMessage: %s", err)
		}
		if buffer == doneMsg {
			break
		}
		if err := json.Unmarshal([]byte(buffer), &threat); err != nil {
			return nil, fmt.Errorf("in Unmarshal: %s", err)
		}
		threats = append(threats, NewThreats(threat))
	}
	return threats, nil
}

// GetRegistry returns a list of Registry as "H_KEY" tab
func GetRegistry(conn *websocket.Conn, taskId string, proc *Process) ([]*Registries, error) {
	regis := make([]*Registries, 0)

	id := generateRandStr(len("dMXwEbLvfYZMH2Tca"), LettersDigits)
	//fmt.Println(msg)
	doneMsg := getDoneMsg(id)

	if err := sendAll(conn, getRegistryMsg(id, taskId, proc.OID)); err != nil {
		return nil, err
	}
	for { // receive registry
		var registry *RawRegistries
		buffer, err := readAll(conn)
		if err != nil {
			return nil, fmt.Errorf("in recvMessage: %s", err)
		}
		if buffer == doneMsg {
			break
		}
		if err := json.Unmarshal([]byte(buffer), &registry); err != nil {
			return nil, fmt.Errorf("in Unmarshal: %s", err)
		}
		regis = append(regis, NewRegistries(registry))
	}
	return regis, nil
}

// GetDropFile returns a list of File delete as tab of process
func GetDropFile(conn *websocket.Conn, taskId string, proc *Process) ([]*DropFile, error) {
	drop := make([]*DropFile, 0)

	id := generateRandStr(len("ToDENCSZ9gnoxbPP3"), LettersDigits)
	
	doneMsg := getDoneMsg(id)

	if err := sendAll(conn, getDropFileMsg(id, taskId, proc.OID)); err != nil {
		return nil, err
	}
	for { // receive event.drop
		var dropfile *RawDropFile
		buffer, err := readAll(conn)
		if err != nil {
			return nil, fmt.Errorf("in recvMessage: %s", err)
		}
		if buffer == doneMsg {
			break
		}
		if err := json.Unmarshal([]byte(buffer), &dropfile); err != nil {
			return nil, fmt.Errorf("in Unmarshal: %s", err)
		}
		drop = append(drop, NewDropFile(dropfile))
	}
	return drop, nil
}


func dumpToFile(fileName string, bytes []byte) error {
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(bytes)
	if err != nil {
		return err
	}
	return nil
}

func dumpTask(conn *websocket.Conn, malwareTag string, task *Task) error {
	processes, err := dumpProcessTree(conn, task.ID)
	if err != nil {
		return err
	}
	incidents, err := dumpAllIncidents(conn, task.ID)
	if err != nil {
		return err
	}
	mainObject := task.Fields.Public.Objects.MainObject
	processData := &ProcessData{
		Name:      mainObject.Names.Basename,
		Md5:       mainObject.Hashes.Md5,
		UUID:      task.Fields.UUID,
		Processes: processes,
		Incidents: incidents,
	}
	bytes, err := json.MarshalIndent(processData, "", " ")
	if err != nil {
		return err
	}
	taskFileName := fmt.Sprintf("%s/%s.json", malwareTag, getTaskUrl(task))
	if err := dumpToFile(taskFileName, bytes); err != nil {
		return err
	}
	return nil
}

func NewAppAnyClient() *websocket.Conn {
	reqHeader := make(http.Header)
	reqHeader.Add("Host", "app.any.run")
	reqHeader.Add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.105 Safari/537.36")
	reqHeader.Add("Origin", "https://app.any.run")

	//rand.Seed(time.Now().Unix())
	conn, _, err := websocket.DefaultDialer.Dial(endpoints[rand.Intn(len(endpoints))], reqHeader)
	if err != nil {
		log.Fatal(err)
	}
	conn.ReadMessage()
	conn.ReadMessage()

	// connect
	sendAll(conn, connectMsg)
	msg, err := readAll(conn)
	if err != nil {
		log.Fatal(err)
	}
	if !strings.Contains(msg, "connected") {
		log.Fatal("connection to app.any failed")
	}
	return conn
}

//GetNumOfTasks
func countTasksByTag(conn *websocket.Conn, malwareTag string) (int, error) {
	// count public tasks by tag
	var countResult Result
	if err := sendAll(conn, getPublicTasksCounterUrl(malwareTag)); err != nil {
		return 0, err
	}
	// a["{\"msg\":\"updated\",\"methods\":[\"4\"]}"]
	conn.ReadMessage()
	msg, err := readAll(conn)
	if err != nil {
		return 0, err
	}
	if err := json.Unmarshal([]byte(msg), &countResult); err != nil {
		return 0, err
	}
	return countResult.Result.Count, nil
}

//GetTasks
func getTasksByTag(conn *websocket.Conn, malwareTag string, numOfEntries, index int) ([]*Task, error) {
	tasks := make([]*Task, 0)
	// get public tasks
	if err := sendAll(conn, getPublicTasksUrl(malwareTag, numOfEntries, index)); err != nil {
		return nil, err
	}
	for { // receive all
		task := new(Task)
		msg, err := readAll(conn)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(msg), &task); err != nil {
			log.Println(msg)
			return nil, err
		}
		if task.Collection == "" && msg == publicTasksDoneMsg {
			break
		}
		tasks = append(tasks, task)
	}
	return tasks, nil
}

func getTaskIdentity(task *Task) string {
	mainObject := task.Fields.Public.Objects.MainObject
	format := "name: %s, MD5: %s, TaskID: %s"
	switch mainObject.Type {
	case "file":
		return fmt.Sprintf(format, mainObject.Names.Basename, mainObject.Hashes.Md5, mainObject.Task.Value)
	case "url":
		return fmt.Sprintf(format, mainObject.Names.URL, mainObject.Hashes.Md5, mainObject.Task.Value)
	}
	return "unknown"
}

func getTaskUrl(task *Task) string {
	return task.Fields.UUID
}

func crawlTasks(malwareTag string, taskIndex, numOfTasks int) {
	conn := NewAppAnyClient()

	taskCount, err := countTasksByTag(conn, malwareTag)
	if err != nil {
		conn.Close()
		log.Println("cannot count tasks, ", err)
		return
	}
	log.Printf("Number of tasks for %s: %d\n", malwareTag, taskCount)
	conn.Close()
	if numOfTasks <= 0 || numOfTasks > taskCount {
		numOfTasks = taskCount
	}
	log.Printf("Start crawling %d tasks\n", numOfTasks)

	var counter = taskIndex
	for i := taskIndex; i < numOfTasks; i += 50 {
		conn := NewAppAnyClient()
		tasks, err := getTasksByTag(conn, malwareTag, 50, i)
		if err != nil {
			conn.Close()
			log.Println("cannot get tasks, ", err)
			return
		}
		os.Mkdir(malwareTag, os.ModePerm)
		conn.Close()

		for _, task := range tasks {
			log.Println(counter, getTaskIdentity(task))
			counter++
			conn := NewAppAnyClient()
			if err := dumpTask(conn, malwareTag, task); err != nil {
				log.Println("cannot dump task, ", err)
				conn.Close()
				return
			}
			conn.Close()
		}
	}
}

type TaskExistsResult struct {
	Msg        string `json:"msg"`
	Collection string `json:"collection"`
	ID         string `json:"id"`
	Fields     struct {
		TaskID       string `json:"taskId"`
		TaskObjectID struct {
			Type  string `json:"$type"`
			Value string `json:"$value"`
		} `json:"taskObjectId"`
	} `json:"fields"`
}

func crawlTaskByUUID(outDirPath, taskUuid string) error {
	conn := NewAppAnyClient()
	// check existence and get internal id
	var result TaskExistsResult
	if err := sendAll(conn, getTaskExistsUrl(taskUuid)); err != nil {
		return fmt.Errorf("in sendAll: %s", err)
	}
	msg, err := readAll(conn)
	if err != nil {
		return fmt.Errorf("in readAll: %s", err)
	}
	if err := json.Unmarshal([]byte(msg), &result); err != nil {
		return fmt.Errorf("in Unmarshal: %s", err)
	}
	conn.ReadMessage()

	// get process tree and incidents
	taskId := result.Fields.TaskObjectID.Value
	processes, err := dumpProcessTree(conn, taskId)
	if err != nil {
		return err
	}
	incidents, err := dumpAllIncidents(conn, taskId)
	if err != nil {
		return err
	}

	ips, err := GetIps(conn, taskId)
	if err != nil {
		fmt.Println( "cannot dump RawTask GetIps gia tri err:", err)
		return err
	}

	domain, err := GetDNSQueries(conn, taskId)
	if err != nil {
		fmt.Println( "cannot dump RawTask GetDNSQueries gia tri err:", err)
		return err
	}

	httpRequests, err := GetHttpRequests(conn, taskId)
	if err != nil {
		fmt.Println( "cannot dump RawTask GetHttpRequests gia tri err:", err)
		return err
	}

	threats, err := GetThreats(conn, taskId,taskUuid )
	if err != nil {
		fmt.Println( "cannot dump RawTask GetThreats gia tri err:", err)
		return err
	}

	registry := make([]*Registries, 0) 
	for _, pro := range processes{
		regis, err := GetRegistry(conn, taskId, pro)
		if err != nil {
			fmt.Println( "cannot dump RawTask GetRegistry gia tri err:", err)
			return err
		}else{
			registry = append(registry, regis...)
		}	
	}

	drop := make([]*DropFile, 0)
	for _, pro := range processes{
		dropFile, err := GetDropFile(conn, taskId, pro)
		if err != nil {
			fmt.Println( "cannot dump RawTask GetDropFile gia tri err:", err)
			return err
		}else{
			drop = append(drop, dropFile...)
		}	
	}

	// task information
	var taskInfo *Task
	if err := sendAll(conn, getSingleTaskUrl(taskId)); err != nil {
		return fmt.Errorf("in sendAll: %s", err)
	}
	msg, err = readAll(conn)
	if err != nil {
		return fmt.Errorf("in readAll: %s", err)
	}
	if err := json.Unmarshal([]byte(msg), &taskInfo); err != nil {
		return fmt.Errorf("in Unmarshal: %s", err)
	}
	// save
	// mainObject := taskInfo.Fields.Public.Objects.MainObject
	// processData := &ProcessData{
	// 	Name:      mainObject.Names.Basename,
	// 	Md5:       mainObject.Hashes.Md5,
	// 	UUID:      taskInfo.Fields.UUID,
	// 	Processes: processes,
	// 	Incidents: incidents,
	// }

	//set task info
	mainObject := taskInfo.Fields.Public.Objects.MainObject
	processData := &ProcessData{
		Name:      			mainObject.Names.Basename,
		Md5:       			mainObject.Hashes.Md5,
		UUID:      			taskInfo.Fields.UUID,
		Processes: 			processes,
		Incidents: 			incidents,
		Ips: 	   			ips,
		Domain:	   			domain,
		HttpRequests: 		httpRequests,
		Threats:            threats,
		Registries:			registry,
		DropFile:			drop,
		//ProConnect:			proCon,
		//ProModule:			proMod,
	}

	bytes, err := json.MarshalIndent(processData, "", " ")
	if err != nil {
		return err
	}
	if _, err := os.Stat(outDirPath); os.IsNotExist(err) {
		if err = os.Mkdir(outDirPath, 0755); err != nil {
			return fmt.Errorf("failed to create dir for saving: %s", err)
		}
	}
	taskFileName := fmt.Sprintf("%s/%s.json", outDirPath, getTaskUrl(taskInfo))
	if err := dumpToFile(taskFileName, bytes); err != nil {
		return err
	}
	return nil
}

func autoCrawl(inputFilePath string, outputFolderPath string ) error{
	if inputFilePath != "" && outputFolderPath != "" {
		
		file, err := os.Open(inputFilePath)
		if err != nil {
			fmt.Println( "open file error", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fmt.Println( "uuid : ", scanner.Text())
			crawlTaskByUUID(outputFolderPath, scanner.Text())
		}

		if err := scanner.Err(); err != nil {
			fmt.Println( "read file error" )
		}
		// return
	}
	return nil
}
