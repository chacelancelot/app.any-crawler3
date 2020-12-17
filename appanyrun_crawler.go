package main

//import (
//	"encoding/json"
//	"fmt"
//	"github.com/gorilla/websocket"
//	"log"
//	"os"
//)
//
//const (
//	taskExistsUrlFormat = `["{\"msg\":\"sub\",\"id\":\"L6La59ezwZEf9qP2F\",\"name\":\"taskexists\",\"params\":[\"%s\"]}"]`
//	taskExistsDoneMsg   = `["{\"msg\":\"ready\",\"subs\":[\"L6La59ezwZEf9qP2F\"]}"]`
//
//	singleTaskUrlFormat = `["{\"msg\":\"sub\",\"id\":\"mkdKdJqprjPj98Z2e\",\"name\":\"singleTask\",\"params\":[{\"$type\":\"oid\",\"$value\":\"%s\"},true]}"]`
//	singleTaskDoneMsg   = `a["{\"msg\":\"ready\",\"subs\":[\"mkdKdJqprjPj98Z2e\"]}"]`
//)
//
//func getTaskExistsUrl(taskUuid string) string {
//	return fmt.Sprintf(taskExistsUrlFormat, taskUuid)
//}
//
//func getSingleTaskUrl(taskId string) string {
//	return fmt.Sprintf(singleTaskUrlFormat, taskId)
//}
//
//func dumpToFile(fileName string, bytes []byte) error {
//	file, err := os.Create(fileName)
//	if err != nil {
//		return err
//	}
//	defer file.Close()
//	_, err = file.Write(bytes)
//	if err != nil {
//		return err
//	}
//	return nil
//}
//
//func dumpTask(conn *websocket.Conn, malwareTag string, Task *RawTask) error {
//	processes, err := dumpProcessTree(conn, Task.ID)
//	if err != nil {
//		return err
//	}
//	incidents, err := dumpAllIncidents(conn, Task.ID)
//	if err != nil {
//		return err
//	}
//	mainObject := Task.Fields.Public.Objects.MainObject
//	processData := &ProcessData{
//		Name:      mainObject.Names.Basename,
//		Md5:       mainObject.Hashes.Md5,
//		UUID:      Task.Fields.UUID,
//		Processes: processes,
//		Incidents: incidents,
//	}
//	bytes, err := json.MarshalIndent(processData, "", " ")
//	if err != nil {
//		return err
//	}
//	taskFileName := fmt.Sprintf("%s/%s.json", malwareTag, getTaskUrl(Task))
//	if err := dumpToFile(taskFileName, bytes); err != nil {
//		return err
//	}
//	return nil
//}
//
//func getTaskIdentity(Task *RawTask) string {
//	mainObject := Task.Fields.Public.Objects.MainObject
//	format := "name: %s, MD5: %s, TaskID: %s"
//	switch mainObject.Type {
//	case "file":
//		return fmt.Sprintf(format, mainObject.Names.Basename, mainObject.Hashes.Md5, mainObject.Task.Value)
//	case "url":
//		return fmt.Sprintf(format, mainObject.Names.URL, mainObject.Hashes.Md5, mainObject.Task.Value)
//	}
//	return "unknown"
//}
//
//func getTaskUrl(Task *RawTask) string {
//	return Task.Fields.UUID
//}
//
//func crawlTasks(malwareTag string, taskIndex, numOfTasks int) {
//	conn := NewAppAnyClient()
//
//	taskCount, err := countTasksByTag(conn, malwareTag)
//	if err != nil {
//		conn.Close()
//		log.Println("cannot count tasks, ", err)
//		return
//	}
//	log.Printf("Number of tasks for %s: %d\n", malwareTag, taskCount)
//	conn.Close()
//	if numOfTasks <= 0 || numOfTasks > taskCount {
//		numOfTasks = taskCount
//	}
//	log.Printf("Start crawling %d tasks\n", numOfTasks)
//
//	var counter = taskIndex
//	for i := taskIndex; i < numOfTasks; i += 50 {
//		conn := NewAppAnyClient()
//		tasks, err := getTasksByTag(conn, malwareTag, 50, i)
//		if err != nil {
//			conn.Close()
//			log.Println("cannot get tasks, ", err)
//			return
//		}
//		os.Mkdir(malwareTag, os.ModePerm)
//		conn.Close()
//
//		for _, Task := range tasks {
//			log.Println(counter, getTaskIdentity(Task))
//			counter++
//			conn := NewAppAnyClient()
//			if err := dumpTask(conn, malwareTag, Task); err != nil {
//				log.Println("cannot dump RawTask, ", err)
//				conn.Close()
//				return
//			}
//			conn.Close()
//		}
//	}
//}
//
//type TaskExistsResult struct {
//	Msg        string `json:"msg"`
//	Collection string `json:"collection"`
//	ID         string `json:"id"`
//	Fields     struct {
//		TaskID       string `json:"taskId"`
//		TaskObjectID struct {
//			Type  string `json:"$type"`
//			Value string `json:"$value"`
//		} `json:"taskObjectId"`
//	} `json:"fields"`
//}
//
//func crawlTaskByUUID(outDirPath, taskUuid string) error {
//	conn := NewAppAnyClient()
//	// check existence and get internal id
//	var result TaskExistsResult
//	if err := sendAll(conn, getTaskExistsUrl(taskUuid)); err != nil {
//		return fmt.Errorf("in sendAll: %s", err)
//	}
//	msg, err := readAll(conn)
//	if err != nil {
//		return fmt.Errorf("in readAll: %s", err)
//	}
//	if err := json.Unmarshal([]byte(msg), &result); err != nil {
//		return fmt.Errorf("in Unmarshal: %s", err)
//	}
//	conn.ReadMessage()
//
//	// get process tree and incidents
//	taskId := result.Fields.TaskObjectID.Value
//	processes, err := dumpProcessTree(conn, taskId)
//	if err != nil {
//		return err
//	}
//	incidents, err := dumpAllIncidents(conn, taskId)
//	if err != nil {
//		return err
//	}
//	// RawTask information
//	var taskInfo *RawTask
//	if err := sendAll(conn, getSingleTaskUrl(taskId)); err != nil {
//		return fmt.Errorf("in sendAll: %s", err)
//	}
//	msg, err = readAll(conn)
//	if err != nil {
//		return fmt.Errorf("in readAll: %s", err)
//	}
//	if err := json.Unmarshal([]byte(msg), &taskInfo); err != nil {
//		return fmt.Errorf("in Unmarshal: %s", err)
//	}
//	// save
//	mainObject := taskInfo.Fields.Public.Objects.MainObject
//	processData := &ProcessData{
//		Name:      mainObject.Names.Basename,
//		Md5:       mainObject.Hashes.Md5,
//		UUID:      taskInfo.Fields.UUID,
//		Processes: processes,
//		Incidents: incidents,
//	}
//	bytes, err := json.MarshalIndent(processData, "", " ")
//	if err != nil {
//		return err
//	}
//	if _, err := os.Stat(outDirPath); os.IsNotExist(err) {
//		if err = os.Mkdir(outDirPath, 0755); err != nil {
//			return fmt.Errorf("failed to create dir for saving: %s", err)
//		}
//	}
//	taskFileName := fmt.Sprintf("%s/%s.json", outDirPath, getTaskUrl(taskInfo))
//	if err := dumpToFile(taskFileName, bytes); err != nil {
//		return err
//	}
//	return nil
//}
