package main

import (
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"time"
	"encoding/json"
	"strconv"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	configFilePath string
	startTaskIndex uint
	numOfTasks     uint
)

func init() {
	rand.Seed(time.Now().UnixNano())
	log.Logger = log.Output(zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: time.RFC3339,
	})
	flag.StringVar(&configFilePath, "c", "config.yml", "the `configuration` file")
	flag.StringVar(&configFilePath, "config", "config.yml", "the `configuration` file")
	flag.UintVar(&startTaskIndex, "i", 0, "crawl tasks start from the `index`")
	flag.UintVar(&startTaskIndex, "index", 0, "crawl tasks start from the `index`")
	flag.UintVar(&numOfTasks, "n", 0, "number of tasks to crawl")
	flag.UintVar(&numOfTasks, "number", 0, "number of tasks to crawl")
}

// app.any.run endpoint
var endpointList = [...]string{
	"wss://app.any.run/sockjs/402/me83v5fg/websocket",,
	"wss://app.any.run/sockjs/823/dqj28hrf/websocket",
}

// ghi file
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


func dumpTask(client *AppAnyClient, malwareTag string, task *RawTask) error {
	//get task info
	//var  task2 *RawTask
	processes, err := client.GetProcesses(task)
	if err != nil {
		return err
	}
	incidents, err := client.GetIncidents(task)
	if err != nil {
		return err
	}

	ips, err := client.GetIps(task)
	if err != nil {
		return err
	}

	domain, err := client.GetDNSQueries(task)
	if err != nil {
		return err
	}

	httpRequests, err := client.GetHttpRequests(task)
	if err != nil {
		return err
	}

	threats, err := client.GetThreats(task)
	if err != nil {
		return err
	}

	//set task info
	mainObject := task.Fields.Public.Objects.MainObject
	processData := &ProcessData{
		Name:      			mainObject.Names.Basename,
		Md5:       			mainObject.Hashes.Md5,
		UUID:      			task.Fields.UUID,
		Processes: 			processes,
		Incidents: 			incidents,
		Ips: 	   			ips,
		Domain:	   			domain,
		HttpRequests: 		httpRequests,
		Threats:            threats,
	}

	//convert struct to json
	bytes, err := json.MarshalIndent(processData, "", " ")
	if err != nil {
		return err
	}

	//write json file
	taskFileName := fmt.Sprintf("%s/%s.json", malwareTag, task.Fields.UUID)
	if err := dumpToFile(taskFileName, bytes); err != nil {
		return err
	}
	return nil
}


func main() {
	flag.Parse()
	appConfig, err := ReadAppConfig(configFilePath)
	if err != nil {
		log.Fatal().Err(err).Msgf("failed to parse configuration file '%s'", configFilePath)
	}

	reqHeader := make(http.Header)
	reqHeader.Add("Host", "app.any.run")
	reqHeader.Add("User-Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:82.0) Gecko/20100101 Firefox/82.0")
	reqHeader.Add("Origin", "https://app.any.run")

	config := &AppAnyClientConfig{
		Endpoint:  endpointList[rand.Intn(len(endpointList))],
		ReqHeader: reqHeader,
		AppConfig: appConfig,
	}
	client, err := NewAppAnyClient(config)
	if err != nil {
		log.Fatal().Err(err).Msg("in NewAppAnyClient")
	}
	if err := client.Connect(); err != nil {
		log.Fatal().Err(err).Msg("unable to send connect msg")
	}
	log.Info().Msg("connected to App.Any.Run")

	totalTaskCount, err := client.GetNumOfTasks()
	if err != nil {
		log.Fatal().Err(err).Msg("in GetNumOfTasks")
	}
	log.Info().Msgf("Number of possible tasks: %d", totalTaskCount)
	if startTaskIndex >= totalTaskCount {
		log.Fatal().Msgf("the requested start index (%d) must not be less than number of tasks available (%d)", startTaskIndex, totalTaskCount)
	}
	if numOfTasks == 0 {
		numOfTasks = totalTaskCount - startTaskIndex
	}
	if startTaskIndex+numOfTasks > totalTaskCount {
		numOfTasks = totalTaskCount - startTaskIndex
		log.Warn().Msgf("only able to crawl %d tasks", numOfTasks)
	}
	log.Info().Msgf("Start crawling tasks (number %d, startIndex: %d)", numOfTasks, startTaskIndex)
	tasks, err := client.GetTasks(int(numOfTasks), int(startTaskIndex))
	if err != nil {
		log.Fatal().Err(err).Msg("in GetProcesses")
	}

	//create folder
	var Tag string  = appConfig.taskTag + "-"
	for _, extension := range appConfig.taskExtensions{
        Tag = Tag + extension + ","
	}
	Tag = Tag + "-"
	for _, detection := range appConfig.taskDetections{
        Tag = Tag + strconv.Itoa(detection) 
	}
	os.Mkdir(Tag, os.ModePerm)

	//for each task of list task
	
	for _, task := range tasks {
		fmt.Print("\n\n")
		// print task info
		log.Info().Msg(task.GetIdentity())

		if err := dumpTask(client, Tag, task); err != nil {
			log.Info().Msg("cannot dump RawTask, ")
			client.conn.Close()
			return
		}
	}
	// for _, task := range tasks {
	// 	fmt.Print("\n\n")
	// 	log.Info().Msg(task.GetIdentity())
	// 	processes, err := client.GetProcesses(task)
	// 	if err != nil {
	// 		log.Fatal().Err(err).Msgf("failed to get processes")
	// 	}
	// 	incidents, err := client.GetIncidents(task)
	// 	if err != nil {
	// 		log.Fatal().Err(err).Msgf("failed to get incidents")
	// 	}
	// 	for _, proc := range processes {
	// 		log.Info().Msgf("[PROCESS] %d - %s - %s", proc.Fields.Pid, proc.Fields.Scores.ImportantReason, proc.Fields.Image)
	// 	}
	// 	for _, incident := range incidents {
	// 		log.Info().Msgf("[MITRE ATT&CK] %s, %v", incident.Fields.Title, incident.Fields.Mitre)
	// 	}
	// }
}
