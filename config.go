package main

import (
	"encoding/json"
	"fmt"
	"github.com/prometheus/common/log"
	"github.com/spf13/viper"
	"strconv"
	"strings"
)

const (
	DefTaskTag           = ""
	DefTaskIsSignificant = false
	DefTaskExtensions    = ""
	DefTaskDetections    = ""
	DefExportProcesses   = true
	DefExportATTCKMatrix = true
	DefExportIp			 = true
	DefExportLimit 		 = 50
)

type AppConfig struct {
	taskTag           string
	taskIsSignificant bool
	taskExtensions    []string
	taskDetections    []int
	taskLimit		  int
	exportProcesses   bool
	exportATTCKMatrix bool
	exportIp		  bool
}

func ReadAppConfig(configFilePath string) (*AppConfig, error) {
	viper.SetConfigName(configFilePath)
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Warn("the configuration file not found, switched to default configuration")
		} else {
			return nil, fmt.Errorf("failed to read configuration file: %s", err)
		}
	}
	viper.SetDefault("public_tasks.tag", DefTaskTag)
	viper.SetDefault("public_tasks.significant", DefTaskIsSignificant)
	viper.SetDefault("public_tasks.extensions", DefTaskExtensions)
	viper.SetDefault("public_tasks.detections", DefTaskDetections)
	viper.SetDefault("export.processes", DefExportProcesses)
	viper.SetDefault("export.ATT&CK_matrix", DefExportATTCKMatrix)
	viper.SetDefault("export.ip", DefExportIp)
	viper.SetDefault("public_tasks.limit", DefExportLimit)
	
	

	taskTag := strings.TrimSpace(viper.GetString("public_tasks.tag"))
	rawTaskExtensions := strings.TrimSpace(viper.GetString("public_tasks.extensions"))
	rawTaskDetections := strings.TrimSpace(viper.GetString("public_tasks.detections"))

	var taskExtensions []string
	for _, ext := range strings.Split(rawTaskExtensions, ",") {
		val, ok := SupportedTaskExtensions[ext]
		if !ok {
			return nil, fmt.Errorf("invalid extension '%s': possible values are %s", ext, FormatStrSlice(GetStrMapKeys(SupportedTaskExtensions)))
		}
		taskExtensions = append(taskExtensions, val)
	}
	var taskDetections []int
	for _, detection := range strings.Split(rawTaskDetections, ",") {
		val, ok := SupportedTaskDetections[detection]
		if !ok {
			return nil, fmt.Errorf("invalid detection '%s': possible values are %s", detection, FormatStrSlice(GetIntMapKeys(SupportedTaskDetections)))
		}
		taskDetections = append(taskDetections, val)
	}
	return &AppConfig{
		taskTag:           taskTag,
		taskIsSignificant: viper.GetBool("public_tasks.significant"),
		taskExtensions:    taskExtensions,
		taskDetections:    taskDetections,
		exportProcesses:   viper.GetBool("export.processes"),
		exportATTCKMatrix: viper.GetBool("export.ATT&CK_matrix"),
		exportIp:		   viper.GetBool("export.ip"),
	}, nil
}

func (config *AppConfig) ToTaskParamsJsonQuoted(limit int) string {
	taskParams := &TaskParams{
		IsPublic:    true,
		Runtype:     []string{},
		Verdict:     config.taskDetections,
		Ext:         config.taskExtensions,
		Significant: config.taskIsSignificant,
		Tag:         config.taskTag,
		Limit:		 limit,
	}
	bytes, _ := json.Marshal(taskParams)
	return strings.Trim(strconv.Quote(string(bytes)), `"`)
}
