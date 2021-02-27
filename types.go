package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

var (
	SupportedTaskExtensions = map[string]string{
		"PE EXE":           "0",
		"PE DLL":           "1",
		"JAVA":             "2",
		"HTML Documents":   "3",
		"Adobe Flash":      "4",
		"Adobe PDF":        "5",
		"Microsoft Office": "6",
		"Scripts":          "7",
		"Email files":      "8",
		"Archive files":    "9",
	}
	SupportedTaskDetections = map[string]int{
		"No threats": 0,
		"Suspicious": 1,
		"Malicious":  2,
	}

	SupportedTaskRunType = map[string]string{
		"Url":           "0",
		"File":          "1",
	}
)

type (
	PublicTasksCounterResult struct {
		Msg    string `json:"msg"`
		ID     string `json:"id"`
		Result struct {
			Count uint `json:"count"`
		} `json:"result"`
	}
	// This is not a complete structure because many ignored fields are verbose or just used internally by App.Any.Run
	// runType can be "file", "url", "download"
	RawTask struct {
		Msg        string `json:"msg"`
		Collection string `json:"collection"`
		ID         string `json:"id"`
		Fields     struct {
			Significant bool `json:"significant"`
			Public      struct {
				Objects struct {
					MainObject struct {
						Names struct {
							Basename   string `json:"basename"`
							Real       string `json:"real"`
							URL        string `json:"url"`
							Location   string `json:"location"`
							NeedRename bool   `json:"need_rename"`
						} `json:"names"`
						Hashes struct {
							Ssdeep   string `json:"ssdeep"`
							HeadHash string `json:"head_hash"`
							Sha256   string `json:"sha256"`
							Sha1     string `json:"sha1"`
							Md5      string `json:"md5"`
						} `json:"hashes"`
						Info struct {
							Cmd  string `json:"cmd"`
							Meta struct {
								File string `json:"file"`
								Mime string `json:"mime"`
							} `json:"meta"`
						} `json:"info"`
						Content struct {
							Ext string `json:"ext"`
						} `json:"content"`
						Type string `json:"type"`
					} `json:"mainObject"`
					RunType string `json:"runType"`
				} `json:"objects"`
			} `json:"public"`
			Tags   []string `json:"tags"`
			Scores struct {
				Verdict struct {
					ThreatLevel int    `json:"threat_level"`
					Text        string `json:"text"`
				} `json:"verdict"`
			} `json:"scores"`
			UUID string `json:"uuid"`
		} `json:"fields"`
	}

	RawProcess struct {
		Msg        string `json:"msg"`
		Collection string `json:"collection"`
		ID         string `json:"id"`
		Fields     struct {
			Ms   int `json:"ms"`
			Tl   int `json:"tl"`
			Rb   int `json:"rb"`
			Pid  int `json:"pid"`
			Task struct {
				Type  string `json:"$type"`
				Value string `json:"$value"`
			} `json:"task"`
			ParentPID  int         `json:"parentPID"`
			ParentTID  int         `json:"parentTID"`
			RealPPID   int         `json:"_realPPID"`
			RealPSTART int64       `json:"_realPSTART"`
			RealSTART  int64       `json:"_realSTART"`
			Cmd        string      `json:"cmd"`
			Resolved   interface{} `json:"resolved"`
			Exit       struct {
				Code int `json:"code"`
				How  int `json:"how"`
			} `json:"exit"`
			HeadHash string `json:"head_hash"`
			Times    struct {
				Created struct {
					Date int64 `json:"$date"`
				} `json:"created"`
				Closed struct {
					Date int64 `json:"$date"`
				} `json:"closed"`
			} `json:"times"`
			User struct {
				Name string `json:"name"`
				Sid  string `json:"sid"`
				Il   string `json:"il"`
			} `json:"user"`
			Version struct {
				Description string `json:"description"`
				Company     string `json:"company"`
				Version     string `json:"version"`
			} `json:"version"`
			EventsCounters struct {
				Raw struct {
					Registry int `json:"registry"`
					Files    int `json:"files"`
					Modules  int `json:"modules"`
				} `json:"raw"`
				DroppedFiles int `json:"dropped_files"`
				DebugStrings int `json:"debug_strings"`
				Network      int `json:"network"`
			} `json:"events_counters"`
			Image     string `json:"image"`
			ImageUp   string `json:"imageUp"`
			Important bool   `json:"important"`
			Scores    struct {
				Specs struct {
					Network           bool `json:"network"`
					UacRequest        bool `json:"uac_request"`
					KnownThreat       bool `json:"known_threat"`
					Injects           bool `json:"injects"`
					NetworkLoader     bool `json:"network_loader"`
					ServiceLuncher    bool `json:"service_luncher"`
					ExecutableDropped bool `json:"executable_dropped"`
					Multiprocessing   bool `json:"multiprocessing"`
					CrashedApps       bool `json:"crashed_apps"`
					DebugOutput       bool `json:"debug_output"`
					Stealing          bool `json:"stealing"`
					Exploitable       bool `json:"exploitable"`
					StaticDetections  bool `json:"static_detections"`
					SuspStruct        bool `json:"susp_struct"`
					Autostart         bool `json:"autostart"`
					LowAccess         bool `json:"low_access"`
				} `json:"specs"`
				Type            string `json:"type"`
				Important       bool   `json:"important"`
				ImportantReason string `json:"important_reason"`
				// ImportantSince  struct {
				// 	Date int64 `json:"$date"`
				// } `json:"important_since"`
				Injected     interface{}   `json:"injected"`
				Serviced     interface{}   `json:"serviced"`
				IsMainObject bool          `json:"isMainObject"`
				IsDropped    bool          `json:"isDropped"`
				IsSigned     bool          `json:"isSigned"`
				IsInjected   bool          `json:"isInjected"`
				IsLoadSusp   bool          `json:"isLoadSusp"`
				WasBefore    bool          `json:"wasBefore"`
				FileType     string        `json:"fileType"`
				Signs        []interface{} `json:"signs"`
			} `json:"scores"`
			Status int `json:"status"`
		} `json:"fields"`
	}

	RawIncident struct {
		Msg        string `json:"msg"`
		Collection string `json:"collection"`
		ID         string `json:"id"`
		Fields     struct {
			Task struct {
				Type  string `json:"$type"`
				Value string `json:"$value"`
			} `json:"task"`
			ProcessOID struct {
				Type  string `json:"$type"`
				Value string `json:"$value"`
			} `json:"processOID"`
			Threatlevel int    `json:"threatlevel"`
			Title       string `json:"title"`
			// FirstSeen   struct {
			// 	Date int64 `json:"$date"`
			// } `json:"firstSeen"`
			Mitre []string `json:"mitre"`
		} `json:"fields"`
	}

	RawDNSQueries struct {
        Msg        string `json:"msg"`
        Collection string `json:"collection"`
        ID         string `json:"id"`
        Fields     struct {
            Task struct {
                Type  string `json:"$type"`
                Value string `json:"$value"`
            } `json:"task"`
            ID   string `json:"id"`
            // Time struct {
            //     Date int64 `json:"$date"`
            // } `json:"time"`
            // TimeClose struct {
            //     Date int64 `json:"$date"`
            // } `json:"timeClose"`
            Status int      `json:"status"`
            Domain string   `json:"domain"`
            Ips    []string `json:"ips"`
            V      int      `json:"__v"`
            Type   int      `json:"type"`
        } `json:"fields"`
	}
	
	RawIps struct{
        Msg        string `json:"msg"`
        Collection string `json:"collection"`
        ID         string `json:"id"`
        Fields     struct {
            ID   string `json:"id"`
            Task struct {
                Type  string `json:"$type"`
                Value string `json:"$value"`
            } `json:"task"`
            // Time      int64       `json:"time"`
            // TimeClose interface{} `json:"timeClose"`
            IP        string      `json:"ip"`
            Port      int         `json:"port"`
            Prot      string      `json:"prot"`
            LocalPort int         `json:"localPort"`
            Direction string      `json:"direction"`
            Country   string      `json:"country"`
            Asn       interface{} `json:"asn"`
            Traffic   struct {
                Send int `json:"send"`
                Recv int `json:"recv"`
            } `json:"traffic"`
            ProcessOID struct {
                Type  string `json:"$type"`
                Value string `json:"$value"`
            } `json:"processOID"`
            ProcessName string `json:"processName"`
            Pid         int    `json:"pid"`
            Domain      string `json:"domain"`
            Type        int    `json:"type"`
        } `json:"fields"`
	}
	
	RawHttpRequests struct {
        Msg        string `json:"msg"`
        Collection string `json:"collection"`
        ID         string `json:"id"`
        Fields     struct {
            Sha256     string `json:"sha256"`
            ProcessOID struct {
                Type  string `json:"$type"`
                Value string `json:"$value"`
            } `json:"processOID"`
            Task struct {
                Type  string `json:"$type"`
                Value string `json:"$value"`
            } `json:"task"`
            ID   string `json:"id"`
            // Time struct {
            //     Date int64 `json:"$date"`
            // } `json:"time"`
            // TimeClose interface{} `json:"timeClose"`
            Country   string      `json:"country"`
            Asn       string      `json:"asn"`
            Host      string      `json:"host"`
            URL       string      `json:"url"`
            Method    string      `json:"method"`
            Request   string      `json:"request"`
            Body      struct {
                Response struct {
                    FileID interface{} `json:"fileID"`
                    Size   interface{} `json:"size"`
                } `json:"response"`
                Request struct {
                    FileID interface{} `json:"fileID"`
                    Size   int         `json:"size"`
                } `json:"request"`
            } `json:"body"`
            // To struct {
            //     IP   string `json:"ip"`
            //     Port int    `json:"port"`
            // } `json:"to"`
            Opendir []interface{} `json:"opendir"`
            Linked  struct {
                Discovered struct {
                    Response bool `json:"response"`
                    Request  bool `json:"request"`
                } `json:"discovered"`
                Undiscovered struct {
                    Response bool `json:"response"`
                    Request  bool `json:"request"`
                } `json:"undiscovered"`
            } `json:"linked"`
            V           int    `json:"__v"`
            ProcessName string `json:"processName"`
            Pid         int    `json:"pid"`
            Type        int    `json:"type"`
        } `json:"fields"`
	}
	
	RawThreats struct{ 
        Msg        string `json:"msg"`
        Collection string `json:"collection"`
        ID         string `json:"id"`
        Fields     struct {
            UUID   string `json:"uuid"`
            Taskid struct {
                Type  string `json:"$type"`
                Value string `json:"$value"`
            } `json:"taskid"`
            //Date       int64  `json:"date"`
            Msg        string `json:"msg"`
            Dstport    int    `json:"dstport"`
            Dstip      string `json:"dstip"`
            Srcport    int    `json:"srcport"`
            Linked     bool   `json:"linked"`
            Pro        int    `json:"pro"`
            Class      string `json:"class"`
            Priority   int    `json:"priority"`
            Srcip      string `json:"srcip"`
            Sid        int    `json:"sid"`
            Discovered bool   `json:"discovered"`
            ProcessOID struct {
                Type  string `json:"$type"`
                Value string `json:"$value"`
            } `json:"processOID"`
            ProcessName string `json:"processName"`
            Pid         int    `json:"pid"`
        } `json:"fields"`
	}
	
	//  H_KEY
    RawRegistries struct {
        Msg        string `json:"msg"`
        Collection string `json:"collection"`
        ID         string `json:"id"`
        Fields     struct {
            Task struct {
                Type  string `json:"$type"`
                Value string `json:"$value"`
            } `json:"task"`
            ProcessOID struct {
                Type  string `json:"$type"`
                Value string `json:"$value"`
            } `json:"processOID"`
            // Time struct {
            //     Date int64 `json:"$date"`
            // } `json:"time"`
            Operation string `json:"operation"`
            Name      string `json:"name"`
            Value     string `json:"value"`
            Key       string `json:"key"`
            TypeValue string `json:"typeValue"`
        } `json:"fields"`
	}
	
	RawDropFile struct{
		Msg        string `json:"msg"`
		Collection string `json:"collection"`
		ID         string `json:"id"`
		Fields     struct {
			Size      int    `json:"size"`
			Md5       string `json:"md5"`
			Available bool   `json:"available"`
			Nocontent bool   `json:"nocontent"`
			EOF       bool   `json:"eof"`
			Filename  string `json:"filename"`
			// Time      struct {
			// 	Date int64 `json:"$date"`
			// } `json:"time"`
			ProcessOID struct {
				Type  string `json:"$type"`
				Value string `json:"$value"`
			} `json:"processOID"`
			ContentType string `json:"contentType"`
		} `json:"fields"`
		
	}

	RawProConnect struct{
		Msg        string `json:"msg"`
		Collection string `json:"collection"`
		ID         string `json:"id"`
		Fields     struct {
			ID   string `json:"id"`
			Task struct {
				Type  string `json:"$type"`
				Value string `json:"$value"`
			} `json:"task"`
			// Time      int64  `json:"time"`
			// TimeClose int64  `json:"timeClose"`
			IP        string `json:"ip"`
			Port      int    `json:"port"`
			Prot      string `json:"prot"`
			LocalPort int    `json:"localPort"`
			Direction string `json:"direction"`
			Country   string `json:"country"`
			Asn       string `json:"asn"`
			Traffic   struct {
				Send int `json:"send"`
				Recv int `json:"recv"`
			} `json:"traffic"`
			ProcessOID struct {
				Type  string `json:"$type"`
				Value string `json:"$value"`
			} `json:"processOID"`
			ProcessName string `json:"processName"`
			Pid         int    `json:"pid"`
			Domain      string `json:"domain"`
			Type        int    `json:"type"`
		} `json:"fields"`
	}

	RawProModule struct{
		Msg        string `json:"msg"`
		Collection string `json:"collection"`
		ID         string `json:"id"`
		Fields     struct {
			Task struct {
				Type  string `json:"$type"`
				Value string `json:"$value"`
			} `json:"task"`
			ProcessOID struct {
				Type  string `json:"$type"`
				Value string `json:"$value"`
			} `json:"processOID"`
			Image    string `json:"image"`
			HeadHash string `json:"head_hash"`
			Protect  string `json:"protect"`
			// Time     struct {
			// 	Date int64 `json:"$date"`
			// } `json:"time"`
			Status string `json:"status"`
		} `json:"fields"`	
	}
)

//Mapping all
// simplified structs
type(
	// mapping to RawProcess 
    Process struct {
        OID                        string
        ProcessID                  int
        ParentPID                  int
        CommandLine                string
        Image                      string
        ProcessType                string
        CreationTimestamp          int64
        Registry                   int
        Files                      int
        Modules                    int
        DroppedFiles               int
        DebugStrings               int
        EventsCounters_Network     int
        Scores_Network             bool
        Autostart                  bool
        LowAccess                  bool
        FileType                   string
	}
	
	//  mapping to RawIncident 
    Incident struct {
        ProcessOID   string
        ThreatLevel  int
        MitreAttacks []string
    }

    //  mapping to RawDNSQueries 
    DNSQueries struct{
        Domain      string
        Ips         []string
        Status      int
        Type        int
	}
	
	// mapping to RawIps
	Ips struct {
        ProcessOID  string
        ProcessName string
        Domain      string
        IP          string
        Port        int
        Prot        string
        Send        int
        Recv        int
        Type        int       
	}
	
    //mapping to RawHttpRequests
    HttpRequests struct{
		ProcessOID      string
		ProcessName 	string
        URL             string
        Method          string
        Type            int
	}
	
	//mapping to RawThreats
    Threats struct{
        ProcessOID      string
        ProcessName     string
        Priority        int
	}

	Registries struct{
        ProcessOID      string
        Key             string
        Value           string
        Operation       string
        TypeValue       string
	}
	
	DropFile struct{
		ProcessOID		string
		Size 			int
		Nocontent 		bool
		EOF 			bool
		Filename		string
		ContentType 	string
	}

	ProConnect struct{
		ProcessOID 		string
		IP				string
		Port 			int
		Prot 			string
		Domain 			string
		Type 			int
	}

	ProModule struct{
		ProcessOID 		string
		Image 			string
		HeadHash 		string
		Protect 		string
		Status 			string
	}
	
	ProcessData struct {
        Name                string
        Md5                 string
        UUID                string
        Processes           []*Process
        Incidents           []*Incident
        Ips                 []*Ips
        Domain              []*DNSQueries
        HttpRequests        []*HttpRequests
		Threats             []*Threats 
		Registries          []*Registries 
		DropFile			[]*DropFile
		//ProConnect			[]*ProConnect
		ProModule     		[]*ProModule
    }
)

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

func (task *RawTask) GetIdentity() string {
	mainObject := task.Fields.Public.Objects.MainObject
	format := "UUID: %s, MD5: %s, name: %s"
	switch mainObject.Type {
	case "file":
		return fmt.Sprintf(format, task.Fields.UUID, mainObject.Hashes.Md5, mainObject.Names.Basename)
	case "url":
		return fmt.Sprintf(format, task.Fields.UUID, mainObject.Hashes.Md5, mainObject.Names.URL)
	}
	return "[unknown]"
}

func ToJson(i interface{}) string {
	buffer, err := json.MarshalIndent(i, "", " ")
	if err != nil {
		return err.Error()
	}
	return string(buffer)
}

func GetStrMapKeys(m map[string]string) []string {
	keys := make([]string, 0)
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func GetIntMapKeys(m map[string]int) []string {
	keys := make([]string, 0)
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func FormatStrSlice(values []string) string {
	tokens := make([]string, 0)
	for _, v := range values {
		tokens = append(tokens, fmt.Sprintf(`"%s"`, v))
	}
	return fmt.Sprintf(`[%s]`, strings.Join(tokens, ","))
}

func NewProcess(rawProc *RawProcess) *Process {
	return &Process{
		OID:                        rawProc.ID,
		ProcessID:                  rawProc.Fields.Pid,
		ParentPID:                  rawProc.Fields.ParentPID,
		CommandLine:                rawProc.Fields.Cmd,
		Image:                      rawProc.Fields.Image,
		ProcessType:                rawProc.Fields.Scores.ImportantReason,
        CreationTimestamp:          rawProc.Fields.Times.Created.Date,
        Registry:                   rawProc.Fields.EventsCounters.Raw.Registry,       
        Files:                      rawProc.Fields.EventsCounters.Raw.Files,        
        Modules:                    rawProc.Fields.EventsCounters.Raw.Modules,
        DroppedFiles:               rawProc.Fields.EventsCounters.DroppedFiles,
        DebugStrings:               rawProc.Fields.EventsCounters.DebugStrings,
        EventsCounters_Network:     rawProc.Fields.EventsCounters.Network,
        Scores_Network:             rawProc.Fields.Scores.Specs.Network,
        Autostart:                  rawProc.Fields.Scores.Specs.Autostart,
        LowAccess:                  rawProc.Fields.Scores.Specs.LowAccess,
        FileType:                   rawProc.Fields.Scores.FileType,
	}
}

func NewIncident(rawIncident *RawIncident) *Incident {
	return &Incident{
		ProcessOID:   rawIncident.Fields.ProcessOID.Value,
		ThreatLevel:  rawIncident.Fields.Threatlevel,
		MitreAttacks: rawIncident.Fields.Mitre,
	}
}

func NewDNSQueries(rawDNS *RawDNSQueries) *DNSQueries{
	return &DNSQueries{
		Domain:     rawDNS.Fields.Domain,     
        Ips:        rawDNS.Fields.Ips,
        Status:     rawDNS.Fields.Status,
        Type:       rawDNS.Fields.Type,
	}
}

func NewIps(rawIps *RawIps) *Ips {
	return &Ips{
		ProcessOID:     rawIps.Fields.ProcessOID.Value,
        ProcessName:    rawIps.Fields.ProcessName,
        Domain:         rawIps.Fields.Domain,
        IP:             rawIps.Fields.IP,
        Port:           rawIps.Fields.Port,
        Prot:           rawIps.Fields.Prot,
        Send:           rawIps.Fields.Traffic.Send,
        Recv:           rawIps.Fields.Traffic.Recv,
        Type:           rawIps.Fields.Type,
	}
}

func NewHttpRequests(rawHttp *RawHttpRequests) *HttpRequests {
	return &HttpRequests{
		ProcessOID:                 rawHttp.Fields.ProcessOID.Value,
		ProcessName:				rawHttp.Fields.ProcessName,
        URL:                        rawHttp.Fields.URL,
        Method:                     rawHttp.Fields.Method,
        Type:                       rawHttp.Fields.Type,
	}
}

func NewThreats(rawThreat *RawThreats) *Threats{
	return &Threats{
        ProcessOID:      rawThreat.Fields.ProcessOID.Value,
        ProcessName:     rawThreat.Fields.ProcessName,
        Priority:        rawThreat.Fields.Priority,
	}
}

func NewRegistries(rawRegistries *RawRegistries) *Registries{
	return &Registries{
	    ProcessOID:      rawRegistries.Fields.ProcessOID.Value,
        Key:             rawRegistries.Fields.Key,
        Value:           rawRegistries.Fields.Value,
        Operation:       rawRegistries.Fields.Operation,
        TypeValue:       rawRegistries.Fields.TypeValue,
	}
}

func NewDropFile(rawDropFile *RawDropFile) *DropFile{
	return &DropFile{
        ProcessOID:		rawDropFile.Fields.ProcessOID.Value,
		Size: 			rawDropFile.Fields.Size,
		Nocontent: 		rawDropFile.Fields.Nocontent,
		EOF: 			rawDropFile.Fields.EOF,
		Filename:		rawDropFile.Fields.Filename,
		ContentType: 	rawDropFile.Fields.ContentType,
	}
}

func NewProConnect(rawProConnect *RawProConnect) *ProConnect{
	return &ProConnect{
		ProcessOID: 		rawProConnect.Fields.ProcessOID.Value,
		IP:					rawProConnect.Fields.IP,
		Port: 				rawProConnect.Fields.Port,
		Prot: 				rawProConnect.Fields.Prot,
		Domain: 			rawProConnect.Fields.Domain,
		Type: 				rawProConnect.Fields.Type,
	}
}

func NewProModule(rawProModule *RawProModule) *ProModule{
	return &ProModule{
        ProcessOID: 		rawProModule.Fields.ProcessOID.Value,
		Image: 				rawProModule.Fields.Image,
		HeadHash: 			rawProModule.Fields.HeadHash,
		Protect: 			rawProModule.Fields.Protect,
		Status: 			rawProModule.Fields.Status,
	}
}


