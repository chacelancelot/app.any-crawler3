package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
)

// ToJson serializes the object into json format
func ToJson(v interface{}) string {
	bytes, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		return err.Error()
	}
	return string(bytes)
}

type ProcessTree struct {
	Root         *ProcessNode
	NodesByPid   map[int]*ProcessNode
	NodesById    map[string]*ProcessNode
	NodesAtLevel map[int]int
}

func NewProcessTree() *ProcessTree {
	return &ProcessTree{
		NodesByPid:   make(map[int]*ProcessNode),
		NodesById:    make(map[string]*ProcessNode),
		NodesAtLevel: make(map[int]int),
	}
}

func LoadProcessTree(fileAt string) (*ProcessTree, *ProcessData, error) {
	file, err := os.Open(fileAt)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, nil, err
	}
	var procData *ProcessData
	if err := json.Unmarshal(bytes, &procData); err != nil {
		return nil, nil, err
	}

	procTree := NewProcessTree()
	var mainProc *Process
	for i := 0; i < len(procData.Processes); i++ {
		if procData.Processes[i].ProcessType == "Main process" {
			mainProc = procData.Processes[i]
			break
		}
	}
	if mainProc == nil {
		return nil, procData, errors.New("corrupted data, cannot find \"Main process\" process")
	}
	proc := NewProcessNode(mainProc)
	procTree.Root = proc
	procTree.AddProc(proc)

	for _, proc := range procData.Processes[1:] {
		procNode := NewProcessNode(proc)
		procTree.AddProc(procNode)
		if parentNode, ok := procTree.NodesByPid[procNode.ParentPID]; ok {
			parentNode.Children = append(parentNode.Children, procNode)
		}
	}

	for _, incident := range procData.Incidents {
		if len(incident.MitreAttacks) == 0 {
			continue
		}
		if procNode, ok := procTree.NodesById[incident.ProcessOID]; ok {
			for _, techId := range incident.MitreAttacks {
				procNode.Techniques[techId] = true
			}
		}
	}
	procTree.Refactor()
	return procTree, procData, nil
}

func (procTree *ProcessTree) AddProc(proc *ProcessNode) {
	procTree.NodesByPid[proc.ProcessID] = proc
	procTree.NodesById[proc.OID] = proc
}

func (procTree *ProcessTree) Refactor() {
	for _, procNode := range procTree.NodesByPid {
		sort.Slice(procNode.Children, func(i, j int) bool {
			return procNode.Children[i].CreationTimestamp > procNode.Children[j].CreationTimestamp
		})
	}
	procTree.WalkDfs(func(node *ProcessNode, parent *ProcessNode, level int) bool {
		procTree.NodesAtLevel[level]++
		return true
	})
}

func (procTree *ProcessTree) DepthFirstSearch() []*ProcessNode {
	flatTree := make([]*ProcessNode, 0, len(procTree.NodesByPid))
	stack := make([]*ProcessNode, 1, len(procTree.NodesByPid))
	stack[0] = procTree.Root

	var procNode *ProcessNode
	for len(stack) > 0 {
		procNode, stack = stack[len(stack)-1], stack[:len(stack)-1]
		flatTree = append(flatTree, procNode)
		for i := len(procNode.Children) - 1; i >= 0; i-- {
			stack = append(stack, procNode.Children[i])
		}
	}
	return flatTree
}

func getTreeHeight(root *ProcessNode) int {
	if root == nil {
		return 0
	}
	ans := 0
	for _, child := range root.Children {
		tmpHeight := getTreeHeight(child)
		if ans < tmpHeight {
			ans = tmpHeight
		}
	}
	return ans + 1
}

func getNumOfNodes(root *ProcessNode) int {
	if root == nil {
		return 0
	}
	count := 0
	root.WalkDfs(func(node *ProcessNode, parent *ProcessNode, level int) bool {
		count++
		return true
	}, nil, 1)
	return count
}

func (procTree *ProcessTree) GetTreeHeight() int {
	return getTreeHeight(procTree.Root)
}

type WalkDfsFunc func(node *ProcessNode, parent *ProcessNode, level int) bool

func (procTree *ProcessTree) WalkDfs(walkFunc WalkDfsFunc) {
	procTree.Root.WalkDfs(walkFunc, nil, 1)
}

func (procNode *ProcessNode) WalkDfs(walkFunc WalkDfsFunc, parent *ProcessNode, level int) {
	if walkFunc(procNode, parent, level) {
		for _, child := range procNode.Children {
			if !child.Removed {
				child.WalkDfs(walkFunc, procNode, level+1)
			}
		}
	}
}

func (procNode *ProcessNode) ToTree() *ProcessTree {
	cloneTree := NewProcessTree()
	procNode.WalkDfs(func(procNode *ProcessNode, parent *ProcessNode, level int) bool {
		cloneNode := procNode.MakeCopy()
		cloneTree.AddProc(cloneNode)
		if parent == nil {
			cloneTree.Root = cloneNode
			return true
		}
		cloneParentNode, ok := cloneTree.NodesById[parent.OID]
		if !ok {
			log.Println("Warn: something unexpected happened in ToTree")
			return false
		}
		cloneParentNode.addChild(cloneNode)
		return true
	}, nil, 1)
	cloneTree.Refactor()

	return cloneTree
}

func (procNode *ProcessNode) StripTreeAt(stripLevel int) *ProcessTree {
	cloneTree := procNode.ToTree()
	cloneTree.WalkDfs(func(procNode *ProcessNode, parent *ProcessNode, level int) bool {
		if level >= stripLevel {
			procNode.Children = nil
			return false
		}
		return true
	})
	for i := stripLevel + 1; i <= getTreeHeight(procNode); i++ {
		delete(cloneTree.NodesAtLevel, i)
	}
	return cloneTree
}

func CalculateSimilarScore(flatTreeA, flatTreeB []*ProcessNode) float64 {
	var ans float64
	// product/summation operator
	for i := 0; i < len(flatTreeA); i++ {
		ans += flatTreeA[i].compareTo(flatTreeB[i])
	}
	return ans / float64(len(flatTreeA))
}

var shouldTraverseNext = false

func compareToLooseCase(profileTree, checkTree *ProcessTree, numOfProfileNodes int) float64 {
	checkTree.WalkDfs(func(node *ProcessNode, parent *ProcessNode, level int) bool {
		if shouldTraverseNext {
			return false
		}
		if parent == nil {
			return true
		}
		numOfCheckNodes := getNumOfNodes(checkTree.Root)
		if numOfCheckNodes < numOfProfileNodes {
			return false
		} else if numOfCheckNodes == numOfProfileNodes {
			log.Println("ping")
			checkTree.DumpTree()
			shouldTraverseNext = true
			return false
		}

		if profileTree.NodesAtLevel[level] > checkTree.NodesAtLevel[level] {
			return false
		}
		if profileTree.NodesAtLevel[level] < checkTree.NodesAtLevel[level] {
			// try to remove subtree at node
			node.Removed = true
			node.WalkDfs(func(node *ProcessNode, parent *ProcessNode, level int) bool {
				checkTree.NodesAtLevel[level]--
				return true
			}, parent, level)

			compareToLooseCase(profileTree, checkTree, numOfProfileNodes)

			node.WalkDfs(func(node *ProcessNode, parent *ProcessNode, level int) bool {
				checkTree.NodesAtLevel[level]++
				return true
			}, parent, level)
			shouldTraverseNext = false
			node.Removed = false
		}
		return true
	})
	return 0
}

func (procTree *ProcessTree) CompareToLooseCase(another *ProcessTree) float64 {
	numOfProfileNodes := getNumOfNodes(procTree.Root)
	return compareToLooseCase(procTree, another, numOfProfileNodes)
}

func (procTree *ProcessTree) CompareTo(checkTree *ProcessTree) float64 {
	profileTreeNodes := getNumOfNodes(procTree.Root)
	checkTreeNodes := getNumOfNodes(checkTree.Root)
	profileTreeHeight := procTree.GetTreeHeight()

	if profileTreeNodes > checkTreeNodes {
		return 0
	}
	if profileTreeNodes == checkTreeNodes { // exactly-matching
		flatProfileTree := procTree.DepthFirstSearch()
		flatCheckTree := checkTree.DepthFirstSearch()
		return CalculateSimilarScore(flatProfileTree, flatCheckTree)
	}

	checkTree.WalkDfs(func(node *ProcessNode, parent *ProcessNode, level int) bool {
		if getTreeHeight(node) < profileTreeHeight || getNumOfNodes(node) < profileTreeNodes {
			return false
		}
		potentialTree := node.StripTreeAt(profileTreeHeight)
		if getNumOfNodes(potentialTree.Root) < profileTreeNodes {
			return true
		}
		log.Printf("potential node: (pid: %d, image: %s)\n", node.ProcessID, node.Image)
		potentialTree.DumpTree()
		// how to check potentialTree vs profileTree
		log.Println(procTree.CompareToLooseCase(potentialTree))
		os.Exit(1)
		return true
	})
	return 0
}

func (procTree *ProcessTree) DumpTree() {
	procTree.WalkDfs(func(node *ProcessNode, parent *ProcessNode, level int) bool {
		log.Printf("Level: %d, ID: %d, Image: %s\n", node.ProcessID, level, node.Image)
		return true
	})
}

type ProcessNode struct {
	*Process
	Children   []*ProcessNode
	Parent     *ProcessNode
	Techniques map[string]bool

	Removed bool // to simulate the removal of tree node
}

func NewProcessNode(proc *Process) *ProcessNode {
	return &ProcessNode{
		Process:    proc,
		Children:   make([]*ProcessNode, 0),
		Techniques: make(map[string]bool),
	}
}

// clone the node with the same properties except for the children
func (procNode *ProcessNode) MakeCopy() *ProcessNode {
	return &ProcessNode{
		Process:    procNode.Process,
		Children:   make([]*ProcessNode, 0),
		Techniques: procNode.Techniques,
	}
}

func (procNode *ProcessNode) addChild(child *ProcessNode) {
	// future: should change Children to linked list
	procNode.Children = append(procNode.Children, child)
}

func (procNode *ProcessNode) compareTo(another *ProcessNode) float64 {
	// should web consider the process name, image and commandline or only consider its techniques

	if len(procNode.Techniques) == 0 { // no technique case
		if strings.EqualFold(GetImageName(procNode.Image), GetImageName(another.Image)) {
			return 1
		}
		return 0
	}

	numOfMatchedTechIds := 0
	for techId := range another.Techniques {
		if procNode.Techniques[techId] {
			numOfMatchedTechIds++
		}
	}
	return float64(numOfMatchedTechIds) / float64(len(procNode.Techniques))
}

type TreeGroup struct {
	Profile        *ProcessTree
	ProfileData    *ProcessData
	SimilarDegrees []float64
	NodeInfos      []*ProcessData
}

func NewTreeGroup() *TreeGroup {
	return &TreeGroup{
		SimilarDegrees: make([]float64, 0),
		NodeInfos:      make([]*ProcessData, 0),
	}
}

func checkWithProfile(profile *ProcessTree, profileData *ProcessData, procTrees map[*ProcessData]*ProcessTree,
	deleted bool) *TreeGroup {
	treeGroup := NewTreeGroup()

	for procData, procTree := range procTrees {
		if profileData.UUID == procData.UUID {
			continue
		}
		similarDegree := profile.CompareTo(procTree)
		if similarDegree >= maliciousThreshold {
			treeGroup.SimilarDegrees = append(treeGroup.SimilarDegrees, similarDegree)
			treeGroup.NodeInfos = append(treeGroup.NodeInfos, procData)
			if deleted {
				delete(procTrees, procData)
			}
		}
	}
	treeGroup.Profile = profile
	treeGroup.ProfileData = profileData
	return treeGroup
}

func printResult(treeGroup *TreeGroup, numOfTrees int) {
	profileData := treeGroup.ProfileData
	similarDegrees := treeGroup.SimilarDegrees
	nodeInfos := treeGroup.NodeInfos

	log.Println()
	log.Printf("[*] coverage: %.2f%%, md5: %s, uuid: %s, profile: %s\n", float64(len(similarDegrees))*100/float64(numOfTrees),
		profileData.Md5, profileData.UUID, profileData.Name)

	tempGroups := make(map[*ProcessData]float64, 0)
	// sort by P
	for i := 0; i < len(similarDegrees); i++ {
		tempGroups[nodeInfos[i]] = similarDegrees[i]
	}
	sort.Slice(nodeInfos, func(i, j int) bool {
		return tempGroups[nodeInfos[i]] > tempGroups[nodeInfos[j]]
	})

	for i := 0; i < len(similarDegrees); i++ {
		procData := nodeInfos[i]
		result := tempGroups[procData]
		log.Printf("P: %.2f, md5: %s, uuid: %s, name: %s\n", result, procData.Md5, procData.UUID, procData.Name)
	}
}

var (
	malwareTag         string
	crawlByTag         bool
	crawlByTask        bool
	isEvaluator        bool
	maliciousThreshold float64
	minNodeNum         int
)

const evaluationUsageFormat = "Usage: %s -e <Malware Tag> [TaskFileName A] [TaskFileName B]\n"

func init() {
	log.SetOutput(os.Stdout)
	flag.BoolVar(&crawlByTag, "c", false, "crawling tasks from app.any.run")
	flag.BoolVar(&crawlByTask, "i", false, "crawling a task from app.any.run")
	flag.BoolVar(&isEvaluator, "e", false, "grouping tasks by its similarity")
	flag.Float64Var(&maliciousThreshold, "t", 0.7, "threshold value for classification purpose")
	flag.IntVar(&minNodeNum, "m", 1, "only consider the process tree whose node number >= ")
}

func main() {
	flag.Parse()

	switch {
	case crawlByTag:
		if flag.NArg() < 2 {
			fmt.Printf("Usage: %s -c <Malware Tag> <Task Index Index> <Number of Tasks>\n", os.Args[0])
			os.Exit(0)
		}
		malwareTag = flag.Args()[0]
		taskIndex, _ := strconv.Atoi(flag.Args()[1])
		numOfTasks, _ := strconv.Atoi(flag.Args()[2])
		crawlTasks(malwareTag, taskIndex, numOfTasks)
	case crawlByTask:
		if flag.NArg() < 2 {
			fmt.Printf("Usage: %s -i <Output Directory> <Task UUID>\n", os.Args[0])
			os.Exit(0)
		}
		outDirPath := flag.Args()[0]
		taskUuid := flag.Args()[1]
		if err := crawlTaskByUUID(outDirPath, taskUuid); err != nil {
			log.Fatalf("failed to crawl the task with uuid %s: %s", taskUuid, err)
		}
	case isEvaluator:
		if flag.NArg() < 1 {
			fmt.Printf(evaluationUsageFormat, os.Args[0])
			os.Exit(0)
		}
		malwareTag = flag.Args()[0]
		switch flag.NArg() {
		case 1, 2:
			// loading process tree data
			files, err := ioutil.ReadDir(malwareTag)
			if err != nil {
				log.Fatal(err)
			}
			procTrees := make(map[*ProcessData]*ProcessTree)
			for _, file := range files {
				if !file.IsDir() && strings.HasSuffix(file.Name(), ".json") {
					procTree, procData, err := LoadProcessTree(fmt.Sprintf("%s/%s", malwareTag, file.Name()))
					if err != nil {
						log.Printf("Warn: cannot load process tree model at %s, %s", file.Name(), err)
						continue
					}
					if getNumOfNodes(procTree.Root) >= minNodeNum {
						procTrees[procData] = procTree
					}
				}
			}
			taskCount := len(procTrees)
			log.Printf("considering %d tasks\n", taskCount)

			if flag.NArg() == 2 {
				profileAt := flag.Args()[1]
				profile, profileData, err := LoadProcessTree(fmt.Sprintf("%s/%s.json", malwareTag, profileAt))
				if err != nil {
					log.Fatal(err)
				}
				treeGroup := checkWithProfile(profile, profileData, procTrees, false)
				printResult(treeGroup, taskCount)
				return
			}

			treeGroups := make([]*TreeGroup, 0)
			for procData, procTree := range procTrees {
				treeGroup := checkWithProfile(procTree, procData, procTrees, true)
				if len(treeGroup.NodeInfos) == 0 {
					continue
				}
				treeGroups = append(treeGroups, treeGroup)
			}
			sort.Slice(treeGroups, func(i, j int) bool {
				return len(treeGroups[i].NodeInfos) > len(treeGroups[j].NodeInfos)
			})
			var totalCoverage float64
			for _, treeGroup := range treeGroups {
				printResult(treeGroup, taskCount)
				totalCoverage += float64(len(treeGroup.NodeInfos)) / float64(taskCount)
			}
			log.Printf("[*] total effective profile: %d/%d, total coverage: %.2f %%\n", len(treeGroups), taskCount,
				totalCoverage*100)

		case 3:
			profileAt := flag.Args()[1]
			profile, profileData, err := LoadProcessTree(fmt.Sprintf("%s/%s.json", malwareTag, profileAt))
			if err != nil {
				log.Fatal(err)
			}
			checkProfileAt := flag.Args()[2]
			checkProfile, checkProfileData, err := LoadProcessTree(fmt.Sprintf("%s/%s.json", malwareTag,
				checkProfileAt))
			if err != nil {
				log.Fatal(err)
			}
			result := profile.CompareTo(checkProfile)
			log.Printf("[*] md5: %s, uuid: %s, profile: %s\n", profileData.Md5, profileData.UUID, profileData.Name)
			log.Printf("P: %.2f, md5: %s, uuid: %s, name: %s\n", result, checkProfileData.Md5, checkProfileData.UUID, checkProfileData.Name)
		default:
			fmt.Printf(evaluationUsageFormat, os.Args[0])
			os.Exit(0)
		}
	default:
		flag.Usage()
		os.Exit(0)
	}
}
