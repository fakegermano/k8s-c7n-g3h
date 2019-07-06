package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
	// "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	//
	// Uncomment to load all auth plugins
	// _ "k8s.io/client-go/plugin/pkg/client/auth"
	//
	// Or uncomment to load specific auth plugins
	// _ "k8s.io/client-go/plugin/pkg/client/auth/azure"
	// _ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	// _ "k8s.io/client-go/plugin/pkg/client/auth/oidc"
	// _ "k8s.io/client-go/plugin/pkg/client/auth/openstack"
	"encoding/json"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Edge struct {
	Src, Dst string
}

type WeightedEdge struct {
	Edge          Edge
	WeightPercent float64
	Weight        int
}

type Map map[string][]string

type Graph struct {
	Neighbours Map
	Edges      []WeightedEdge
}

func (g *Graph) Create(edges []WeightedEdge) {
	gEdges := make([]WeightedEdge, 0)
	g.Neighbours = make(Map)
	totalsVertex := make(map[string]float64)
	for _, edge := range edges {
		if edge.Edge.Src != "" && edge.Edge.Dst != "" && edge.Edge.Src != edge.Edge.Dst && edge.Weight > 0 {
			if _, ok := totalsVertex[edge.Edge.Src]; ok {
				totalsVertex[edge.Edge.Src] += float64(edge.Weight)
			} else {
				totalsVertex[edge.Edge.Src] = float64(edge.Weight)
			}
			g.Neighbours[edge.Edge.Src] = append(g.Neighbours[edge.Edge.Src], edge.Edge.Dst)
			gEdges = append(gEdges, edge)
		}
	}
	g.Edges = make([]WeightedEdge, 0)
	for _, edge := range gEdges {
		pEdge := WeightedEdge{edge.Edge, float64(edge.Weight) / totalsVertex[edge.Edge.Src], edge.Weight}
		g.Edges = append(g.Edges, pEdge)
	}
}

func startCommand(program string, args ...string) *exec.Cmd {
	cmd := exec.Command(program, args...)
	err := cmd.Start()
	if err != nil {
		fmt.Printf("%v\n", err)
		return nil
	}
	return cmd
}

func tick(ticker *time.Ticker) {
	for _ = range ticker.C {
		fmt.Printf("waiting...\n")
	}
}

// TODO: Better decode the layers (using maybe a faster recyclable way)
func getPacketInfo(packet gopacket.Packet) (ipSrc string, ipDst string) {
	if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		ip, _ := ip4Layer.(*layers.IPv4)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			// Only care for packets that have a TCP layer (data stream)
			return ip.SrcIP.String(), ip.DstIP.String()
		}
	} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		ip, _ := ip4Layer.(*layers.IPv6)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			// Only care for packets that have a TCP layer (data stream)
			return ip.SrcIP.String(), ip.DstIP.String()
		}
	}
	return "", ""
}

func parseTCPDumpFile(filename string, ip2name map[string]string, edges chan Edge, wg *sync.WaitGroup) {
	defer wg.Done()
	handleRead, err := pcap.OpenOffline(filename)
	if err != nil {
		fmt.Printf("PCAP Offline open file error: %s\n", err)
	}
	defer handleRead.Close()
	packets := gopacket.NewPacketSource(handleRead, handleRead.LinkType())

	for packet := range packets.Packets() {

		ipSrc, ipDst := getPacketInfo(packet)
		w := 0
		if ipSrc != "" && ipDst != "" {
			w = 1
		}
		if w == 1 {
			if _, ok := ip2name[ipSrc]; ok {
				if _, ok2 := ip2name[ipDst]; ok2 {
					edges <- Edge{ip2name[ipSrc], ip2name[ipDst]}
				}
			}
		}
	}
}

func main() {

	var kubeconfig *string
	if home := homeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}

	// use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		panic(err.Error())
	}
	flag.Parse()
	// create the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}
	namespace := "default"
	pods, err := clientset.CoreV1().Pods(namespace).List(metav1.ListOptions{})
	if err != nil {
		panic(err.Error())
	}
	services, err := clientset.CoreV1().Services(namespace).List(metav1.ListOptions{})
	if err != nil {
		panic(err.Error())
	}
	fmt.Printf("There are %d pods in the namespace %s of the cluster\n", len(pods.Items), namespace)
	fmt.Printf("There are %d services in the namespace %s of the cluster\n", len(services.Items), namespace)

	ip2name := make(map[string]string)
	for i, service := range services.Items {
		fmt.Printf("SERVICE: %d: name [%s] ip [%s]\n", i, service.Name, service.Spec.ClusterIP)
		ip2name[service.Spec.ClusterIP] = service.Name
	}

	cmds := make(map[string]*exec.Cmd)
	dumpfiles := make([]string, 0, len(pods.Items))
	for i, pod := range pods.Items {
		fmt.Printf("POD: %d: name [%s] ip [%s] containers [", i, pod.Name, pod.Status.PodIP)
		ip2name[pod.Status.PodIP] = pod.Name
		for j, container := range pod.Spec.Containers {
			if j == 0 {
				fmt.Printf("%s", container.Name)
			} else {
				fmt.Printf(" %s", container.Name)
			}
		}
		fmt.Printf("]\n")
		// TODO say error if kubectl sniff is not installed
		dumpfilename := pod.Spec.Containers[0].Name + ".tcpdump"
		cmds[pod.Name] = startCommand("kubectl", "sniff", pod.Name, "-c", pod.Spec.Containers[0].Name, "-o", dumpfilename)
		if cmds[pod.Name] == nil {
			panic(fmt.Sprintf("Cound't start sniffer on pod %s", pod.Name))
		} else {
			dumpfiles = append(dumpfiles, dumpfilename)
		}
	}
	fmt.Printf("Go use the application!.... [waiting]\n")
	ticker := time.NewTicker(5 * time.Second)
	go tick(ticker)
	fmt.Printf("Say [done] when done\n")
	reader := bufio.NewReader(os.Stdin)
	for {
		byteArray, _, _ := reader.ReadLine()
		input := string(byteArray[:])
		if input == "done" {
			break
		}
	}
	fmt.Printf("Killing processes\n")
	for key, value := range cmds {
		fmt.Printf("Killing %s sniffer\n", key)
		value.Process.Signal(os.Kill)
	}
	fmt.Printf("Done\n")
	edges := make(chan Edge)
	wg := &sync.WaitGroup{}
	for _, file := range dumpfiles {
		wg.Add(1)
		go parseTCPDumpFile(file, ip2name, edges, wg)
		defer os.Remove(file)
	}
	go func() {
		wg.Wait()
		close(edges)
	}()
	wEdges := make(map[Edge]*WeightedEdge)
	for edge := range edges {
		if _, ok := wEdges[edge]; ok {
			wEdges[edge].Weight += 1
		} else {
			wEdge := WeightedEdge{edge, 0, 1}
			wEdges[edge] = &wEdge
		}
	}
	gEdges := make([]WeightedEdge, len(wEdges), len(wEdges))
	for _, val := range wEdges {
		gEdges = append(gEdges, *val)
	}
	var graph Graph
	graph.Create(gEdges)
	jsonData, err := json.MarshalIndent(graph, "", "    ")
	ferr := ioutil.WriteFile("couplingGraph.json", jsonData, 0644)
	if ferr != nil {
		panic(ferr)
	}
	fmt.Printf("Finished! Wrote file couplingGraph.json\n")
}

func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return os.Getenv("USERPROFILE") // windows
}
