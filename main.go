package main

import (
	"bufio"
	"flag"
	"fmt"
	//"io"
	"os"
	"os/exec"
	"path/filepath"
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
	//"encoding/json"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Edge struct {
	Src, Dst string
	Weight   int
}

type Map map[string][]string

type Graph struct {
	Neighbours Map
	Edges      []Edge
}

func (g *Graph) Create(edges []Edge) {
	g.Edges = edges
	g.Neighbours = make(Map)
	for _, edge := range edges {
		g.Neighbours[edge.Src] = append(g.Neighbours[edge.Src], edge.Dst)
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

func getPacketInfo(packet gopacket.Packet, i int) {
	fmt.Printf("Decoding packet %d", i)
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer != nil {
		fmt.Printf("\tEth Layer Detected\n")
		ethPacket, _ := ethLayer.(*layers.Ethernet)
		fmt.Printf("\t\tSource MAC %s\n", ethPacket.SrcMAC)
		fmt.Printf("\t\tDest MAC %s\n", ethPacket.DstMAC)
		fmt.Printf("\t\tEth type %s\n", ethPacket.EthernetType)
	}
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		fmt.Printf("\tIP Layer Detected\n")
		ip, _ := ipLayer.(*layers.IPv4)
		fmt.Printf("\t\tFrom %s to %s\n", ip.SrcIP, ip.DstIP)
		fmt.Printf("\t\tProtocol: %s", ip.Protocol)
	}
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		fmt.Printf("\tTCP Layer Detected\n")
		tcp, _ := tcpLayer.(*layers.TCP)
		fmt.Printf("\t\tFrom port %d to %d\n", tcp.SrcPort, tcp.DstPort)
		fmt.Printf("\t\tSequence Number: %d\n", tcp.Seq)
	}
}
func parseTCPDumpFile(filename string) {
	handleRead, err := pcap.OpenOffline(filename)
	if err != nil {
		fmt.Printf("PCAP Offline open file error: %s\n", err)
	}
	defer handleRead.Close()
	packets := gopacket.NewPacketSource(handleRead, handleRead.LinkType())
	i := 0
	for packet := range packets.Packets() {
		getPacketInfo(packet, i)
		i += 1
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
	fmt.Printf("There are %d pods in the namespace %s of the cluster\n", len(pods.Items), namespace)
	cmds := make(map[string]*exec.Cmd)
	for i, pod := range pods.Items {
		fmt.Printf("%d: name [%s] ip [%s] containers [", i, pod.Name, pod.Status.PodIP)
		for j, container := range pod.Spec.Containers {
			if j == 0 {
				fmt.Printf("%s", container.Name)
			} else {
				fmt.Printf(" %s", container.Name)
			}
		}
		fmt.Printf("]\n")
		cmds[pod.Name] = startCommand("kubectl", "sniff", pod.Name, "-c", pod.Spec.Containers[0].Name, "-o", pod.Spec.Containers[0].Name+".tcpdump")
		if cmds[pod.Name] == nil {
			panic(fmt.Sprintf("Cound't start sniffer on pod %s", pod.Name))
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
		fmt.Printf("Killing %s\n", key)
		value.Process.Signal(os.Kill)
	}
	fmt.Printf("Done\n")
	parseTCPDumpFile(pods.Items[0].Spec.Containers[0].Name + ".tcpdump")
	/*

		var edges []Edge
		edges = append(edges, Edge{"0", "1", 2})
		edges = append(edges, Edge{"2", "1", -1})
		edges = append(edges, Edge{"1", "0", 3})
		edges = append(edges, Edge{"2", "0", -3})
		var graph Graph
		graph.Create(edges)
		jsonData, err := json.MarshalIndent(graph, "", "    ")
		fmt.Printf("%s\n", jsonData)
	*/
}

func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return os.Getenv("USERPROFILE") // windows
}
