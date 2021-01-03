// +build windows

package collector

import (
	"context"
	"fmt"
	"os"
	"strings"
    "bytes"

	"github.com/Microsoft/hcsshim"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"

	client "github.com/docker/docker/client"

	docker "github.com/fsouza/go-dockerclient"
)

func init() {
	registerCollector("container", NewContainerMetricsCollector)
}

// A ContainerMetricsCollector is a Prometheus collector for containers metrics
type ContainerMetricsCollector struct {
	// Presence
	ContainerAvailable *prometheus.Desc

	// Number of containers
	ContainersCount *prometheus.Desc
	// memory
	UsageCommitBytes            *prometheus.Desc
	UsageCommitPeakBytes        *prometheus.Desc
	UsagePrivateWorkingSetBytes *prometheus.Desc

	// CPU
	RuntimeTotal  *prometheus.Desc
	RuntimeUser   *prometheus.Desc
	RuntimeKernel *prometheus.Desc
	// CPU Windows
	cpuPercent *prometheus.Desc
	memPercent *prometheus.Desc

	// Network
	BytesReceived          *prometheus.Desc
	BytesSent              *prometheus.Desc
	PacketsReceived        *prometheus.Desc
	PacketsSent            *prometheus.Desc
	DroppedPacketsIncoming *prometheus.Desc
	DroppedPacketsOutgoing *prometheus.Desc
}

//info docker info
type dockerInfo struct {
	id         string
	name       string
	network    string
	states     string
	namespace  string
	podname    string
	cpuPercent float64
	memPercent float64
}

// NewContainerMetricsCollector constructs a new ContainerMetricsCollector
func NewContainerMetricsCollector() (Collector, error) {
	const subsystem = "container"
	return &ContainerMetricsCollector{
		ContainerAvailable: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "available"),
			"Available",
			[]string{"container_id", "hostname", "namespace", "podname"},
			nil,
		),
		ContainersCount: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "count"),
			"Number of containers",
			nil,
			nil,
		),
		UsageCommitBytes: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "memory_usage_commit_bytes"),
			"Memory Usage Commit Bytes",
			[]string{"container_id", "hostname", "namespace", "podname"},
			nil,
		),
		UsageCommitPeakBytes: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "memory_usage_commit_peak_bytes"),
			"Memory Usage Commit Peak Bytes",
			[]string{"container_id", "hostname", "namespace", "podname"},
			nil,
		),
		UsagePrivateWorkingSetBytes: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "memory_usage_private_working_set_bytes"),
			"Memory Usage Private Working Set Bytes",
			[]string{"container_id", "hostname", "namespace", "podname"},
			nil,
		),
		memPercent: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "memory_usage_memPercent"),
			"Memory Usage Private Working memPercent",
			[]string{"container_id", "hostname", "namespace", "podname"},
			nil,
		),
		cpuPercent: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "cpu_usage_cpuPercent"),
			"Total cpuPercent",
			[]string{"container_id", "hostname", "namespace", "podname"},
			nil,
		),
		RuntimeTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "cpu_usage_seconds_total"),
			"Total Run time in Seconds",
			[]string{"container_id", "hostname", "namespace", "podname"},
			nil,
		),
		RuntimeUser: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "cpu_usage_seconds_usermode"),
			"Run Time in User mode in Seconds",
			[]string{"container_id", "hostname", "namespace", "podname"},
			nil,
		),
		RuntimeKernel: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "cpu_usage_seconds_kernelmode"),
			"Run time in Kernel mode in Seconds",
			[]string{"container_id", "hostname", "namespace", "podname"},
			nil,
		),
		BytesReceived: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "network_receive_bytes_total"),
			"Bytes Received on Interface",
			[]string{"container_id", "interface", "hostname", "namespace", "podname"},
			nil,
		),
		BytesSent: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "network_transmit_bytes_total"),
			"Bytes Sent on Interface",
			[]string{"container_id", "interface", "hostname", "namespace", "podname"},
			nil,
		),
		PacketsReceived: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "network_receive_packets_total"),
			"Packets Received on Interface",
			[]string{"container_id", "interface", "hostname", "namespace", "podname"},
			nil,
		),
		PacketsSent: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "network_transmit_packets_total"),
			"Packets Sent on Interface",
			[]string{"container_id", "interface", "hostname", "namespace", "podname"},
			nil,
		),
		DroppedPacketsIncoming: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "network_receive_packets_dropped_total"),
			"Dropped Incoming Packets on Interface",
			[]string{"container_id", "interface", "hostname", "namespace", "podname"},
			nil,
		),
		DroppedPacketsOutgoing: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "network_transmit_packets_dropped_total"),
			"Dropped Outgoing Packets on Interface",
			[]string{"container_id", "interface", "hostname", "namespace", "podname"},
			nil,
		),
	}, nil
}

// Collect sends the metric values for each metric
// to the provided prometheus Metric channel.
func (c *ContainerMetricsCollector) Collect(ctx *ScrapeContext, ch chan<- prometheus.Metric) error {
	if desc, err := c.collect(ch); err != nil {
		log.Error("failed collecting ContainerMetricsCollector metrics:", desc, err)
		return err
	}
	return nil
}

// containerClose closes the container resource
func containerClose(c hcsshim.Container) {
	err := c.Close()
	if err != nil {
		log.Error(err)
	}
}

// get docker container info
func listContainers(client *docker.Client, containerID string) dockerInfo {
	opts := docker.ListContainersOptions{}
	p := dockerInfo{"", "", "", "", "", "", 0.0, 0.0}

	containers, err := client.ListContainers(opts)
	if err != nil {
		panic(err)
	}

	for _, container := range containers {
		if container.ID == containerID {

			dinfo, err := client.InspectContainer(container.ID)
			if err != nil {
				log.Fatal(err)
				continue
			}

			// statsChan := make(chan *docker.Stats)
			// doneChan := make(chan bool)

			// statsOpts := docker.StatsOptions{
			// 	ID:     container.ID[0:10], // Replace container ID here
			// 	Stats:  statsChan,
			// 	Done:   doneChan,
			// 	Stream: false,
			// }

			// go func() {
			// 	err := client.Stats(statsOpts)
			// 	if err != nil {
			// 		// panic: io: read/write on closed pipe
			// 		//panic(err)
			// 	}
			// }()

			// time.Sleep(2 * time.Second)

			// doneChan <- true
			// stats := <-statsChan

			// //close(statsChan)  // client.Stats() will close it
			// close(doneChan)

			// cpuPercent := 0.0
			// memPercent := 0.0

			// if stats != nil {
			// 	// Refer from
			// 	// https://github.com/docker/cli/blob/5c5cdd0e3665f9dfa32eb2f0de136c262b811803/cli/command/container/stats_helpers.go#L187-L201

			// 	possIntervals := uint64(stats.Read.Sub(stats.PreRead).Nanoseconds())

			// 	possIntervals /= 100                    // Convert to number of 100ns intervals
			// 	possIntervals *= uint64(stats.NumProcs) // Multiple by the number of processors

			// 	// Intervals used
			// 	intervalsUsed := stats.CPUStats.CPUUsage.TotalUsage - stats.PreCPUStats.CPUUsage.TotalUsage

			// 	// Percentage avoiding divide-by-zero
			// 	if possIntervals > 0 {
			// 		cpuPercent = float64(intervalsUsed) / float64(possIntervals) * 100.0
			// 	}
			// 	//windows mem
			// 	memPercent = float64(stats.MemoryStats.PrivateWorkingSet)

			// 	log.Info("container.ID[0:10]t=", container.ID[0:10])
			// 	log.Info("cpuPercent ", cpuPercent)
			// 	log.Info("memPercent ", memPercent)

			// }

			contStr := fmt.Sprint(container.Names)
			contStr = strings.ReplaceAll(contStr, "[", "")
			contStr = strings.ReplaceAll(contStr, "]", "")
			contStr = strings.ReplaceAll(contStr, "/", "")

			networkStr := fmt.Sprint(container.Networks)
			//stateStr := fmt.Sprint(container.State)

			stateStr := fmt.Sprint(container.SizeRw)
			p := dockerInfo{container.ID, contStr, networkStr, stateStr, dinfo.Config.Labels["io.kubernetes.pod.namespace"], dinfo.Config.Labels["io.kubernetes.pod.name"], 0.07, 0.06}
			return p
		}
	}

	return p
}

func (c *ContainerMetricsCollector) collect(ch chan<- prometheus.Metric) (*prometheus.Desc, error) {

	// Types Container is passed to get the containers compute systems only
	containers, err := hcsshim.GetContainers(hcsshim.ComputeSystemQuery{Types: []string{"Container"}})
	if err != nil {
		log.Error("Err in Getting containers:", err)
		return nil, err
	}

	count := len(containers)

	ch <- prometheus.MustNewConstMetric(
		c.ContainersCount,
		prometheus.GaugeValue,
		float64(count),
	)
	if count == 0 {
		return nil, nil
	}

	//client
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		panic(err)
	}

	//Types used docker api get container info
	client, err := docker.NewClientFromEnv()
	if err != nil {
		panic(err)
	}
	//Type used os get hostname
	hostname, err := os.Hostname()
	if err != nil {
		panic(err)
	}

	for _, containerDetails := range containers {
		containerId := containerDetails.ID
		container, err := hcsshim.OpenContainer(containerId)

		if container != nil {
			defer containerClose(container)
		}
		if err != nil {
			log.Error("err in opening container: ", containerId, err)
			continue
		}

		cstats, err := container.Statistics()
		if err != nil {
			log.Error("err in fetching container Statistics: ", containerId, err)
			continue
		}

		//container
		containerStats, err := cli.ContainerStats(ctx, containerId, true)
		if err != nil {
			panic(err)
		}

		log.Info("containerStats: ", containerStats)
		log.Info("containerStats.Body: ", containerStats.Body)

		buf := new(bytes.Buffer)
		//io.ReadCloser 转换成 Buffer 然后转换成json字符串
		buf.ReadFrom(containerStats.Body)
		newStr := buf.String()
		log.Info("newStr",newStr)

		// HCS V1 is for docker runtime. Add the docker:// prefix on container_id
		//add method for container info
		containerInfo := listContainers(client, containerId)

		stdnamespaceout := containerInfo.namespace
		podnameout := containerInfo.podname

		if containerInfo.name != "" {
			containerId = containerInfo.name
		} else {
			containerId = "docker://" + containerId[0:10]
		}

		ch <- prometheus.MustNewConstMetric(
			c.ContainerAvailable,
			prometheus.CounterValue,
			1,
			containerId, hostname, stdnamespaceout, podnameout,
		)
		ch <- prometheus.MustNewConstMetric(
			c.UsageCommitBytes,
			prometheus.GaugeValue,
			float64(cstats.Memory.UsageCommitBytes),
			containerId, hostname, stdnamespaceout, podnameout,
		)
		ch <- prometheus.MustNewConstMetric(
			c.UsageCommitPeakBytes,
			prometheus.GaugeValue,
			float64(cstats.Memory.UsageCommitPeakBytes),
			containerId, hostname, stdnamespaceout, podnameout,
		)
		ch <- prometheus.MustNewConstMetric(
			c.UsagePrivateWorkingSetBytes,
			prometheus.GaugeValue,
			float64(cstats.Memory.UsagePrivateWorkingSetBytes),
			containerId, hostname, stdnamespaceout, podnameout,
		)

		ch <- prometheus.MustNewConstMetric(
			c.memPercent,
			prometheus.GaugeValue,
			containerInfo.memPercent,
			containerId, hostname, stdnamespaceout, podnameout,
		)

		ch <- prometheus.MustNewConstMetric(
			c.cpuPercent,
			prometheus.CounterValue,
			containerInfo.cpuPercent,
			containerId, hostname, stdnamespaceout, podnameout,
		)

		ch <- prometheus.MustNewConstMetric(
			c.RuntimeTotal,
			prometheus.CounterValue,
			float64(cstats.Processor.TotalRuntime100ns)*ticksToSecondsScaleFactor,
			containerId, hostname, stdnamespaceout, podnameout,
		)
		ch <- prometheus.MustNewConstMetric(
			c.RuntimeUser,
			prometheus.CounterValue,
			float64(cstats.Processor.RuntimeUser100ns)*ticksToSecondsScaleFactor,
			containerId, hostname, stdnamespaceout, podnameout,
		)
		ch <- prometheus.MustNewConstMetric(
			c.RuntimeKernel,
			prometheus.CounterValue,
			float64(cstats.Processor.RuntimeKernel100ns)*ticksToSecondsScaleFactor,
			containerId, hostname, stdnamespaceout, podnameout,
		)

		if len(cstats.Network) == 0 {
			log.Info("Network get BytesReceived: ", cstats.Network)
			continue
		}

		networkStats := cstats.Network

		//log.Info("Network get BytesReceived: ", cstats.Network)

		//log.Info("Network get Storage: ", cstats.Processor.TotalRuntime100ns)

		for _, networkInterface := range networkStats {

			ch <- prometheus.MustNewConstMetric(
				c.BytesReceived,
				prometheus.CounterValue,
				float64(networkInterface.BytesReceived),
				containerId, networkInterface.EndpointId, hostname, stdnamespaceout, podnameout,
			)
			ch <- prometheus.MustNewConstMetric(
				c.BytesSent,
				prometheus.CounterValue,
				float64(networkInterface.BytesSent),
				containerId, networkInterface.EndpointId, hostname, stdnamespaceout, podnameout,
			)
			ch <- prometheus.MustNewConstMetric(
				c.PacketsReceived,
				prometheus.CounterValue,
				float64(networkInterface.PacketsReceived),
				containerId, networkInterface.EndpointId, hostname, stdnamespaceout, podnameout,
			)
			ch <- prometheus.MustNewConstMetric(
				c.PacketsSent,
				prometheus.CounterValue,
				float64(networkInterface.PacketsSent),
				containerId, networkInterface.EndpointId, hostname, stdnamespaceout, podnameout,
			)
			ch <- prometheus.MustNewConstMetric(
				c.DroppedPacketsIncoming,
				prometheus.CounterValue,
				float64(networkInterface.DroppedPacketsIncoming),
				containerId, networkInterface.EndpointId, hostname, stdnamespaceout, podnameout,
			)
			ch <- prometheus.MustNewConstMetric(
				c.DroppedPacketsOutgoing,
				prometheus.CounterValue,
				float64(networkInterface.DroppedPacketsOutgoing),
				containerId, networkInterface.EndpointId, hostname, stdnamespaceout, podnameout,
			)
			break
		}
	}

	return nil, nil
}
