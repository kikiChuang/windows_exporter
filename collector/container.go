// +build windows

package collector

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/Microsoft/hcsshim"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"

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
	id      string
	name    string
	network string
	states  string
}

//PowerShell script
type PowerShell struct {
	powerShell string
}

//New func
func New() *PowerShell {
	ps, _ := exec.LookPath("powershell.exe")
	return &PowerShell{
		powerShell: ps,
	}
}

//Execute func
func (p *PowerShell) Execute(args ...string) (stdOut string, stdErr string, err error) {
	args = append([]string{"-NoProfile", "-NonInteractive"}, args...)
	cmd := exec.Command(p.powerShell, args...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	stdOut, stdErr = stdout.String(), stderr.String()
	return
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
	p := dockerInfo{"", "", "", ""}
	containers, err := client.ListContainers(opts)
	if err != nil {
		panic(err)
	}

	for _, container := range containers {
		if container.ID == containerID {

			contStr := fmt.Sprint(container.Names)
			contStr = strings.ReplaceAll(contStr, "[", "")
			contStr = strings.ReplaceAll(contStr, "]", "")
			contStr = strings.ReplaceAll(contStr, "/", "")

			networkStr := fmt.Sprint(container.Networks)
			//stateStr := fmt.Sprint(container.State)

			stateStr := fmt.Sprint(container.SizeRw)

			p := dockerInfo{container.ID, contStr, networkStr, stateStr}
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

		// HCS V1 is for docker runtime. Add the docker:// prefix on container_id
		//add method for container info
		containerInfo := listContainers(client, containerId)

		namespacecmd := fmt.Sprintf(`docker inspect %s --format='{{index .Config.Labels \"io.kubernetes.pod.namespace\"}}'`, containerId[0:10])
		podnamecmd := fmt.Sprintf(`docker inspect %s --format='{{index .Config.Labels \"io.kubernetes.pod.name\"}}'`, containerId[0:10])

		posh := New()
		stdnamespaceout, stderr, err := posh.Execute(namespacecmd)
		if err != nil {
			log.Error("stdnamespaceout ", stdnamespaceout, stderr, err)
			continue
		}
		stdnamespaceout = strings.Replace(stdnamespaceout, "\n", "", -1)

		podnameout, podnameserr, podnameerr := posh.Execute(podnamecmd)
		if err != nil {
			log.Error("podnamecmd ", podnameout, podnameserr, podnameerr)
			continue
		}
		podnameout = strings.Replace(podnameout, "\n", "", -1)

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

		log.Info("Network get BytesReceived: ", cstats.Network)

		//log.Info("Network get Storage: ",)

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
