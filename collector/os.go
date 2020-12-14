// +build windows

package collector

import (
	"errors"
	"os"
	"time"

	"github.com/StackExchange/wmi"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
)

func init() {
	registerCollector("os", NewOSCollector)
}

// A OSCollector is a Prometheus collector for WMI metrics
type OSCollector struct {
	OSInformation           *prometheus.Desc
	PhysicalMemoryFreeBytes *prometheus.Desc
	PagingFreeBytes         *prometheus.Desc
	VirtualMemoryFreeBytes  *prometheus.Desc
	ProcessesLimit          *prometheus.Desc
	ProcessMemoryLimitBytes *prometheus.Desc
	Processes               *prometheus.Desc
	Users                   *prometheus.Desc
	PagingLimitBytes        *prometheus.Desc
	VirtualMemoryBytes      *prometheus.Desc
	VisibleMemoryBytes      *prometheus.Desc
	Time                    *prometheus.Desc
	Timezone                *prometheus.Desc
}

// NewOSCollector ...
func NewOSCollector() (Collector, error) {
	const subsystem = "os"

	return &OSCollector{
		OSInformation: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "info"),
			"OperatingSystem.Caption, OperatingSystem.Version",
			[]string{"product", "version", "hostname"},
			nil,
		),
		PagingLimitBytes: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "paging_limit_bytes"),
			"OperatingSystem.SizeStoredInPagingFiles",
			[]string{"hostname"},
			nil,
		),
		PagingFreeBytes: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "paging_free_bytes"),
			"OperatingSystem.FreeSpaceInPagingFiles",
			[]string{"hostname"},
			nil,
		),
		PhysicalMemoryFreeBytes: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "physical_memory_free_bytes"),
			"OperatingSystem.FreePhysicalMemory",
			[]string{"hostname"},
			nil,
		),
		Time: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "time"),
			"OperatingSystem.LocalDateTime",
			[]string{"hostname"},
			nil,
		),
		Timezone: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "timezone"),
			"OperatingSystem.LocalDateTime",
			[]string{"timezone", "hostname"},
			nil,
		),
		Processes: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "processes"),
			"OperatingSystem.NumberOfProcesses",
			[]string{"hostname"},
			nil,
		),
		ProcessesLimit: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "processes_limit"),
			"OperatingSystem.MaxNumberOfProcesses",
			[]string{"hostname"},
			nil,
		),
		ProcessMemoryLimitBytes: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "process_memory_limix_bytes"),
			"OperatingSystem.MaxProcessMemorySize",
			[]string{"hostname"},
			nil,
		),
		Users: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "users"),
			"OperatingSystem.NumberOfUsers",
			[]string{"hostname"},
			nil,
		),
		VirtualMemoryBytes: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "virtual_memory_bytes"),
			"OperatingSystem.TotalVirtualMemorySize",
			[]string{"hostname"},
			nil,
		),
		VisibleMemoryBytes: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "visible_memory_bytes"),
			"OperatingSystem.TotalVisibleMemorySize",
			[]string{"hostname"},
			nil,
		),
		VirtualMemoryFreeBytes: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "virtual_memory_free_bytes"),
			"OperatingSystem.FreeVirtualMemory",
			[]string{"hostname"},
			nil,
		),
	}, nil
}

// Collect sends the metric values for each metric
// to the provided prometheus Metric channel.
func (c *OSCollector) Collect(ctx *ScrapeContext, ch chan<- prometheus.Metric) error {
	if desc, err := c.collect(ch); err != nil {
		log.Error("failed collecting os metrics:", desc, err)
		return err
	}
	return nil
}

// Win32_OperatingSystem docs:
// - https://msdn.microsoft.com/en-us/library/aa394239 - Win32_OperatingSystem class
type Win32_OperatingSystem struct {
	Caption                 string
	FreePhysicalMemory      uint64
	FreeSpaceInPagingFiles  uint64
	FreeVirtualMemory       uint64
	LocalDateTime           time.Time
	MaxNumberOfProcesses    uint32
	MaxProcessMemorySize    uint64
	NumberOfProcesses       uint32
	NumberOfUsers           uint32
	SizeStoredInPagingFiles uint64
	TotalVirtualMemorySize  uint64
	TotalVisibleMemorySize  uint64
	Version                 string
}

func (c *OSCollector) collect(ch chan<- prometheus.Metric) (*prometheus.Desc, error) {
	var dst []Win32_OperatingSystem
	q := queryAll(&dst)
	if err := wmi.Query(q, &dst); err != nil {
		return nil, err
	}

	if len(dst) == 0 {
		return nil, errors.New("WMI query returned empty result set")
	}

	//Type used os get hostname
	hostname, err := os.Hostname()
	if err != nil {
		panic(err)
	}

	ch <- prometheus.MustNewConstMetric(
		c.OSInformation,
		prometheus.GaugeValue,
		1.0,
		dst[0].Caption,
		dst[0].Version,
		hostname,
	)

	ch <- prometheus.MustNewConstMetric(
		c.PhysicalMemoryFreeBytes,
		prometheus.GaugeValue,
		float64(dst[0].FreePhysicalMemory*1024), // KiB -> bytes
		hostname,
	)

	time := dst[0].LocalDateTime

	ch <- prometheus.MustNewConstMetric(
		c.Time,
		prometheus.GaugeValue,
		float64(time.Unix()),
		hostname,
	)

	timezoneName, _ := time.Zone()

	ch <- prometheus.MustNewConstMetric(
		c.Timezone,
		prometheus.GaugeValue,
		1.0,
		timezoneName,
		hostname,
	)

	ch <- prometheus.MustNewConstMetric(
		c.PagingFreeBytes,
		prometheus.GaugeValue,
		float64(dst[0].FreeSpaceInPagingFiles*1024), // KiB -> bytes
		hostname,
	)

	ch <- prometheus.MustNewConstMetric(
		c.VirtualMemoryFreeBytes,
		prometheus.GaugeValue,
		float64(dst[0].FreeVirtualMemory*1024), // KiB -> bytes
		hostname,
	)

	ch <- prometheus.MustNewConstMetric(
		c.ProcessesLimit,
		prometheus.GaugeValue,
		float64(dst[0].MaxNumberOfProcesses),
		hostname,
	)

	ch <- prometheus.MustNewConstMetric(
		c.ProcessMemoryLimitBytes,
		prometheus.GaugeValue,
		float64(dst[0].MaxProcessMemorySize*1024), // KiB -> bytes
		hostname,
	)

	ch <- prometheus.MustNewConstMetric(
		c.Processes,
		prometheus.GaugeValue,
		float64(dst[0].NumberOfProcesses),
		hostname,
	)

	ch <- prometheus.MustNewConstMetric(
		c.Users,
		prometheus.GaugeValue,
		float64(dst[0].NumberOfUsers),
		hostname,
	)

	ch <- prometheus.MustNewConstMetric(
		c.PagingLimitBytes,
		prometheus.GaugeValue,
		float64(dst[0].SizeStoredInPagingFiles*1024), // KiB -> bytes
		hostname,
	)

	ch <- prometheus.MustNewConstMetric(
		c.VirtualMemoryBytes,
		prometheus.GaugeValue,
		float64(dst[0].TotalVirtualMemorySize*1024), // KiB -> bytes
		hostname,
	)

	ch <- prometheus.MustNewConstMetric(
		c.VisibleMemoryBytes,
		prometheus.GaugeValue,
		float64(dst[0].TotalVisibleMemorySize*1024), // KiB -> bytes
		hostname,
	)

	return nil, nil
}
