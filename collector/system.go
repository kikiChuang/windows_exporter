// +build windows

package collector

import (
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
)

func init() {
	registerCollector("system", NewSystemCollector, "System")
}

// A SystemCollector is a Prometheus collector for WMI metrics
type SystemCollector struct {
	ContextSwitchesTotal     *prometheus.Desc
	ExceptionDispatchesTotal *prometheus.Desc
	ProcessorQueueLength     *prometheus.Desc
	SystemCallsTotal         *prometheus.Desc
	SystemUpTime             *prometheus.Desc
	Threads                  *prometheus.Desc
}

// NewSystemCollector ...
func NewSystemCollector() (Collector, error) {
	const subsystem = "system"

	return &SystemCollector{
		ContextSwitchesTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "context_switches_total"),
			"Total number of context switches (WMI source: PerfOS_System.ContextSwitchesPersec)",
			[]string{"hostname"},
			nil,
		),
		ExceptionDispatchesTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "exception_dispatches_total"),
			"Total number of exceptions dispatched (WMI source: PerfOS_System.ExceptionDispatchesPersec)",
			[]string{"hostname"},
			nil,
		),
		ProcessorQueueLength: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "processor_queue_length"),
			"Length of processor queue (WMI source: PerfOS_System.ProcessorQueueLength)",
			[]string{"hostname"},
			nil,
		),
		SystemCallsTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "system_calls_total"),
			"Total number of system calls (WMI source: PerfOS_System.SystemCallsPersec)",
			[]string{"hostname"},
			nil,
		),
		SystemUpTime: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "system_up_time"),
			"System boot time (WMI source: PerfOS_System.SystemUpTime)",
			[]string{"hostname"},
			nil,
		),
		Threads: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "threads"),
			"Current number of threads (WMI source: PerfOS_System.Threads)",
			[]string{"hostname"},
			nil,
		),
	}, nil
}

// Collect sends the metric values for each metric
// to the provided prometheus Metric channel.
func (c *SystemCollector) Collect(ctx *ScrapeContext, ch chan<- prometheus.Metric) error {
	if desc, err := c.collect(ctx, ch); err != nil {
		log.Error("failed collecting system metrics:", desc, err)
		return err
	}
	return nil
}

// Win32_PerfRawData_PerfOS_System docs:
// - https://web.archive.org/web/20050830140516/http://msdn.microsoft.com/library/en-us/wmisdk/wmi/win32_perfrawdata_perfos_system.asp
type system struct {
	ContextSwitchesPersec     float64 `perflib:"Context Switches/sec"`
	ExceptionDispatchesPersec float64 `perflib:"Exception Dispatches/sec"`
	ProcessorQueueLength      float64 `perflib:"Processor Queue Length"`
	SystemCallsPersec         float64 `perflib:"System Calls/sec"`
	SystemUpTime              float64 `perflib:"System Up Time"`
	Threads                   float64 `perflib:"Threads"`
}

func (c *SystemCollector) collect(ctx *ScrapeContext, ch chan<- prometheus.Metric) (*prometheus.Desc, error) {
	var dst []system
	if err := unmarshalObject(ctx.perfObjects["System"], &dst); err != nil {
		return nil, err
	}

	//Type used os get hostname
	hostname, err := os.Hostname()
	if err != nil {
		panic(err)
	}

	ch <- prometheus.MustNewConstMetric(
		c.ContextSwitchesTotal,
		prometheus.CounterValue,
		dst[0].ContextSwitchesPersec,
		hostname,
	)
	ch <- prometheus.MustNewConstMetric(
		c.ExceptionDispatchesTotal,
		prometheus.CounterValue,
		dst[0].ExceptionDispatchesPersec,
		hostname,
	)
	ch <- prometheus.MustNewConstMetric(
		c.ProcessorQueueLength,
		prometheus.GaugeValue,
		dst[0].ProcessorQueueLength,
		hostname,
	)
	ch <- prometheus.MustNewConstMetric(
		c.SystemCallsTotal,
		prometheus.CounterValue,
		dst[0].SystemCallsPersec,
		hostname,
	)
	ch <- prometheus.MustNewConstMetric(
		c.SystemUpTime,
		prometheus.GaugeValue,
		dst[0].SystemUpTime,
		hostname,
	)
	ch <- prometheus.MustNewConstMetric(
		c.Threads,
		prometheus.GaugeValue,
		dst[0].Threads,
		hostname,
	)
	return nil, nil
}
