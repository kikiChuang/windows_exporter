// +build windows

package collector

import (
	"fmt"
	"os"
	"regexp"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
	"gopkg.in/alecthomas/kingpin.v2"
)

func init() {
	registerCollector("net", NewNetworkCollector, "Network Interface")
}

var (
	nicWhitelist = kingpin.Flag(
		"collector.net.nic-whitelist",
		"Regexp of NIC:s to whitelist. NIC name must both match whitelist and not match blacklist to be included.",
	).Default(".+").String()
	nicBlacklist = kingpin.Flag(
		"collector.net.nic-blacklist",
		"Regexp of NIC:s to blacklist. NIC name must both match whitelist and not match blacklist to be included.",
	).Default("").String()
	nicNameToUnderscore = regexp.MustCompile("[^a-zA-Z0-9]")
)

// A NetworkCollector is a Prometheus collector for Perflib Network Interface metrics
type NetworkCollector struct {
	BytesReceivedTotal       *prometheus.Desc
	BytesSentTotal           *prometheus.Desc
	BytesTotal               *prometheus.Desc
	PacketsOutboundDiscarded *prometheus.Desc
	PacketsOutboundErrors    *prometheus.Desc
	PacketsTotal             *prometheus.Desc
	PacketsReceivedDiscarded *prometheus.Desc
	PacketsReceivedErrors    *prometheus.Desc
	PacketsReceivedTotal     *prometheus.Desc
	PacketsReceivedUnknown   *prometheus.Desc
	PacketsSentTotal         *prometheus.Desc
	CurrentBandwidth         *prometheus.Desc

	nicWhitelistPattern *regexp.Regexp
	nicBlacklistPattern *regexp.Regexp
}

// NewNetworkCollector ...
func NewNetworkCollector() (Collector, error) {
	const subsystem = "net"

	return &NetworkCollector{
		BytesReceivedTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "bytes_received_total"),
			"(Network.BytesReceivedPerSec)",
			[]string{"nic", "hostname"},
			nil,
		),
		BytesSentTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "bytes_sent_total"),
			"(Network.BytesSentPerSec)",
			[]string{"nic", "hostname"},
			nil,
		),
		BytesTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "bytes_total"),
			"(Network.BytesTotalPerSec)",
			[]string{"nic", "hostname"},
			nil,
		),
		PacketsOutboundDiscarded: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "packets_outbound_discarded"),
			"(Network.PacketsOutboundDiscarded)",
			[]string{"nic", "hostname"},
			nil,
		),
		PacketsOutboundErrors: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "packets_outbound_errors"),
			"(Network.PacketsOutboundErrors)",
			[]string{"nic", "hostname"},
			nil,
		),
		PacketsReceivedDiscarded: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "packets_received_discarded"),
			"(Network.PacketsReceivedDiscarded)",
			[]string{"nic", "hostname"},
			nil,
		),
		PacketsReceivedErrors: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "packets_received_errors"),
			"(Network.PacketsReceivedErrors)",
			[]string{"nic", "hostname"},
			nil,
		),
		PacketsReceivedTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "packets_received_total"),
			"(Network.PacketsReceivedPerSec)",
			[]string{"nic", "hostname"},
			nil,
		),
		PacketsReceivedUnknown: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "packets_received_unknown"),
			"(Network.PacketsReceivedUnknown)",
			[]string{"nic", "hostname"},
			nil,
		),
		PacketsTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "packets_total"),
			"(Network.PacketsPerSec)",
			[]string{"nic", "hostname"},
			nil,
		),
		PacketsSentTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "packets_sent_total"),
			"(Network.PacketsSentPerSec)",
			[]string{"nic", "hostname"},
			nil,
		),
		CurrentBandwidth: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "current_bandwidth"),
			"(Network.CurrentBandwidth)",
			[]string{"nic", "hostname"},
			nil,
		),

		nicWhitelistPattern: regexp.MustCompile(fmt.Sprintf("^(?:%s)$", *nicWhitelist)),
		nicBlacklistPattern: regexp.MustCompile(fmt.Sprintf("^(?:%s)$", *nicBlacklist)),
	}, nil
}

// Collect sends the metric values for each metric
// to the provided prometheus Metric channel.
func (c *NetworkCollector) Collect(ctx *ScrapeContext, ch chan<- prometheus.Metric) error {
	if desc, err := c.collect(ctx, ch); err != nil {
		log.Error("failed collecting net metrics:", desc, err)
		return err
	}
	return nil
}

// mangleNetworkName mangles Network Adapter name (non-alphanumeric to _)
// that is used in networkInterface.
func mangleNetworkName(name string) string {
	return nicNameToUnderscore.ReplaceAllString(name, "_")
}

// Win32_PerfRawData_Tcpip_NetworkInterface docs:
// - https://technet.microsoft.com/en-us/security/aa394340(v=vs.80)
type networkInterface struct {
	BytesReceivedPerSec      float64 `perflib:"Bytes Received/sec"`
	BytesSentPerSec          float64 `perflib:"Bytes Sent/sec"`
	BytesTotalPerSec         float64 `perflib:"Bytes Total/sec"`
	Name                     string
	PacketsOutboundDiscarded float64 `perflib:"Packets Outbound Discarded"`
	PacketsOutboundErrors    float64 `perflib:"Packets Outbound Errors"`
	PacketsPerSec            float64 `perflib:"Packets/sec"`
	PacketsReceivedDiscarded float64 `perflib:"Packets Received Discarded"`
	PacketsReceivedErrors    float64 `perflib:"Packets Received Errors"`
	PacketsReceivedPerSec    float64 `perflib:"Packets Received/sec"`
	PacketsReceivedUnknown   float64 `perflib:"Packets Received Unknown"`
	PacketsSentPerSec        float64 `perflib:"Packets Sent/sec"`
	CurrentBandwidth         float64 `perflib:"Current Bandwidth"`
}

func (c *NetworkCollector) collect(ctx *ScrapeContext, ch chan<- prometheus.Metric) (*prometheus.Desc, error) {
	var dst []networkInterface

	if err := unmarshalObject(ctx.perfObjects["Network Interface"], &dst); err != nil {
		return nil, err
	}

	//Type used os get hostname
	hostname, err := os.Hostname()
	if err != nil {
		panic(err)
	}

	for _, nic := range dst {
		if c.nicBlacklistPattern.MatchString(nic.Name) ||
			!c.nicWhitelistPattern.MatchString(nic.Name) {
			continue
		}

		name := mangleNetworkName(nic.Name)
		if name == "" {
			continue
		}

		// Counters
		ch <- prometheus.MustNewConstMetric(
			c.BytesReceivedTotal,
			prometheus.CounterValue,
			nic.BytesReceivedPerSec,
			name,
			hostname,
		)
		ch <- prometheus.MustNewConstMetric(
			c.BytesSentTotal,
			prometheus.CounterValue,
			nic.BytesSentPerSec,
			name,
			hostname,
		)
		ch <- prometheus.MustNewConstMetric(
			c.BytesTotal,
			prometheus.CounterValue,
			nic.BytesTotalPerSec,
			name,
			hostname,
		)
		ch <- prometheus.MustNewConstMetric(
			c.PacketsOutboundDiscarded,
			prometheus.CounterValue,
			nic.PacketsOutboundDiscarded,
			name,
			hostname,
		)
		ch <- prometheus.MustNewConstMetric(
			c.PacketsOutboundErrors,
			prometheus.CounterValue,
			nic.PacketsOutboundErrors,
			name,
			hostname,
		)
		ch <- prometheus.MustNewConstMetric(
			c.PacketsTotal,
			prometheus.CounterValue,
			nic.PacketsPerSec,
			name,
			hostname,
		)
		ch <- prometheus.MustNewConstMetric(
			c.PacketsReceivedDiscarded,
			prometheus.CounterValue,
			nic.PacketsReceivedDiscarded,
			name,
			hostname,
		)
		ch <- prometheus.MustNewConstMetric(
			c.PacketsReceivedErrors,
			prometheus.CounterValue,
			nic.PacketsReceivedErrors,
			name,
			hostname,
		)
		ch <- prometheus.MustNewConstMetric(
			c.PacketsReceivedTotal,
			prometheus.CounterValue,
			nic.PacketsReceivedPerSec,
			name,
			hostname,
		)
		ch <- prometheus.MustNewConstMetric(
			c.PacketsReceivedUnknown,
			prometheus.CounterValue,
			nic.PacketsReceivedUnknown,
			name,
			hostname,
		)
		ch <- prometheus.MustNewConstMetric(
			c.PacketsSentTotal,
			prometheus.CounterValue,
			nic.PacketsSentPerSec,
			name,
			hostname,
		)
		ch <- prometheus.MustNewConstMetric(
			c.CurrentBandwidth,
			prometheus.GaugeValue,
			nic.CurrentBandwidth,
			name,
			hostname,
		)
	}
	return nil, nil
}
