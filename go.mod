module github.com/prometheus-community/windows_exporter

go 1.13

require (
	github.com/Microsoft/hcsshim v0.8.9
	github.com/StackExchange/wmi v0.0.0-20180725035823-b12b22c5341f
	github.com/dimchansky/utfbom v1.1.0
	github.com/docker/docker v17.12.0-ce-rc1.0.20200505174321-1655290016ac+incompatible
	github.com/fsouza/go-dockerclient v1.6.6
	github.com/go-ole/go-ole v1.2.1 // indirect
	github.com/leoluk/perflib_exporter v0.1.0
	github.com/prometheus/client_golang v0.9.2
	github.com/prometheus/client_model v0.0.0-20190812154241-14fe0d1b01d4
	github.com/prometheus/common v0.2.0
	golang.org/x/sys v0.0.0-20200302150141-5c8b2ff67527
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
)
