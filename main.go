package main

import (
	"encoding/json"
	"fmt"
	math "math/rand"
	"os"
	"time"

	"github.com/alecthomas/kong"
	"github.com/jaxxstorm/stunner/pkg/stunstatus"
	"github.com/olekukonko/tablewriter"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// NAT types

var Version = "dev"

type CLIFlags struct {
	STUNServers []string `help:"STUN servers to use for detection" name:"stun-server" short:"s"`
	STUNPort    int      `help:"STUN port to use for detection" default:"3478" short:"p"`
	SourceIP    string   `help:"Local IP to bind" default:"0.0.0.0" short:"i"`
	SourcePort  int      `help:"Local port to bind" short:"P"`
	Debug       bool     `help:"Enable debug logging" default:"false" short:"d"`
	Software    string   `help:"Software to send for STUN request" default:"tailnode" short:"S"`
	DerpMapUrl  string   `help:"URL to fetch DERP map from" name:"derp-map-url" default:"https://login.tailscale.com/derpmap/default"`
	Version     bool     `help:"Show version"`
	NoIP        bool     `help:"Omit IP addresses in output" default:"false" short:"o"`
	JsonOutput  bool     `help:"Output the results as JSON" default:"false" short:"j"`
}

var CLI CLIFlags
var logger *zap.SugaredLogger

func main() {
	math.New(math.NewSource(time.Now().UnixNano()))

	var CLI CLIFlags
	kctx := kong.Parse(&CLI,
		kong.Name("stunner"),
		kong.Description("A CLI tool to check your NAT Type"),
		kong.Vars{"version": Version},
	)

	if CLI.Version {
		fmt.Printf("stunner %s\n", Version)
		kctx.Exit(0)
	}
	initZapLogger(CLI.Debug)
	defer logger.Sync()

	mc := stunstatus.STUNOptions{}
	var err error
	mc.SourcePort = CLI.SourcePort
	mc.StunServers = CLI.STUNServers
	mc.SourceIP = CLI.SourceIP
	mc.Software = CLI.Software

	results, err := stunstatus.ComputeSTUNStatus(&mc)
	if err != nil {
		logger.Fatal(err)
	}

	if CLI.JsonOutput {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "")
		encoder.Encode(results)
	} else {
		printTables(results, CLI.NoIP)
	}
}

func initZapLogger(debug bool) {
	cfg := zap.NewDevelopmentConfig()
	if debug {
		cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	} else {
		cfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}
	cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	cfg.DisableCaller = true
	cfg.DisableStacktrace = true
	logr, err := cfg.Build()
	if err != nil {
		panic(err)
	}
	logger = logr.Sugar()
}

func printTables(results *stunstatus.STUNResults, omit bool) {
	// func printTables(results []PerServerResult, finalNAT string, omit bool) {

	fmt.Println("================= STUN Results =================")

	tbl := tablewriter.NewWriter(os.Stdout)
	tbl.SetHeader([]string{"Stun Server", "Port", "IP", "Mapping"})

	for _, r := range results.Results {
		portStr := "None"
		ipStr := "None"
		if r.ExternalIP != "" {
			portStr = fmt.Sprintf("%d", r.ExternalPort)
			if omit {
				ipStr = "<omitted>"
			} else {
				ipStr = r.ExternalIP
			}
		}
		tbl.Append([]string{
			r.Server,
			portStr,
			ipStr,
			r.MappingProtocol,
		})
	}
	tbl.SetBorder(true)
	tbl.Render()

	fmt.Println("================= NAT Type Detection =================")

	details := stunstatus.NatDetailFor(results.FinalNAT)
	tbl2 := tablewriter.NewWriter(os.Stdout)
	tbl2.SetHeader([]string{"Result", "NAT Type", "Easy/Hard", "Detail", "Direct Connections With"})

	var directConns string

	if results.FinalNAT == stunstatus.OpenInternet {
		directConns = "All"
	} else {
		switch details.EasyVsHard {
		case "Easy":
			directConns = "No NAT, Easy NAT"
		case "Hard":
			directConns = "No NAT Only"
		default:
			directConns = "Unknown"
		}
	}

	tbl2.Append([]string{
		"Final",
		results.FinalNAT,
		details.EasyVsHard,
		details.Notes,
		directConns,
	})
	tbl2.SetBorder(true)
	tbl2.Render()
}
