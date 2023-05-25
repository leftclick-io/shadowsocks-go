package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/database64128/shadowsocks-go/jsonhelper"
	"github.com/database64128/shadowsocks-go/logging"
	"github.com/database64128/shadowsocks-go/service"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	testConf = flag.Bool("testConf", false, "Test the configuration file without starting the services")
	confPath = flag.String("confPath", "", "Path to JSON configuration file")
	zapConf  = flag.String("zapConf", "", "Preset name or path to JSON configuration file for building the zap logger.\nAvailable presets: console (default), systemd, production, development")
	logLevel = flag.String("logLevel", "", "Override the logger configuration's log level.\nAvailable levels: debug, info, warn, error, dpanic, panic, fatal")
)

func main() {
	flag.Parse()

	if *confPath == "" {
		fmt.Println("Missing -confPath <path>.")
		flag.Usage()
		os.Exit(1)
	}

	var (
		zc zap.Config
		sc service.Config
	)

	switch *zapConf {
	case "console", "":
		zc = logging.NewProductionConsoleConfig(false)
	case "systemd":
		zc = logging.NewProductionConsoleConfig(true)
	case "production":
		zc = zap.NewProductionConfig()
	case "development":
		zc = zap.NewDevelopmentConfig()
	default:
		if err := jsonhelper.LoadAndDecodeDisallowUnknownFields(*zapConf, &zc); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	if *logLevel != "" {
		l, err := zapcore.ParseLevel(*logLevel)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		zc.Level.SetLevel(l)
	}

	logger := logging.NewZapLogger(zc)
	defer logger.Sync()

	if err := jsonhelper.LoadAndDecodeDisallowUnknownFields(*confPath, &sc); err != nil {
		logger.Fatal("Failed to load config",
			logger.WithField("confPath", confPath),
			logger.WithError(err),
		)
	}

	m, err := sc.Manager(logger)
	if err != nil {
		logger.Fatal("Failed to create service manager",
			logger.WithField("confPath", confPath),
			logger.WithError(err),
		)
	}
	defer m.Close()

	if *testConf {
		logger.Info("Config test OK", logger.WithField("confPath", confPath))
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		logger.Info("Received exit signal", logger.WithField("signal", sig))
		cancel()
	}()

	if err = m.Start(ctx); err != nil {
		logger.Fatal("Failed to start services",
			logger.WithField("confPath", confPath),
			logger.WithError(err),
		)
	}

	<-ctx.Done()
	m.Stop()
}
