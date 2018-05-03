package main

import (
	"gopkg.in/alecthomas/kingpin.v2"
	vaultApi "github.com/hashicorp/vault/api"
	consulApi "github.com/hashicorp/consul/api"
	"go.uber.org/zap"
	"strings"
	"os"
	"fmt"
	"time"
)

var (
	app          = kingpin.New("vault-auto-unsealer", "Unseal automatically instance of vault it finds. Use UNSEAL_KEY_% env vars to provide keys. (Starts at UNSEAL_KEY_1)")
	debug        = app.Flag("debug", "Trigger debug mode.").Short('d').Envar("DEBUG").Bool()
	consulAddr   = app.Flag("consul-addr", "Name of the consul cluster to join.").Short('c').Envar("CONSUL_HTTP_ADDR").Default("http://localhost:8500").URL()
	consulToken  = app.Flag("consul-token", "Consul token used.").Envar("CONSUL_ACL_TOKEN").Short('t').String()
	vaultService = app.Flag("vault-service-name", "Service name in consul to find sealed Vaults.").Short('v').Envar("VAULT_SERVICE_NAME").Default("vault").String()
	resilient    = app.Flag("resilient", "Stay alive in case of consul or vault being unreachable").Short('r').Envar("STAY_ALIVE").Bool()
)

type Unsealer struct {
	l    *zap.Logger
	v    *vaultApi.Client
	c    *consulApi.Client
	keys []string
	//exit chan struct{}
}

func detectKeys() []string {
	ret := []string{}
	i := 0
	var envVar string
	for envVar = "" ; envVar != "" || i == 0; i++ {
		envVar :=os.Getenv(fmt.Sprintf("UNSEAL_KEY_%d", i))
		ret = append(ret, envVar)
	}
	return ret
}

func NewUnsealer(logger *zap.Logger, v *vaultApi.Client, c *consulApi.Client) *Unsealer {
	return &Unsealer{l: logger, v: v, c: c, keys: detectKeys()}
}

func (u *Unsealer) Unseal(addr string) (error) {
	v, err := u.v.Clone()
	if err != nil {
		return err
	}
	err = v.SetAddress(addr)
	if err != nil {
		return err
	}

	if inited, err := v.Sys().InitStatus(); err != nil {
		return err
	} else if !inited {
		return fmt.Errorf("vault is not inited yet")
	}

	for _, key := range u.keys {
		resp, err := v.Sys().Unseal(key)
		if err != nil {
			return fmt.Errorf("erroring while applying key: %s", err)
		}
		if !resp.Sealed {
			return nil
		}
	}
	return nil
}

func (u *Unsealer) WatchChanges(service, tags string) (chan string, error) {
	ret := make(chan string)

	l := u.l.With(zap.String("service", service), zap.Strings("tags", strings.Split(tags, " ")))
	l.Info("launching watcher")
	go func() {
		var index uint64 = 0
		for {
			resp, meta, err := u.c.Health().Service(service, tags, false, &consulApi.QueryOptions{AllowStale: true, WaitIndex: index})
			if err != nil {
				close(ret)
				//close(u.exit)
				u.l.Error("error in the response from consul", zap.Error(err))
				return
			}
			index = meta.LastIndex
			l := l.With(zap.Uint64("index", index))
			l.Debug("received a response from consul", zap.Int("services_num", len(resp)))

			for _, service := range resp {
				status := service.Checks.AggregatedStatus()
				l := l.With(zap.String("health_status", status), zap.String("node", service.Node.Node))
				l.Debug("new change")
				if status == consulApi.HealthCritical || status == consulApi.HealthWarning {
					l.Info("new sealed vault detected")
					ret <- fmt.Sprintf("http://%s:%d", service.Service.Address, service.Service.Port)
				}
			}
		}
	}()
	return ret, nil
}

func main() {

	l, _ := zap.NewProduction()
	app.HelpFlag.Short('h')
	_, err := app.Parse(os.Args[1:])
	if err != nil {
		app.FatalUsage("error while parsing command", err)
	}

	if *debug {
		l, _ = zap.NewDevelopment()
	}

	l.Debug("bb")
	c, err := consulApi.NewClient(consulApi.DefaultConfig())
	if err != nil {
		l.Fatal("error while creating the consul client", zap.Error(err))
	}

	v, err := vaultApi.NewClient(vaultApi.DefaultConfig())
	if err != nil {
		l.Fatal("error while creating the vault client", zap.Error(err))
	}

	unsealer := NewUnsealer(l, v, c)

	var i uint = 1
	for run := true; run; run = *resilient && run {
		ch, _ := unsealer.WatchChanges(*vaultService, "")

		for target := range ch {
			if err := unsealer.Unseal(target); err != nil {
				l.Error("unsealing failed", zap.Error(err))
			}
			l.Info("here")
			i = 1
		}
		time.Sleep(time.Duration(1<<i) * time.Second)
		if i < 8{
			i++
		}
		l.Info("current", zap.Uint("time", 1<<i))
	}
}
