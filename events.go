package main

import (
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/fsouza/go-dockerclient"
	"strconv"
	"strings"
	"sync"
	"time"
)

const PingInterval = 10 * time.Second
const ReconnectTime = 10 * time.Second

type RoutesHandleFunc func(routes Routes)

func createRoutes(client *docker.Client) (routes Routes, err error) {
	opts := docker.ListContainersOptions{}
	containers, err := client.ListContainers(opts)
	if err != nil {
		return
	}

	wg := sync.WaitGroup{}
	ch := make(chan *docker.Container)

	for _, container := range containers {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			container, err := client.InspectContainer(id)
			if err != nil {
				logrus.WithField("id", id).WithError(err).Errorln("Failed inspecing container")
				return
			}
			ch <- container
		}(container.ID)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	routes = make(Routes)

	for container := range ch {
		route := NewRouteBuilder()
		for _, env := range container.Config.Env {
			route.parse(env)
		}

		route.Upstream.Container = container.Name

		var bindings []docker.PortBinding
		if route.Upstream.Port != 0 {
			// Try to find binding when custom port is specified
			portDef := fmt.Sprintf("%d/tcp", route.Upstream.Port)
			bindings = container.NetworkSettings.Ports[docker.Port(portDef)]
		}

		if bindings == nil {
			// Try to find binding for predefined ports
			for _, portText := range strings.Split(*ports, ",") {
				portDef := fmt.Sprintf("%s/tcp", portText)
				bindings = container.NetworkSettings.Ports[docker.Port(portDef)]
				if len(bindings) > 0 {
					route.Upstream.Port, _ = strconv.Atoi(portText)
					break
				}
			}
		}

		// Try to use bindings in order to access host
		for _, binding := range bindings {
			if binding.HostIP != "0.0.0.0" {
				route.Upstream.IP = binding.HostIP
				route.Upstream.Port, _ = strconv.Atoi(binding.HostPort)
				break
			}
		}

		// If we are not running on Swarm we can use local networking address
		if container.Node == nil {
			// Try to use address when connected to local bridge
			if route.Upstream.IP == "" {
				route.Upstream.IP = container.NetworkSettings.IPAddress
			}

			// Try to use address when connected to other network
			if route.Upstream.IP == "" {
				for _, network := range container.NetworkSettings.Networks {
					if network.IPAddress != "" {
						route.Upstream.IP = network.IPAddress
						break
					}
				}
			}
		}

		if !route.isValid() {
			continue
		}

		logrus.WithField("name", container.Name).WithField("id", container.ID[0:7]).WithField("route", route).Debugln("Adding route...")
		routes.Add(route)
	}

	return
}

func watchEvents(updateFunc RoutesHandleFunc) {
	var client *docker.Client
	var err error
	var routes Routes

	for {
		if client == nil || client.Ping() == nil {
			client, err = docker.NewClientFromEnv()
			if err != nil {
				logrus.Errorln("Unable to connect to docker daemon:", err)
				time.Sleep(ReconnectTime)
				continue
			}

			logrus.Debugln("Connected to docker daemon...")
			routes, err = createRoutes(client)
			if err != nil {
				logrus.Errorln("Error enumerating routes:", err)
			}
			if err == nil && updateFunc != nil {
				updateFunc(routes)
			}
		}

		eventChan := make(chan *docker.APIEvents, 100)
		defer close(eventChan)

		watching := false
		for {
			if client == nil {
				break
			}
			err := client.Ping()
			if err != nil {
				logrus.Errorln("Unable to ping docker daemon:", err)
				if watching {
					client.RemoveEventListener(eventChan)
					watching = false
					client = nil
				}
				time.Sleep(ReconnectTime)
				break
			}

			if !watching {
				err = client.AddEventListener(eventChan)
				if err != nil && err != docker.ErrListenerAlreadyExists {
					logrus.Errorln("Error registering docker event listener:", err)
					time.Sleep(ReconnectTime)
					continue
				}
				watching = true
				logrus.Infoln("Watching docker events...")
			}

			select {
			case event := <-eventChan:
				if event == nil {
					if watching {
						client.RemoveEventListener(eventChan)
						watching = false
						client = nil
					}
					break
				}

				if event.Status == "start" || event.Status == "stop" || event.Status == "die" {
					logrus.Debugln("Received event", event.Status, "for container", event.ID[:12])
					routes, err = createRoutes(client)
					if err != nil {
						logrus.Errorln("Error enumerating routes:", err)
					}
					if err == nil && updateFunc != nil {
						updateFunc(routes)
					}
				}
			case <-time.After(PingInterval):
				// check for docker liveness
			}
		}
	}
}
