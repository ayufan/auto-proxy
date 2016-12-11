package main

import (
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/fsouza/go-dockerclient"
	"strings"
	"sync"
	"time"
)

const PingInterval = 10 * time.Second
const ReconnectTime = 10 * time.Second

func createRoute(container *docker.Container, route RouteBuilder, routes Routes) {
	// Try to find first suitable port if not specified from list of ports
	if route.Upstream.Port == "" {
		for _, port := range strings.Split(*ports, ",") {
			portDef := fmt.Sprintf("%s/tcp", port)
			if _, ok := container.NetworkSettings.Ports[docker.Port(portDef)]; ok {
				route.Upstream.Port = port
				break
			}
		}
	}

	// Fail if we can't find a port
	if route.Upstream.Port == "" {
		logrus.WithField("name", container.Name).WithField("id", container.ID[0:7]).
			Debugln("Couldn't find a port to expose...")
	}

	route.Upstream.Container = container.Name
	route.Upstream.ID = container.ID

	// Try to find bindings for specified ports
	portDef := fmt.Sprintf("%s/tcp", route.Upstream.Port)
	bindings := container.NetworkSettings.Ports[docker.Port(portDef)]

	// Try to use bindings in order to access host (useful for Swarm nodes)
	for _, binding := range bindings {
		if binding.HostIP != "0.0.0.0" {
			route.Upstream.IP = binding.HostIP
			route.Upstream.Port = binding.HostPort
			break
		}
	}

	// Try to use address when connected to local bridge
	if container.Node == nil && route.Upstream.IP == "" {
		// This address make sense only when accessing locally
		route.Upstream.IP = container.NetworkSettings.IPAddress
	}

	// Try to use address when connected to other network
	if container.Node == nil && route.Upstream.IP == "" {
		for _, network := range container.NetworkSettings.Networks {
			if network.IPAddress != "" {
				route.Upstream.IP = network.IPAddress
				break
			}
		}
	}

	if route.Upstream.IP == "" {
		logrus.WithField("name", container.Name).WithField("id", container.ID[0:7]).
			Debugln("Couldn't find an IP to access container...")
	}

	route.Upstream.Running = container.State.Running

	if !route.isValid() {
		return
	}

	logrus.WithField("name", container.Name).WithField("id", container.ID[0:7]).WithField("route", route).
		Debugln("Adding route...")
	routes.Add(route)
}

func findContainersAndCreateRoutes(client *docker.Client) (newRoutes Routes, err error) {
	opts := docker.ListContainersOptions{
		All: true,
	}
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

	newRoutes = make(Routes)

	for container := range ch {
		for _, route := range FindRoutes(container.Config.Env...) {
			createRoute(container, route, newRoutes)
		}
	}

	return
}

func (a *theApp) watchEvents() {
	var err error
	var routes Routes

	eventChan := make(chan *docker.APIEvents, 100)
	defer close(eventChan)

	watching := false
	for {
		err = a.client.Ping()
		if err != nil {
			logrus.Errorln("Unable to ping docker daemon:", err)
			if watching {
				a.client.RemoveEventListener(eventChan)
				watching = false
			}
			time.Sleep(ReconnectTime)
			continue
		}

		if !watching {
			err = a.client.AddEventListener(eventChan)
			if err != nil && err != docker.ErrListenerAlreadyExists {
				logrus.Errorln("Error registering docker event listener:", err)
				time.Sleep(ReconnectTime)
				continue
			}
			watching = true
			logrus.Infoln("Watching docker events...")

			// Run first iteration
			routes, err = findContainersAndCreateRoutes(a.client)
			if err != nil {
				logrus.Errorln("Error enumerating routes:", err)

				if watching {
					a.client.RemoveEventListener(eventChan)
					watching = false
				}

				time.Sleep(ReconnectTime)
				continue
			}
			a.update(routes)
		}

		select {
		case event := <-eventChan:
			if event == nil {
				if watching {
					a.client.RemoveEventListener(eventChan)
					watching = false
					a.client = nil
				}
				break
			}

			if event.Status == "start" || event.Status == "stop" || event.Status == "die" {
				logrus.Debugln("Received event", event.Status, "for container", event.ID[:12])
				routes, err = findContainersAndCreateRoutes(a.client)
				if err != nil {
					logrus.Errorln("Error enumerating routes:", err)
				}
				if err == nil {
					a.update(routes)
				}
			}
		case <-time.After(PingInterval):
			// check for docker liveness
		}
	}
}
