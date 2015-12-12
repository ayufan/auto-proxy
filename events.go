package main

import (
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
		route.Upstream.IP = container.NetworkSettings.IPAddress

		// Fill container PORT
		if route.Upstream.Port == 0 {
			for _, portText := range strings.Split(*ports, ",") {
				if _, ok := container.NetworkSettings.Ports[docker.Port(portText+"/tcp")]; ok {
					port, _ := strconv.Atoi(portText)
					route.Upstream.Port = port
					break
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
