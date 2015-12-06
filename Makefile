test-container:
		docker run --name=letsencrypt --volume="/var/run/docker.sock:/var/run/docker.sock" --net=host -it golang:1.5 /bin/bash

run-remotely:
		rm -f auto-proxy
		docker cp . letsencrypt:/go/src/app
		docker exec -it letsencrypt bash -c 'cd /go/src/app; go-wrapper download; go-wrapper install && exec go-wrapper run'

build:
		go build


