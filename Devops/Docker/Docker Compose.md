# Docker Compose

It is a tool to build and manage containers.

Sample node web application code
```js
const express = require('express');
const redis = require('redis');

const app = express();
const client = redis.createClient({
  host: 'redis-server',
  port: 6379,
});

client.set('visits', 0);

app.get('/', (req, res) => {
  client.get('visits', (err, visits) => {
    res.send('Number of visits ' + visits);
    client.set('visits', parseInt(visits) + 1);
  });
});

app.listen(8081, () => {
  console.log('listening on port 8081');
});
```

## docker-compose.yaml

There can be multiple docker compose files these are `.yaml` files

```yaml
version: '3'                 # Docker-compose api version
services:                    # Containers
	redis-server:            # Container 1
		image: 'redis'       # Image to pull from repo
	node-app:                # Container 2
		restart: 'no'        # Restart Policy
		build: .             # Used to build the application
		ports:               # Port mapping
			- "4001:8081"    # Item 1
	
			
		ports:
			- "3000:3000"
		
```

## Commands

| **Command**           | **Description**                                                     |
| --------------------- | ------------------------------------------------------------------- |
| **Start**             |                                                                     |
| `docker-compose up`   | Looks for a `docker-compose.yaml` file to run the containers        |
| `--build`             | Rebuild the images within the docker compose file                   |
| `-f file1.yaml`       | Start the docker containers from the current files in the directory |
| `-d`                  | Starts in detached mode or background mode                          |
| **Stop**              |                                                                     |
| `docker-compose down` | Stops all the docker-compose containers                             |
| **List**              | Should be run in the directory of docker-compose file               |
| `docker-compose ps`   | Lists all the docker compose containers                             |

## Networking

- When a docker compose file is used a default network is automatically created if nothing is mentioned
- Defining the services within the docker compose file allows them to communicate with each other just by using the service names as the hostname of the destination

## Maintenance

### Restart-Policies

| **Policy**       | **Description**                                         |
| ---------------- | ------------------------------------------------------- |
| `no`             | Will not attempt to restart                             |
| `always`         | Will always restart the containers                      |
| `on-failure`     | Only restart if container stops with error code         |
| `unless-stopped` | Always restart unless the container is forcibly stopped |
