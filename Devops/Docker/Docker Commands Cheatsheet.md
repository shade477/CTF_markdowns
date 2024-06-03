# Docker Commands

| **Command**                                                                   | **Description**                                                    |
| ----------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| **Direct Run**                                                                |                                                                    |
| `docker run <image>`                                                          | Runs an image as a container                                       |
| `docker run <image> <command>`                                                | Runs an image as a container and override the startup command      |
| `-d`                                                                          | Detached mode                                                      |
| `-i`                                                                          | Standard input                                                     |
| `-t`                                                                          | `tty` mode or terminal mode                                        |
| `--name <tag-name>`                                                           | Tags a name to the container                                       |
| **Docker login**                                                              |                                                                    |
| `docker login`                                                                | Attempts login                                                     |
| `-u <username>`                                                               | Username                                                           |
| `-p <password>`                                                               | Password                                                           |
| **Pull Image from Repo**                                                      |                                                                    |
| `docker pull <image>`                                                         | Pulls the image from the repository and stores it locally          |
| `docker pull <image>:<tag>`                                                   | Pull specific image from the repo and store it locally             |
| **Tag an image**                                                              |                                                                    |
| `docker tag <dockerhub Username>/<Docker Repository>:<Tag Name>`              | attach a tag to the image                                          |
| `docker tag <image_id> <dockerhub_username>/<repository_name>:<tag>`          | attach tag to image using id                                       |
| `docker tag <local_image>:<tag> <dockerhub_username>/<repository_name>:<tag>` | attach full tag name to the docker image                           |
| **Push image to repo**                                                        |                                                                    |
| `docker push <dockerhub Username>/<Docker Repository>`                        | Push image to docker                                               |
| `-a`                                                                          | Pushes all the tagged image to repo                                |
| `docker push <dockerhub Username>/<Docker Repository>:<tag>`                  | Push specific tag image to repo                                    |
| **Create Container**                                                          |                                                                    |
| `docker create <image>` image name or id                                      | Creates a container from the image                                 |
| `-t <tag-name>`                                                               | `-t` tags the container with the name provided                     |
| `-p <host-port>:<container-port>`                                             | maps container port with host. [**Multiple Enabled**]              |
| **Start Container**                                                           |                                                                    |
| `docker start <container_id or name>`                                         | Starts a container with the specific image id returns container id |
| `-a`                                                                          | displays all startup output in the current terminal                |
| `docker start <container_id or name> <command>`                               | Starts a container with command                                    |
| **Container stop**                                                            |                                                                    |
| `docker stop <container_id or name>`                                          | Gracefully stops a container                                       |
| `docker kill <container_id or name>`                                          | Kills a container                                                  |
| **View Container logs**                                                       |                                                                    |
| `docker logs <container_name or id>`                                          | View logs of the container                                         |
| **Execute Commands within container**                                         |                                                                    |
| `docker exec -it <container_name or id> <command>`                            | Executes command within the command                                |
| `docker commit -c 'CMD ["startup","command"]' <container_id or name>`         | Manually commits and builds an image from the container            |
| **List Containers**                                                           |                                                                    |
| `docker ps`                                                                   | Lists all active containers                                        |
| `-a` or `--all`                                                               | Lists all containers                                               |
| `docker container ls`                                                         | Lists all active containers                                        |
| `-a` or `--all`                                                               | Lists all containers                                               |
| **Remove containers**                                                         |                                                                    |
| `docker system prune`                                                         | Removes all stopped containers, networks and build cache           |
| **Build**                                                                     |                                                                    |
| `docker build .`                                                              | Uses dockerfile to build image                                     |
| `docker build -f dockerfile`                                                  | Uses specific dockerfile to build image                            |
|                                                                               |                                                                    |
