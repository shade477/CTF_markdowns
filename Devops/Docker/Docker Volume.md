# Volumes

It maps a container volume to a host volume

| **Command**                                            | **Description**                                                                                          |
| ------------------------------------------------------ | -------------------------------------------------------------------------------------------------------- |
| `docker run -v $(pwd):/app <image_id>`                 | Maps `pwd` of the host to `/app` within the container                                                    |
| `docker run -v /app/modules -v $(pwd):/app <image_id>` | Keeps `/app/modules` as a placeholder for a folder that will be generated later during the build process |
