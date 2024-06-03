# Development cycle

## Development

### Auto Refresh files

During development multiple features have to be built and tested separately and multiple times. To immediately reflect changes the volume parameter can be utilized to map the container directory to the host directory

```yaml
service:
	react:
		volumes:
			- /app/modules   # Maps volume to a placeholder
			- .:/app         # Maps volume to the host volume
```

### Multiple Dockerfiles

In production there may be multiple dockerfiles present within a project. Docker-compose has a built in function to address that issue

```yaml
services:
	web:
		build:
			context: .       # Specifies where to pull files from(relative path)
			dockerfile: Dockerfile.dev     # Name of the docker file to build from
```
## Testing

### For running tests

There may be multiple tools present to test the code. Multiple containers may be deployed from the same image but with different starting commands

```yaml
services:
	web:
		build: .
	test:
		build: .
		command: ["start","test","tool"]   # Overrides the starting command
```

### Cons

When automating testing the terminal only gets connected to the `stdin` and `stdout` of the parent process any additional input needs to be provided separately in a shell
## Deployment

During Deployment Multi Step builds are used to only use the source files with a production level server

sample dockerfile with 2 step build process
```dockerfile
FROM node:16-alpine as builder

WORKDIR /app
COPY package.json .
RUN npm install
COPY . .
RUN npm run build

FROM nginx
COPY --from=builder /app/build /usr/share/nginx/html
```