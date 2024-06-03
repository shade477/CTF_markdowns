# Dockerfile

It is a file that contains build instructions for a docker container

## Sample Dockerfile

```dockerfile
# Specify Base Image
FROM IMAGE:TAG 

# Set Working directory
WORKDIR /app

# Copy dependency requirements to directory
COPY ./dependency_requirement.file .

# Get dependencies
RUN get dependency

# Copy the rest of the files
COPY ./ ./

# Set starting command.
# Separate all the words with a comma
CMD ['start','command']
```

- All commands run in a sequential flow
- All steps are cached
	- When something within the flow is changed all steps before the changed are built from the cache

Sample dockerfile
```dockerfile
# Specify a base image
FROM node:14-alpine

WORKDIR /usr/app

# Install some depenendencies
COPY ./package.json ./
RUN npm install
COPY ./ ./

# Default command
CMD ["npm", "start"]
```