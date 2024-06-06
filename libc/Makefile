# Makefile to build the Docker image, run the container, and copy the libc.so file to the host

# Image name
IMAGE_NAME = glibc-builder

# Container name
CONTAINER_NAME = glibc-container

# Host directory to copy libc.so to
HOST_DIR = $(PWD)/output

# All-in-one command
all: build run clean

# Docker build command
build:
	DOCKER_BUILDKIT=1 time docker build --platform=linux/amd64 -t $(IMAGE_NAME) .

# Docker run command
run:
	# Ensure the host directory exists
	mkdir -p $(HOST_DIR)
	# Run the Docker container and mount the host directory
	time docker run --rm --name $(CONTAINER_NAME) -v $(HOST_DIR):/host -it $(IMAGE_NAME)

# Docker cleanup command
clean:
	# Stop and remove the container if it's still running (useful if something goes wrong)
	docker rm -f $(CONTAINER_NAME) || true
	# Remove the Docker image
	docker rmi $(IMAGE_NAME) || true