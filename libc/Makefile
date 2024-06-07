# Makefile to build the Docker image, run the container, and copy the libc.so file to the host

# Image name
IMAGE_NAME = glibc-builder

# Container name
CONTAINER_NAME = glibc-container

# Host directory to copy libc.so to
HOST_DIR = $(PWD)/output

# Glibc/ubuntu version (can be changed as needed)
GLIBC_VERSION = 2.29
UBUNTU_VERSION = 20.04

# All-in-one command
all: build run clean

# Docker build command
build:
	DOCKER_BUILDKIT=1 time docker build --build-arg UBUNTU_VERSION=$(UBUNTU_VERSION) --build-arg GLIBC_VERSION=$(GLIBC_VERSION) --platform=linux/amd64 -t $(IMAGE_NAME) .

# Docker run command
run:
	# Ensure the host directory exists
	mkdir -p $(HOST_DIR)
	# Run the Docker container and mount the host directory
	time docker run --rm --name $(CONTAINER_NAME) -v $(HOST_DIR):/opt/glibc-${GLIBC_VERSION} $(IMAGE_NAME)

# Docker cleanup command
clean:
	# Remove the Docker container if it's still running
	docker rm -f $(CONTAINER_NAME) || true
	# Remove the Docker image
	docker rmi $(IMAGE_NAME) || true