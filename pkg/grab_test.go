package pkg_test

import (
	"context"
	"os"
	"so-grabber/pkg"
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/stretchr/testify/assert"
)

func TestSoGrabber_Collect(t *testing.T) {
	// vars
	outputDir := "./so_files"
	soToCollect := "libvulkan.so.1"
	containerName := "test_so_container"

	// Ensure Docker is running
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	assert.NoError(t, err)

	// Clean up any existing containers with the same name
	cleanupContainers(cli, containerName)

	// Create a SoGrabber instance
	dm, err := pkg.NewSoGrabber("x86_64", "ubuntu", outputDir, containerName, true)
	assert.NoError(t, err)

	// Ensure the output directory is clean
	os.RemoveAll(outputDir)
	os.MkdirAll(outputDir, 0755)

	// Run the Collect method
	err = dm.Collect(soToCollect)
	assert.NoError(t, err)

	// Check if the file is downloaded and exists
	_, err = os.Stat(outputDir + "/" + soToCollect)
	assert.NoError(t, err)

	// Clean up after test
	cleanupContainers(cli, containerName)
	os.RemoveAll(outputDir)
}

func cleanupContainers(cli *client.Client, containerName string) {
	ctx := context.Background()
	containers, err := cli.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return
	}

	for _, cnt := range containers {
		if cnt.Names[0] == "/"+containerName {
			cli.ContainerRemove(ctx, cnt.ID, container.RemoveOptions{Force: true})
		}
	}
}
