package pkg

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
)

const defaultContainerName = "so-container"

type SoFinder struct {
	ctx           context.Context
	cli           *client.Client
	containerID   string
	arch          string
	distro        string
	tag           string
	outputDir     string
	remove        bool
	containerName string
	output        map[string]string
}

func NewSoFinder(arch, distroWithTag, outputDir, containerName string, remove bool) (*SoFinder, error) {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %w", err)
	}

	if containerName == "" {
		containerName = defaultContainerName
	}

	d := strings.Split(distroWithTag, ":")
	tag := "latest"
	if len(d) > 1 {
		tag = d[1]
	}

	return &SoFinder{
		ctx:           ctx,
		cli:           cli,
		arch:          arch,
		distro:        d[0],
		outputDir:     outputDir,
		remove:        remove,
		containerName: containerName,
		tag:           tag,
		output:        make(map[string]string),
	}, nil
}

func (dm *SoFinder) Collect(soFileNames ...string) error {
	containerID, err := dm.findExistingContainer()
	if err != nil {
		return fmt.Errorf("failed to find existing container: %w", err)
	}

	if containerID == "" {
		containerID, err = dm.createContainer()
		if err != nil {
			return fmt.Errorf("failed to create container: %w", err)
		}
		dm.containerID = containerID
	} else {
		dm.containerID = containerID
	}

	if err := dm.cli.ContainerStart(dm.ctx, dm.containerID, container.StartOptions{}); err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}

	// Install necessary packages based on distro
	err = dm.installUbuntuPackages()
	if err != nil {
		return fmt.Errorf("failed to install packages: %w", err)
	}

	err = dm.checkAndDownloadDependencies(soFileNames)
	if err != nil {
		return fmt.Errorf("failed to find or download so libs. err: %w", err)
	}

	if dm.remove {
		if err := dm.cli.ContainerRemove(dm.ctx, dm.containerID, container.RemoveOptions{Force: true}); err != nil {
			return fmt.Errorf("failed to remove container: %w", err)
		}
	}

	return nil
}

func (dm *SoFinder) processLddDependencies(soFilePath string) error {
	// Get the ldd output
	// TODO: read into string rather than into file
	err := dm.getLddOutput(soFilePath)
	if err != nil {
		return fmt.Errorf("failed to run ldd on %s: %w", soFilePath, err)
	}

	// Read the ldd output to find all dependencies
	content, _, err := dm.cli.CopyFromContainer(dm.ctx, dm.containerID, "/so_files_archive/ldd_output.txt")
	if err != nil {
		return fmt.Errorf("failed to copy ldd output from container: %w", err)
	}
	lddOutput, err := extractLddOutput(content)
	if err != nil {
		return fmt.Errorf("failed to extract ldd output: %w", err)
	}

	// Check and download all dependencies
	err = dm.checkAndDownloadDependencies(lddOutput)
	if err != nil {
		return fmt.Errorf("failed to check and download dependencies: %w", err)
	}

	// Copy the collected .so files from the container to the host
	content, _, err = dm.cli.CopyFromContainer(dm.ctx, dm.containerID, dm.outputDir)
	if err != nil {
		return fmt.Errorf("failed to copy files from container: %w", err)
	}

	err = extractTar(content, getRootFolder(dm.outputDir))
	if err != nil {
		return fmt.Errorf("failed to extract files: %w", err)
	}

	return nil
}

func (dm *SoFinder) checkAndDownloadDependencies(dependencies []string) error {
	for _, dep := range dependencies {
		depPath := filepath.Base(dep)
		if _, ok := dm.output[depPath]; ok {
			continue
		}
		soFilePath, err := dm.findAndCopyLocalSoFile(depPath, "/")
		if err != nil {
			fmt.Printf("Dependency %s not found, try to download from apt sources...\n", depPath)
			// If the dependency is not found, download it
			soFilePath, err = dm.downloadPackage(depPath)
			if err != nil {
				return fmt.Errorf("warning: failed to download dependency %s: %v", depPath, err)
			}
		}

		// store this so file
		dm.output[depPath] = soFilePath

		// process nested LDD dependencies
		err = dm.processLddDependencies(soFilePath)
		if err != nil {
			return fmt.Errorf("warning: failed to process LDD dependency %s: %v", depPath, err)
		}
	}
	return nil
}

func (dm *SoFinder) findExistingContainer() (string, error) {
	filters := filters.NewArgs()
	filters.Add("name", dm.containerName)
	containers, err := dm.cli.ContainerList(dm.ctx, container.ListOptions{All: true, Filters: filters})
	if err != nil {
		return "", err
	}
	if len(containers) > 0 {
		return containers[0].ID, nil
	}
	return "", nil
}

func (dm *SoFinder) createContainer() (string, error) {
	img := dm.distro + ":" + dm.tag

	// Pull the selected image
	reader, err := dm.cli.ImagePull(dm.ctx, img, image.PullOptions{
		Platform: getPlatform(dm.arch),
	})
	if err != nil {
		return "", fmt.Errorf("failed to pull image %s: %w", img, err)
	}
	io.Copy(os.Stdout, reader)

	// Create the container
	resp, err := dm.cli.ContainerCreate(dm.ctx, &container.Config{
		Image: img,
		Cmd:   []string{"/bin/sh", "-c", "while :; do sleep 1; done"},
		Tty:   true,
	}, nil, nil, nil, dm.containerName)
	if err != nil {
		return "", fmt.Errorf("failed to create container: %w", err)
	}
	return resp.ID, nil
}

func getPlatform(arch string) string {
	if arch == "arm64" {
		return "linux/arm64"
	}
	return "linux/amd64"
}

func (dm *SoFinder) installUbuntuPackages() error {
	commands := []string{
		"apt-get update",
		"apt-get install -y build-essential apt-file",
	}
	return dm.execCommands(commands)
}

func (dm *SoFinder) getLddOutput(soFilePath string) error {
	lddCmd := fmt.Sprintf("ldd %s > /so_files_archive/ldd_output.txt", soFilePath)
	return dm.execCommand(lddCmd)
}

func (dm *SoFinder) downloadPackage(soFileName string) (string, error) {
	packageCmd := fmt.Sprintf("apt-file search %s | awk -F: '{print $1}' | head -1", soFileName)

	packageName, err := dm.execCommandOutput(packageCmd)
	if err != nil {
		return "", fmt.Errorf("failed to find package for %s: %w", soFileName, err)
	}
	packageName = cleanAptFileOutput(strings.TrimSpace(packageName))
	if packageName == "" {
		return "", fmt.Errorf("package for %s not found", soFileName)
	}

	var downloadCmd, packageFilePath, copyCmd string
	downloadCmd = fmt.Sprintf("apt-get download %s", packageName)
	packageFilePath = fmt.Sprintf("/%s_*.deb", packageName)
	copyCmd = fmt.Sprintf("cp %s /so_files_archive/", packageFilePath)

	err = dm.execCommand("mkdir -p /so_files_archive")
	if err != nil {
		return "", fmt.Errorf("failed to create archive directory: %w", err)
	}

	err = dm.execCommand(downloadCmd)
	if err != nil {
		return "", fmt.Errorf("failed to download package %s: %w", packageName, err)
	}

	existCmd := fmt.Sprintf("find /so_files_archive -name %s", filepath.Base(packageFilePath))
	output, err := dm.execCommandOutput(existCmd)
	if err != nil || strings.TrimSpace(output) == "" {
		return "", fmt.Errorf("package file %s does not exist: %w", packageFilePath, err)
	}

	err = dm.execCommand(copyCmd)
	if err != nil {
		return "", fmt.Errorf("failed to copy package file %s: %w", packageFilePath, err)
	}

	// Extract the copied package file from the archive directory
	var extractCmd string
	packageFilePath = fmt.Sprintf("/so_files_archive/%s_*.deb", packageName)
	extractCmd = fmt.Sprintf("dpkg-deb -xv %s /so_files_archive", packageFilePath)

	err = dm.execCommand(extractCmd)
	if err != nil {
		return "", fmt.Errorf("failed to extract package %s: %w", packageName, err)
	}

	// Handle the symlink case: resolve and copy the actual .so file, then rename it
	finalSOFilePath, err := dm.findAndCopyLocalSoFile(soFileName, "/so_files_archive")
	if err != nil {
		return "", fmt.Errorf("failed to copy and rename .so file: %w", err)
	}

	return finalSOFilePath, nil
}

func (dm *SoFinder) findAndCopyLocalSoFile(soFileName, searchPath string) (string, error) {
	// Search for the .so file in the extracted directories
	searchCmd := fmt.Sprintf("find %s -name %s|head -1", searchPath, soFileName)
	soFilePath, err := dm.execCommandOutput(searchCmd)
	if err != nil {
		return "", fmt.Errorf("failed to find %s in %s: %w", searchPath, soFileName, err)
	}
	soFilePath = cleanAptFileOutput(strings.TrimSpace(soFilePath))

	// Resolve the symlink if it is a symlink
	resolveCmd := fmt.Sprintf("readlink -f %s", soFilePath)
	resolvedPath, err := dm.execCommandOutput(resolveCmd)
	if err != nil {
		return "", fmt.Errorf("failed to resolve symlink for %s: %w", soFileName, err)
	}
	resolvedPath = cleanAptFileOutput(strings.TrimSpace(resolvedPath))

	// create the output directory if it doesn't exist
	err = dm.execCommand("mkdir -p " + dm.outputDir)
	if err != nil {
		return "", fmt.Errorf("failed to create output directory: %w", err)
	}

	// Copy the .so file to the output directory
	finalSOFilePath := fmt.Sprintf("%s/%s", dm.outputDir, soFileName)
	copyCmd := fmt.Sprintf("cp %s %s", resolvedPath, finalSOFilePath)
	err = dm.execCommand(copyCmd)
	if err != nil {
		return "", fmt.Errorf("failed to copy .so file from %s to %s: %w", resolvedPath, dm.outputDir, err)
	}

	return finalSOFilePath, nil
}

// The cleanAptFileOutput function removes non-printable characters and extra whitespace from a given
// string.
func cleanAptFileOutput(output string) string {
	// Remove everything up to the first forward slash
	if idx := strings.Index(output, "/"); idx != -1 {
		output = output[idx:]
	}

	// Remove non-printable characters and extra whitespace
	cleaned := strings.Map(func(r rune) rune {
		if r < ' ' || r > '~' {
			return -1
		}
		return r
	}, output)

	return strings.TrimSpace(cleaned)
}

func (dm *SoFinder) execCommands(cmds []string) error {
	for _, cmd := range cmds {
		err := dm.execCommand(cmd)
		if err != nil {
			return err
		}
	}
	return nil
}

func (dm *SoFinder) execCommand(cmd string) error {
	execIDResp, err := dm.cli.ContainerExecCreate(dm.ctx, dm.containerID, types.ExecConfig{
		Cmd:          []string{"/bin/sh", "-c", cmd},
		AttachStdout: true,
		AttachStderr: true,
	})
	if err != nil {
		return fmt.Errorf("failed to create exec: %w", err)
	}

	resp, err := dm.cli.ContainerExecAttach(dm.ctx, execIDResp.ID, types.ExecStartCheck{})
	if err != nil {
		return fmt.Errorf("failed to attach exec: %w", err)
	}
	defer resp.Close()

	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, resp.Reader); err != nil {
		return fmt.Errorf("failed to read exec output: %w", err)
	}

	output := buf.String()
	if strings.Contains(output, "not found") || strings.Contains(output, "No such file or directory") {
		return errors.New(output)
	}

	fmt.Println(output)
	return nil
}

func (dm *SoFinder) execCommandOutput(cmd string) (string, error) {
	execIDResp, err := dm.cli.ContainerExecCreate(dm.ctx, dm.containerID, types.ExecConfig{
		Cmd:          []string{"/bin/sh", "-c", cmd},
		AttachStdout: true,
		AttachStderr: true,
	})
	if err != nil {
		return "", fmt.Errorf("failed to create exec: %w", err)
	}

	resp, err := dm.cli.ContainerExecAttach(dm.ctx, execIDResp.ID, types.ExecStartCheck{})
	if err != nil {
		return "", fmt.Errorf("failed to attach exec: %w", err)
	}
	defer resp.Close()

	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, resp.Reader); err != nil {
		return "", fmt.Errorf("failed to read exec output: %w", err)
	}

	return buf.String(), nil
}

// The function `extractLddOutput` reads a tar archive, extracts the contents of a file named
// "ldd_output.txt", parses the dependencies listed in the file, and returns them as a slice of
// strings.
func extractLddOutput(tarContent io.Reader) ([]string, error) {
	var deps []string
	tarReader := tar.NewReader(tarContent)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error reading tar archive: %w", err)
		}

		if header.Name == "ldd_output.txt" {
			buf := new(bytes.Buffer)
			_, err = io.Copy(buf, tarReader)
			if err != nil {
				return nil, fmt.Errorf("failed to read ldd output: %w", err)
			}

			lines := strings.Split(buf.String(), "\n")
			for _, line := range lines {
				parts := strings.Fields(line)
				if len(parts) >= 3 && parts[1] == "=>" {
					deps = append(deps, parts[2])
				}
			}
		}
	}

	return deps, nil
}

// The `extractTar` function reads a tar archive from an `io.Reader` and extracts its contents to a
// specified destination directory.
func extractTar(tarContent io.Reader, dest string) error {
	tarReader := tar.NewReader(tarContent)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("error reading tar archive: %w", err)
		}

		target := filepath.Join(dest, header.Name)
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}
		case tar.TypeReg:
			file, err := os.Create(target)
			if err != nil {
				return fmt.Errorf("failed to create file: %w", err)
			}
			if _, err := io.Copy(file, tarReader); err != nil {
				file.Close()
				return fmt.Errorf("failed to copy file contents: %w", err)
			}
			file.Close()
		}
	}
	return nil
}

func getRootFolder(path string) string {
	parts := strings.Split(filepath.ToSlash(path), "/")
	if parts[0] == "" {
		return parts[1]
	} else {
		return strings.Join(parts[:len(parts)-1], "/")
	}
}
