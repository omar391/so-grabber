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
	containerID, err := dm.findOrCreateContainer()
	if err != nil {
		return fmt.Errorf("failed to find or create container: %w", err)
	}
	dm.containerID = containerID

	if err := dm.cli.ContainerStart(dm.ctx, dm.containerID, container.StartOptions{}); err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}

	if err := dm.installUbuntuPackages(); err != nil {
		return fmt.Errorf("failed to install packages: %w", err)
	}

	if err := dm.checkAndDownloadDependencies(soFileNames); err != nil {
		return fmt.Errorf("failed to find or download so libs: %w", err)
	}

	if dm.remove {
		if err := dm.cli.ContainerRemove(dm.ctx, dm.containerID, container.RemoveOptions{Force: true}); err != nil {
			return fmt.Errorf("failed to remove container: %w", err)
		}
	}

	return nil
}

func (dm *SoFinder) processLddDependencies(soFilePath string) error {
	if err := dm.getLddOutput(soFilePath); err != nil {
		return fmt.Errorf("failed to run ldd on %s: %w", soFilePath, err)
	}

	content, _, err := dm.cli.CopyFromContainer(dm.ctx, dm.containerID, "/so_files_archive/ldd_output.txt")
	if err != nil {
		return fmt.Errorf("failed to copy ldd output from container: %w", err)
	}

	lddOutput, err := extractLddOutput(content)
	if err != nil {
		return fmt.Errorf("failed to extract ldd output: %w", err)
	}

	if err := dm.checkAndDownloadDependencies(lddOutput); err != nil {
		return fmt.Errorf("failed to check and download dependencies: %w", err)
	}

	content, _, err = dm.cli.CopyFromContainer(dm.ctx, dm.containerID, dm.outputDir)
	if err != nil {
		return fmt.Errorf("failed to copy files from container: %w", err)
	}

	if err := extractTar(content, getRootFolder(dm.outputDir)); err != nil {
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
			fmt.Printf("Dependency %s not found, trying to download from apt sources...\n", depPath)
			soFilePath, err = dm.downloadPackage(depPath)
			if err != nil {
				return fmt.Errorf("failed to download dependency %s: %v", depPath, err)
			}
		}

		dm.output[depPath] = soFilePath

		if err := dm.processLddDependencies(soFilePath); err != nil {
			return fmt.Errorf("failed to process LDD dependency %s: %v", depPath, err)
		}
	}
	return nil
}

func (dm *SoFinder) findOrCreateContainer() (string, error) {
	containerID, err := dm.findExistingContainer()
	if err != nil {
		return "", err
	}
	if containerID != "" {
		return containerID, nil
	}
	return dm.createContainer()
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

	imageExists, err := dm.checkImageExists(img)
	if err != nil {
		return "", err
	}

	if !imageExists {
		if err := dm.pullImage(img); err != nil {
			return "", err
		}
	}

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

func (dm *SoFinder) checkImageExists(img string) (bool, error) {
	images, err := dm.cli.ImageList(dm.ctx, image.ListOptions{})
	if err != nil {
		return false, fmt.Errorf("failed to list images: %w", err)
	}
	for _, image := range images {
		for _, tag := range image.RepoTags {
			if tag == img {
				return true, nil
			}
		}
	}
	return false, nil
}

func (dm *SoFinder) pullImage(img string) error {
	reader, err := dm.cli.ImagePull(dm.ctx, img, image.PullOptions{
		Platform: getPlatform(dm.arch),
	})
	if err != nil {
		return fmt.Errorf("failed to pull image %s: %w", img, err)
	}
	defer reader.Close()
	_, err = io.Copy(os.Stdout, reader)
	return err
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
	// create so_files_archive if doesn't exist
	lddCmd := fmt.Sprintf("mkdir -p /so_files_archive/ && ldd %s > /so_files_archive/ldd_output.txt", soFilePath)
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

	downloadCmd := fmt.Sprintf("apt-get download %s", packageName)
	if err := dm.execCommand(downloadCmd); err != nil {
		return "", fmt.Errorf("failed to download package %s: %w", packageName, err)
	}

	packageFilePath := fmt.Sprintf("/%s_*.deb", packageName)
	extractCmd := fmt.Sprintf("dpkg-deb -xv %s /so_files_archive", packageFilePath)
	if err := dm.execCommand(extractCmd); err != nil {
		return "", fmt.Errorf("failed to extract package %s: %w", packageName, err)
	}

	return dm.findAndCopyLocalSoFile(soFileName, "/so_files_archive")
}

func (dm *SoFinder) findAndCopyLocalSoFile(soFileName, searchPath string) (string, error) {
	searchCmd := fmt.Sprintf("find %s -name %s|head -1", searchPath, soFileName)
	soFilePath, err := dm.execCommandOutput(searchCmd)
	if err != nil {
		return "", fmt.Errorf("failed to find %s in %s: %w", searchPath, soFileName, err)
	}
	soFilePath = cleanAptFileOutput(strings.TrimSpace(soFilePath))

	resolveCmd := fmt.Sprintf("readlink -f %s", soFilePath)
	resolvedPath, err := dm.execCommandOutput(resolveCmd)
	if err != nil {
		return "", fmt.Errorf("failed to resolve symlink for %s: %w", soFileName, err)
	}
	resolvedPath = cleanAptFileOutput(strings.TrimSpace(resolvedPath))

	err = dm.execCommand("mkdir -p " + dm.outputDir)
	if err != nil {
		return "", fmt.Errorf("failed to create output directory: %w", err)
	}

	finalSOFilePath := fmt.Sprintf("%s/%s", dm.outputDir, soFileName)
	copyCmd := fmt.Sprintf("cp %s %s", resolvedPath, finalSOFilePath)
	if err := dm.execCommand(copyCmd); err != nil {
		return "", fmt.Errorf("failed to copy .so file from %s to %s: %w", resolvedPath, dm.outputDir, err)
	}

	return finalSOFilePath, nil
}

func cleanAptFileOutput(output string) string {
	if idx := strings.Index(output, "/"); idx != -1 {
		output = output[idx:]
	}

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
		if err := dm.execCommand(cmd); err != nil {
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
		WorkingDir: "/",
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
			if _, err := io.Copy(buf, tarReader); err != nil {
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
	}
	return strings.Join(parts[:len(parts)-1], "/")
}
