# SoFinder

**SoFinder** is a powerful tool designed to help developers identify and collect all required shared libraries (`.so` files) and their dependencies for running binaries that may not be fully supported on the current system. With SoFinder, you can leverage Docker and popular Linux distributions like Ubuntu and Arch Linux to locate and retrieve the exact shared libraries needed for your applications.

## Features

- **Automated Library Discovery**: Easily find and collect the exact `.so` files required for your binaries.
- **Comprehensive Dependency Management**: Recursively identify and gather all dependent shared libraries.
- **Multi-Distribution Support**: Compatible with both Ubuntu and Arch Linux distributions.
- **Architecture Flexibility**: Supports `x86_64` and `arm64` architectures.
- **Efficient Docker Integration**: Manages Docker containers to facilitate library discovery and collection.
- **Organized Output**: Collect and store all dependencies in a specified directory for easy access and integration.

## Why Use SoFinder?

When running binaries that depend on specific shared libraries, missing dependencies can lead to runtime errors and hinder development. SoFinder automates the discovery and collection process, ensuring that all necessary `.so` files and their dependencies are available, regardless of the host system's limitations. This tool simplifies your workflow, reduces errors, and enhances productivity by leveraging Docker to emulate different Linux environments.

## Getting Started

### Prerequisites

- **Docker**: Ensure Docker is installed and running on your machine.

### Installation

1. **Clone the Repository**:

   ```sh
   git clone https://github.com/omar391/sofinder.git
   cd sofinder
   ```

2. **Build the Project**:
   ```sh
   go build -o sofinder
   ```

### Usage

```sh
./sofinder <so-file-names> [architecture: x86_64|arm64] [distro: ubuntu|arch] [output-directory] [remove-container]
```

### Example

```sh
./sofinder lib1.so,lib2.so x86_64 ubuntu ./so_files true
```

In this example, SoFinder will:

1. Identify and download `lib1.so` (and `lib2.so`) and its dependencies.
2. Collect all necessary `.so` files in the specified output directory (`./so_files`).
3. Optionally remove the Docker container after completion.

## Contributing

We welcome contributions from the community! Feel free to submit pull requests, report issues, or suggest enhancements. Together, we can make SoFinder even better.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
