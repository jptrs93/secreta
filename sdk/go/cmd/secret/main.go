package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/jptrs93/secreta/sdk/go/secreta"
)

func main() {
	socketPath := flag.String("socket", "", "Unix socket path")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		printUsage()
		os.Exit(1)
	}

	if *socketPath != "" {
		secreta.SocketPath = *socketPath
	}

	switch args[0] {
	case "create":
		handleCreate(args[1:])
	case "fetch":
		handleFetch(args[1:])
	case "read":
		handleRead(args[1:])
	default:
		printUsage()
		os.Exit(1)
	}
}

func handleCreate(args []string) {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	name := fs.String("name", "", "Secret name")
	value := fs.String("value", "", "Secret value")
	cacheSeconds := fs.Int("cache-seconds", -1, "Cache TTL in seconds")
	fs.Parse(args)

	if *name == "" || *value == "" {
		fmt.Fprintln(os.Stderr, "name and value are required")
		os.Exit(1)
	}

	var ttl *int
	if *cacheSeconds >= 0 {
		ttl = cacheSeconds
	}

	response, err := secreta.CreateSecret(*name, *value, ttl, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Printf("created secret %s (cache %ds)\n", response.StoredName, response.CacheSeconds)
}

func handleFetch(args []string) {
	fs := flag.NewFlagSet("fetch", flag.ExitOnError)
	name := fs.String("name", "", "Secret name")
	reason := fs.String("reason", "", "Reason for access")
	fs.Parse(args)

	if *name == "" {
		fmt.Fprintln(os.Stderr, "name is required")
		os.Exit(1)
	}

	response, err := secreta.FetchSecret(*name, *reason)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Println(response.SecretValue)
}

func handleRead(args []string) {
	fs := flag.NewFlagSet("read", flag.ExitOnError)
	path := fs.String("path", "", "File path")
	reason := fs.String("reason", "", "Reason for access")
	fs.Parse(args)

	if *path == "" {
		fmt.Fprintln(os.Stderr, "path is required")
		os.Exit(1)
	}

	response, err := secreta.ReadFile(*path, *reason)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Println(response.Plaintext)
}

func printUsage() {
	fmt.Println("secret <command> [options]")
	fmt.Println("commands:")
	fmt.Println("  create --name <name> --value <value> [--cache-seconds <seconds>]")
	fmt.Println("  fetch --name <name> [--reason <reason>]")
	fmt.Println("  read --path <path> [--reason <reason>]")
}
