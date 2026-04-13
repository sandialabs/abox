package cloudinit

// Contribution holds cloud-init content from a single feature.
type Contribution struct {
	WriteFiles []string          // YAML blocks starting with "  - path: ..."
	Bootcmd    string            // Full bootcmd section including key (only DNS uses this)
	Runcmd     []string          // Individual runcmd items starting with "  - ..."
	ISOFiles   map[string]string // dstFilename -> srcPath for ISO piggyback
}

// Contributor produces cloud-init content for a specific feature.
type Contributor interface {
	Contribute() (*Contribution, error)
}
