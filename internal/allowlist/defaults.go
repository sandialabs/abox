package allowlist

import (
	"os"
)

// DefaultDomains is the default allowlist content for new instances.
// No domains are allowed by default for security; users must explicitly add domains.
const DefaultDomains = `# Domain Allowlist for abox instance
# One domain per line. Subdomains are automatically allowed.
# Lines starting with # are comments.
#
# No domains are allowed by default. Add domains as needed:
#   abox allowlist add <instance> example.com
`

// CreateDefaultAllowlist creates a default allowlist file at the given path.
// Returns nil if the file already exists.
func CreateDefaultAllowlist(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	_, err = f.WriteString(DefaultDomains)
	return err
}
