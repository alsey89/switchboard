package setup

import (
	"fmt"
	"io"
)

// Windows automation lands in v0.4 (see DESIGN.md §5): NRPT is the
// /etc/resolver equivalent, with a hosts-file block as fallback. Until
// then, setup prints exact manual steps.

func installResolver(tld string, dnsPort int, out io.Writer) ([]string, error) {
	fmt.Fprintf(out, `  Windows DNS automation is planned for v0.4. Manual option (admin PowerShell):

    Add-DnsClientNrptRule -Namespace ".%s" -NameServers "127.0.0.1"

  Note: NRPT cannot target a custom port, so set dns_port = 53 in the
  Switchboard config so the daemon binds 127.0.0.1:53.

`, tld)
	return []string{"resolver: manual NRPT rule required on Windows (printed above)"}, nil
}

func removeResolver(tld string, out io.Writer) error {
	fmt.Fprintf(out, "  remove the NRPT rule (admin PowerShell):\n"+
		"    Get-DnsClientNrptRule | Where-Object Namespace -eq \".%s\" | Remove-DnsClientNrptRule -Force\n", tld)
	return nil
}

func installTrust(rootPath string, out io.Writer) ([]string, error) {
	fmt.Fprintf(out, `  Manual trust install (admin prompt):

    certutil -addstore -f ROOT "%s"

`, rootPath)
	return []string{"trust: manual certutil install required on Windows (printed above)"}, nil
}

func removeTrust(rootPath string, out io.Writer) error {
	fmt.Fprintln(out, "  remove with: certutil -delstore ROOT \"Switchboard Local CA\"")
	return nil
}
