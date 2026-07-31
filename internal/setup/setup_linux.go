package setup

import (
	"fmt"
	"io"
)

// Linux automation lands in v0.5 (see DESIGN.md §5): there is no
// /etc/resolver equivalent, so split-DNS needs systemd-resolved or dnsmasq
// integration. Until then, setup prints exact manual steps instead of
// failing opaquely.

func installResolver(tld string, dnsPort int, out io.Writer) ([]string, error) {
	fmt.Fprintf(out, `  Linux DNS automation is planned for v0.5. Manual options until then:

  systemd-resolved (most desktop distros):
    1. create /etc/systemd/resolved.conf.d/switchboard.conf with:
         [Resolve]
         DNS=127.0.0.1:%d
         Domains=~%s
    2. sudo systemctl restart systemd-resolved

  dnsmasq:
    add to /etc/dnsmasq.d/switchboard.conf:
         server=/%s/127.0.0.1#%d

`, dnsPort, tld, tld, dnsPort)
	return []string{"resolver: manual configuration required on Linux (printed above)"}, nil
}

func removeResolver(tld string, out io.Writer) error {
	fmt.Fprintf(out, "  remove your manual resolver config for .%s (see setup notes)\n", tld)
	return nil
}

func installTrust(rootPath string, out io.Writer) ([]string, error) {
	fmt.Fprintf(out, `  Linux trust-store automation is planned for v0.5. Manual steps:

  Debian/Ubuntu:
    sudo cp %s /usr/local/share/ca-certificates/switchboard-root.crt
    sudo update-ca-certificates

  Fedora/RHEL:
    sudo cp %s /etc/pki/ca-trust/source/anchors/switchboard-root.crt
    sudo update-ca-trust

  Firefox/Chromium (NSS user store):
    certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n switchboard -i %s

`, rootPath, rootPath, rootPath)
	return []string{"trust: manual installation required on Linux (printed above)"}, nil
}

func removeTrust(rootPath string, out io.Writer) error {
	fmt.Fprintln(out, "  remove the CA from wherever you installed it (see setup notes)")
	return nil
}
