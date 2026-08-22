// Read-only diagnostic endpoints. Everything here reads the filesystem or
// launchd rather than s.cfg, because their whole purpose is reporting the
// state the daemon is running in, including the parts that are broken.
package dashboard

import (
	"errors"
	"net/http"

	"github.com/alsey89/switchboard/internal/config"
	"github.com/alsey89/switchboard/internal/doctor"
	"github.com/alsey89/switchboard/internal/service"
)

// checkView is one doctor.Check on the wire. Status goes out as its string,
// not its int: doctor.Status already has a String method, and an int would
// make every consumer keep a second copy of the mapping.
type checkView struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
	Hint   string `json:"hint,omitempty"`
}

func (s *Server) handleDoctor(w http.ResponseWriter, r *http.Request) {
	p, ok := s.pathsOr503(w)
	if !ok {
		return
	}
	// Read from disk, not from s.cfg. Reporting a config that fails to parse
	// is one of doctor's jobs, and s.cfg only ever holds one that parsed.
	// doctor.Run substitutes defaults itself when cfgErr is non-nil.
	cfg, cfgErr := config.Load(p.configPath)
	checks := doctor.Run(cfg, p.configPath, p.dataDir, cfgErr)

	out := make([]checkView, 0, len(checks))
	for _, c := range checks {
		out = append(out, checkView{
			Name:   c.Name,
			Status: c.Status.String(),
			Detail: c.Detail,
			Hint:   c.Hint,
		})
	}
	writeJSON(w, out)
}

// serviceView is what the dashboard knows about the background service.
//
// Supported exists because service.Status is macOS-only. Everywhere else it
// returns an error next to NotInstalled, and that is not a failure the user
// caused or can act on. A Linux user should see "not supported here", not a
// red 500.
type serviceView struct {
	State     string `json:"state"`
	PlistPath string `json:"plistPath,omitempty"`
	Supported bool   `json:"supported"`
}

// serviceStateFor turns a service.Status() result into what the endpoint
// reports.
//
// The three-way split matters. service.ErrUnsupported means there is no
// service manager on this platform at all, which is not a failure the user
// caused or can act on. Any other error means the platform does support one
// and something went wrong looking it up, which is a real problem they can
// fix. Collapsing the two would tell a macOS user with a broken home
// directory that launchd does not exist.
//
// Split from handleService so both error branches can be tested anywhere.
// Calling service.Status() directly only ever exercises whichever branch the
// test machine happens to reach.
func serviceStateFor(state service.State, plistPath string, err error) serviceView {
	switch {
	case errors.Is(err, service.ErrUnsupported):
		return serviceView{State: "not supported on this platform"}
	case err != nil:
		return serviceView{State: "could not be determined: " + err.Error(), Supported: true}
	default:
		return serviceView{State: state.String(), PlistPath: plistPath, Supported: true}
	}
}

func (s *Server) handleService(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, serviceStateFor(service.Status()))
}
