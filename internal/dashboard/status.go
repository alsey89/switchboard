// Read-only diagnostic endpoints. Everything here reads the filesystem or
// launchd rather than s.cfg, because their whole purpose is reporting the
// state the daemon is running in, including the parts that are broken.
package dashboard

import (
	"net/http"

	"github.com/alsey89/switchboard/internal/config"
	"github.com/alsey89/switchboard/internal/doctor"
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
