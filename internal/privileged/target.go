package privileged

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
)

// Target is the unprivileged identity the daemon will run as.
type Target struct {
	UID, GID int
	Name     string
	Home     string
}

// FromSudo derives the target from the SUDO_* variables sudo sets. This is
// valid only for `sudo switchboard start`, where a real user did elevate.
//
// It is deliberately not a general "figure out who to run as": under launchd
// there is no SUDO_UID, no invoking user, and nothing to infer from. That
// path passes the identity explicitly instead — see FromFlags. A single
// function that tried to guess in both cases would silently pick root's home
// in the launchd case, and the failure would surface much later as a CA in
// /var/root that `switchboard setup` cannot find.
func FromSudo() (Target, error) {
	name := os.Getenv("SUDO_USER")
	if name == "" || name == "root" {
		return Target{}, errors.New("SUDO_USER is not set, so there is no unprivileged " +
			"user to drop to. Run this as `sudo switchboard start` from your own account, " +
			"or use `switchboard daemon install` to have launchd start it")
	}
	uid, err := envInt("SUDO_UID")
	if err != nil {
		return Target{}, err
	}
	gid, err := envInt("SUDO_GID")
	if err != nil {
		return Target{}, err
	}
	home, err := homeOf(name)
	if err != nil {
		return Target{}, err
	}
	return Target{UID: uid, GID: gid, Name: name, Home: home}, nil
}

// FromFlags builds a Target from values supplied explicitly, filling in the
// home directory from the user database when it was not given. Used by the
// launchd path, where the plist carries the identity written at install time.
func FromFlags(uid, gid int, home string) (Target, error) {
	if uid <= 0 || gid <= 0 {
		return Target{}, fmt.Errorf("--uid and --gid are required and must not be root (got %d/%d)", uid, gid)
	}
	t := Target{UID: uid, GID: gid, Home: home}
	u, err := user.LookupId(strconv.Itoa(uid))
	if err == nil {
		t.Name = u.Username
		if t.Home == "" {
			t.Home = u.HomeDir
		}
	}
	if t.Home == "" {
		return Target{}, fmt.Errorf("--home is required: uid %d is not in the user database, "+
			"so its home directory cannot be looked up", uid)
	}
	return t, nil
}

func envInt(key string) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return 0, fmt.Errorf("%s is not set", key)
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s=%q is not a number: %w", key, v, err)
	}
	if n == 0 {
		return 0, fmt.Errorf("%s is 0; refusing to run the daemon as root", key)
	}
	return n, nil
}

func homeOf(name string) (string, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return "", fmt.Errorf("looking up %q: %w", name, err)
	}
	if u.HomeDir == "" {
		return "", fmt.Errorf("%q has no home directory", name)
	}
	return u.HomeDir, nil
}
