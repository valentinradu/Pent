//! The classes of the user in pentd, also for another name of the same
//! file.
//!
//! The classifier of `pent-profile` compares paths as text. A path can have
//! more than one name: `/home` can be a link to `/var/home` (Silverblue),
//! and `/var/run` is a link to `/run`. Thus pentd classifies each access in
//! two forms, the path as the session sent it and the path with its links
//! resolved, with the home directory and the directories of pent in both
//! forms too. The strictest class wins (pent, then sensitive, then normal),
//! and a normal access gets the shortest menu of the forms of the home
//! directory, so no form offers a subtree that another form refuses.

use std::path::{Path, PathBuf};

use pent_profile::{
    exact_target, Class, Classifier, FileKind, GuardClass, Request, RulePath, Target,
};

/// The classes of the user, in each form of the home directory.
#[derive(Debug, Clone)]
pub(crate) struct Classes {
    views: Vec<Classifier>,
}

impl Classes {
    /// The classes for the home directory `home` and the directories of
    /// pent `pent_dirs`, each also with its links resolved.
    pub(crate) fn new(home: &Path, pent_dirs: &[PathBuf]) -> Self {
        let mut dirs = pent_dirs.to_vec();
        for dir in pent_dirs {
            let real = resolve(dir);
            if !dirs.contains(&real) {
                dirs.push(real);
            }
        }
        let mut views = vec![Classifier::new(home, &dirs)];
        let real_home = resolve(home);
        if real_home != home {
            views.push(Classifier::new(&real_home, &dirs));
        }
        Self { views }
    }

    /// The class and the menu of `request`.
    pub(crate) fn decide(&self, request: &Request) -> (Class, Vec<Target>) {
        let resolved = resolved_request(request);
        let forms: Vec<&Request> = std::iter::once(request).chain(resolved.as_ref()).collect();
        let class = self
            .views
            .iter()
            .flat_map(|view| forms.iter().map(|r| view.classify(&r.as_access())))
            .max_by_key(strictness)
            .unwrap_or(Class::Normal);
        let access = request.as_access();
        let menu = match class {
            Class::Pent => Vec::new(),
            Class::Sensitive(_) => vec![exact_target(&access)],
            Class::Normal => self
                .views
                .iter()
                .map(|view| view.widths(&access))
                .min_by_key(Vec::len)
                .unwrap_or_else(|| vec![exact_target(&access)]),
        };
        (class, menu)
    }
}

impl Classes {
    /// Return true if the access `request` is in the pent class, for a
    /// path with no link in it: the path of a FUSE request is made of real
    /// names below a canonical area. The views already hold the home and
    /// the directories of pent in both forms, so no link is resolved and no
    /// menu is made; the FUSE server asks this for each request.
    pub(crate) fn is_pent_unlinked(&self, request: &Request) -> bool {
        let access = request.as_access();
        self.views
            .iter()
            .any(|view| view.classify(&access) == Class::Pent)
    }

    /// The holes of a graft of `dir` for an access of the kind `kind`: the
    /// places of the guard list below it that FUSE keeps serving, so that
    /// each access there still asks. A spot that exists (a directory or a
    /// file) is its own hole. A missing spot gets a hole at its nearest
    /// existing directory below `dir`, so that a new file there still asks.
    /// `None` when no graft is safe: a missing spot directly in `dir` (a
    /// file could appear there in the graft with no question), a directory
    /// or a file of pent (its FUSE node is hidden), or `dir` inside a
    /// spot.
    pub(crate) fn graft_holes(&self, dir: &Path, kind: FileKind) -> Option<Vec<PathBuf>> {
        let mut holes: Vec<PathBuf> = Vec::new();
        for view in &self.views {
            // A mask of pent would show an empty directory in the graft,
            // where FUSE gives `ENOENT`.
            if view.holds_pent_dir(dir) {
                return None;
            }
            for spot in view.guard_spots_in(dir, kind) {
                if spot.class == GuardClass::PentFiles || spot.path == dir {
                    return None;
                }
                holes.push(hole_of(spot.path, dir)?);
            }
        }
        holes.sort();
        holes.dedup();
        // A hole inside another hole is in it already.
        let outer: Vec<PathBuf> = holes
            .iter()
            .filter(|h| !holes.iter().any(|o| o != *h && h.starts_with(o)))
            .cloned()
            .collect();
        Some(outer)
    }

    /// Return true if a subtree rule of the kind `kind` on `dir`, or on
    /// `dir` with its links resolved, covers a location of the guard list
    /// that makes such an access sensitive, in one form of the home
    /// directory.
    pub(crate) fn subtree_holds_guard(&self, dir: &Path, kind: FileKind) -> bool {
        let real = resolve(dir);
        self.views.iter().any(|view| {
            view.subtree_holds_guard_for(dir, kind) || view.subtree_holds_guard_for(&real, kind)
        })
    }
}

/// The hole of the guard spot `spot` in a graft of `dir`: the spot when it
/// exists, else its nearest existing directory strictly below `dir`.
fn hole_of(spot: &Path, dir: &Path) -> Option<PathBuf> {
    if std::fs::symlink_metadata(spot).is_ok() {
        return Some(spot.to_path_buf());
    }
    spot.ancestors()
        .skip(1)
        .take_while(|a| a.starts_with(dir) && *a != dir)
        .find(|a| std::fs::symlink_metadata(a).is_ok_and(|m| m.is_dir()))
        .map(Path::to_path_buf)
}

/// How strict a class is: the pent class, then a sensitive class, then the
/// normal class.
fn strictness(class: &Class) -> u8 {
    match class {
        Class::Normal => 0,
        Class::Sensitive(_) => 1,
        Class::Pent => 2,
    }
}

/// `path` with the links of its longest existing ancestor resolved, and the
/// rest as it is. A path with no existing ancestor stays as it is.
fn resolve(path: &Path) -> PathBuf {
    for ancestor in path.ancestors() {
        if let Ok(real) = std::fs::canonicalize(ancestor) {
            return match path.strip_prefix(ancestor) {
                Ok(rest) if rest.as_os_str().is_empty() => real,
                Ok(rest) => real.join(rest),
                Err(_) => path.to_path_buf(),
            };
        }
    }
    path.to_path_buf()
}

/// `request` with its path resolved, or `None` when the path is the same or
/// the request has no path.
fn resolved_request(request: &Request) -> Option<Request> {
    let real = |p: &RulePath| -> Option<RulePath> {
        let resolved = resolve(p.as_path());
        (resolved != p.as_path())
            .then(|| RulePath::new(resolved).ok())
            .flatten()
    };
    match request {
        Request::File { kind, path } => real(path).map(|path| Request::File { kind: *kind, path }),
        Request::UnixSocket(path) => real(path).map(Request::UnixSocket),
        Request::Domain(_) | Request::Localhost(_) => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // a test fails on a value that it must not get
mod tests {
    use pent_profile::{PathWidth, Sensitive};

    use super::*;

    fn read(p: &Path) -> Request {
        Request::File {
            kind: FileKind::Read,
            path: RulePath::new(p).unwrap(),
        }
    }

    /// A real home below a temporary directory, and a link to it.
    fn homes() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let real = root.join("var/home/u");
        std::fs::create_dir_all(real.join(".ssh")).unwrap();
        std::fs::create_dir_all(real.join(".config/foo")).unwrap();
        std::os::unix::fs::symlink(root.join("var/home"), root.join("home")).unwrap();
        (tmp, root.join("home/u"), real)
    }

    #[test]
    fn each_name_of_a_credential_is_sensitive() {
        let (_tmp, link_home, real_home) = homes();
        // pentd knows the home by its link name, as `$HOME` gives it.
        let classes = Classes::new(&link_home, &[]);
        for home in [&link_home, &real_home] {
            let (class, menu) = classes.decide(&read(&home.join(".ssh/id_ed25519")));
            assert_eq!(class, Class::Sensitive(Sensitive::Credential), "{home:?}");
            assert_eq!(menu.len(), 1, "{home:?}");
        }
        // And by its real name.
        let classes = Classes::new(&real_home, &[]);
        let (class, _) = classes.decide(&read(&link_home.join(".ssh/id_ed25519")));
        assert_eq!(class, Class::Sensitive(Sensitive::Credential));
    }

    #[test]
    fn a_graft_gets_a_hole_for_each_sensitive_place() {
        let tmp = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(tmp.path()).unwrap();
        let classes = Classes::new(&home, &[]);
        let holes = |dir: &str| classes.graft_holes(&home.join(dir), FileKind::Read);
        // A missing credential directly in the width: no safe hole.
        std::fs::create_dir_all(home.join(".cargo/registry")).unwrap();
        assert_eq!(holes(".cargo"), None);
        // The files exist: each one is a hole.
        std::fs::write(home.join(".cargo/credentials.toml"), "").unwrap();
        std::fs::write(home.join(".cargo/credentials"), "").unwrap();
        assert_eq!(
            holes(".cargo"),
            Some(vec![
                home.join(".cargo/credentials"),
                home.join(".cargo/credentials.toml"),
            ])
        );
        // A missing directory spot gets a hole at its nearest existing
        // directory below the width; a file spot that exists is a hole.
        std::fs::create_dir_all(home.join(".aws/sso")).unwrap();
        std::fs::write(home.join(".aws/credentials"), "").unwrap();
        assert_eq!(
            holes(".aws"),
            Some(vec![home.join(".aws/credentials"), home.join(".aws/sso")])
        );
        // A clean width has no hole; a directory of pent keeps the width
        // with FUSE, for each kind.
        std::fs::create_dir_all(home.join("projects")).unwrap();
        assert_eq!(holes("projects"), Some(Vec::new()));
        assert_eq!(holes(".config"), None);
        // `~/.local/state` holds no spot of a read, only the state of pent.
        std::fs::create_dir_all(home.join(".local/state")).unwrap();
        assert_eq!(holes(".local/state"), None);
    }

    #[test]
    fn the_quick_check_of_the_pent_class_takes_the_real_names() {
        let (_tmp, link_home, real_home) = homes();
        // The directories of pent by their link names, as the XDG
        // variables give them; the FUSE server sends the real names.
        let pent = link_home.join(".config/pent");
        let classes = Classes::new(&link_home, std::slice::from_ref(&pent));
        let real_pent = real_home.join(".config/pent");
        assert!(classes.is_pent_unlinked(&read(&real_pent.join("rules/x.toml"))));
        assert!(classes.is_pent_unlinked(&read(&pent.join("rules/x.toml"))));
        assert!(!classes.is_pent_unlinked(&read(&real_home.join(".config/foo/x"))));
        // A credential is sensitive, not hidden.
        assert!(!classes.is_pent_unlinked(&read(&real_home.join(".ssh/id_ed25519"))));
    }

    #[test]
    fn each_name_of_a_file_of_pent_is_in_the_pent_class() {
        let (_tmp, link_home, real_home) = homes();
        let runtime = real_home.join("run/pent");
        std::fs::create_dir_all(&runtime).unwrap();
        let classes = Classes::new(&link_home, &[runtime]);
        for home in [&link_home, &real_home] {
            let (class, menu) = classes.decide(&Request::UnixSocket(
                RulePath::new(home.join("run/pent/pentd.sock")).unwrap(),
            ));
            assert_eq!(class, Class::Pent, "{home:?}");
            assert!(menu.is_empty());
        }
    }

    #[test]
    fn a_normal_file_gets_the_shortest_menu_of_each_name_of_the_home() {
        let (_tmp, link_home, real_home) = homes();
        let classes = Classes::new(&link_home, &[]);
        // Under the real name, the menu must not offer the real home, its
        // parent or `.config`.
        let (class, menu) = classes.decide(&read(&real_home.join(".config/foo/x")));
        assert_eq!(class, Class::Normal);
        let subtrees: Vec<PathBuf> = menu
            .iter()
            .filter_map(|t| match t {
                Target::File {
                    width: PathWidth::Subtree(p),
                    ..
                } => Some(p.as_path().to_path_buf()),
                _ => None,
            })
            .collect();
        assert_eq!(subtrees, [real_home.join(".config/foo")], "{menu:?}");
    }

    #[test]
    fn a_missing_file_resolves_through_its_existing_parent() {
        let (_tmp, link_home, real_home) = homes();
        assert_eq!(
            resolve(&link_home.join("new/dir/file")),
            real_home.join("new/dir/file")
        );
        assert_eq!(resolve(Path::new("/")), PathBuf::from("/"));
    }
}
