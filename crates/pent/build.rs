// Pull in the CLI definition so we can generate man pages from it.
// We use include! rather than a crate import because build.rs runs as a
// separate compilation unit that cannot import pub(crate) items.
// Note: do not add `use` statements here for anything already imported by
// cli.rs (e.g. PathBuf), as include! pastes that file verbatim.
include!("src/cli.rs");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Write man pages to a stable `man/` directory at the repo root so that
    // packaging scripts (PKGBUILD, cargo-deb, Homebrew formula) can find them
    // at a known path regardless of Cargo's OUT_DIR.
    let manifest_dir = std::path::PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR")?,
    );
    let man_dir = manifest_dir.join("../../man");
    std::fs::create_dir_all(&man_dir)?;

    let cmd = <Cli as clap::CommandFactory>::command();
    generate_man_pages(&cmd, &man_dir)?;

    // Re-run only when the CLI definition changes.
    println!("cargo:rerun-if-changed=src/cli.rs");
    Ok(())
}

fn generate_man_pages(
    cmd: &clap::Command,
    out_dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let name = cmd.get_name().to_string();
    write_man_page(cmd, &name, out_dir)?;

    for sub in cmd.get_subcommands() {
        let sub_name = format!("{name}-{}", sub.get_name());
        let sub_renamed = sub.clone().name(sub_name.clone());
        write_man_page(&sub_renamed, &sub_name, out_dir)?;

        for subsub in sub.get_subcommands() {
            let subsub_name = format!("{sub_name}-{}", subsub.get_name());
            let subsub_renamed = subsub.clone().name(subsub_name.clone());
            write_man_page(&subsub_renamed, &subsub_name, out_dir)?;
        }
    }
    Ok(())
}

fn write_man_page(
    cmd: &clap::Command,
    name: &str,
    out_dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let page = clap_mangen::Man::new(cmd.clone());
    let mut buf = Vec::new();
    page.render(&mut buf)?;
    std::fs::write(out_dir.join(format!("{name}.1")), &buf)?;
    Ok(())
}
