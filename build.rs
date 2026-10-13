use std::env;
use std::fs;
use std::io::Error;
use std::path::PathBuf;

use clap::CommandFactory;
use clap_complete::{Shell, generate_to};

include!("src/cli.rs");

/// Renders the man page and the bash/zsh/fish completions into
/// `$OUT_DIR/assets/{man,completions}`, where a build script may write (with
/// `cargo install` the package source is the registry's, possibly read-only).
/// A packager that wants them at a fixed path sets `SPING_ASSETS_DIR` to an
/// absolute directory, which then replaces `$OUT_DIR/assets`; the release
/// builds use `$PWD/target/assets`, where `Cargo.toml`'s `.deb` assets are.
fn main() -> Result<(), Error> {
    println!("cargo:rerun-if-changed=src/cli.rs");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=SPING_ASSETS_DIR");

    let assets_dir = match env::var_os("SPING_ASSETS_DIR") {
        Some(dir) => {
            let dir = PathBuf::from(dir);
            if !dir.is_absolute() {
                return Err(Error::other(format!(
                    "SPING_ASSETS_DIR must be an absolute path, not '{}'",
                    dir.display()
                )));
            }
            dir
        }
        None => {
            PathBuf::from(env::var_os("OUT_DIR").ok_or_else(|| Error::other("OUT_DIR is not set"))?)
                .join("assets")
        }
    };
    let man_dir = assets_dir.join("man");
    let comp_dir = assets_dir.join("completions");
    fs::create_dir_all(&man_dir)?;
    fs::create_dir_all(&comp_dir)?;

    let mut cmd = Args::command();

    let man = clap_mangen::Man::new(cmd.clone());
    let mut buf: Vec<u8> = Vec::new();
    man.render(&mut buf)?;
    fs::write(man_dir.join("sping.1"), buf)?;

    for shell in [Shell::Bash, Shell::Zsh, Shell::Fish] {
        generate_to(shell, &mut cmd, "sping", &comp_dir)?;
    }

    Ok(())
}
