use std::env;
use std::fs;
use std::io::Error;
use std::path::PathBuf;

use clap::CommandFactory;
use clap_complete::{Shell, generate_to};

include!("src/cli.rs");

fn main() -> Result<(), Error> {
    println!("cargo:rerun-if-changed=src/cli.rs");
    println!("cargo:rerun-if-changed=build.rs");

    let target_dir = env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target"));
    let man_dir = target_dir.join("assets/man");
    let comp_dir = target_dir.join("assets/completions");
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
