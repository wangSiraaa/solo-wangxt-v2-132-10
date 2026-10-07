//! Offline cache package maintenance:
//!   cache-pack export --cache-dir DIR --output FILE /obj/a /obj/b
//!   cache-pack import --cache-dir DIR FILE

use std::path::PathBuf;

use range_cache_proxy::pack;

#[derive(Debug)]
struct Args {
    cache_dir: PathBuf,
    command: Command,
}

#[derive(Debug)]
enum Command {
    Export {
        output: PathBuf,
        objects: Vec<String>,
    },
    Import {
        package: PathBuf,
    },
}

fn usage() -> ! {
    eprintln!(
        "usage:\n  cache-pack export --cache-dir DIR --output FILE PATH...\n  cache-pack import --cache-dir DIR FILE"
    );
    std::process::exit(2);
}

fn parse_args() -> Args {
    let mut args = std::env::args().skip(1);
    let command = match args.next() {
        Some(c) if c == "export" || c == "import" => c,
        _ => usage(),
    };
    let mut cache_dir = std::env::var("CACHE_DIR").map(PathBuf::from).ok();
    let mut output = None;
    let mut positional = Vec::new();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--cache-dir" => {
                let value = args.next().unwrap_or_else(|| usage());
                cache_dir = Some(PathBuf::from(value));
            }
            "--output" if command == "export" => {
                output = Some(PathBuf::from(args.next().unwrap_or_else(|| usage())));
            }
            "--help" | "-h" => usage(),
            value if value.starts_with("--") => usage(),
            value => positional.push(value.to_string()),
        }
    }

    let Some(cache_dir) = cache_dir else {
        usage();
    };
    let command = if command == "export" {
        match (output, positional.is_empty()) {
            (Some(output), false) => Command::Export {
                output,
                objects: positional,
            },
            _ => usage(),
        }
    } else {
        match positional.as_slice() {
            [package] => Command::Import {
                package: PathBuf::from(package),
            },
            _ => usage(),
        }
    };
    Args { cache_dir, command }
}

fn main() -> anyhow::Result<()> {
    let args = parse_args();
    match args.command {
        Command::Export { output, objects } => {
            pack::export_objects(&args.cache_dir, &output, &objects)?;
            println!("exported {} object(s)", objects.len());
        }
        Command::Import { package } => {
            let report = pack::import_package(&args.cache_dir, &package)?;
            println!(
                "imported {} version(s), skipped {} existing",
                report.imported(),
                report.skipped()
            );
        }
    }
    Ok(())
}
