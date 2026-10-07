//! Caching Range-aware proxy entry point and offline cache maintenance.
//!
//! Env:
//!   UPSTREAM_BASE  e.g. http://127.0.0.1:9000/   (loopback only, must end /)
//!   LISTEN_ADDR    e.g. 127.0.0.1:8000           (default 127.0.0.1:8000)
//!   CACHE_DIR      e.g. ./cache-data
//!   ALLOW_NON_LOOPBACK=1 to disable the loopback-only guard (discouraged)
//!
//! Offline package commands:
//!   proxy export-cache --object /obj/alpha [--etag alpha-v1] --out alpha.rcpkg
//!   proxy import-cache --input alpha.rcpkg

use std::path::PathBuf;

use range_cache_proxy::package::{self, ImportOutcome};
use range_cache_proxy::ProxyConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,range_cache_proxy=debug".parse().unwrap()),
        )
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("export-cache") => export_cache(&args[1..]).await,
        Some("import-cache") => import_cache(&args[1..]).await,
        Some(arg) if arg == "--help" || arg == "-h" || arg == "help" => {
            print_usage();
            Ok(())
        }
        Some(arg) => {
            anyhow::bail!("unknown argument or subcommand: {arg}")
        }
        None => serve().await,
    }
}

fn print_usage() {
    eprintln!(
        "usage:\n\
         \n  proxy                         run the caching proxy\n  proxy export-cache --object PATH [--etag TAG] --out FILE\n  proxy import-cache --input FILE\n\
         \nCACHE_DIR defaults to ./cache-data for both subcommands."
    );
}

fn cache_dir_from_args(args: &[String]) -> PathBuf {
    option_value(args, "--cache-dir")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("CACHE_DIR").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("./cache-data"))
}

fn option_value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == name {
            return iter.next().map(String::as_str);
        }
        if let Some(rest) = arg.strip_prefix(&format!("{name}=")) {
            return Some(rest);
        }
    }
    None
}

fn normalize_etag_arg(value: &str) -> &str {
    let strong = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value);
    let strong = strong
        .strip_prefix("W/")
        .or_else(|| strong.strip_prefix("w/"))
        .map(|v| v.trim())
        .and_then(|v| v.strip_prefix('"'))
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(strong);
    strong
}

async fn export_cache(args: &[String]) -> anyhow::Result<()> {
    let object = option_value(args, "--object")
        .ok_or_else(|| anyhow::anyhow!("export-cache requires --object PATH"))?;
    let output = option_value(args, "--out")
        .ok_or_else(|| anyhow::anyhow!("export-cache requires --out FILE"))?;
    let etag = option_value(args, "--etag").map(str::to_string);
    let cache_dir = cache_dir_from_args(args);
    package::export_version(
        &cache_dir,
        object,
        etag.as_deref().map(normalize_etag_arg).as_deref(),
        std::path::Path::new(output),
    )
    .await?;
    eprintln!("exported {object} to {output}");
    Ok(())
}

async fn import_cache(args: &[String]) -> anyhow::Result<()> {
    let input = option_value(args, "--input")
        .ok_or_else(|| anyhow::anyhow!("import-cache requires --input FILE"))?;
    let cache_dir = cache_dir_from_args(args);
    match package::import_package(&cache_dir, std::path::Path::new(input)).await? {
        ImportOutcome::Imported { version_id } => {
            eprintln!("imported historical version {version_id} from {input}")
        }
        ImportOutcome::SameVersionAlreadyPresent => {
            eprintln!("same strong version already present; cache unchanged: {input}")
        }
    }
    Ok(())
}

async fn serve() -> anyhow::Result<()> {
    let upstream_base = std::env::var("UPSTREAM_BASE")
        .map_err(|_| anyhow::anyhow!("UPSTREAM_BASE is required"))?;
    let listen = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:8000".into());
    let cache_dir = std::env::var("CACHE_DIR").unwrap_or_else(|_| "./cache-data".into());

    let mut config = ProxyConfig::new(upstream_base, cache_dir);
    if std::env::var("ALLOW_NON_LOOPBACK").as_deref() == Ok("1") {
        config.require_loopback_upstream = false;
    }

    let (app, state) = range_cache_proxy::build_app(config).await?;
    tracing::info!(upstream = %state.config.upstream_base, "proxy starting");

    let listener = tokio::net::TcpListener::bind(&listen).await?;
    tracing::info!(%listen, "listening");
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}
