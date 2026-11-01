mod sha256;
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Component, Path},
    process,
};
type Manifest = BTreeMap<String, String>;
fn collect(root: &Path, dir: &Path, result: &mut Manifest) -> Result<(), String> {
    let entries = fs::read_dir(dir).map_err(|e| e.to_string())?;
    for item in entries {
        let item = item.map_err(|e| e.to_string())?;
        let path = item.path();
        let meta = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            let name = item.file_name();
            if [".git", "target", "node_modules", "data", "reports"]
                .iter()
                .any(|x| name == *x)
            {
                continue;
            }
            collect(root, &path, result)?;
        } else if meta.is_file() {
            if meta.len() > 20 * 1024 * 1024 {
                return Err("A file exceeds the 20 MiB limit".into());
            }
            if result.len() >= 10000 {
                return Err("File count exceeds 10000".into());
            }
            let relative = path
                .strip_prefix(root)
                .map_err(|e| e.to_string())?
                .to_str()
                .ok_or("Non-UTF8 path")?
                .replace('\\', "/");
            if relative.contains(['\t', '\n', '\r']) {
                return Err("Control characters in path".into());
            }
            result.insert(
                relative,
                sha256::digest(&fs::read(&path).map_err(|e| e.to_string())?),
            );
        }
    }
    Ok(())
}
fn snapshot(root: &Path) -> Result<Manifest, String> {
    let root = fs::canonicalize(root).map_err(|e| e.to_string())?;
    if !root.is_dir() {
        return Err("Directory required".into());
    }
    let mut result = BTreeMap::new();
    collect(&root, &root, &mut result)?;
    Ok(result)
}
fn parse(input: &str) -> Result<Manifest, String> {
    let mut result = BTreeMap::new();
    for line in input.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (hash, name) = line
            .split_once('\t')
            .ok_or("Manifest requires digest<TAB>relative-path")?;
        if hash.len() != 64
            || !hash.bytes().all(|c| c.is_ascii_hexdigit())
            || name.is_empty()
            || name.contains('\\')
            || name.contains(':')
            || Path::new(name).is_absolute()
            || Path::new(name)
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
        {
            return Err("Invalid manifest entry".into());
        }
        if result.insert(name.into(), hash.to_lowercase()).is_some() {
            return Err("Duplicate manifest path".into());
        }
    }
    Ok(result)
}
fn changes(old: &Manifest, new: &Manifest) -> Vec<String> {
    let keys: BTreeSet<_> = old.keys().chain(new.keys()).collect();
    keys.into_iter()
        .filter_map(|k| match (old.get(k), new.get(k)) {
            (None, Some(_)) => Some(format!("ADDED\t{k}")),
            (Some(_), None) => Some(format!("MISSING\t{k}")),
            (Some(a), Some(b)) if a != b => Some(format!("CHANGED\t{k}")),
            _ => None,
        })
        .collect()
}
fn run() -> Result<i32, String> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 4 {
        return Err("Usage: integrity-watch <snapshot|verify> <directory> <manifest.tsv>. Store the manifest OUTSIDE the scanned directory.".into());
    }
    let root = fs::canonicalize(&args[2]).map_err(|e| e.to_string())?;
    let manifest = Path::new(&args[3]);
    let parent = manifest
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let absolute = fs::canonicalize(parent)
        .map_err(|e| e.to_string())?
        .join(manifest.file_name().ok_or("Manifest filename required")?);
    if absolute.starts_with(&root) {
        return Err("Manifest must be outside the scanned directory".into());
    }
    match args[1].as_str() {
        "snapshot" => {
            let data = snapshot(&root)?;
            let text = data
                .iter()
                .map(|(name, hash)| format!("{hash}\t{name}\n"))
                .collect::<String>();
            use std::io::Write;
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(manifest)
                .map_err(|e| format!("Manifest must not already exist: {e}"))?;
            f.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
            println!("Snapshot created: {} files", data.len());
            Ok(0)
        }
        "verify" => {
            let text = fs::read_to_string(manifest).map_err(|e| e.to_string())?;
            if text.len() > 5 * 1024 * 1024 {
                return Err("Manifest exceeds 5 MiB".into());
            }
            let old = parse(&text)?;
            let new = snapshot(&root)?;
            let changed = changes(&old, &new);
            for line in &changed {
                println!("{line}")
            }
            println!("{} differences", changed.len());
            Ok(if changed.is_empty() { 0 } else { 1 })
        }
        _ => Err("Unknown command".into()),
    }
}
fn main() {
    match run() {
        Ok(code) => process::exit(code),
        Err(message) => {
            eprintln!("{message}");
            process::exit(2)
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn diff_detects_all_types() {
        let old = BTreeMap::from([("a".into(), "1".into()), ("b".into(), "2".into())]);
        let new = BTreeMap::from([("a".into(), "3".into()), ("c".into(), "4".into())]);
        assert_eq!(
            changes(&old, &new),
            vec!["CHANGED\ta", "MISSING\tb", "ADDED\tc"]
        );
    }
    #[test]
    fn hostile_manifest_rejected() {
        assert!(parse(&format!("{}\t../secret", "a".repeat(64))).is_err());
        assert!(parse(&format!("{}\ta\n{}\ta", "a".repeat(64), "b".repeat(64))).is_err());
    }
}
