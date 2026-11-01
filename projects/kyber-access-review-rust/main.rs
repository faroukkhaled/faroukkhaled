// Offline role inheritance review. No permissions are changed.
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs, process,
};
#[derive(Clone, Debug)]
struct Grant {
    principal: String,
    resource: String,
    actions: String,
    scope: String,
}
#[derive(Debug)]
struct Finding {
    principal: String,
    resource: String,
    rule: String,
}
fn parse(text: &str) -> Result<(Vec<Grant>, BTreeMap<String, Vec<String>>), String> {
    let mut grants = vec![];
    let mut memberships: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let p: Vec<_> = line.split('\t').collect();
        match p.as_slice() {
            ["grant", principal, resource, actions, scope]
                if !principal.is_empty()
                    && !resource.is_empty()
                    && !actions.is_empty()
                    && ["internal", "external", "public"].contains(scope) =>
            {
                grants.push(Grant {
                    principal: principal.to_string(),
                    resource: resource.to_string(),
                    actions: actions.to_string(),
                    scope: scope.to_string(),
                })
            }
            ["member", principal, role] if !principal.is_empty() && role.starts_with("role:") => {
                memberships
                    .entry(principal.to_string())
                    .or_default()
                    .push(role.to_string())
            }
            _ => return Err(format!("Invalid TSV entry on line {}", i + 1)),
        }
    }
    Ok((grants, memberships))
}
fn expand(
    name: &str,
    members: &BTreeMap<String, Vec<String>>,
    visiting: &mut BTreeSet<String>,
    result: &mut BTreeSet<String>,
) -> Result<(), String> {
    if !visiting.insert(name.into()) {
        return Err(format!("Role inheritance cycle at {name}"));
    }
    if visiting.len() > 64 {
        return Err("Role inheritance exceeds 64 levels".into());
    }
    result.insert(name.into());
    if let Some(roles) = members.get(name) {
        for role in roles {
            expand(role, members, visiting, result)?;
        }
    }
    visiting.remove(name);
    Ok(())
}
fn analyze(
    grants: &[Grant],
    members: &BTreeMap<String, Vec<String>>,
) -> Result<Vec<Finding>, String> {
    let principals: BTreeSet<_> = grants
        .iter()
        .map(|g| g.principal.clone())
        .chain(members.keys().cloned())
        .collect();
    let mut findings = vec![];
    for principal in principals {
        let mut effective = BTreeSet::new();
        expand(&principal, members, &mut BTreeSet::new(), &mut effective)?;
        for grant in grants.iter().filter(|g| effective.contains(&g.principal)) {
            let mut add = |rule: &str| {
                findings.push(Finding {
                    principal: principal.clone(),
                    resource: grant.resource.clone(),
                    rule: rule.into(),
                })
            };
            let actions: Vec<_> = grant.actions.split(',').map(str::trim).collect();
            if grant.resource.contains('*') || actions.contains(&"*") {
                add("wildcard-access")
            }
            if grant.scope == "public" && (actions.contains(&"write") || actions.contains(&"admin"))
            {
                add("public-write-or-admin")
            }
            if grant.scope != "internal" && grant.resource.starts_with("sensitive:") {
                add("sensitive-resource-shared-externally")
            }
            if actions.contains(&"admin") {
                add("administrative-access-review")
            }
        }
    }
    findings.sort_by(|a, b| {
        (&a.principal, &a.resource, &a.rule).cmp(&(&b.principal, &b.resource, &b.rule))
    });
    findings.dedup_by(|a, b| {
        a.principal == b.principal && a.resource == b.resource && a.rule == b.rule
    });
    Ok(findings)
}
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn html(findings: &[Finding]) -> String {
    let rows = findings
        .iter()
        .map(|f| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                escape(&f.principal),
                escape(&f.resource),
                escape(&f.rule)
            )
        })
        .collect::<String>();
    format!("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>KYBER Access Review</title><style>body{{font:16px system-ui;max-width:1050px;margin:40px auto;padding:20px;background:#f3f7fa;color:#203147}}td,th{{padding:12px;border-bottom:1px solid #ddd;text-align:left}}table{{background:white;width:100%;border-collapse:collapse}}</style><h1>Access Review</h1><p>Offline heuristic review. Findings require an owner decision; no permissions were changed.</p><table><tr><th>Principal</th><th>Resource</th><th>Review signal</th></tr>{rows}</table></html>")
}
fn run() -> Result<i32, String> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 && args.len() != 4 {
        return Err("Usage: access-review policy.tsv [--html report.html]".into());
    }
    let metadata = fs::metadata(&args[1]).map_err(|e| e.to_string())?;
    if metadata.len() > 2 * 1024 * 1024 {
        return Err("Input exceeds 2 MiB".into());
    }
    let text = fs::read_to_string(&args[1]).map_err(|e| e.to_string())?;
    let (grants, members) = parse(&text)?;
    let findings = analyze(&grants, &members)?;
    println!("principal\tresource\trule");
    for f in &findings {
        println!("{}\t{}\t{}", f.principal, f.resource, f.rule)
    }
    if args.len() == 4 {
        if args[2] != "--html" {
            return Err("Unknown option".into());
        }
        fs::write(&args[3], html(&findings)).map_err(|e| e.to_string())?
    }
    Ok(if findings.is_empty() { 0 } else { 1 })
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
    fn inherited_access() {
        let (g, m) =
            parse("grant\trole:ops\tsensitive:billing\tread\t external\n").unwrap_or_default();
        assert!(g.is_empty());
        assert!(m.is_empty());
        let (g, m) = parse(
            "member\tuser:demo\trole:ops\ngrant\trole:ops\tsensitive:billing\tread\texternal",
        )
        .unwrap();
        let f = analyze(&g, &m).unwrap();
        assert!(f.iter().any(
            |x| x.principal == "user:demo" && x.rule == "sensitive-resource-shared-externally"
        ));
    }
    #[test]
    fn cycles_and_rendering() {
        let (g, m) = parse("member\trole:a\trole:b\nmember\trole:b\trole:a").unwrap();
        assert!(analyze(&g, &m).is_err());
        assert!(!html(&[Finding {
            principal: "<script>".into(),
            resource: "demo".into(),
            rule: "review".into()
        }])
        .contains("<script>"));
    }
    #[test]
    fn public_write_and_wildcards() {
        let (g, m) = parse("grant\tuser:demo\t*\twrite\tpublic").unwrap();
        assert_eq!(analyze(&g, &m).unwrap().len(), 2);
    }
}
