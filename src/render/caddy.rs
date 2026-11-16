use anyhow::{Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use crate::state::State;
use crate::validate::{validate_happ_routing, validate_profile_title};

pub const DEFAULT_PROFILE_TITLE: &str = "Kinveil";

fn escape_re2(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if matches!(
            ch,
            '\\' | '.' | '+' | '*' | '?' | '(' | ')' | '|' | '[' | ']' | '{' | '}' | '^' | '$'
        ) {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

pub fn render_caddyfile(state: &State) -> Result<String> {
    let sub = &state.subscription;
    let sub_settings = &state.settings.subscription;
    if sub.domain.is_empty() || !sub.base_path.starts_with('/') || !sub.base_path.ends_with('/') {
        bail!("invalid subscription domain or base_path");
    }
    let escaped_prefix = escape_re2(sub.base_path.as_str());
    let title = sub_settings
        .profile_title
        .as_deref()
        .unwrap_or(DEFAULT_PROFILE_TITLE);
    validate_profile_title(title)?;
    let profile_title_b64 = STANDARD.encode(title.as_bytes());
    let routing_line = match &sub_settings.happ_routing {
        Some(routing) => {
            validate_happ_routing(routing)?;
            format!("\n            routing \"{routing}\"")
        }
        None => String::new(),
    };
    Ok(format!(
        r#"{{
    admin off
    servers {{
        protocols h1 h2
    }}
}}

{domain} {{
    log {{
        output discard
    }}

    @sub_path path_regexp sub ^{prefix}([A-Za-z0-9_-]+)$
    handle @sub_path {{
        root * /var/lib/kinveil/sub
        header {{
            Cache-Control "private, no-store"
            Vary "User-Agent"
            Profile-Title "base64:{profile_title_b64}"
            Profile-Update-Interval "{hours}"
            Content-Type "text/plain; charset=utf-8"{routing_line}
        }}
        @throne {{
            header_regexp User-Agent (?i)^throne/
        }}
        @throne_query {{
            query ssh=1
        }}
        handle @throne {{
            rewrite * /{{re.sub.1}}/throne
            file_server
        }}
        handle @throne_query {{
            rewrite * /{{re.sub.1}}/throne
            file_server
        }}
        rewrite * /{{re.sub.1}}/happ
        file_server
    }}

    handle {{
        respond 404
    }}
}}
"#,
        domain = sub.domain,
        prefix = escaped_prefix,
        profile_title_b64 = profile_title_b64,
        hours = sub_settings.update_interval_hours,
        routing_line = routing_line,
    ))
}
