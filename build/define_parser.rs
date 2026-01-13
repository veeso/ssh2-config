use std::collections::HashMap;
use std::io::BufRead;

struct Scope {
    name: String,
    tokens: Vec<String>,
}

pub fn parse_defines(reader: impl BufRead) -> anyhow::Result<HashMap<String, String>> {
    let mut defines = HashMap::new();

    // iterate over each line in the reader
    let mut scope: Option<Scope> = None;

    for line in reader.lines() {
        let line = line?;
        // check if the line is a `define`
        if line.trim().starts_with("#define") {
            if let Some(prev_scope) = scope.take() {
                // if we have a previous scope, store it
                defines.insert(prev_scope.name, prev_scope.tokens.join(" "));
            }
            // start a new scope
            let mut tokens = line.split_whitespace();
            let name = tokens
                .nth(1)
                .ok_or_else(|| anyhow::anyhow!("Expected a name after #define"))?
                .to_string();

            let mut tokens = tokens.collect::<Vec<_>>();
            let mut single_line = true;

            // if last token is a \; remove it
            if let Some(last) = tokens.last()
                && *last == "\\"
            {
                tokens.pop();
                single_line = false;
            }

            // get tokens after the name
            let mut parsed_tokens: Vec<String> = vec![];
            for token in tokens {
                let parsed = parse_token(&defines, token, false)?;
                parsed_tokens.extend(parsed);
            }

            scope = Some(Scope {
                name,
                tokens: parsed_tokens,
            });

            // if is single line, push to defines and set scope to None
            if single_line && let Some(scope) = scope.take() {
                defines.insert(scope.name, scope.tokens.join(" "));
            }
        } else {
            // if we are in a scope, add the line to the tokens
            let Some(inner_scope) = scope.as_mut() else {
                continue;
            };

            let tokens = line.split_whitespace();
            let mut tokens: Vec<String> = tokens.map(|s| s.to_string()).collect();

            // check if it ends with a \, if so, remove it
            let mut last_line = true;
            if let Some(last) = tokens.last()
                && last == "\\"
            {
                tokens.pop();
                last_line = false;
            }

            // parse tokens
            for token in tokens {
                let parsed = parse_token(&defines, &token, false)?;
                inner_scope.tokens.extend(parsed);
            }

            // if last line, push to defines and set scope to None
            if last_line && let Some(scope) = scope.take() {
                defines.insert(scope.name, scope.tokens.join(" "));
            }
        }
    }

    // put last scope
    if let Some(scope) = scope {
        defines.insert(scope.name, scope.tokens.join(" "));
    }

    Ok(defines)
}

/// Parse token
fn parse_token(
    defines: &HashMap<String, String>,
    token: &str,
    nested: bool,
) -> anyhow::Result<Vec<String>> {
    let token = token.trim().trim_end_matches(',');

    // if token is a define, parse it
    if let Some(value) = defines.get(token) {
        return parse_token(defines, value, true);
    }

    // otherwise, check if it is a string
    if token.starts_with('"') && token.ends_with('"') {
        return Ok(vec![
            token[1..token.len() - 1].trim_end_matches(',').to_string(),
        ]);
    }

    // check if it is a number
    if token.parse::<i64>().is_ok() {
        return Ok(vec![token.to_string()]);
    }

    if nested {
        return Ok(vec![token.to_string()]);
    }

    anyhow::bail!("Unknown token: {token}; defines: {defines:#?}",)
}
