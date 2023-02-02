//! # host
//!
//! Ssh host type

use std::cmp::Ordering;

/**
 * MIT License
 *
 * ssh2-config - Copyright (c) 2021 Christian Visintin
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
use super::HostParams;

use wildmatch::WildMatch;

/// Describes the rules to be used for a certain host
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    /// List of hosts for which params are valid. String is string pattern, bool is whether condition is negated
    pub pattern: Vec<HostClause>,
    pub params: HostParams,
}

impl Host {
    pub fn new(pattern: Vec<HostClause>, params: HostParams) -> Self {
        Self { pattern, params }
    }

    /// Returns whether `host` argument intersects the host clauses
    pub fn intersects(&self, host: &str) -> bool {
        let mut has_matched = false;
        for entry in self.pattern.iter() {
            let matches = entry.intersects(host);
            // If the entry is negated and it matches we can stop searching
            if matches && entry.negated {
                return false;
            }
            has_matched |= matches;
        }
        has_matched
    }

    pub(crate) fn cmp(&self, other: &Self) -> Ordering {
        let self_max_pattern = self.pattern.iter().max_by(|x, y| x.cmp(y));
        let other_max_pattern = other.pattern.iter().max_by(|x, y| x.cmp(y));
        match (self_max_pattern, other_max_pattern) {
            (Some(_self), Some(other)) => _self.cmp(other),
            _ => Ordering::Equal,
        }
    }
}

/// Describes a single clause to match host
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostClause {
    pub pattern: String,
    pub negated: bool,
}

impl HostClause {
    /// Creates a new `HostClause` from arguments
    pub fn new(pattern: String, negated: bool) -> Self {
        Self { pattern, negated }
    }

    /// Returns whether `host` argument intersects the clause
    pub fn intersects(&self, host: &str) -> bool {
        WildMatch::new(self.pattern.as_str()).matches(host)
    }

    fn cmp(&self, b: &Self) -> Ordering {
        self.pattern.cmp(&b.pattern)
    }
}

#[cfg(test)]
mod test {

    use super::*;

    use pretty_assertions::assert_eq;

    #[test]
    fn should_build_host_clause() {
        let clause = HostClause::new("192.168.1.1".to_string(), false);
        assert_eq!(clause.pattern.as_str(), "192.168.1.1");
        assert_eq!(clause.negated, false);
    }

    #[test]
    fn should_intersect_host_clause() {
        let clause = HostClause::new("192.168.*.*".to_string(), false);
        assert!(clause.intersects("192.168.2.30"));
        let clause = HostClause::new("192.168.?0.*".to_string(), false);
        assert!(clause.intersects("192.168.40.28"));
    }

    #[test]
    fn should_not_intersect_host_clause() {
        let clause = HostClause::new("192.168.*.*".to_string(), false);
        assert_eq!(clause.intersects("172.26.104.4"), false);
    }

    #[test]
    fn should_init_host() {
        let host = Host::new(
            vec![HostClause::new("192.168.*.*".to_string(), false)],
            HostParams::default(),
        );
        assert_eq!(host.pattern.len(), 1);
    }

    #[test]
    fn should_intersect_clause() {
        let host = Host::new(
            vec![
                HostClause::new("192.168.*.*".to_string(), false),
                HostClause::new("172.26.*.*".to_string(), false),
                HostClause::new("10.8.*.*".to_string(), false),
                HostClause::new("10.8.0.8".to_string(), true),
            ],
            HostParams::default(),
        );
        assert!(host.intersects("192.168.1.32"));
        assert!(host.intersects("172.26.104.4"));
        assert!(host.intersects("10.8.0.10"));
    }

    #[test]
    fn should_not_intersect_clause() {
        let host = Host::new(
            vec![
                HostClause::new("192.168.*.*".to_string(), false),
                HostClause::new("172.26.*.*".to_string(), false),
                HostClause::new("10.8.*.*".to_string(), false),
                HostClause::new("10.8.0.8".to_string(), true),
            ],
            HostParams::default(),
        );
        assert_eq!(host.intersects("192.169.1.32"), false);
        assert_eq!(host.intersects("172.28.104.4"), false);
        assert_eq!(host.intersects("10.9.0.8"), false);
        assert_eq!(host.intersects("10.8.0.8"), false);
    }
}
