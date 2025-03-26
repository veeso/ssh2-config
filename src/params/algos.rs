use std::fmt;
use std::str::FromStr;

use crate::SshParserError;

/// List of algorithms to be used.
/// The algorithms can be appended to the default set, placed at the head of the list,
/// excluded from the default set, or set as the default set.
///
/// # Configuring SSH Algorithms
///
/// In order to configure ssh you should use the `to_string()` method to get the string representation
/// with the correct format for ssh2.
///
/// # Algorithms vector
///
/// Otherwise you can access the inner [`Vec`] of algorithms with the [`Algorithms::algos`] method.
///
/// Beware though, that you must **TAKE CARE of the current variant**.
///
/// For instance in case the variant is [`Algorithms::Exclude`] the algos contained in the vec are the ones **to be excluded**.
///
/// While in case of [`Algorithms::Append`] the algos contained in the vec are the ones to be appended to the default ones.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub enum Algorithms {
    /// Append the given algorithms to the default set.
    Append(Vec<String>),
    /// Place the given algorithms at the head of the list.
    Head(Vec<String>),
    /// Exclude the given algorithms from the default set.
    Exclude(Vec<String>),
    /// Set the given algorithms as the default set.
    Set(Vec<String>),
    /// Mark as undefined; in case just use default
    #[default]
    Undefined,
}

#[derive(Debug, PartialEq, Eq)]
/// The type of algorithm operation.
enum AlgoType {
    Append,
    Head,
    Exclude,
    Set,
}

impl Algorithms {
    /// Returns the underlying algorithms as a vec of string.
    ///
    /// Beware that this method MAY not do what you expect.
    pub(crate) fn algos(&self) -> Vec<String> {
        match self {
            Self::Append(algos) => algos.iter().map(|s| s.to_string()).collect(),
            Self::Head(algos) => algos.iter().map(|s| s.to_string()).collect(),
            Self::Exclude(algos) => algos.iter().map(|s| s.to_string()).collect(),
            Self::Set(algos) => algos.iter().map(|s| s.to_string()).collect(),
            Self::Undefined => vec![],
        }
    }

    /// Check if the algorithms are defined.
    pub fn is_some(&self) -> bool {
        !matches!(self, Self::Undefined)
    }

    /// Merge the algorithms from `b` into `self`.
    pub fn merge(&mut self, b: &Self) {
        // If `self` is undefined, set it to `b`.
        if matches!(self, Self::Undefined) {
            *self = b.clone();
            return;
        }

        let current_algo_type = self.algo_type();

        let mut current_algos = self.algos();

        match b {
            Self::Append(_) => {
                // append but exclude duplicates
                for algo in b.algos() {
                    if !current_algos.iter().any(|s| s == &algo) {
                        current_algos.push(algo);
                    }
                }
            }
            Self::Head(_) => {
                current_algos = b.algos();
                current_algos.extend(self.algos());
            }
            Self::Exclude(_) if current_algo_type == AlgoType::Exclude => {
                // if both are exclude, merge them, exclude duplicates
                for algo in b.algos() {
                    if !current_algos.iter().any(|s| s == &algo) {
                        current_algos.push(algo);
                    }
                }
            }
            Self::Exclude(exclude) => {
                current_algos = current_algos
                    .iter()
                    .filter(|algo| !exclude.contains(algo))
                    .map(|s| s.to_string())
                    .collect();
            }
            Self::Set(_) if current_algos.is_empty() => {
                // set to b only if current algo is not set
                current_algos = b.algos();
            }
            Self::Undefined | Self::Set(_) => {} // ignore
        }

        match current_algo_type {
            AlgoType::Append => *self = Self::Append(current_algos),
            AlgoType::Head => *self = Self::Head(current_algos),
            AlgoType::Exclude => *self = Self::Exclude(current_algos),
            AlgoType::Set => *self = Self::Set(current_algos),
        }
    }

    fn algo_type(&self) -> AlgoType {
        match self {
            Self::Append(_) => AlgoType::Append,
            Self::Head(_) => AlgoType::Head,
            Self::Exclude(_) => AlgoType::Exclude,
            Self::Set(_) => AlgoType::Set,
            Self::Undefined => AlgoType::Set,
        }
    }
}

impl FromStr for Algorithms {
    type Err = SshParserError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Ok(Self::Undefined);
        }

        // get first char
        let (op, start) = match s.chars().next().expect("can't be empty") {
            '+' => (AlgoType::Append, 1),
            '^' => (AlgoType::Head, 1),
            '-' => (AlgoType::Exclude, 1),
            _ => (AlgoType::Set, 0),
        };

        let algos = s[start..]
            .split(',')
            .map(|s| s.trim().to_string())
            .collect::<Vec<String>>();

        match op {
            AlgoType::Append => Ok(Self::Append(algos)),
            AlgoType::Head => Ok(Self::Head(algos)),
            AlgoType::Exclude => Ok(Self::Exclude(algos)),
            AlgoType::Set => Ok(Self::Set(algos)),
        }
    }
}

impl fmt::Display for Algorithms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Self::Append(_) => write!(f, "+"),
            Self::Head(_) => write!(f, "^"),
            Self::Exclude(_) => write!(f, "-"),
            Self::Set(_) => write!(f, ""),
            Self::Undefined => write!(f, ""),
        }?;

        let algos = self.algos().join(",");
        write!(f, "{}", algos)
    }
}

#[cfg(test)]
mod test {

    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn test_should_parse_algos_set() {
        let algo =
            Algorithms::from_str("aes128-ctr,aes192-ctr,aes256-ctr").expect("failed to parse");
        assert_eq!(
            algo,
            Algorithms::Set(vec![
                "aes128-ctr".to_string(),
                "aes192-ctr".to_string(),
                "aes256-ctr".to_string()
            ])
        );
    }

    #[test]
    fn test_should_parse_algos_append() {
        let algo =
            Algorithms::from_str("+aes128-ctr,aes192-ctr,aes256-ctr").expect("failed to parse");
        assert_eq!(
            algo,
            Algorithms::Append(vec![
                "aes128-ctr".to_string(),
                "aes192-ctr".to_string(),
                "aes256-ctr".to_string()
            ])
        );
    }

    #[test]
    fn test_should_parse_algos_head() {
        let algo =
            Algorithms::from_str("^aes128-ctr,aes192-ctr,aes256-ctr").expect("failed to parse");
        assert_eq!(
            algo,
            Algorithms::Head(vec![
                "aes128-ctr".to_string(),
                "aes192-ctr".to_string(),
                "aes256-ctr".to_string()
            ])
        );
    }

    #[test]
    fn test_should_parse_algos_exclude() {
        let algo =
            Algorithms::from_str("-aes128-ctr,aes192-ctr,aes256-ctr").expect("failed to parse");
        assert_eq!(
            algo,
            Algorithms::Exclude(vec![
                "aes128-ctr".to_string(),
                "aes192-ctr".to_string(),
                "aes256-ctr".to_string()
            ])
        );
    }

    #[test]
    fn test_should_merge_append() {
        let mut algo1 = Algorithms::from_str("aes128-ctr,aes192-ctr").expect("failed to parse");
        let algo2 = Algorithms::from_str("+aes256-ctr").expect("failed to parse");
        algo1.merge(&algo2);
        assert_eq!(
            algo1,
            Algorithms::Set(vec![
                "aes128-ctr".to_string(),
                "aes192-ctr".to_string(),
                "aes256-ctr".to_string()
            ])
        );
    }

    #[test]
    fn test_should_merge_append_if_undefined() {
        let mut algo1 = Algorithms::Undefined;
        let algo2 = Algorithms::from_str("+aes256-ctr").expect("failed to parse");
        algo1.merge(&algo2);
        assert_eq!(algo1, Algorithms::Append(vec!["aes256-ctr".to_string()]));
    }

    #[test]
    fn test_should_merge_two_appends() {
        let mut algo1 = Algorithms::from_str("+aes128-ctr,aes192-ctr").expect("failed to parse");
        let algo2 = Algorithms::from_str("+aes256-ctr").expect("failed to parse");
        algo1.merge(&algo2);
        assert_eq!(
            algo1,
            Algorithms::Append(vec![
                "aes128-ctr".to_string(),
                "aes192-ctr".to_string(),
                "aes256-ctr".to_string()
            ])
        );
    }

    #[test]
    fn test_should_merge_head() {
        let mut algo1 = Algorithms::from_str("aes128-ctr,aes192-ctr").expect("failed to parse");
        let algo2 = Algorithms::from_str("^aes256-ctr").expect("failed to parse");
        algo1.merge(&algo2);
        assert_eq!(
            algo1,
            Algorithms::Set(vec![
                "aes256-ctr".to_string(),
                "aes128-ctr".to_string(),
                "aes192-ctr".to_string()
            ])
        );
    }

    #[test]
    fn test_should_merge_head_if_undefined() {
        let mut algo1 = Algorithms::Undefined;
        let algo2 = Algorithms::from_str("^aes256-ctr").expect("failed to parse");
        algo1.merge(&algo2);
        assert_eq!(algo1, Algorithms::Head(vec!["aes256-ctr".to_string()]));
    }

    #[test]
    fn test_should_merge_two_heads() {
        let mut algo1 = Algorithms::from_str("^aes128-ctr,aes192-ctr").expect("failed to parse");
        let algo2 = Algorithms::from_str("^aes256-ctr").expect("failed to parse");
        algo1.merge(&algo2);
        assert_eq!(
            algo1,
            Algorithms::Head(vec![
                "aes256-ctr".to_string(),
                "aes128-ctr".to_string(),
                "aes192-ctr".to_string()
            ])
        );
    }

    #[test]
    fn test_should_merge_exclude() {
        let mut algo1 =
            Algorithms::from_str("aes128-ctr,aes192-ctr,aes256-ctr").expect("failed to parse");
        let algo2 = Algorithms::from_str("-aes192-ctr").expect("failed to parse");
        algo1.merge(&algo2);
        assert_eq!(
            algo1,
            Algorithms::Set(vec!["aes128-ctr".to_string(), "aes256-ctr".to_string()])
        );
    }

    #[test]
    fn test_should_merge_exclude_if_undefined() {
        let mut algo1 = Algorithms::Undefined;
        let algo2 = Algorithms::from_str("-aes192-ctr").expect("failed to parse");
        algo1.merge(&algo2);
        assert_eq!(algo1, Algorithms::Exclude(vec!["aes192-ctr".to_string()]));
    }

    #[test]
    fn test_should_merge_two_excludes() {
        let mut algo1 =
            Algorithms::from_str("-aes128-ctr,aes192-ctr,aes256-ctr").expect("failed to parse");
        let algo2 = Algorithms::from_str("-aes192-ctr").expect("failed to parse");
        algo1.merge(&algo2);
        assert_eq!(
            algo1,
            Algorithms::Exclude(vec![
                "aes128-ctr".to_string(),
                "aes192-ctr".to_string(),
                "aes256-ctr".to_string()
            ])
        );
    }

    #[test]
    fn test_should_merge_set() {
        let mut algo1 = Algorithms::from_str("aes128-ctr,aes192-ctr").expect("failed to parse");
        let algo2 = Algorithms::from_str("aes256-ctr").expect("failed to parse");
        algo1.merge(&algo2);
        assert_eq!(
            algo1,
            Algorithms::Set(vec!["aes128-ctr".to_string(), "aes192-ctr".to_string()])
        );
    }

    #[test]
    fn test_should_merge_set_if_undefined() {
        let mut algo1 = Algorithms::Undefined;
        let algo2 = Algorithms::from_str("aes256-ctr").expect("failed to parse");
        algo1.merge(&algo2);
        assert_eq!(algo1, Algorithms::Set(vec!["aes256-ctr".to_string()]));
    }
}
