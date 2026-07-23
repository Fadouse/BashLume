use std::cmp::Ordering;
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatchClass {
    Exact,
    Prefix,
    CaseInsensitivePrefix,
    Substring,
    Fuzzy,
}

impl MatchClass {
    fn candidate_set_tier(self) -> u8 {
        match self {
            // An exact command is not an unambiguous completion when longer
            // prefix matches also exist (`who` and `whoami`). Keep both in
            // the same result set while the score still sorts exact first.
            Self::Exact | Self::Prefix => 4,
            Self::CaseInsensitivePrefix => 3,
            Self::Substring => 2,
            Self::Fuzzy => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CandidateKind {
    Alias,
    Function,
    Builtin,
    Keyword,
    Command,
    Directory,
    Executable,
    File,
    Variable,
    User,
    Host,
}

impl CandidateKind {
    fn context_weight(self) -> i64 {
        match self {
            Self::Alias => 950,
            Self::Function => 925,
            Self::Builtin => 900,
            Self::Keyword => 875,
            Self::Command => 850,
            Self::Directory => 800,
            Self::Executable => 790,
            Self::File => 775,
            Self::Variable => 750,
            Self::User => 725,
            Self::Host => 700,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Candidate {
    /// Human-readable candidate without shell quoting.
    pub display: String,
    /// Text representing the complete shell word (or line for history).
    pub value: String,
    /// Optional human-readable detail supplied by a command-aware rule.
    pub description: Option<String>,
    pub kind: CandidateKind,
    pub append_space: bool,
    pub score: i64,
    pub match_class: MatchClass,
}

impl Candidate {
    pub fn new(
        query: &str,
        display: String,
        value: String,
        kind: CandidateKind,
        append_space: bool,
        recency_bonus: i64,
    ) -> Option<Self> {
        let (match_class, match_score) = match_score(query, &display)?;
        Some(Self::matched(
            display,
            value,
            kind,
            append_space,
            recency_bonus,
            match_class,
            match_score,
        ))
    }

    pub fn from_borrowed(
        query: &str,
        display: &str,
        value: &str,
        kind: CandidateKind,
        append_space: bool,
        recency_bonus: i64,
    ) -> Option<Self> {
        let (match_class, match_score) = match_score(query, display)?;
        Some(Self::matched(
            display.to_owned(),
            value.to_owned(),
            kind,
            append_space,
            recency_bonus,
            match_class,
            match_score,
        ))
    }

    fn matched(
        display: String,
        value: String,
        kind: CandidateKind,
        append_space: bool,
        recency_bonus: i64,
        match_class: MatchClass,
        match_score: i64,
    ) -> Self {
        Self {
            display,
            value,
            description: None,
            kind,
            append_space,
            score: match_score + kind.context_weight() + recency_bonus,
            match_class,
        }
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        let description = description.into();
        if !description.is_empty() {
            self.description = Some(description);
        }
        self
    }

    pub fn is_strong_prefix(&self) -> bool {
        matches!(self.match_class, MatchClass::Exact | MatchClass::Prefix)
    }
}

pub struct CandidateSink {
    limit: usize,
    best_tier: u8,
    candidates: HashMap<String, Candidate>,
}

impl CandidateSink {
    pub fn new(limit: usize) -> Self {
        Self {
            limit: limit.max(1),
            best_tier: 0,
            candidates: HashMap::with_capacity(limit.min(512)),
        }
    }

    pub fn push(&mut self, candidate: Candidate) {
        let tier = candidate.match_class.candidate_set_tier();
        if tier < self.best_tier {
            return;
        }
        if tier > self.best_tier {
            self.candidates.clear();
            self.best_tier = tier;
        }

        match self.candidates.get_mut(&candidate.value) {
            Some(current) if candidate.score > current.score => {
                let description = candidate
                    .description
                    .clone()
                    .or_else(|| current.description.clone());
                *current = Candidate {
                    description,
                    ..candidate
                };
            }
            Some(current) => {
                if current.description.is_none() {
                    current.description = candidate.description;
                }
                return;
            }
            None => {
                self.candidates.insert(candidate.value.clone(), candidate);
            }
        }

        if self.candidates.len() >= self.limit.saturating_mul(2) {
            self.truncate();
        }
    }

    pub fn finish(mut self) -> Vec<Candidate> {
        self.truncate();
        let mut values: Vec<_> = self.candidates.into_values().collect();
        values.sort_unstable_by(compare_candidates);
        values
    }

    fn truncate(&mut self) {
        if self.candidates.len() <= self.limit {
            return;
        }
        let mut ranked: Vec<_> = self
            .candidates
            .iter()
            .map(|(key, candidate)| (key.clone(), candidate.score, candidate.display.clone()))
            .collect();
        ranked.sort_unstable_by(|left, right| {
            right.1.cmp(&left.1).then_with(|| left.2.cmp(&right.2))
        });
        for (key, _, _) in ranked.into_iter().skip(self.limit) {
            self.candidates.remove(&key);
        }
    }
}

fn compare_candidates(left: &Candidate, right: &Candidate) -> Ordering {
    right
        .score
        .cmp(&left.score)
        .then_with(|| left.display.len().cmp(&right.display.len()))
        .then_with(|| left.display.cmp(&right.display))
}

pub fn match_score(query: &str, candidate: &str) -> Option<(MatchClass, i64)> {
    if query == candidate {
        return Some((MatchClass::Exact, 5_000_000));
    }
    if candidate.starts_with(query) {
        let length_penalty = candidate.len().saturating_sub(query.len()) as i64;
        return Some((MatchClass::Prefix, 4_000_000 - length_penalty));
    }
    if candidate
        .get(..query.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(query))
    {
        let length_penalty = candidate.len().saturating_sub(query.len()) as i64;
        return Some((
            MatchClass::CaseInsensitivePrefix,
            3_000_000 - length_penalty,
        ));
    }

    if query.is_ascii() && candidate.is_ascii() {
        let query_bytes = query.as_bytes();
        let candidate_bytes = candidate.as_bytes();
        if candidate_bytes.len() >= query_bytes.len()
            && candidate_bytes[..query_bytes.len()].eq_ignore_ascii_case(query_bytes)
        {
            let length_penalty = candidate.len().saturating_sub(query.len()) as i64;
            return Some((
                MatchClass::CaseInsensitivePrefix,
                3_000_000 - length_penalty,
            ));
        }
        if let Some(position) = candidate_bytes
            .windows(query_bytes.len())
            .position(|window| window.eq_ignore_ascii_case(query_bytes))
        {
            return Some((
                MatchClass::Substring,
                2_000_000 - (position as i64 * 32) - candidate.len() as i64,
            ));
        }
        return fuzzy_score_ascii(query_bytes, candidate_bytes)
            .map(|score| (MatchClass::Fuzzy, 1_000_000 + score));
    } else {
        let query_lower = query.to_lowercase();
        let candidate_lower = candidate.to_lowercase();
        if let Some(position) = candidate_lower.find(&query_lower) {
            return Some((
                MatchClass::Substring,
                2_000_000 - (position as i64 * 32) - candidate.len() as i64,
            ));
        }
    }

    fuzzy_score(query, candidate).map(|score| (MatchClass::Fuzzy, 1_000_000 + score))
}

fn fuzzy_score_ascii(query: &[u8], candidate: &[u8]) -> Option<i64> {
    let mut wanted = query.iter().map(u8::to_ascii_lowercase);
    let mut current = wanted.next()?;
    let mut matched = 0_i64;
    let mut gap_penalty = 0_i64;
    let mut consecutive = 0_i64;
    let mut previous_match = None;
    for (index, character) in candidate.iter().map(u8::to_ascii_lowercase).enumerate() {
        if character != current {
            continue;
        }
        matched += 1;
        if previous_match == Some(index.saturating_sub(1)) {
            consecutive += 1;
        } else if let Some(previous) = previous_match {
            gap_penalty += index.saturating_sub(previous + 1) as i64;
        } else {
            gap_penalty += index as i64;
        }
        previous_match = Some(index);
        match wanted.next() {
            Some(next) => current = next,
            None => {
                return Some(
                    matched * 100 + consecutive * 25 - gap_penalty * 10 - candidate.len() as i64,
                );
            }
        }
    }
    None
}

fn fuzzy_score(query: &str, candidate: &str) -> Option<i64> {
    if query.is_empty() {
        return Some(-(candidate.len() as i64));
    }

    let mut wanted = query.chars().flat_map(char::to_lowercase);
    let mut current = wanted.next()?;
    let mut matched = 0_i64;
    let mut gap_penalty = 0_i64;
    let mut consecutive = 0_i64;
    let mut previous_match = None;

    for (index, character) in candidate.chars().flat_map(char::to_lowercase).enumerate() {
        if character != current {
            continue;
        }

        matched += 1;
        if previous_match == Some(index.saturating_sub(1)) {
            consecutive += 1;
        } else if let Some(previous) = previous_match {
            gap_penalty += index.saturating_sub(previous + 1) as i64;
        } else {
            gap_penalty += index as i64;
        }
        previous_match = Some(index);

        match wanted.next() {
            Some(next) => current = next,
            None => {
                return Some(
                    matched * 100 + consecutive * 25
                        - gap_penalty * 10
                        - candidate.chars().count() as i64,
                );
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_layers_have_strict_priority() {
        let exact = match_score("git", "git").unwrap().1;
        let prefix = match_score("gi", "git").unwrap().1;
        let insensitive = match_score("GI", "git").unwrap().1;
        let substring = match_score("it", "git").unwrap().1;
        let fuzzy = match_score("gt", "git").unwrap().1;
        assert!(exact > prefix && prefix > insensitive && insensitive > substring);
        assert!(substring > fuzzy);
    }

    #[test]
    fn sink_keeps_exact_and_longer_prefixes_but_discards_weaker_matches() {
        let mut sink = CandidateSink::new(16);
        for name in ["whoami", "somewho", "who"] {
            sink.push(
                Candidate::from_borrowed("who", name, name, CandidateKind::Command, true, 0)
                    .unwrap(),
            );
        }
        let candidates = sink.finish();
        assert_eq!(
            candidates
                .iter()
                .map(|candidate| candidate.display.as_str())
                .collect::<Vec<_>>(),
            ["who", "whoami"]
        );
    }

    #[test]
    fn sink_merges_description_into_duplicate_candidate() {
        let mut sink = CandidateSink::new(4);
        let plain =
            Candidate::from_borrowed("fo", "for", "for", CandidateKind::Keyword, true, 0).unwrap();
        sink.push(plain);
        sink.push(
            Candidate::from_borrowed("fo", "for", "for", CandidateKind::Keyword, true, 0)
                .unwrap()
                .with_description("Iterate over words"),
        );
        let candidates = sink.finish();
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].description.as_deref(),
            Some("Iterate over words")
        );
    }

    #[test]
    fn sink_deduplicates_and_bounds_candidates() {
        let mut sink = CandidateSink::new(2);
        for name in ["alpha", "alpine", "alphabet", "alto"] {
            sink.push(
                Candidate::new(
                    "al",
                    name.into(),
                    name.into(),
                    CandidateKind::File,
                    false,
                    0,
                )
                .unwrap(),
            );
        }
        let values = sink.finish();
        assert_eq!(values.len(), 2);
        assert_eq!(values[0].display, "alto");
    }

    #[test]
    #[ignore = "development performance budget"]
    fn generic_ranking_stays_under_hot_path_budget() {
        let names = (0..5_000)
            .map(|index| format!("command-{index:04}"))
            .collect::<Vec<_>>();
        let mut samples = Vec::with_capacity(1_000);
        for _ in 0..1_000 {
            let started = std::time::Instant::now();
            let mut sink = CandidateSink::new(4_096);
            for name in &names {
                if let Some(candidate) =
                    Candidate::from_borrowed("cm42", name, name, CandidateKind::Command, true, 0)
                {
                    sink.push(candidate);
                }
            }
            std::hint::black_box(sink.finish());
            samples.push(started.elapsed());
        }
        samples.sort_unstable();
        let p99 = samples[samples.len() * 99 / 100];
        eprintln!("completion ranking p99: {p99:?} for {} names", names.len());
        if !cfg!(debug_assertions) {
            assert!(p99 < std::time::Duration::from_micros(500));
        }
    }
}
