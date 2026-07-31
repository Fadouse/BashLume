use std::borrow::Borrow;
use std::cmp::Ordering;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

const MAX_CANDIDATE_TEXT_BYTES: usize = 64 * 1024;
const MAX_ASCII_SUBSTRING_COMPARISONS: usize = 64 * 1024;

fn candidate_text_size_is_safe(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_CANDIDATE_TEXT_BYTES
}

fn candidate_text_has_control(value: &str) -> bool {
    value.bytes().any(|byte| byte.is_ascii_control())
        || !value.is_ascii() && value.chars().any(char::is_control)
}

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

    fn sort_tier(self) -> u8 {
        match self {
            Self::Exact => 5,
            Self::Prefix => 4,
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
    Option,
    Subcommand,
    Value,
    Directory,
    Executable,
    File,
    Variable,
    User,
    Group,
    Host,
    Service,
    Signal,
    Job,
}

impl CandidateKind {
    fn context_weight(self) -> i64 {
        match self {
            Self::Alias => 950,
            Self::Function => 925,
            Self::Builtin => 900,
            Self::Keyword => 875,
            Self::Command => 850,
            Self::Option => 840,
            Self::Subcommand => 835,
            Self::Value => 825,
            Self::Directory => 800,
            Self::Executable => 790,
            Self::File => 775,
            Self::Variable => 750,
            Self::User => 725,
            Self::Group => 720,
            Self::Host => 700,
            Self::Service => 690,
            Self::Signal => 680,
            Self::Job => 670,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Candidate {
    /// Human-readable candidate without shell quoting.
    pub display: Arc<str>,
    /// Text representing the complete shell word (or line for history).
    pub value: Arc<str>,
    /// Optional human-readable detail supplied by a command-aware rule.
    pub description: Option<String>,
    /// Bitset of contributing external rule sources (bash, fish, zsh, user).
    pub source_mask: u8,
    pub kind: CandidateKind,
    pub append_space: bool,
    pub score: i64,
    pub match_class: MatchClass,
    pub preserve_order: bool,
    pub(crate) insertion_order: u64,
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
        if !candidate_text_size_is_safe(&display) || !candidate_text_size_is_safe(&value) {
            return None;
        }
        let same_text = display == value;
        let (match_class, match_score) = match_score(query, &display)?;
        if candidate_text_has_control(&display) || !same_text && candidate_text_has_control(&value)
        {
            return None;
        }
        let display = Arc::<str>::from(display);
        let value = if same_text {
            Arc::clone(&display)
        } else {
            Arc::<str>::from(value)
        };
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
        if !candidate_text_size_is_safe(display) || !candidate_text_size_is_safe(value) {
            return None;
        }
        let same_text =
            std::ptr::eq(display.as_ptr(), value.as_ptr()) && display.len() == value.len();
        let (match_class, match_score) = match_score(query, display)?;
        if candidate_text_has_control(display) || !same_text && candidate_text_has_control(value) {
            return None;
        }
        let display = Arc::<str>::from(display);
        let value = if same_text {
            Arc::clone(&display)
        } else {
            Arc::<str>::from(value)
        };
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

    fn matched(
        display: Arc<str>,
        value: Arc<str>,
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
            source_mask: 0,
            kind,
            append_space,
            score: match_score + kind.context_weight() + recency_bonus,
            match_class,
            preserve_order: false,
            insertion_order: u64::MAX,
        }
    }

    pub fn with_source_mask(mut self, source_mask: u8) -> Self {
        self.source_mask = source_mask;
        self
    }

    pub fn with_preserve_order(mut self, preserve_order: bool) -> Self {
        self.preserve_order = preserve_order;
        self
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        let description = description
            .into()
            .chars()
            .map(|character| {
                if character.is_control() {
                    ' '
                } else {
                    character
                }
            })
            .collect::<String>();
        let end = description
            .char_indices()
            .map(|(index, _)| index)
            .take_while(|index| *index <= MAX_CANDIDATE_TEXT_BYTES)
            .last()
            .unwrap_or(0);
        let description = if description.len() > MAX_CANDIDATE_TEXT_BYTES {
            description[..end].trim_end().to_owned()
        } else {
            description
        };
        if !description.is_empty() {
            self.description = Some(description);
        }
        self
    }

    pub fn is_strong_prefix(&self) -> bool {
        matches!(self.match_class, MatchClass::Exact | MatchClass::Prefix)
    }
}

struct CandidateEntry(Candidate);

impl Borrow<str> for CandidateEntry {
    fn borrow(&self) -> &str {
        &self.0.value
    }
}

impl PartialEq for CandidateEntry {
    fn eq(&self, other: &Self) -> bool {
        self.0.value == other.0.value
    }
}

impl Eq for CandidateEntry {}

impl Hash for CandidateEntry {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.value.hash(state);
    }
}

pub struct CandidateSink {
    limit: usize,
    best_tier: u8,
    candidates: HashSet<CandidateEntry>,
    next_insertion_order: u64,
}

impl CandidateSink {
    pub fn new(limit: usize) -> Self {
        Self {
            limit: limit.max(1),
            best_tier: 0,
            candidates: HashSet::with_capacity(limit.min(512)),
            next_insertion_order: 0,
        }
    }

    pub fn remaining_capacity_hint(&self) -> usize {
        self.limit.saturating_sub(self.candidates.len()).max(1)
    }

    pub fn push(&mut self, mut candidate: Candidate) {
        if candidate.preserve_order {
            candidate.insertion_order = self.next_insertion_order;
            self.next_insertion_order = self.next_insertion_order.saturating_add(1);
        }
        let tier = candidate.match_class.candidate_set_tier();
        if tier < self.best_tier {
            return;
        }
        if tier > self.best_tier {
            self.candidates.clear();
            self.best_tier = tier;
        }

        match self.candidates.take(candidate.value.as_ref()) {
            Some(CandidateEntry(current)) if candidate.score > current.score => {
                let description = candidate
                    .description
                    .clone()
                    .or_else(|| current.description.clone());
                let new_source = candidate.source_mask & !current.source_mask != 0;
                let score = candidate
                    .score
                    .saturating_add(i64::from(new_source && current.source_mask != 0) * 8);
                let source_mask = current.source_mask | candidate.source_mask;
                let append_space = current.append_space && candidate.append_space;
                let preserve_order = current.preserve_order || candidate.preserve_order;
                let insertion_order = current.insertion_order.min(candidate.insertion_order);
                self.candidates.insert(CandidateEntry(Candidate {
                    description,
                    source_mask,
                    append_space,
                    score,
                    preserve_order,
                    insertion_order,
                    ..candidate
                }));
            }
            Some(CandidateEntry(mut current)) => {
                if current.description.is_none() {
                    current.description = candidate.description;
                }
                let new_source = candidate.source_mask & !current.source_mask != 0;
                if new_source && current.source_mask != 0 {
                    current.score = current.score.saturating_add(8);
                }
                current.source_mask |= candidate.source_mask;
                current.append_space &= candidate.append_space;
                current.preserve_order |= candidate.preserve_order;
                current.insertion_order = current.insertion_order.min(candidate.insertion_order);
                self.candidates.insert(CandidateEntry(current));
                return;
            }
            None => {
                self.candidates.insert(CandidateEntry(candidate));
            }
        }

        if self.candidates.len() >= self.limit.saturating_mul(2) {
            self.truncate();
        }
    }

    pub fn finish(mut self) -> Vec<Candidate> {
        self.truncate();
        let mut values = self
            .candidates
            .into_iter()
            .map(|entry| entry.0)
            .collect::<Vec<_>>();
        let uniform_unpreserved_class =
            values
                .first()
                .map(|first| first.match_class)
                .filter(|match_class| {
                    values.iter().all(|candidate| {
                        !candidate.preserve_order && candidate.match_class == *match_class
                    })
                });
        if uniform_unpreserved_class.is_some() {
            values.sort_unstable_by(compare_ranked_candidates);
        } else {
            values.sort_unstable_by(compare_candidates);
        }
        values
    }

    fn truncate(&mut self) {
        if self.candidates.len() <= self.limit {
            return;
        }
        let mut ranked = self.candidates.iter().collect::<Vec<_>>();
        ranked.sort_unstable_by(|left, right| compare_candidates(&left.0, &right.0));
        let remove = ranked
            .into_iter()
            .skip(self.limit)
            .map(|entry| entry.0.value.clone())
            .collect::<Vec<_>>();
        for key in remove {
            self.candidates.remove(key.as_ref());
        }
    }
}

fn compare_candidates(left: &Candidate, right: &Candidate) -> Ordering {
    right
        .match_class
        .sort_tier()
        .cmp(&left.match_class.sort_tier())
        .then_with(|| match (left.preserve_order, right.preserve_order) {
            (true, true) => left.insertion_order.cmp(&right.insertion_order),
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => compare_ranked_candidates(left, right),
        })
}

fn compare_ranked_candidates(left: &Candidate, right: &Candidate) -> Ordering {
    right
        .score
        .cmp(&left.score)
        .then_with(|| left.display.len().cmp(&right.display.len()))
        .then_with(|| left.display.cmp(&right.display))
        .then_with(|| left.value.cmp(&right.value))
}

pub fn match_score(query: &str, candidate: &str) -> Option<(MatchClass, i64)> {
    if query.is_ascii() {
        let query_bytes = query.as_bytes();
        let candidate_bytes = candidate.as_bytes();
        if let Some(prefix) = candidate_bytes.get(..query_bytes.len()) {
            if prefix.eq_ignore_ascii_case(query_bytes) {
                let length_penalty = candidate.len().saturating_sub(query.len()) as i64;
                return if prefix == query_bytes {
                    if candidate.len() == query.len() {
                        Some((MatchClass::Exact, 5_000_000))
                    } else {
                        Some((MatchClass::Prefix, 4_000_000 - length_penalty))
                    }
                } else {
                    Some((
                        MatchClass::CaseInsensitivePrefix,
                        3_000_000 - length_penalty,
                    ))
                };
            }
        }
        let (candidate_is_ascii, score) =
            match_ascii_substring_and_fuzzy(query_bytes, candidate_bytes);
        if candidate_is_ascii {
            return score;
        }
    } else {
        if candidate.starts_with(query) {
            if candidate.len() == query.len() {
                return Some((MatchClass::Exact, 5_000_000));
            }
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
    }

    let query_lower = query.to_lowercase();
    let candidate_lower = candidate.to_lowercase();
    if let Some(position) = candidate_lower.find(&query_lower) {
        return Some((
            MatchClass::Substring,
            2_000_000 - (position as i64 * 32) - candidate.len() as i64,
        ));
    }
    fuzzy_score(query, candidate).map(|score| (MatchClass::Fuzzy, 1_000_000 + score))
}

fn match_ascii_substring_and_fuzzy(
    query: &[u8],
    candidate: &[u8],
) -> (bool, Option<(MatchClass, i64)>) {
    let Some((&first, _)) = query.split_first() else {
        return (candidate.is_ascii(), None);
    };
    let first = first.to_ascii_lowercase();
    if !candidate.is_ascii() {
        return (false, None);
    }
    if query.len() >= 3 {
        let last = query[query.len() - 1].to_ascii_lowercase();
        let contains_last = if last.is_ascii_alphabetic() {
            candidate
                .iter()
                .any(|character| character.to_ascii_lowercase() == last)
        } else {
            candidate.contains(&last)
        };
        if !contains_last {
            return (true, None);
        }
    }
    let mut substring_position = None;
    let mut substring_work_remaining = MAX_ASCII_SUBSTRING_COMPARISONS;
    let mut substring_search_deferred = false;
    let mut query_index = 1_usize;
    let mut current = first;
    let mut matched = 0_i64;
    let mut gap_penalty = 0_i64;
    let mut consecutive = 0_i64;
    let mut previous_match = None;
    let mut fuzzy = None;

    for (index, &character) in candidate.iter().enumerate() {
        let folded = character.to_ascii_lowercase();
        // Position zero was already rejected by the prefix comparison in
        // `match_score`; do not compare the same window a second time.
        if index != 0
            && substring_position.is_none()
            && !substring_search_deferred
            && folded == first
        {
            if query.len() > substring_work_remaining {
                substring_search_deferred = true;
            } else {
                substring_work_remaining -= query.len();
                if candidate
                    .get(index..index.saturating_add(query.len()))
                    .is_some_and(|window| window.eq_ignore_ascii_case(query))
                {
                    substring_position = Some(index);
                }
            }
        }
        if fuzzy.is_some() || folded != current {
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
        if query_index == query.len() {
            fuzzy =
                Some(matched * 100 + consecutive * 25 - gap_penalty * 10 - candidate.len() as i64);
        } else {
            current = query[query_index].to_ascii_lowercase();
            query_index += 1;
        }
    }

    if substring_position.is_none() && substring_search_deferred {
        // The short-query path above avoids allocations for command names. For
        // adversarial long repeated prefixes, defer to str's bounded two-way
        // search after folding the already-proven ASCII inputs once.
        let query_lower = std::str::from_utf8(query)
            .expect("ASCII query bytes are valid UTF-8")
            .to_ascii_lowercase();
        let candidate_lower = std::str::from_utf8(candidate)
            .expect("ASCII candidate bytes are valid UTF-8")
            .to_ascii_lowercase();
        substring_position = candidate_lower.find(&query_lower);
    }
    if let Some(position) = substring_position {
        return (
            true,
            Some((
                MatchClass::Substring,
                2_000_000 - (position as i64 * 32) - candidate.len() as i64,
            )),
        );
    }
    (
        true,
        fuzzy.map(|score| (MatchClass::Fuzzy, 1_000_000 + score)),
    )
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
    fn empty_and_unicode_queries_preserve_exact_and_prefix_classes() {
        assert_eq!(match_score("", ""), Some((MatchClass::Exact, 5_000_000)));
        assert_eq!(
            match_score("", "é"),
            Some((MatchClass::Prefix, 4_000_000 - "é".len() as i64))
        );
        assert_eq!(match_score("é", "é"), Some((MatchClass::Exact, 5_000_000)));
        assert_eq!(
            match_score("é", "éclair"),
            Some((MatchClass::Prefix, 4_000_000 - "clair".len() as i64))
        );
    }

    #[test]
    fn ascii_queries_preserve_unicode_fallback_scoring() {
        assert_eq!(
            match_score("k", "Kelvin"),
            Some((MatchClass::Substring, 2_000_000 - "Kelvin".len() as i64))
        );
        assert_eq!(
            match_score("ab", "éa-b"),
            Some((MatchClass::Fuzzy, 1_000_176))
        );
    }

    #[test]
    fn repeated_ascii_prefixes_use_the_bounded_substring_path() {
        let query = format!("{}b", "a".repeat(1023));
        let candidate = "a".repeat(MAX_CANDIDATE_TEXT_BYTES);
        assert_eq!(match_score(&query, &candidate), None);
    }

    #[test]
    fn ascii_fuzzy_prefilter_preserves_case_insensitive_tail_matches() {
        assert_eq!(
            match_score("cmZ", "Command-00z"),
            Some((MatchClass::Fuzzy, 1_000_209))
        );
        assert_eq!(match_score("cm2", "command-0001"), None);
    }

    #[test]
    fn identical_candidate_text_shares_immutable_storage() {
        let text = "shared";
        let borrowed =
            Candidate::from_borrowed("", text, text, CandidateKind::Value, true, 0).unwrap();
        assert!(Arc::ptr_eq(&borrowed.display, &borrowed.value));

        let owned = Candidate::new(
            "",
            text.to_owned(),
            text.to_owned(),
            CandidateKind::Value,
            true,
            0,
        )
        .unwrap();
        assert!(Arc::ptr_eq(&owned.display, &owned.value));
    }

    #[test]
    fn candidates_reject_control_characters_before_matching_or_insertion() {
        assert!(
            Candidate::from_borrowed("", "unsafe\nrow", "unsafe", CandidateKind::Value, true, 0)
                .is_none()
        );
        assert!(
            Candidate::from_borrowed("", "safe", "unsafe\u{1b}", CandidateKind::Value, true, 0)
                .is_none()
        );
        let candidate = Candidate::from_borrowed("", "safe", "safe", CandidateKind::Value, true, 0)
            .unwrap()
            .with_description("line\nterminal\u{1b}");
        assert_eq!(candidate.description.as_deref(), Some("line terminal "));
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
                .map(|candidate| candidate.display.as_ref())
                .collect::<Vec<_>>(),
            ["who", "whoami"]
        );
    }

    #[test]
    fn sink_merges_description_into_duplicate_candidate() {
        let mut sink = CandidateSink::new(4);
        let plain = Candidate::from_borrowed("fo", "for", "for", CandidateKind::Keyword, true, 0)
            .unwrap()
            .with_source_mask(1);
        sink.push(plain);
        sink.push(
            Candidate::from_borrowed("fo", "for", "for", CandidateKind::Keyword, true, 0)
                .unwrap()
                .with_source_mask(2)
                .with_description("Iterate over words"),
        );
        let candidates = sink.finish();
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].description.as_deref(),
            Some("Iterate over words")
        );
        assert_eq!(candidates[0].source_mask, 3);
        assert_eq!(candidates[0].score, 4_000_882);
    }

    #[test]
    fn sink_honors_explicit_order_for_equally_ranked_candidates() {
        let mut preserved = CandidateSink::new(4);
        for name in ["alpha", "zz"] {
            preserved.push(
                Candidate::from_borrowed("", name, name, CandidateKind::Value, true, 0)
                    .unwrap()
                    .with_preserve_order(true),
            );
        }
        assert_eq!(preserved.finish()[0].display.as_ref(), "alpha");

        let mut ranked = CandidateSink::new(4);
        for name in ["alpha", "zz"] {
            ranked.push(
                Candidate::from_borrowed("", name, name, CandidateKind::Value, true, 0).unwrap(),
            );
        }
        assert_eq!(ranked.finish()[0].display.as_ref(), "zz");
    }

    #[test]
    fn sink_breaks_display_ties_by_insertion_value() {
        let mut sink = CandidateSink::new(1);
        for value in ["beta", "alpha"] {
            sink.push(
                Candidate::new(
                    "",
                    "same".into(),
                    value.into(),
                    CandidateKind::Value,
                    true,
                    0,
                )
                .unwrap(),
            );
        }
        assert_eq!(sink.finish()[0].value.as_ref(), "alpha");
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
        assert_eq!(values[0].display.as_ref(), "alto");
    }

    fn thread_cpu_time() -> std::time::Duration {
        let mut value = std::mem::MaybeUninit::<libc::timespec>::uninit();
        // SAFETY: CLOCK_THREAD_CPUTIME_ID writes one initialized timespec and
        // is available on every supported Linux target.
        let result =
            unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, value.as_mut_ptr()) };
        assert_eq!(result, 0);
        // SAFETY: a zero return from clock_gettime initialized the value.
        let value = unsafe { value.assume_init() };
        std::time::Duration::new(value.tv_sec as u64, value.tv_nsec as u32)
    }

    #[test]
    #[ignore = "development performance budget"]
    fn generic_ranking_stays_under_hot_path_budget() {
        let names = (0..5_000)
            .map(|index| format!("command-{index:04}"))
            .collect::<Vec<_>>();
        let mut samples = Vec::with_capacity(1_000);
        for _ in 0..1_000 {
            let started = thread_cpu_time();
            let mut sink = CandidateSink::new(4_096);
            for name in &names {
                if let Some(candidate) =
                    Candidate::from_borrowed("cm42", name, name, CandidateKind::Command, true, 0)
                {
                    sink.push(candidate);
                }
            }
            std::hint::black_box(sink.finish());
            samples.push(thread_cpu_time().saturating_sub(started));
        }
        samples.sort_unstable();
        let p99 = samples[samples.len() * 99 / 100];
        eprintln!(
            "completion ranking thread-CPU p99: {p99:?} for {} names",
            names.len()
        );
        if !cfg!(debug_assertions) {
            assert!(p99 < std::time::Duration::from_micros(500));
        }
    }
}
