use utils::policy::pest::{PolicyValue, PolicyType};
use pest::iterators::Pair;

#[derive(Parser)]
#[grammar = "json.policy.pest"]
pub(crate) struct JSONPolicyParser;

pub(crate) fn parse(pair: Pair<Rule>) -> PolicyValue {
    match pair.as_rule() {
        Rule::string => PolicyValue::String(pair.into_inner().next().unwrap().as_str()),
        Rule::number => PolicyValue::String(pair.into_inner().next().unwrap().as_str()),
        Rule::and => {
            let mut vec = Vec::new();
            for child in pair.into_inner() {
                vec.push(parse(child));
            }
            PolicyValue::Object((PolicyType::And, Box::new(PolicyValue::Array(vec))))
        },
        Rule::or => {
            let mut vec = Vec::new();
            for child in pair.into_inner() {
                vec.push(parse(child));
            }
            PolicyValue::Object((PolicyType::Or, Box::new(PolicyValue::Array(vec))))
        },
        Rule::content
        | Rule::EOI
        | Rule::inner
        | Rule::orinner
        | Rule::andinner
        | Rule::node
        | Rule::value
        | Rule::andvalue
        | Rule::orvalue
        | Rule::char
        | Rule::NAME
        | Rule::CHILDREN
        | Rule::COMMENT
        | Rule::QUOTE
        | Rule::WHITESPACE => unreachable!(),
    }
}