use utils::policy::pest::{PolicyValue, PolicyType};
use pest::iterators::Pair;

#[derive(Parser)]
#[grammar = "json.policy.pest"]
pub(crate) struct JSONPolicyParser;

pub(crate) fn parse(pair: Pair<Rule>) -> PolicyValue {
    match pair.as_rule() {
        Rule::string => {
            let p = pair.into_inner().next().unwrap();
            PolicyValue::String((p.as_str(), p.line_col().1))
        },
        Rule::number => {
            let p = pair.into_inner().next().unwrap();
            PolicyValue::String((p.as_str(), p.line_col().1))
        },
        Rule::and => {
            let mut vec = Vec::new();
            for child in pair.into_inner() {
                vec.push(parse(child, ));
            }
            PolicyValue::Object((PolicyType::And, Box::new(PolicyValue::Array(vec))))
        },
        Rule::or => {
            let mut vec = Vec::new();
            for child in pair.into_inner() {
                vec.push(parse(child, ));
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