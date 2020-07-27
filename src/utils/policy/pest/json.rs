use std::fmt;
use pest::error::Error;
use utils::policy::pest::{
    PolicyValue,
    PolicyLanguage,
    PolicyValue::{
        Object,
        Array,
        String,
        Number,
        Boolean,
        Null
    }
};
use pest::iterators::Pair;

#[derive(Parser)]
#[grammar = "json.policy.pest"]
pub(crate) struct JSONPolicyParser;

pub(crate) fn parse(pair: Pair<Rule>) -> PolicyValue {
    match pair.as_rule() {
        Rule::node => PolicyValue::Object(
            pair.into_inner()
                .map(|pair| {
                    let mut inner_rules = pair.into_inner();
                    let name = inner_rules
                        .next()
                        .unwrap()
                        .into_inner()
                        .next()
                        .unwrap()
                        .as_str();
                    let value: PolicyValue = parse(inner_rules.next().unwrap());
                    Box::new((name, Some(value)))
                })
                .next().unwrap(),
        ),
        Rule::array => PolicyValue::Array(pair.into_inner().map(parse).collect()),
        Rule::string => PolicyValue::String(pair.into_inner().next().unwrap().as_str()),
        Rule::number => PolicyValue::Number(pair.as_str().parse().unwrap()),
        Rule::boolean => PolicyValue::Boolean(pair.as_str().parse().unwrap()),
        Rule::null => PolicyValue::Null,
        Rule::content
        | Rule::EOI
        | Rule::nodepair
        | Rule::childpair
        | Rule::inner
        | Rule::char
        | Rule::value
        | Rule::NAME
        | Rule::CHILDREN
        | Rule::NODES
        | Rule::WHITESPACE => unreachable!(),
    }
}