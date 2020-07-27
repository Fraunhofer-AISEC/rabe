use pest::iterators::Pair;
use utils::policy::pest::PolicyValue;

#[derive(Parser)]
#[grammar = "human.policy.pest"]
pub(crate) struct HumanPolicyParser;

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
                    let value = parse(inner_rules.next().unwrap());
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
        | Rule::attribute
        | Rule::inner
        | Rule::char
        | Rule::OP
        | Rule::BRACEOPEN
        | Rule::BRACECLOSE
        | Rule::WHITESPACE => unreachable!(),
    }
}