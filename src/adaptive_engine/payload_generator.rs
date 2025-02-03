use serde_json::{Value};
use std::collections::HashMap;

pub struct PayloadGenerator {
    context_rules: HashMap<&'static str, Vec<&'static str>>,
    base_payloads: Value
}

impl PayloadGenerator {
    pub fn new() -> Self {
        let mut rules = HashMap::new();
        rules.insert("react", vec!["{{}}", "dangerouslySetInnerHTML"]);
        rules.insert("angular", vec!["{{}}", "[innerHTML]"]);
        rules.insert("vue", vec!["v-html", "template"]);
        
        let payloads = include_str!("../../configs/payloads/xss_payloads.json");
        
        PayloadGenerator {
            context_rules: rules,
            base_payloads: serde_json::from_str(payloads).unwrap()
        }
    }

    pub fn generate(&self, tech_stack: &str) -> String {
        let context = self.detect_context(tech_stack);
        let mut output = String::new();
        
        for payload in self.base_payloads[context].as_array().unwrap() {
            output.push_str(&self.adapt_payload(payload.as_str().unwrap(), tech_stack));
            output.push('\n');
        }
        
        output
    }

    fn detect_context(&self, tech: &str) -> &str {
        self.context_rules.keys()
            .find(|&&k| tech.to_lowercase().contains(k))
            .unwrap_or(&"universal")
    }

    fn adapt_payload(&self, payload: &str, tech: &str) -> String {
        match tech {
            "react" => format!("<>{}</>", payload.replace("'", "{\"'\"}")),
            "angular" => format!("{{{{ {} }}}}", payload),
            _ => payload.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_react_payload() {
        let gen = PayloadGenerator::new();
        let payload = gen.generate("react");
        assert!(payload.contains("dangerouslySetInnerHTML"));
    }
}