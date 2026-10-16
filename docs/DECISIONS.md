# Decisions

- **Own rule engine, not Progent's code.** Progent's `secagent` uses global mutable state, `input()` prompts, and `sys.exit()`, and allows Python callables as rules. We keep its JSON-Schema argument constraints and its Z3 idea, but rules are pure data so the updater can write them and the gate can audit them.
- **Provenance at the tool-call boundary, not CaMeL's interpreter.** CaMeL's README warns that its interpreter is a research artifact that likely has bugs, and running it costs an extra planner model per task. We label each argument by where its value appears: the user prompt, a specific tool-output field, or nowhere (unknown). This gives CaMeL-style origin checks deterministically. It's weaker than full dataflow tracking: a value the model transforms becomes "unknown", which fails closed.
- **Labeling config = named source groups.** Labels are field-level (e.g. `get_most_recent_transactions:subject`), so rules can trust a bank-generated `recipient` field while distrusting an attacker-writable `subject` field.
- **Absent arguments are unconstrained** (Progent semantics), so optional arguments like `update_scheduled_transaction.recipient` don't break rules.
- **ask_user in live runs:** approved in benign episodes (counted as a confirmation) and declined when an injection is present. This models an attentive user; confirmations are reported as the usability cost.
- **Agent model:** gpt-4o-mini via OpenRouter. It's cheap, widely studied on AgentDojo, and vulnerable enough to give the loop something to learn from.
