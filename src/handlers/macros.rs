/// Extract the required `from` JID attribute from a `NodeRef`, or log a warning
/// and return from the enclosing function.
///
/// Handler functions across the crate share the exact same pattern: pull `from`,
/// bail out with a warning if it is missing. This macro collapses that five-line
/// `match` into one line while preserving the (optional) log target.
///
/// # Variants
///
/// * `require_from_jid!(node, "Context")` — warns without a target, then `return;`.
/// * `require_from_jid!(node, target: "Client/Foo", "Context")` — warns with target.
#[macro_export]
macro_rules! require_from_jid {
    ($node:expr, $context:literal) => {
        match $node.attrs().optional_jid("from") {
            Some(jid) => jid,
            None => {
                ::log::warn!(concat!($context, " missing required 'from' attribute"));
                return;
            }
        }
    };
    ($node:expr, target: $target:literal, $context:literal) => {
        match $node.attrs().optional_jid("from") {
            Some(jid) => jid,
            None => {
                ::log::warn!(
                    target: $target,
                    concat!($context, " missing required 'from' attribute"),
                );
                return;
            }
        }
    };
}
