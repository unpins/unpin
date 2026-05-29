// Quick verification - if generate returns Result and we're not using it,
// would Rust warn us?
#[must_use]
fn returns_result() -> Result<(), std::io::Error> {
    Ok(())
}

fn test() {
    returns_result();  // This should warn if #[must_use] is present
}
