mod define_parser;
mod openssh;
mod src_writer;

fn main() -> anyhow::Result<()> {
    // If reload SSH ALGO is not set, we don't need to do anything
    if std::env::var("RELOAD_SSH_ALGO").is_err() {
        return Ok(());
    }

    let prefs = openssh::get_my_prefs()?;
    src_writer::write_source(prefs)?;

    Ok(())
}
