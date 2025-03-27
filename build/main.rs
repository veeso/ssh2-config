mod define_parser;
mod openssh;
mod src_writer;

fn main() -> anyhow::Result<()> {
    if !src_writer::should_rebuild() {
        return Ok(());
    }

    // if we are on docs.rs, WE DON'T HAVE ACCESS TO NETWORK, USE DEFAULT PREFS
    let prefs = if std::env::var("DOCS_RS").is_ok() {
        openssh::MyPrefs::default()
    } else {
        openssh::get_my_prefs()?
    };

    src_writer::write_source(prefs)?;

    Ok(())
}
