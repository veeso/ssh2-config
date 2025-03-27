mod define_parser;
mod openssh;
mod src_writer;

fn main() -> anyhow::Result<()> {
    if !src_writer::should_rebuild() {
        return Ok(());
    }

    // if we are on docs.rs, WE DON'T HAVE ACCESS TO NETWORK, USE DEFAULT PREFS
    #[cfg(docsrs)]
    {
        let prefs = openssh::MyPrefs::default();
        src_writer::write_source(prefs)?;
    }

    #[cfg(not(docsrs))]
    {
        let prefs = openssh::get_my_prefs()?;
        src_writer::write_source(prefs)?;
    }

    Ok(())
}
