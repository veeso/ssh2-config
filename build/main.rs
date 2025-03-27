mod define_parser;
mod openssh;
mod src_writer;

fn main() -> anyhow::Result<()> {
    if !src_writer::should_rebuild() {
        return Ok(());
    }

    let prefs = openssh::get_my_prefs()?;
    src_writer::write_source(prefs)?;

    Ok(())
}
